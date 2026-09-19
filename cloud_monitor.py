"""One cloud scan, with durable job IDs, pending alerts and an access-stop latch."""
import argparse
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import browser_monitor as browser
import monitor as core

STATE = Path(__file__).with_name('cloud-state.json')
TABLES = {'meta': 2, 'seen': 1, 'outbox': 4}


def restore(db):
    if not STATE.exists():
        return
    data = json.loads(STATE.read_text(encoding='utf-8'))
    if data.get('version') != 1:
        raise core.MonitorError('Unrecognized saved state; refusing to reset the baseline.')
    with db:
        for table, columns in TABLES.items():
            rows = data[table]
            if not isinstance(rows, list) or any(len(row) != columns for row in rows):
                raise core.MonitorError('Invalid saved state; refusing to reset the baseline.')
            db.executemany(f'INSERT INTO {table} VALUES ({",".join("?" for _ in range(columns))})', rows)


def save(db):
    data = {'version': 1}
    for table in TABLES:
        data[table] = db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall()
    temp = STATE.with_suffix('.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temp.replace(STATE)


def normalized(value):
    return ' '.join(value.split())


def snapshot(job):
    text = job.get('description', '')
    # Compare the qualifications section, excluding benefits and other site chrome.
    match = re.search(r'\bQualifications\b(.*?)(?:\nBenefits\b|\nMicrosoft is an equal opportunity|\Z)', text, re.I | re.S)
    qualifications = normalized(match.group(1) if match else '')
    posted = job.get('posted', '')
    # Relative age is not a new posting date and must never cause repeat alerts.
    try:
        posted = datetime.strptime(posted.strip(), '%b %d, %Y').date().isoformat()
    except ValueError:
        posted = posted if re.fullmatch(r'\d{4}-\d{2}-\d{2}', posted) else None
    number = re.search(r'Job number\s*\n\s*(\d+)', text)
    return dict(title=normalized(job['title']), location=normalized(job['location']),
                posted=posted, qualifications=qualifications,
                job_number=number.group(1) if number else None)


def scan_v2(db, source, secrets):
    started = datetime.now(timezone.utc).isoformat(timespec='seconds')
    rows = source.listings()  # Must finish both cities before recording any absence.
    # Only a complete search can establish disappearance. Persist presence per job
    # so a later detail failure cannot duplicate a reappearance alert.
    with db:
        for key, raw in db.execute("SELECT key,value FROM meta WHERE key LIKE 'v2_job:%'").fetchall():
            old_record = json.loads(raw)
            if key[len('v2_job:'):] not in rows and old_record.get('present', True):
                old_record['present'] = False
                core.setmeta(db, key, json.dumps(old_record, ensure_ascii=False))
    first = core.getmeta(db, 'initialized') != '1'
    checked = queued = 0
    for jid, card in rows.items():
        if not browser.candidate(card):
            with db:
                db.execute('INSERT OR IGNORE INTO seen VALUES (?)', (jid,))
            continue
        job = source.detail(card)  # Recheck existing IDs as well as new IDs.
        checked += 1
        label = browser.verdict(job)
        current = snapshot(job)
        key = 'v2_job:' + jid
        old_raw = core.getmeta(db, key)
        old = json.loads(old_raw) if old_raw else None
        seen = bool(db.execute('SELECT 1 FROM seen WHERE id=?', (jid,)).fetchone())
        legacy_alert = bool(db.execute('SELECT 1 FROM outbox WHERE id=? LIMIT 1', (jid,)).fetchone())
        event = None
        if label and not first:
            if old is None:
                if not seen:
                    event = 'Newly detected job'
                elif not legacy_alert:
                    event = 'Catch-up: existing job never previously alerted'
            elif not old['eligible']:
                event = 'Previously reviewed job now potentially eligible'
            elif not old.get('present', True):
                event = 'Job returned to search results'
            elif old['snapshot'] != current:
                event = 'Updated listing: posting date, title, location or qualifications changed'
        revision = (old or {}).get('revision', 0) + (1 if event else 0)
        observed = datetime.now(timezone.utc).isoformat(timespec='seconds')
        record = dict(snapshot=current, eligible=bool(label), revision=revision, present=True,
                      first_observed=(old or {}).get('first_observed', observed),
                      last_checked=observed,
                      decision=event or ('Excluded by eligibility filter' if not label else 'Unchanged or already alerted'))
        with db:
            if event:
                event_key = f'{jid}:v2:{revision}'
                body = event + '\n' + core.message(job, label).replace('First detected:', 'Alert detected:')
                if current['job_number']:
                    body = 'Microsoft job number: ' + current['job_number'] + '\n' + body
                for channel in core.channels(secrets):
                    db.execute('INSERT OR IGNORE INTO outbox(id,channel,body) VALUES (?,?,?)',
                               (event_key, channel, body))
                queued += 1
            core.setmeta(db, key, json.dumps(record, ensure_ascii=False))
            db.execute('INSERT OR IGNORE INTO seen VALUES (?)', (jid,))
        logging.info('Job %s: %s; source date=%s', jid, record['decision'], current['posted'])
        try:
            core.flush(db, secrets)
        except core.MonitorError:
            logging.error('Delivery pending; keeping alert for the next run.')
    if first and not checked:
        raise core.MonitorError('No software-engineer candidates verified; refusing to initialize.')
    with db:
        core.setmeta(db, 'initialized', '1')
        core.setmeta(db, 'v2_search_ids', json.dumps(sorted(rows)))
        core.setmeta(db, 'last_scan_started', started)
        if first:
            for channel in core.channels(secrets):
                db.execute('INSERT OR IGNORE INTO outbox(id,channel,body) VALUES (?,?,?)',
                           ('baseline-v2', channel, 'Monitoring started. Existing jobs saved as baseline. New and changed matching listings will trigger alerts.'))
    core.flush(db, secrets)
    with db:
        core.setmeta(db, 'last_success', datetime.now(timezone.utc).isoformat())
    logging.info('Successful scan: %d unique jobs; %d candidate details checked; %d alert events queued.', len(rows), checked, queued)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['check', 'start', 'scan'])
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    import sqlite3
    db = core.database(Path('data/cloud-runtime.sqlite3'))
    # The runner is disposable; JSON is authoritative. Never merge stale local data.
    for table in TABLES:
        db.execute(f'DELETE FROM {table}')
    db.commit()
    restore(db)
    source = None
    secrets = core.load_secrets()
    core.channels(secrets)
    try:
        if core.getmeta(db, 'cloud_paused') == '1':
            raise core.MonitorError('Paused after an access restriction. Review the failed run; do not automatically retry or switch runners. After resolving the cause, set cloud_paused to 0 in cloud-state.json manually.')
        if args.mode == 'scan' and core.getmeta(db, 'initialized') != '1':
            raise core.MonitorError('Run check and then start manually before enabling the schedule.')
        if args.mode == 'start' and core.getmeta(db, 'cloud_verified') != '1':
            raise core.MonitorError('Run check successfully before start.')
        source = browser.BrowserSource()
        if args.mode == 'check':
            rows = source.listings()
            for city in browser.CITIES:
                jobs = [j for j in rows.values() if browser.candidate(j) and city.lower() in j['location'].lower()]
                if not jobs:
                    raise core.MonitorError('No candidate available to verify in ' + city)
                source.detail(jobs[0])
            for channel in core.channels(secrets):
                core.send(channel, 'Cloud check passed: Microsoft search and job details loaded for both cities. Telegram delivery works. This was only a test; it did not start or stop your existing schedule.', secrets)
            with db:
                core.setmeta(db, 'cloud_verified', '1')
            print('PASS: cloud browser and notification check completed.')
        else:
            try:
                core.flush(db, secrets)
            except core.MonitorError:
                logging.error('Pending deliveries remain; continuing detection.')
            scan_v2(db, source, secrets)
    except Exception as error:
        if isinstance(error, browser.SiteStop):
            with db:
                core.setmeta(db, 'cloud_paused', '1')
        reason = str(error) if isinstance(error, core.MonitorError) else type(error).__name__ + ': cloud scan failed; no successful scan recorded.'
        logging.error('%s', reason)
        for channel in core.channels(secrets):
            try:
                core.send(channel, 'Microsoft cloud monitor needs attention: ' + reason + '\nOpen GitHub Actions to review. Last successful scan: ' + core.getmeta(db, 'last_success', 'never'), secrets)
            except Exception:
                logging.error('Attention notification could not be delivered. Review the failed GitHub run.')
        return 1
    finally:
        if source:
            source.close()
        save(db)
        db.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
