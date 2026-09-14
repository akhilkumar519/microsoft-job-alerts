"""One cloud scan, with durable job IDs, pending alerts and an access-stop latch."""
import argparse
import json
import logging
import os
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
                core.send(channel, 'Cloud check passed: Microsoft search and job details loaded for both cities. Telegram delivery works. Monitoring has NOT started yet; run start in GitHub Actions.', secrets)
            with db:
                core.setmeta(db, 'cloud_verified', '1')
            print('PASS: cloud browser and notification check completed.')
        else:
            try:
                core.flush(db, secrets)
            except core.MonitorError:
                logging.error('Pending deliveries remain; continuing detection.')
            browser.scan(db, source, secrets)
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
