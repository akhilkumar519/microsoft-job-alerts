"""Visible-browser Microsoft monitor. Keep beside monitor.py and secrets.json.
Install: python -m pip install playwright
Browser: python -m playwright install chromium
Check:   python browser_monitor.py --check
Run:     python browser_monitor.py --loop
Uses a separate browser and database; no login, stealth, proxy or API replay.
"""
import argparse
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import time
from urllib.parse import urlencode, urlsplit
import monitor as core

ROOT = Path(__file__).resolve().parent
BASE = core.BASE
LOG = logging.getLogger('browser-monitor')
CARD_SELECTOR = 'a[id^="job-card-"]'
READ_CARDS = "nodes => nodes.map(a => ({href:a.getAttribute('href'),text:a.innerText}))"
CITIES = ('Hyderabad', 'Bangalore')
TITLE = re.compile(r'\bsoftware\s+(?:development\s+)?engineer(?:ing)?\b', re.I)
SENIOR = re.compile(r'\b(senior|sr\.?|principal|lead|manager|director|architect|staff)\b', re.I)
STATE = ROOT / 'data' / 'browser-state.sqlite3'

class SiteStop(core.MonitorError):
    """Access restriction: stop, never automatically try another client."""


def parse_card(raw):
    match = re.fullmatch(r'/careers/job/(\d+)', raw.get('href', ''))
    lines = [s.strip() for s in raw.get('text', '').splitlines() if s.strip()]
    if not match or len(lines) < 2:
        raise core.MonitorError('Job card format changed; scan was not recorded.')
    return dict(id=match[1], title=lines[0], location=lines[1],
                posted=next((s for s in lines[2:] if s.startswith('Posted ')), 'Not supplied'),
                url=BASE + raw['href'], description='')


def candidate(job):
    return bool(TITLE.search(job['title']) and not SENIOR.search(job['title']))


def verdict(job):
    if not candidate(job):
        return None
    # Multi-location cards may hide the target city; keep them for review.
    if not re.search(r'\b(hyderabad|bengaluru|bangalore)\b', job['location'], re.I):
        if not re.search(r'\+\s*\d+\s+more|multiple locations', job['location'], re.I):
            return None
        return ('Check eligibility and location', 'Search returned this multi-location job; confirm the city in the full listing.')
    body = re.sub('[\u200b-\u200f\ufeff]', '', job['description'])
    match = re.search(r'(?:required(?:\s*/\s*minimum)?|minimum|basic)\s+qualifications\s*:?(.*)', body, re.I | re.S)
    if not match:
        return ('Check eligibility', 'No clear minimum-experience section; read the full listing.')
    required = re.split(r'(?:preferred|additional)(?:\s*(?:/|or)\s*(?:preferred|additional))?\s+qualifications|job requirements|other requirements|responsibilities', match[1], flags=re.I)[0]
    years = [int(m.group(1)) for m in re.finditer(r'\b(\d{1,2})\s*(?:\+|(?:-|–|to)\s*\d{1,2})?\s*(?:years?|year\(s\)|yrs?)\b', required, re.I)]
    alternative = bool(re.search(r'\bOR\b|equivalent experience', required, re.I))
    if years and min(years) > 2 and not alternative:
        return None
    if years and max(years) <= 2 and not alternative:
        return ('Potential 0–2-year match', 'Experience figures: ' + ', '.join(str(n) for n in sorted(set(years))) + ' year(s). Check all other requirements.')
    return ('Check eligibility', 'Alternative or unclear requirements. A 2+ year requirement is not assumed suitable for a fresher.')


class BrowserSource:
    def __init__(self):
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as BrowserTimeout
        except ImportError:
            raise core.MonitorError('Install once: python -m pip install playwright ; then python -m playwright install chromium') from None
        self.Timeout = BrowserTimeout
        self.engine = sync_playwright().start()
        try:
            self.browser = self.engine.chromium.launch(headless=False)
            self.context = self.browser.new_context(viewport={'width': 1400, 'height': 1000})
            self.search = self.context.new_page()
            self.details = self.context.new_page()
        except Exception:
            self.engine.stop()
            raise core.MonitorError('Browser could not start. Run python -m playwright install chromium. A desktop session is required.') from None
        self.rules_at = 0
        self.rules = ''
        self.failures = {}
        for page in (self.search, self.details):
            page.set_default_timeout(15000)
            page.on('response', lambda response, p=page: self.observe(p, response))

    def observe(self, page, response):
        url = urlsplit(response.url)
        if url.hostname == 'apply.careers.microsoft.com' and (url.path.startswith('/api/pcsx/') or url.path.startswith('/careers') or url.path == '/robots.txt'):
            if response.status >= 400:
                self.failures[page] = response.status

    def check_error(self, page):
        code = self.failures.get(page)
        if code in (401, 403, 429):
            raise SiteStop(f'Microsoft returned HTTP {code} to the browser. Monitoring stopped; no automatic retry.')
        if code:
            raise core.MonitorError(f'Microsoft returned HTTP {code}; this scan is incomplete.')
        # Only inspect visible challenge/error text, not scripts or hidden state.
        text = page.locator('body').inner_text(timeout=5000)[:10000]
        if re.search(r'verify (?:that )?you are human|checking your browser|unusual traffic|automated queries|access denied|just a moment', text, re.I):
            raise SiteStop('The browser shows an access or human-verification screen. Monitoring stopped.')

    def wait(self, page, ready):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            self.check_error(page)
            value = ready()
            if value is not None:
                return value
            page.wait_for_timeout(750)
        raise core.MonitorError('Page did not finish loading within 90 seconds. No successful scan recorded.')

    def navigate(self, page, url):
        self.failures[page] = None
        try:
            response = page.goto(url, wait_until='domcontentloaded', timeout=60000)
            if response and response.status >= 400:
                self.failures[page] = response.status
            self.check_error(page)
        except self.Timeout:
            self.check_error(page)
            raise core.MonitorError('Browser navigation timed out. Scan incomplete.') from None

    def policy(self):
        if time.time() - self.rules_at < 86400:
            return
        # Public robots.txt already works with the existing program on the user's
        # machine. Job searches/details themselves use only visible browser pages.
        try:
            text = core.request(BASE + '/robots.txt')
        except core.RateLimit:
            raise SiteStop('Microsoft rate limited the robots check. Monitoring stopped.') from None
        for path in ('/careers', '/careers/job/1', '/api/pcsx/search', '/api/pcsx/position_details'):
            if not core.robots_allowed(text, BASE + path):
                raise SiteStop('Current robots rules disallow required browsing paths. Monitoring stopped.')
        self.rules = text
        self.rules_at = time.time()

    def read_page(self, city, start, expected_page):
        url = BASE + '/careers?' + urlencode(dict(query='software', location=city, start=start, sort_by='timestamp'))
        self.navigate(self.search, url)
        page = self.search
        def ready():
            heading = page.get_by_role('heading', name=re.compile(r'^[\d,]+ jobs?$'))
            if heading.count() != 1:
                return None
            total = int(re.sub(r'[^0-9]', '', heading.inner_text()))
            query = page.get_by_role('combobox', name='Search by job title, ID, or keyword', exact=True)
            location = page.get_by_role('combobox', name='City, state, or country/region', exact=True)
            if query.input_value().lower() != 'software' or location.input_value().lower() != city.lower():
                raise core.MonitorError('Displayed search filters differ from requested filters.')
            if not page.get_by_role('button', name='Sort by: Latest', exact=True).count():
                return None
            if total == 0:
                return ([], 0, False)
            cards = page.get_by_role('list', name='Job search results', exact=True).locator(CARD_SELECTOR)
            if not cards.count():
                return None
            nav = page.get_by_role('navigation', name='Jobs pagination', exact=True)
            if not nav.count():
                return None
            numbers = re.findall(r'\d+', nav.inner_text())
            if len(numbers) != 2 or int(numbers[0]) != expected_page:
                return None
            rows = [parse_card(raw) for raw in cards.evaluate_all(READ_CARDS)]
            more = page.get_by_role('button', name='Next jobs', exact=True).is_enabled()
            return rows, total, more
        return self.wait(page, ready)

    def listings(self):
        self.policy()
        result = {}
        for city in CITIES:
            start, page_number, total = 0, 1, None
            city_seen = set()
            while page_number <= 100:
                rows, count, more = self.read_page(city, start, page_number)
                if total is None:
                    total = count
                elif total != count:
                    raise core.MonitorError('Search count changed during pagination. Restarting on a later scan avoids missing jobs.')
                ids = [j['id'] for j in rows]
                if len(ids) != len(set(ids)) or city_seen.intersection(ids):
                    raise core.MonitorError('Repeated job IDs across pages. Scan not recorded as complete.')
                city_seen.update(ids)
                for job in rows:
                    # Preserve a known target location if another search shows a hidden city.
                    old = result.get(job['id'])
                    if not old or re.search(r'Hyderabad|Bangalore|Bengaluru', job['location'], re.I):
                        result[job['id']] = job
                LOG.info('%s: page %d, collected %d/%d jobs', city, page_number, len(city_seen), total)
                if not more:
                    if len(city_seen) != total:
                        raise core.MonitorError('Final page does not match advertised job count; scan incomplete.')
                    break
                if not rows:
                    raise core.MonitorError('Empty intermediate page; scan incomplete.')
                start += len(rows)
                page_number += 1
                self.search.wait_for_timeout(1500)
            else:
                raise core.MonitorError('Search exceeds 100 pages; review before increasing the limit.')
        return result

    def detail(self, job):
        self.navigate(self.details, job['url'])
        page = self.details
        def ready():
            panel = page.get_by_role('tabpanel', name='Job description', exact=True)
            if not panel.count():
                return None
            text = panel.inner_text()
            if 'Job number' not in text or not re.search(r'\bQualifications\b', text, re.I):
                return None
            apply = page.get_by_role('link', name='Apply now', exact=True)
            if not apply.count():
                return None
            href = apply.get_attribute('href') or ''
            if not re.search(r'(?:\?|&)pid=' + re.escape(job['id']) + r'(?:&|$)', href):
                raise core.MonitorError('Loaded detail belongs to another job; refusing to send it.')
            out = dict(job)
            out['description'] = re.sub('[\u200b-\u200f\ufeff]', '', text)
            date = re.search(r'Date posted\s*\n([^\n]+)', text)
            if date:
                out['posted'] = date[1].strip()
            return out
        return self.wait(page, ready)

    def close(self):
        with suppress(Exception):
            self.context.close()
        with suppress(Exception):
            self.browser.close()
        with suppress(Exception):
            self.engine.stop()


def queue(db, job, label, secrets):
    text = core.message(job, label)
    for channel in core.channels(secrets):
        db.execute('INSERT OR IGNORE INTO outbox(id,channel,body) VALUES (?,?,?)', (job['id'], channel, text))


def scan(db, source, secrets):
    rows = source.listings()
    first = core.getmeta(db, 'initialized') != '1'
    if first:
        samples = [j for j in rows.values() if candidate(j)]
        if not samples:
            raise core.MonitorError('No software-engineer candidates found. Review the searches before initializing.')
        source.detail(samples[0])
        with db:
            db.executemany('INSERT OR IGNORE INTO seen VALUES (?)', [(jid,) for jid in rows])
            core.setmeta(db, 'initialized', '1')
            queue(db, dict(id='baseline-v1', title='Monitoring started', location='Hyderabad and Bangalore', posted='Not applicable', description=f'Baseline saved: {len(rows)} existing search results. New matching job IDs will trigger alerts. Cloud baseline saved. Enable MONITOR_ENABLED=true in GitHub repository variables after this run succeeds. Scheduled checks target every 15 minutes, but GitHub can delay or skip runs.', url=BASE+'/careers'), ('Baseline established', 'This is a monitor status message, not a job posting.'), secrets)
    else:
        for jid, job in rows.items():
            if db.execute('SELECT 1 FROM seen WHERE id=?', (jid,)).fetchone():
                continue
            label = None
            if candidate(job):
                job = source.detail(job)
                label = verdict(job)
            with db:
                if label:
                    queue(db, job, label, secrets)
                db.execute('INSERT INTO seen VALUES (?)', (jid,))
            # Deliver promptly even if a later detail fails.
            try:
                core.flush(db, secrets)
            except core.MonitorError:
                LOG.error('Delivery pending; will retry. Continuing job detection.')
    core.flush(db, secrets)
    with db:
        core.setmeta(db, 'last_success', datetime.now(timezone.utc).isoformat())
    LOG.info('Successful scan: %d unique jobs. Notifications up to date.', len(rows))


@contextmanager
def locked():
    STATE.parent.mkdir(exist_ok=True)
    with (STATE.parent / 'browser-monitor.lock').open('a+b') as handle:
        try:
            if os.name == 'nt':
                import msvcrt
                handle.seek(0); handle.write(b'0'); handle.flush(); handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise core.MonitorError('Another browser monitor is already running.') from None
        yield


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--check', action='store_true')
    group.add_argument('--loop', action='store_true')
    group.add_argument('--status', action='store_true')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    secrets = core.load_secrets()
    if args.status:
        db = core.database(STATE)
        print('Last success:', core.getmeta(db, 'last_success', 'never'))
        print('Pending alerts:', db.execute('SELECT COUNT(*) FROM outbox WHERE delivered=0').fetchone()[0])
        db.close(); return
    if not args.check:
        core.channels(secrets)
    with locked():
        source = BrowserSource()
        db = core.database(STATE)
        try:
            if args.check:
                rows = source.listings()
                # One candidate for each city, not just the first few jobs overall.
                checked = []
                for city in CITIES:
                    jobs = [j for j in rows.values() if candidate(j) and city.lower() in j['location'].lower()]
                    if not jobs:
                        raise core.MonitorError(f'No candidate to validate in {city}; inspect the site before relying on alerts.')
                    job = source.detail(jobs[0])
                    checked.append(job)
                    print('\nVERIFIED:', job['title'], '|', job['location'], '|', job['posted'], flush=True)
                    print('Experience:', verdict(job), '\nLink:', job['url'], flush=True)
                print(f'\nPASS: {len(rows)} unique search results; details verified in both cities. No baseline or alerts created.', flush=True)
                return
            failures = 0
            while True:
                started = time.monotonic()
                delay = 900
                try:
                    try:
                        core.flush(db, secrets)
                    except core.MonitorError:
                        LOG.error('Some queued deliveries still pending.')
                    scan(db, source, secrets)
                    failures = 0
                    delay = max(60, 900 - int(time.monotonic() - started))
                except Exception as error:
                    failures += 1
                    reason = str(error) if isinstance(error, core.MonitorError) else 'Browser closed, timed out, or changed unexpectedly.'
                    LOG.error('%s', reason)
                    for channel in core.channels(secrets):
                        try:
                            core.send(channel, 'Microsoft job monitor needs attention: ' + reason + '\nLast success: ' + core.getmeta(db, 'last_success', 'never'), secrets)
                        except core.MonitorError:
                            LOG.error('Could not deliver attention notification.')
                    if isinstance(error, SiteStop) or failures >= 3 or not args.loop:
                        raise core.MonitorError('Monitor stopped. Fix the reported issue before restarting.') from None
                    LOG.warning('Incomplete scan. Retrying after 15 minutes (%d/3 failures).', failures)
                if not args.loop:
                    break
                LOG.info('Next check in %d seconds. Keep this window open and the PC awake.', delay)
                time.sleep(delay)
        finally:
            db.close()
            source.close()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Stopped by user.')
    except Exception as error:
        print('ERROR:', str(error) if isinstance(error, core.MonitorError) else 'Unexpected browser error. Check installation and keep the browser window open.')
        raise SystemExit(1)
