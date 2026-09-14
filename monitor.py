"""Microsoft job monitor. Python 3.11+, standard library only."""
import argparse
import email.utils
import hashlib
import html
import json
import logging
import os
from pathlib import Path
import re
import smtplib
import sqlite3
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parent
BASE = 'https://apply.careers.microsoft.com'
LOG = logging.getLogger('monitor')

class MonitorError(Exception):
    pass

class RateLimit(MonitorError):
    def __init__(self, seconds=3600):
        self.seconds = max(900, seconds)
        super().__init__('Microsoft rate limited the request; waiting before checking again.')

class TextParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []
    def handle_starttag(self, tag, attrs):
        if tag in ('p', 'br', 'li', 'h1', 'h2', 'h3', 'h4', 'div'): self.parts.append('\n')
    def handle_endtag(self, tag):
        if tag in ('p', 'li', 'h1', 'h2', 'h3', 'h4', 'div'): self.parts.append('\n')
    def handle_data(self, data): self.parts.append(data)

def plain(value):
    p = TextParser(); p.feed(str(value or ''))
    return '\n'.join(' '.join(x.split()) for x in ''.join(p.parts).splitlines() if x.strip())

def retry_seconds(value):
    try: return max(900, int(value))
    except (ValueError, TypeError):
        try: return max(900, int(email.utils.parsedate_to_datetime(value).timestamp() - time.time()))
        except (ValueError, TypeError, OverflowError): return 3600

def request(url, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={
        'User-Agent': 'PersonalMicrosoftJobMonitor/1.0',
        'Accept': 'application/json', 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        if e.code == 429 and url.startswith(BASE): raise RateLimit(retry_seconds(e.headers.get('Retry-After'))) from None
        # Never include URLs: Telegram bot tokens are part of their URL.
        raise MonitorError(f'Request rejected (HTTP {e.code}); check access/configuration. No bypass attempted.') from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise MonitorError('Network request failed or timed out.') from None

def api(path, params):
    try: data = json.loads(request(BASE + path + '?' + urllib.parse.urlencode(params)))
    except json.JSONDecodeError: raise MonitorError('Microsoft returned non-JSON content; search adapter needs review.') from None
    if not isinstance(data, dict) or not isinstance(data.get('data'), dict):
        raise MonitorError('Microsoft response schema changed: expected data object.')
    return data['data']

def robots_allowed(document, url, product='PersonalMicrosoftJobMonitor'):
    """REP longest-path matching; merge matching groups (RFC 9309).

    urllib.robotparser on some Python versions uses the first matching rule,
    incorrectly letting Disallow: / override a more specific Allow.
    """
    groups = []
    agents, rules = [], []
    has_rules = False
    for line in document.lstrip('\ufeff').splitlines():
        line = line.split('#', 1)[0].strip()
        if ':' not in line:
            continue
        key, value = (part.strip() for part in line.split(':', 1))
        key = key.lower()
        if key == 'user-agent':
            if has_rules:
                groups.append((agents, rules))
                agents, rules, has_rules = [], [], False
            agents.append(value.lower())
        elif key in ('allow', 'disallow') and agents:
            has_rules = True
            if value:
                rules.append((value, key == 'allow'))
    if agents:
        groups.append((agents, rules))
    if not groups:
        # Do not mistake HTML/challenge responses for a usable robots file.
        raise MonitorError('Robots response contains no user-agent groups; cannot verify site rules.')
    selected = [rules for agents, rules in groups if product.lower() in agents]
    if not selected:
        selected = [rules for agents, rules in groups if '*' in agents]

    def normalized(value):
        value = urllib.parse.quote(value, safe="/%:*?$!&'()+,;=@-._~")
        def percent(match):
            char = chr(int(match.group(1), 16))
            if char.isascii() and (char.isalnum() or char in '-._~'):
                return char
            return '%' + match.group(1).upper()
        return re.sub(r'%([0-9a-fA-F]{2})', percent, value)

    parsed = urllib.parse.urlsplit(url)
    target = normalized((parsed.path or '/') + ('?' + parsed.query if parsed.query else ''))
    matches = []
    for rules in selected:
        for raw, allowed in rules:
            pattern = normalized(raw)
            terminal = pattern.endswith('$')
            body = pattern[:-1] if terminal else pattern
            regex = '^' + '.*'.join(re.escape(part) for part in body.split('*'))
            if terminal:
                regex += '$'
            if re.search(regex, target):
                specificity = len(urllib.parse.unquote_to_bytes(body.replace('*', '')))
                matches.append((specificity, allowed))
    return max(matches, default=(0, True))[1]


class MicrosoftSource:
    """Uses the public site's own endpoint; not a supported/versioned public API."""
    def __init__(self, config): self.config = config; self.robots_at = 0; self.robot = None
    def policy(self):
        if time.time() - self.robots_at > 86400:
            self.robot = request(BASE + '/robots.txt')
            self.robots_at = time.time()
        for path in ('/api/pcsx/search', '/api/pcsx/position_details'):
            if not robots_allowed(self.robot, BASE + path):
                raise MonitorError('Microsoft robots rules disallow this endpoint; monitor stopped fetching.')
    def listings(self):
        self.policy(); jobs = {}
        for city in self.config['search_locations']:
            for query in self.config['queries']:
                start = 0; page_ids = set()
                for _ in range(self.config.get('max_pages', 100)):
                    data = api('/api/pcsx/search', dict(domain='microsoft.com', query=query, location=city, start=start))
                    rows, count = data.get('positions'), data.get('count')
                    if not isinstance(rows, list) or not isinstance(count, int) or count < 0:
                        raise MonitorError('Search schema changed: expected positions list and integer count.')
                    if not rows:
                        if start < count: raise MonitorError('Search returned an incomplete page; baseline unchanged.')
                        break
                    ids = []
                    for row in rows:
                        if not isinstance(row, dict) or row.get('id') is None:
                            raise MonitorError('Search schema changed: missing job id.')
                        jid = str(row['id']); ids.append(jid); jobs[jid] = row
                    signature = tuple(ids)
                    if signature in page_ids: raise MonitorError('Repeated search page; refusing incomplete scan.')
                    page_ids.add(signature); start += len(rows)
                    if start >= count: break
                    time.sleep(2)
                else: raise MonitorError('Pagination limit reached; increase max_pages after reviewing results.')
                time.sleep(2)
        return jobs
    def detail(self, jid, row):
        data = api('/api/pcsx/position_details', dict(domain='microsoft.com', position_id=jid, hl='en'))
        # Explicit known/common field variants; fail closed when core fields are absent.
        data = data.get('position', data)
        if not isinstance(data, dict): raise MonitorError('Unexpected job detail schema.')
        merged = dict(row); merged.update(data)
        title = merged.get('name') or merged.get('title')
        description = merged.get('job_description') or merged.get('description') or merged.get('jobDescription')
        location = merged.get('locations') or merged.get('location') or merged.get('standardizedLocations')
        if not isinstance(title, str) or not isinstance(description, str) or not location:
            raise MonitorError('Job detail fields could not be parsed. Live adapter needs review; no job marked seen.')
        if isinstance(location, (dict, list)): location = json.dumps(location, ensure_ascii=False)
        return dict(id=jid, title=title, location=str(location), description=plain(description),
                    posted=merged.get('posted_ts') or merged.get('postedTs') or merged.get('datePosted') or 'Not supplied',
                    url=BASE + '/careers?' + urllib.parse.urlencode({'pid': jid}))

YEARS = re.compile(r'\b(\d{1,2})\s*(?:\+|(?:-|–|to)\s*\d{1,2})?\s*(?:years?|yrs?)\b', re.I)
SENIOR = re.compile(r'\b(senior|sr\.?|principal|lead|manager|director|architect|staff)\b', re.I)

def classify(job):
    """Conservative triage, not a determination of eligibility."""
    title = job['title']
    if not re.search(r'\bsoftware\s+engineer(?:ing)?\b', title, re.I): return None
    if SENIOR.search(title): return None
    if not re.search(r'\b(hyderabad|bengaluru|bangalore)\b', job['location'], re.I): return None
    text = job['description']
    # Only a clearly identified minimum/required qualifications section can exclude.
    found = re.search(r'(?:required|minimum|basic)\s+qualifications\s*:?(.*)', text, re.I | re.S)
    if not found: return ('Check eligibility', 'Minimum qualifications section not clearly identified.')
    required = re.split(r'(?:preferred|additional)\s+qualifications|responsibilities|benefits', found[1], flags=re.I)[0]
    nums = [int(m.group(1)) for m in YEARS.finditer(required)]
    alternative = bool(re.search(r'\bor\b|equivalent experience', required, re.I))
    if nums and min(nums) > 2 and not alternative: return None
    if nums and max(nums) <= 2 and not alternative:
        return ('Potential 0–2-year match', 'Listed experience requirement: ' + ', '.join(f'{n}+ years' for n in sorted(set(nums))) + '. Check degree and skill requirements.')
    if re.search(r'no (?:prior |professional )?experience required|0\s*[-–]\s*2\s*years', required, re.I) and not any(n > 2 for n in nums):
        return ('Potential 0–2-year match', 'Entry-level experience wording found. Check full qualifications.')
    return ('Check eligibility', 'Alternative, unstated, or mixed experience requirements; review the description.')

def message(job, verdict):
    excerpt = job['description'][:1800]
    return (f"Microsoft: {job['title']}\n{job['location']}\n{verdict[0]}\n{verdict[1]}\n"
            f"Job ID: {job['id']}\nSource posted value: {job['posted']}\n"
            f"First detected: {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n\n"
            f"{excerpt}\n\nApply: {job['url']}")[:3900]

def load_secrets():
    path = ROOT / 'secrets.json'
    data = json.loads(path.read_text()) if path.exists() else {}
    for key in ('TELEGRAM_BOT_TOKEN','TELEGRAM_CHAT_ID','SMTP_HOST','SMTP_PORT','SMTP_USER','SMTP_PASSWORD','EMAIL_FROM','EMAIL_TO','SMTP_MODE','HEALTHCHECK_URL'):
        if os.environ.get(key): data[key] = os.environ[key]
    return data

def channels(secrets):
    result = []
    if secrets.get('TELEGRAM_BOT_TOKEN') and secrets.get('TELEGRAM_CHAT_ID'): result.append('telegram')
    if secrets.get('SMTP_HOST') and secrets.get('EMAIL_FROM') and secrets.get('EMAIL_TO'): result.append('email')
    if not result: raise MonitorError('Configure Telegram or email first: python setup.py')
    return result

def send(channel, text, secrets):
    if channel == 'telegram':
        url = 'https://api.telegram.org/bot' + secrets['TELEGRAM_BOT_TOKEN'] + '/sendMessage'
        try: response = json.loads(request(url, {'chat_id':secrets['TELEGRAM_CHAT_ID'], 'text':text, 'link_preview_options':{'is_disabled':True}}))
        except json.JSONDecodeError: raise MonitorError('Invalid Telegram response.') from None
        if not response.get('ok'): raise MonitorError('Telegram did not confirm delivery.')
    else:
        msg = EmailMessage(); msg['Subject'] = text.splitlines()[0][:160]
        msg['From'] = secrets['EMAIL_FROM']; msg['To'] = secrets['EMAIL_TO']; msg.set_content(text)
        mode = secrets.get('SMTP_MODE','starttls')
        if mode not in ('ssl','starttls'): raise MonitorError('SMTP_MODE must be ssl or starttls.')
        cls = smtplib.SMTP_SSL if mode == 'ssl' else smtplib.SMTP
        try:
            options = {'context': ssl.create_default_context()} if mode == 'ssl' else {}
            with cls(secrets['SMTP_HOST'], int(secrets.get('SMTP_PORT',465 if mode == 'ssl' else 587)), timeout=30, **options) as smtp:
                if mode == 'starttls': smtp.starttls(context=ssl.create_default_context())
                if secrets.get('SMTP_USER'): smtp.login(secrets['SMTP_USER'],secrets.get('SMTP_PASSWORD',''))
                refused = smtp.send_message(msg)
                if refused: raise MonitorError('Email recipient rejected.')
        except (smtplib.SMTPException,OSError): raise MonitorError('Email delivery failed; check SMTP settings.') from None

def database(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript('''CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS outbox (id TEXT, channel TEXT, body TEXT, delivered INTEGER DEFAULT 0, PRIMARY KEY(id,channel));''')
    return db

def getmeta(db,key,default=''):
    row = db.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone()
    return row[0] if row else default

def setmeta(db,key,value):
    db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',(key,str(value)))

def flush(db,secrets):
    failed = False
    for jid,channel,body in db.execute('SELECT id,channel,body FROM outbox WHERE delivered=0').fetchall():
        try:
            send(channel,body,secrets)
            db.execute('UPDATE outbox SET delivered=1 WHERE id=? AND channel=?',(jid,channel)); db.commit()
        except MonitorError:
            failed=True; LOG.error('%s delivery failed; retained for next run.',channel)
    if failed: raise MonitorError('Some notifications remain pending; check delivery settings.')

def cycle(db,source,secrets):
    remaining = float(getmeta(db,'next_allowed','0'))-time.time()
    if remaining > 0: raise RateLimit(int(remaining))
    available = channels(secrets)
    config_hash = hashlib.sha256(json.dumps(source.config,sort_keys=True).encode()).hexdigest()
    if getmeta(db,'config_hash') not in ('',config_hash):
        raise MonitorError('Filters changed. Use a different state_file to establish a new baseline.')
    listings = source.listings()  # Do not mutate baseline until ALL search pages succeeded.
    if getmeta(db,'initialized') != '1':
        # Validate detail parsing before recording a successful initial baseline.
        for jid,row in list(listings.items())[:1]:
            source.detail(jid,row)
        with db:
            db.executemany('INSERT OR IGNORE INTO seen VALUES (?)',[(jid,) for jid in listings])
            setmeta(db,'initialized','1'); setmeta(db,'config_hash',config_hash)
        LOG.info('Baseline saved: %s existing jobs. Future new matching jobs will alert.',len(listings))
    else:
        for jid,row in listings.items():
            if db.execute('SELECT 1 FROM seen WHERE id=?',(jid,)).fetchone(): continue
            job = source.detail(jid,row); verdict = classify(job)
            with db:
                if verdict:
                    for channel in available:
                        db.execute('INSERT OR IGNORE INTO outbox(id,channel,body) VALUES (?,?,?)',(jid,channel,message(job,verdict)))
                db.execute('INSERT INTO seen VALUES (?)',(jid,))
            time.sleep(2)
    flush(db,secrets)
    with db: setmeta(db,'last_success',datetime.now(timezone.utc).isoformat()); setmeta(db,'consecutive_errors',0)
    if secrets.get('HEALTHCHECK_URL'): request(secrets['HEALTHCHECK_URL'])
    LOG.info('Check complete: %d listings; notifications up to date.',len(listings))

def run(args):
    config = json.loads((ROOT / 'config.json').read_text()); secrets = load_secrets()
    source = MicrosoftSource(config)
    if args.test_notify:
        for channel in channels(secrets): send(channel,'Microsoft job monitor: test notification. Monitoring is not started by this test.',secrets)
        print('Test notification accepted by each configured provider.'); return
    if args.check:
        rows = source.listings()
        print('Live search succeeded:',len(rows),'unique listings')
        # Check details even before baseline so incompatible schemas cannot appear healthy.
        for jid,row in list(rows.items())[:3]:
            job=source.detail(jid,row); print(job['title'],job['location'],classify(job)); time.sleep(2)
        print('Read-only check complete; no baseline saved and no alerts sent.'); return
    db = database(ROOT / config.get('state_file','data/state.sqlite3'))
    if args.status:
        print('Initialized:',getmeta(db,'initialized','0'))
        print('Last successful check:',getmeta(db,'last_success','never'))
        print('Pending notifications:',db.execute('SELECT count(*) FROM outbox WHERE delivered=0').fetchone()[0]); return
    channels(secrets)
    interval = max(900,int(config.get('interval_seconds',900)))
    # OS file lock is released even on a crash; prevents duplicate concurrent processes.
    (ROOT/'data').mkdir(exist_ok=True)
    with (ROOT/'data'/'monitor.lock').open('a+b') as lock:
        try:
            if os.name == 'nt':
                import msvcrt
                lock.seek(0); lock.write(b'0'); lock.flush(); lock.seek(0); msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError: raise MonitorError('Another monitor is already running.') from None
        while True:
            delay = interval
            try:
                # Retry previously queued notifications independently of Microsoft's availability.
                flush(db,secrets)
                cycle(db,source,secrets)
            except MonitorError as error:
                LOG.error('%s',error)
                failures=int(getmeta(db,'consecutive_errors','0'))+1
                with db:
                    setmeta(db,'consecutive_errors',failures)
                    if isinstance(error,RateLimit):
                        delay=max(interval,error.seconds); setmeta(db,'next_allowed',time.time()+delay)
                # Alert once per six hours; source errors never look like a successful empty scan.
                if time.time()-float(getmeta(db,'last_failure_alert','0')) > 21600:
                    sent=False
                    for channel in channels(secrets):
                        try: send(channel,'Microsoft job monitor needs attention: '+str(error)+' Last success: '+getmeta(db,'last_success','never'),secrets); sent=True
                        except MonitorError: pass
                    if sent:
                        with db: setmeta(db,'last_failure_alert',time.time())
                if not args.loop: raise
            if not args.loop: return
            LOG.info('Next check in %d seconds.',delay); time.sleep(delay)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group()
    for name in ('loop','check','test-notify','status'): group.add_argument('--'+name,action='store_true')
    try: run(parser.parse_args())
    except KeyboardInterrupt: print('Stopped.')
    except (MonitorError,ValueError,KeyError) as error:
        LOG.error('%s',error); raise SystemExit(1)
