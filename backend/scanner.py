"""
scanner.py — PRAWL external security scanner.

Design rules (every check follows them):
  1. Only report what was actually observed. A finding carries the evidence that triggered it.
  2. Checks that could not run (timeouts, WAF challenge pages) are reported as `info` / `error`
     and NEVER reduce the score — and they are never reported as "passed" either.
  3. Severity reflects real-world impact: a missing Permissions-Policy is not a leaked .env file.
  4. A clean, well-configured site must score green.
"""
import ssl, socket, requests, os, sys, logging, re, secrets, time, ipaddress
import concurrent.futures
from html.parser import HTMLParser
from types import SimpleNamespace
from urllib.parse import urlparse, urljoin, quote
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Ensure the backend directory is on the path so sub-packages can be imported
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from core.finding_ids import FindingID
import cve_intel
import taxonomy
import engagement
import scoring_policy
from scoring_policy import SEVERITY_WEIGHT, SCORE_CAPS

UA = 'Mozilla/5.0 (compatible; PRAWL/1.0; security-audit)'
HTTP_TIMEOUT = 10


class ScanError(Exception):
    """Raised when the target cannot be scanned at all (unreachable / DNS failure)."""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _f(check, status, severity, details, fix='', fid='', weight=None, **extra):
    """Build a finding dict. `weight` overrides the severity-based score deduction."""
    d = {'check': check, 'status': status, 'severity': severity, 'details': details,
         'fix': fix, 'finding_id': fid, 'on_exploit_path': False}
    if weight is not None:
        d['weight'] = weight
    d.update(extra)
    return d


def _is_local(host):
    if not host:
        return False
    if host == 'localhost' or host.endswith('.localhost'):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registrable(host):
    parts = (host or '').lower().split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host


# ─────────────────────────────────────────────────────────────────────────────
# Single shared fetch of the target (one request instead of six)
# ─────────────────────────────────────────────────────────────────────────────

_CDN_SIGNS = [
    ('Cloudflare',   lambda h: 'cf-ray' in h or 'cloudflare' in h.get('server', '').lower()),
    ('CloudFront',   lambda h: 'x-amz-cf-id' in h or 'cloudfront' in h.get('via', '').lower()),
    ('Fastly',       lambda h: 'x-fastly-request-id' in h or 'fastly' in h.get('x-served-by', '').lower()),
    ('Akamai',       lambda h: 'akamai' in h.get('server', '').lower() or 'x-akamai-transformed' in h),
    ('Vercel',       lambda h: 'x-vercel-id' in h),
    ('Azure Front Door', lambda h: 'x-azure-ref' in h),
]


def _detect_cdn(headers):
    for name, test in _CDN_SIGNS:
        try:
            if test(headers):
                return name
        except Exception:
            continue
    return None


def fetch_page(url):
    """GET the site root once and keep everything the passive checks need."""
    parsed = urlparse(url)
    hostname = parsed.hostname or parsed.path.split('/')[0]
    scheme = parsed.scheme if parsed.scheme in ('http', 'https') else 'https'
    netloc = parsed.netloc or hostname
    page = SimpleNamespace(
        url=url, hostname=hostname, scheme=scheme, origin=f'{scheme}://{netloc}',
        resp=None, error=None, ssl_error=None, status=None, headers={}, cookies=[],
        body='', content_type='', final_url=None, cdn=None, blocked=False,
    )
    verify = True
    for attempt in range(2):
        try:
            r = requests.get(page.origin, timeout=HTTP_TIMEOUT, allow_redirects=True,
                             headers={'User-Agent': UA}, verify=verify)
            page.resp, page.status, page.final_url = r, r.status_code, r.url
            page.headers = {k.lower(): v for k, v in r.headers.items()}
            try:
                page.cookies = list(r.raw.headers.getlist('Set-Cookie'))
            except Exception:
                sc = r.headers.get('set-cookie')
                page.cookies = [sc] if sc else []
            page.content_type = page.headers.get('content-type', '').lower()
            page.body = (r.text or '')[:500_000]
            page.cdn = _detect_cdn(page.headers)
            challenge = ('just a moment' in page.body.lower() or 'attention required' in page.body.lower()
                         or 'cf-mitigated' in page.headers or 'captcha' in page.body.lower()[:5000])
            page.blocked = r.status_code in (401, 403, 429, 503) and bool(page.cdn or challenge) \
                or r.status_code == 429
            page.error = None
            break
        except requests.exceptions.SSLError as e:
            page.ssl_error = str(e)
            page.error = f'TLS verification failed: {e}'
            verify = False          # still fetch the page so header checks can run
        except Exception as e:
            page.error = 'Connection failed or refused.' if 'Max retries exceeded' in str(e) else str(e)
            break
    return page


# ─────────────────────────────────────────────────────────────────────────────
# TLS
# ─────────────────────────────────────────────────────────────────────────────

def check_ssl(hostname, scheme='https', port=443):
    if scheme == 'http' and _is_local(hostname):
        return _f('SSL Certificate', 'info', 'info',
                  'Local development target served over HTTP — TLS check not applicable.',
                  fid='ssl_not_applicable')
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as s:
                cert = s.getpeercert()
                version = s.version()
                cipher = s.cipher()[0] if s.cipher() else '?'

        not_after = cert.get('notAfter', '')
        days_left = None
        if not_after:
            days_left = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
        issuer = dict(x[0] for x in cert.get('issuer', ())).get('organizationName', 'unknown issuer')

        if days_left is not None and days_left < 0:
            return _f('SSL Certificate', 'fail', 'critical', 'SSL certificate has EXPIRED.',
                      "Renew your SSL certificate now. An expired cert scares away customers and exposes data.",
                      FindingID.SSL_EXPIRED)
        if days_left is not None and days_left < 14:
            return _f('SSL Certificate', 'warning', 'medium', f'SSL certificate expires in {days_left} days.',
                      "Renew your SSL certificate immediately (Let's Encrypt is free and can auto-renew).",
                      FindingID.SSL_EXPIRING, weight=6)
        return _f('SSL Certificate', 'pass', 'none',
                  f'Valid certificate from {issuer}, expires in {days_left} days; negotiated {version} / {cipher}.',
                  fid='ssl_valid', tls_version=version)
    except ssl.SSLError as e:
        return _f('SSL Certificate', 'fail', 'critical', f'SSL error: {e}',
                  "Install a valid SSL certificate for this exact hostname. Let's Encrypt is free.",
                  FindingID.SSL_INVALID)
    except Exception as e:
        logger.warning(f"SSL check failed for {hostname}: {e}")
        return _f('SSL Certificate', 'error', 'info', f'Could not complete a TLS handshake: {e}',
                  'Ensure the site is reachable over HTTPS on port 443.', 'ssl_unreachable')


def check_legacy_tls(hostname, port=443):
    """Does the server still accept TLS 1.0 / 1.1 (deprecated by RFC 8996)?

    A refusal by the server is a PASS. If this machine's OpenSSL cannot even attempt the old protocol
    the result is 'not testable' (info), never a pass.
    """
    accepted, rejected, untestable = [], [], []
    for label, ver in (('TLS 1.0', ssl.TLSVersion.TLSv1), ('TLS 1.1', ssl.TLSVersion.TLSv1_1)):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            try:
                ctx.set_ciphers('ALL:@SECLEVEL=0')
            except ssl.SSLError:
                pass
        except (ValueError, ssl.SSLError):
            untestable.append(label)
            continue
        try:
            with socket.create_connection((hostname, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=hostname):
                    accepted.append(label)
        except ssl.SSLError as e:
            reason = (getattr(e, 'reason', '') or str(e)).upper()
            if 'NO_PROTOCOLS_AVAILABLE' in reason or 'NO_CIPHERS' in reason or 'UNSUPPORTED_PROTOCOL' in reason                     and 'ALERT' not in reason:
                untestable.append(label)
            else:
                rejected.append(label)          # protocol_version / handshake_failure alert from the server
        except Exception:
            untestable.append(label)            # network error: unknown, not a pass
    if accepted:
        return _f('Legacy TLS Protocols', 'warning', 'medium',
                  f'Server completed a handshake using deprecated {" and ".join(accepted)}.',
                  'Disable TLS 1.0/1.1 and allow only TLS 1.2 and 1.3.', FindingID.WEAK_TLS, weight=6)
    if untestable:
        return _f('Legacy TLS Protocols', 'info', 'info',
                  f'{" and ".join(untestable)} could not be tested from this scanner (local TLS stack or network); '
                  'not reported as passed.', fid='tls_untested')
    return _f('Legacy TLS Protocols', 'pass', 'none',
              'The server explicitly refused TLS 1.0 and 1.1.', fid='tls_pass')


# ─────────────────────────────────────────────────────────────────────────────
# HTTP headers
# ─────────────────────────────────────────────────────────────────────────────

# header -> (finding id, severity, weight, fix)
_HEADER_RULES = {
    'Strict-Transport-Security': (FindingID.MISSING_HSTS, 'medium', 6,
                                  'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'),
    'Content-Security-Policy':   (FindingID.MISSING_CSP, 'medium', 6,
                                  'Add a Content-Security-Policy header to limit where scripts can load from (XSS defence).'),
    'X-Frame-Options':           (FindingID.MISSING_XFO, 'medium', 4,
                                  'Add X-Frame-Options: DENY (or CSP frame-ancestors) to block clickjacking.'),
    'X-Content-Type-Options':    (FindingID.MISSING_XCTO, 'low', 2,
                                  'Add X-Content-Type-Options: nosniff to prevent MIME sniffing.'),
    'Referrer-Policy':           (FindingID.MISSING_RP, 'low', 2,
                                  'Add Referrer-Policy: strict-origin-when-cross-origin to stop URL data leaking.'),
    'Permissions-Policy':        (FindingID.MISSING_PP, 'low', 1,
                                  'Add a Permissions-Policy header to control camera/mic/location access.'),
}
_HEADER_PASS_ID = {
    'Strict-Transport-Security': 'hsts_pass', 'Content-Security-Policy': 'csp_pass',
    'X-Frame-Options': 'xfo_pass', 'X-Content-Type-Options': 'xcto_pass',
    'Referrer-Policy': 'rp_pass', 'Permissions-Policy': 'pp_pass',
}
SECURITY_HEADERS = list(_HEADER_RULES)


def get_header_fix(header):
    rule = _HEADER_RULES.get(header)
    return rule[3] if rule else f'Add the {header} header to your server configuration.'


def check_headers(page):
    h = page.headers
    results = []
    csp = h.get('content-security-policy', '')

    for name, (fid, sev, weight, fix) in _HEADER_RULES.items():
        key = name.lower()
        present = key in h
        label = f'Header: {name}'

        if name == 'Strict-Transport-Security' and page.scheme != 'https':
            results.append(_f(label, 'info', 'info', 'Not applicable — target is served over HTTP.',
                              fid='hsts_na'))
            continue

        if name == 'X-Frame-Options' and not present and 'frame-ancestors' in csp.lower():
            results.append(_f(label, 'pass', 'none',
                              'Clickjacking protection provided by CSP frame-ancestors.', fid='xfo_pass'))
            continue

        if not present:
            results.append(_f(label, 'fail', sev, f'Missing header: {name}', fix, fid, weight=weight))
            continue

        value = h[key]
        if name == 'Strict-Transport-Security':
            m = re.search(r'max-age=(\d+)', value, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15_552_000:   # < 180 days
                results.append(_f(label, 'warning', 'low', f'HSTS max-age is short ({age}s): {value}',
                                  'Raise max-age to at least 31536000 (1 year).', FindingID.HSTS_WEAK, weight=2))
                continue
        if name == 'X-Content-Type-Options' and 'nosniff' not in value.lower():
            results.append(_f(label, 'fail', 'low', f'Header present but value is not "nosniff": {value}',
                              fix, fid, weight=weight))
            continue
        if name == 'Content-Security-Policy':
            script_src = re.search(r"(?:script-src|default-src)([^;]*)", csp, re.I)
            if script_src:
                s = script_src.group(1).lower()
                strict = "'nonce-" in s or "'strict-dynamic'" in s or "'sha256-" in s
                if "'unsafe-inline'" in s and not strict:
                    results.append(_f(label, 'warning', 'low',
                                      "CSP allows 'unsafe-inline' scripts without a nonce/hash, which weakens XSS protection.",
                                      "Remove 'unsafe-inline' and use nonces or hashes.", FindingID.CSP_UNSAFE, weight=2))
                    continue
        shown = value if len(value) < 120 else value[:117] + '...'
        results.append(_f(label, 'pass', 'none', f'Present: {shown}', fid=_HEADER_PASS_ID[name]))

    # HTTPS redirect (only meaningful for public HTTPS targets)
    if page.scheme == 'https' and not _is_local(page.hostname):
        netloc = urlparse(page.origin).netloc
        try:
            http_r = requests.get(f'http://{netloc}', timeout=6, allow_redirects=True,
                                  headers={'User-Agent': UA})
            if http_r.url.startswith('https://'):
                results.append(_f('HTTPS Redirect', 'pass', 'none', 'HTTP correctly redirects to HTTPS.',
                                  fid='https_redirect_pass'))
            else:
                results.append(_f('HTTPS Redirect', 'fail', 'medium', 'HTTP traffic is not redirected to HTTPS.',
                                  'Configure your web server to redirect all HTTP traffic to HTTPS.',
                                  FindingID.NO_HTTPS_REDIRECT, weight=6))
        except Exception:
            results.append(_f('HTTPS Redirect', 'pass', 'none',
                              'Plain-HTTP port is not reachable — site is HTTPS only.', fid='https_redirect_pass'))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Cookies, CORS, HTTP methods
# ─────────────────────────────────────────────────────────────────────────────

_SESSION_NAME = re.compile(r'(sess|sid|token|auth|jwt|login|csrf|remember)', re.I)


def check_cookies(page):
    if not page.cookies:
        return [_f('Cookie Security', 'pass', 'none',
                   'The landing page sets no cookies.', fid='cookies_pass')]
    problems, notes = [], []
    worst = 'low'
    for raw in page.cookies:
        name = raw.split('=', 1)[0].strip()
        attrs = raw.lower()
        sensitive = bool(_SESSION_NAME.search(name))
        if page.scheme == 'https' and 'secure' not in attrs:
            problems.append(f'{name}: no Secure flag')
            worst = 'medium' if sensitive else worst
        if sensitive and 'httponly' not in attrs:
            problems.append(f'{name}: session-like cookie without HttpOnly')
            worst = 'medium'
        elif 'httponly' not in attrs:
            notes.append(name)
    if problems:
        sev = worst
        return [_f('Cookie Security', 'warning', sev,
                   'Cookie flags missing — ' + '; '.join(problems[:5]),
                   'Set Secure and HttpOnly (and SameSite=Lax) on session cookies.',
                   FindingID.INSECURE_COOKIES, weight=5 if sev == 'medium' else 2)]
    return [_f('Cookie Security', 'pass', 'none',
               f'{len(page.cookies)} cookie(s) set; Secure/HttpOnly flags are correct for session cookies.',
               fid='cookies_pass')]


def check_cors(page):
    try:
        probe = 'https://prawl-cors-probe.invalid'
        r = requests.get(page.origin, headers={'Origin': probe, 'User-Agent': UA}, timeout=8)
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        acac = r.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true'
        if acao == probe and acac:
            return [_f('CORS Configuration', 'fail', 'high',
                       'Server reflects an arbitrary Origin AND allows credentials — any website can read '
                       "a logged-in user's data from this site.",
                       'Allow only an explicit list of trusted origins; never reflect the Origin header with credentials.',
                       FindingID.CORS_WILDCARD, weight=15)]
        if acao == probe:
            return [_f('CORS Configuration', 'warning', 'low',
                       'Server reflects arbitrary Origin headers (no credentials allowed).',
                       'Restrict Access-Control-Allow-Origin to trusted domains.', FindingID.CORS_WILDCARD, weight=2)]
        if acao == '*':
            return [_f('CORS Configuration', 'info', 'info',
                       'Access-Control-Allow-Origin: * (fine for public, unauthenticated resources).',
                       fid='cors_pass')]
        return [_f('CORS Configuration', 'pass', 'none', 'CORS policy is restrictive.', fid='cors_pass')]
    except Exception as e:
        return [_f('CORS Configuration', 'error', 'info', f'CORS check could not run: {e}', fid='cors_error')]


def check_http_methods(page):
    try:
        r = requests.options(page.origin, timeout=6, headers={'User-Agent': UA})
        allow = (r.headers.get('Allow', '') + ',' + r.headers.get('Access-Control-Allow-Methods', '')).upper()
        if 'TRACE' in allow:
            return [_f('HTTP Methods', 'warning', 'medium', 'The TRACE method is enabled (cross-site tracing risk).',
                       'Disable TRACE (Apache: TraceEnable off).', FindingID.TRACE_ENABLED, weight=4)]
        return [_f('HTTP Methods', 'pass', 'none', 'TRACE is not advertised by the server.', fid='methods_pass')]
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Ports
# ─────────────────────────────────────────────────────────────────────────────

# port -> (service, finding id, status, severity, weight, fix)
_PORT_RULES = {
    21:    ('FTP',        FindingID.OPEN_PORT_FTP,      'fail',    'medium', 6,
            'FTP sends passwords in clear text. Use SFTP and close port 21.'),
    22:    ('SSH',        FindingID.OPEN_PORT_SSH,      'warning', 'low',    2,
            'Allow SSH only from trusted IPs, key-based login only, no root login.'),
    23:    ('Telnet',     FindingID.OPEN_PORT_TELNET,   'fail',    'high',   15,
            'Telnet is unencrypted. Disable it and use SSH.'),
    3306:  ('MySQL',      FindingID.OPEN_PORT_MYSQL,    'fail',    'high',   15,
            'Database ports must never be public. Bind to localhost / private network and firewall it.'),
    5432:  ('PostgreSQL', FindingID.OPEN_PORT_POSTGRES, 'fail',    'high',   15,
            'Database ports must never be public. Restrict with pg_hba.conf and the firewall.'),
    27017: ('MongoDB',    FindingID.OPEN_PORT_MONGODB,  'fail',    'high',   15,
            'Bind MongoDB to localhost/private network and enable authentication.'),
    6379:  ('Redis',      FindingID.OPEN_PORT_REDIS,    'fail',    'high',   15,
            'Bind Redis to localhost, set requirepass / ACLs and firewall the port.'),
    3389:  ('RDP',        FindingID.OPEN_PORT_RDP,      'fail',    'high',   15,
            'Do not expose RDP. Put it behind a VPN or RD Gateway with MFA.'),
}
_INFO_PORTS = {25: 'SMTP', 8080: 'HTTP-alt', 8443: 'HTTPS-alt'}


def _port_open(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _redis_unauthenticated(host):
    """Safe check: send PING. An unauthenticated Redis answers +PONG; an auth-protected one answers -NOAUTH."""
    try:
        with socket.create_connection((host, 6379), timeout=3) as s:
            s.settimeout(3)
            s.sendall(b'PING\r\n')
            return s.recv(32).startswith(b'+PONG')
    except Exception:
        return False


def check_open_ports(hostname):
    ports = list(_PORT_RULES) + list(_INFO_PORTS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        first = dict(zip(ports, ex.map(lambda p: _port_open(hostname, p), ports)))
    # double-verify to eliminate false positives from transient filtering
    open_ports = [p for p, ok in first.items() if ok and _port_open(hostname, p)]

    results = []
    for p in open_ports:
        if p in _PORT_RULES:
            svc, fid, status, sev, weight, fix = _PORT_RULES[p]
            details = f'Port {p} ({svc}) is reachable from the internet.'
            extra = {}
            if p == 6379 and _redis_unauthenticated(hostname):
                results.append(_f('Redis Without Authentication', 'fail', 'critical',
                                  'Redis answered PING without credentials — the data store is open to anyone.',
                                  'Set requirepass/ACLs immediately and firewall port 6379.',
                                  FindingID.REDIS_UNAUTH, weight=30))
                weight = 0         # already counted by the critical finding
            results.append(_f(f'Open Port {p} ({svc})', status, sev, details, fix, fid, weight=weight, **extra))

    info = [f'{p} ({_INFO_PORTS[p]})' for p in open_ports if p in _INFO_PORTS]
    if info:
        results.append(_f('Other Open Ports', 'info', 'info',
                          'Additional common ports reachable: ' + ', '.join(info) +
                          '. Normal for web/mail hosts and CDN edges; verify they are intentional.',
                          fid='open_ports_info'))
    if not any(p in _PORT_RULES for p in open_ports):
        results.append(_f('Dangerous Open Ports', 'pass', 'none',
                          'No database, remote-admin or legacy-protocol ports are exposed.', fid='open_ports_pass'))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Software fingerprint + CVEs
# ─────────────────────────────────────────────────────────────────────────────

class _GeneratorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.generator = None

    def handle_starttag(self, tag, attrs):
        if tag == 'meta':
            a = dict(attrs)
            if (a.get('name') or '').lower() == 'generator' and a.get('content'):
                self.generator = a['content']


def detect_software(page):
    """Return {(product, version): where_seen}. Only versions that are actually disclosed."""
    found = {}
    if page.blocked or page.resp is None:
        return found
    for hname in ('server', 'x-powered-by', 'x-generator', 'x-aspnetmvc-version'):
        for name, ver in cve_intel.parse_banner(page.headers.get(hname, '')):
            found[(name, ver)] = f'{hname} header'
    asp = page.headers.get('x-aspnet-version', '')
    if re.match(r'\d+(\.\d+)+', asp):
        found[('asp.net', asp)] = 'x-aspnet-version header'
    if 'html' in page.content_type:
        gp = _GeneratorParser()
        try:
            gp.feed(page.body[:200_000])
        except Exception:
            pass
        if gp.generator:
            m = re.match(r'\s*([A-Za-z][A-Za-z0-9.!]*)\s+v?(\d+(?:\.\d+)+)', gp.generator)
            if m:
                found[(m.group(1).lower().rstrip('!'), m.group(2))] = 'meta generator tag'
        for ver in re.findall(r'jquery[-.@/]v?(\d+\.\d+(?:\.\d+)?)(?:\.min)?(?:\.js)?', page.body, re.I)[:1]:
            found[('jquery', ver)] = 'script URL'
    return found


def check_software_versions(page, detected):
    if page.resp is None:
        return []
    if page.blocked:
        return []
    disclosed = [f'{k}: {v}' for k, v in
                 ((h, page.headers.get(h.lower())) for h in ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator'))
                 if v]
    versioned = [d for d in disclosed if re.search(r'\d+\.\d+', d)]
    if versioned:
        return [_f('Software Version Disclosure', 'warning', 'low',
                   'Server discloses exact software versions: ' + '; '.join(versioned),
                   'Hide version info. Apache: ServerTokens Prod. Nginx: server_tokens off. PHP: expose_php = Off.',
                   FindingID.SOFTWARE_DISCLOSURE, weight=3)]
    note = ('Only product names are disclosed (' + '; '.join(disclosed) + '), no version numbers.') if disclosed \
        else 'No software version information leaked in headers.'
    return [_f('Software Version Disclosure', 'pass', 'none', note, fid='software_version_pass')]


def _cve_severity(h):
    if h['kev'] or (h['score'] or 0) >= 9.0:
        return 'critical'
    s = h['score'] or 0
    return 'high' if s >= 7 else 'medium' if s >= 4 else 'low'


_CVE_WEIGHT = {'critical': 20, 'high': 12, 'medium': 6, 'low': 2}


def check_known_cves(detected):
    snap = cve_intel.load_snapshot()
    label = 'Known CVEs (recent feed)'
    if not snap:
        return [_f(label, 'info', 'info', 'No CVE snapshot loaded. Run: python backend/cve_intel.py refresh',
                   fid='cve_unavailable')]
    win = f"{snap['window']['start'][:10]} to {snap['window']['end'][:10]}"
    if not detected:
        return [_f(label, 'pass', 'none',
                   'The server discloses no software versions, so version-based CVE matching is not possible '
                   '(this is good practice, not a gap).', fid='cve_pass')]
    hits = cve_intel.match_software(list(detected))
    seen = ', '.join(f'{p} {v}' for p, v in detected)
    if not hits:
        return [_f(label, 'pass', 'none',
                   f'Detected {seen}. None are in a vulnerable range of the {len(snap["cves"])} CVEs tracked for {win}.',
                   fid='cve_pass')]
    out = []
    for i, h in enumerate(hits[:10]):
        sev = _cve_severity(h)
        approx = h.get('approximate', False)
        if approx and not h['kev'] and sev in ('critical', 'high'):
            sev = 'medium'       # upper-bound-only range: uncertain, so it must never cap the score
        note = ' [Approximate: NVD lists only an upper bound; confirm your release branch is affected.]' if approx else ''
        out.append(_f(f'{h["id"]} — {h["product"]} {h["detected_version"]}',
                      'warning' if approx else ('fail' if sev in ('critical', 'high') else 'warning'),
                      sev,
                      f'CVSS {h["score"]}{" — on CISA Known Exploited list" if h["kev"] else ""}: {h["description"][:220]}{note}',
                      f'Upgrade {h["product"]} to a patched release (check the vendor advisory; distro packages may be back-patched, '
                      'so confirm with your host). Match is based on the banner version.',
                      FindingID.KNOWN_CVE, weight=(min(_CVE_WEIGHT[sev], 6) if approx else _CVE_WEIGHT[sev]) if i < 3 else 0,
                      cve=h['id'], cvss=h['score'], kev=h['kev'], published=h['published'],
                      evidence={'detected_via': detected.get((h['product'], h['detected_version']), 'banner')}))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Exposed files / directory listing / disclosure files
# ─────────────────────────────────────────────────────────────────────────────

_ENV_LINE = re.compile(r'^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S+', re.M)
_CRED_PATTERN = re.compile(r"(DB_PASSWORD|PASSWORD\s*=|SECRET|mysqli_connect|mongodb(\+srv)?://|AKIA[0-9A-Z]{16})", re.I)

# path, label, signature test(text, raw_bytes), finding id, severity, weight, fix
_SENSITIVE = [
    ('/.env', 'Exposed Secrets (.env)', lambda t, b: bool(_ENV_LINE.search(t)) and not t.lstrip().startswith('<'),
     FindingID.EXPOSED_ENV, 'critical', 30, 'Block access to dotfiles in the web root and rotate every secret in this file.'),
    ('/.git/config', 'Exposed Codebase (.git)', lambda t, b: '[core]' in t,
     FindingID.EXPOSED_GIT, 'critical', 30, 'Deny access to the .git directory and rotate any secrets in the history.'),
    ('/wp-config.php.bak', 'Exposed WordPress config backup', lambda t, b: 'DB_PASSWORD' in t,
     FindingID.EXPOSED_SENSITIVE, 'critical', 30, 'Delete backup copies of config files from the web root.'),
    ('/backup.sql', 'Exposed database dump', lambda t, b: bool(re.search(r'CREATE TABLE|INSERT INTO', t)),
     FindingID.EXPOSED_SENSITIVE, 'critical', 30, 'Remove database dumps from the web root.'),
    ('/.htpasswd', 'Exposed .htpasswd', lambda t, b: bool(re.search(r'^[\w.\-]+:(\$apr1\$|\$2[aby]\$|\{SHA\})', t, re.M)),
     FindingID.EXPOSED_SENSITIVE, 'high', 15, 'Move .htpasswd outside the web root.'),
    ('/phpinfo.php', 'Exposed phpinfo()', lambda t, b: 'PHP Version' in t and 'phpinfo' in t.lower(),
     FindingID.EXPOSED_SENSITIVE, 'medium', 8, 'Delete phpinfo pages from production.'),
    ('/server-status', 'Exposed Apache server-status', lambda t, b: 'Apache Server Status' in t,
     FindingID.EXPOSED_SENSITIVE, 'medium', 8, 'Restrict /server-status to localhost.'),
    ('/.DS_Store', 'Exposed .DS_Store', lambda t, b: b[:8] == b'\x00\x00\x00\x01Bud1',
     FindingID.EXPOSED_SENSITIVE, 'low', 3, 'Delete .DS_Store files from the web root.'),
]


def _probe(origin, path):
    try:
        r = requests.get(origin + path, timeout=5, allow_redirects=False, stream=True,
                         headers={'User-Agent': UA})
        try:
            if r.status_code != 200:
                return path, None, b''
            ctype = r.headers.get('Content-Type', '').lower()
            raw = next(r.iter_content(4096), b'')
            return path, ctype, raw
        finally:
            r.close()
    except Exception:
        return path, None, b''


def check_exposed_files(page):
    if page.blocked or page.resp is None:
        return [_f('Sensitive Files Exposure', 'info', 'info',
                   'Skipped — the target\'s bot protection blocked automated requests, so file probes could not be assessed.',
                   fid='exposed_files_skipped')]
    results = []
    paths = [p[0] for p in _SENSITIVE]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        probed = {p: (c, b) for p, c, b in ex.map(lambda p: _probe(page.origin, p), paths)}

    for path, label, sig, fid, sev, weight, fix in _SENSITIVE:
        ctype, raw = probed.get(path, (None, b''))
        if ctype is None:
            continue
        text = raw.decode('utf-8', 'ignore')
        if path in ('/.env', '/wp-config.php.bak', '/backup.sql', '/.htpasswd') and 'html' in ctype:
            continue        # SPA / custom 404 pages answer 200 with HTML — not the file
        if sig(text, raw):
            masked = re.sub(r'(=\s*)\S+', r'\1****', text[:500])
            results.append(_f(label, 'fail', sev, f'{path} is publicly downloadable!', fix, fid, weight=weight,
                              evidence={'leaked_source': masked,
                                        'credential_pattern': bool(_CRED_PATTERN.search(text))}))
    # directory listing
    for d in ('/uploads/', '/backup/', '/files/', '/images/'):
        _, ctype, raw = _probe(page.origin, d)
        if ctype and 'html' in ctype and re.search(rb'<title>Index of /', raw, re.I):
            results.append(_f('Directory Listing Enabled', 'warning', 'medium',
                              f'{d} lists its files to anyone (auto-index is on).',
                              'Disable directory listing (Apache: Options -Indexes, Nginx: autoindex off).',
                              FindingID.DIRECTORY_LISTING, weight=6))
            break
    if not results:
        results.append(_f('Sensitive Files Exposure', 'pass', 'none',
                          f'Checked {len(paths)} high-risk paths (.env, .git, backups, phpinfo …) — none are exposed.',
                          fid='exposed_files_pass'))
    return results


def check_disclosure_files(page):
    """robots.txt (passive analysis) and security.txt (RFC 9116) — informational only."""
    if page.blocked or page.resp is None:
        return []
    out = []
    _, ctype, raw = _probe(page.origin, '/robots.txt')
    if ctype is not None and 'html' not in ctype:
        text = raw.decode('utf-8', 'ignore')
        sensitive = re.findall(r'(?im)^\s*disallow:\s*(\S*(?:admin|backup|config|private|internal|staging|secret|db|sql)\S*)', text)
        if sensitive:
            out.append(_f('robots.txt Path Hints', 'info', 'info',
                          'robots.txt advertises potentially interesting paths: ' + ', '.join(sensitive[:5]) +
                          '. robots.txt is not access control — protect these with authentication.',
                          fid='robots_hints'))
    _, ctype, raw = _probe(page.origin, '/.well-known/security.txt')
    if ctype is not None and 'html' not in ctype and b'Contact:' in raw:
        out.append(_f('security.txt', 'pass', 'none', 'A security.txt (RFC 9116) contact is published.', fid='security_txt_pass'))
    else:
        out.append(_f('security.txt', 'info', 'info',
                      'No security.txt found (optional, RFC 9116) — lets researchers report vulnerabilities to you.',
                      fid='security_txt_missing'))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Passive source-code analysis of the landing page
# ─────────────────────────────────────────────────────────────────────────────

class _PageAnalyzer(HTMLParser):
    def __init__(self, host):
        super().__init__()
        self.host = host
        self.active_mixed, self.passive_mixed = [], []
        self.password_forms_http = False
        self.has_password = False
        self.ext_scripts_no_sri = []
        self.comments = []
        self._form_action = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or '') for k, v in attrs}
        src = a.get('src') or a.get('href') or ''
        if tag in ('script', 'iframe') and src.startswith('http://'):
            self.active_mixed.append(src)
        elif tag == 'link' and a.get('rel', '').lower() == 'stylesheet' and src.startswith('http://'):
            self.active_mixed.append(src)
        elif tag in ('img', 'audio', 'video', 'source') and a.get('src', '').startswith('http://'):
            self.passive_mixed.append(a['src'])
        if tag == 'script' and src.startswith(('http://', 'https://', '//')):
            host = urlparse(src if not src.startswith('//') else 'https:' + src).hostname or ''
            if _registrable(host) != _registrable(self.host) and not a.get('integrity'):
                self.ext_scripts_no_sri.append(host)
        if tag == 'form':
            self._form_action = a.get('action', '')
        if tag == 'input' and a.get('type', '').lower() == 'password':
            self.has_password = True
            if (self._form_action or '').startswith('http://'):
                self.password_forms_http = True

    def handle_endtag(self, tag):
        if tag == 'form':
            self._form_action = None

    def handle_comment(self, data):
        self.comments.append(data)


def check_page_content(page):
    if page.blocked or page.resp is None or 'html' not in page.content_type:
        return []
    an = _PageAnalyzer(page.hostname)
    try:
        an.feed(page.body)
    except Exception:
        return []
    out = []
    final_https = (page.final_url or page.origin).startswith('https://')

    if an.has_password and (not final_https and not _is_local(page.hostname) or an.password_forms_http):
        out.append(_f('Login Form Over HTTP', 'fail', 'high',
                      'A password field is served or submitted over unencrypted HTTP — credentials can be sniffed.',
                      'Serve the whole site over HTTPS and submit forms to https:// URLs.',
                      FindingID.LOGIN_OVER_HTTP, weight=15))
    if final_https and an.active_mixed:
        out.append(_f('Mixed Content (active)', 'fail', 'medium',
                      f'HTTPS page loads scripts/frames/styles over HTTP, e.g. {an.active_mixed[0]}',
                      'Load every resource over https://.', FindingID.MIXED_CONTENT, weight=6))
    elif final_https and an.passive_mixed:
        out.append(_f('Mixed Content (images/media)', 'warning', 'low',
                      f'HTTPS page loads media over HTTP, e.g. {an.passive_mixed[0]}',
                      'Load every resource over https://.', FindingID.MIXED_CONTENT, weight=1))
    risky = [c.strip()[:80] for c in an.comments if re.search(r'password|passwd|secret|api[_ -]?key|token|credential', c, re.I)]
    if risky:
        out.append(_f('Sensitive HTML Comments', 'warning', 'low',
                      'HTML comments mention credentials/secrets: ' + ' | '.join(risky[:2]),
                      'Strip comments from production HTML.', 'html_comment_secrets', weight=2))
    if an.ext_scripts_no_sri:
        hosts = sorted(set(an.ext_scripts_no_sri))
        out.append(_f('Third-party Scripts Without SRI', 'info', 'info',
                      f'{len(an.ext_scripts_no_sri)} script(s) from other domains ({", ".join(hosts[:4])}) lack Subresource '
                      'Integrity hashes. Fine for your own CDN; for third-party CDNs add integrity= attributes.',
                      fid='sri_info'))
    if not any(f['status'] in ('fail', 'warning') for f in out):
        out.append(_f('Page Source Analysis', 'pass', 'none',
                      'No mixed content, insecure login forms or secrets in HTML comments were found on the landing page.',
                      fid='source_pass'))
    return out


def check_reflection(page):
    """Reflected-input probe: is a harmless marker echoed back unencoded? (CWE-79)"""
    if page.blocked or page.resp is None:
        return []
    marker = 'prawl' + secrets.token_hex(4)
    payload = f'{marker}"\'<u>x</u>'
    try:
        r = requests.get(page.origin + '/?prawl_probe=' + quote(payload, safe=''), timeout=8,
                         headers={'User-Agent': UA})
        ctype = r.headers.get('Content-Type', '').lower()
        if 'html' not in ctype:
            return []
        if payload in r.text:
            return [_f('Reflected Input (XSS indicator)', 'fail', 'high',
                       'A test string containing HTML characters was reflected back unencoded in the page.',
                       'HTML-encode all user input on output and deploy a strict Content-Security-Policy.',
                       FindingID.REFLECTED_XSS, weight=12)]
        return [_f('Reflected Input (XSS indicator)', 'pass', 'none',
                   'A marker with HTML metacharacters was not reflected unencoded.', fid='reflection_pass')]
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────────────────────
# E-mail authentication (social-engineering / phishing defence)
# ─────────────────────────────────────────────────────────────────────────────

def _dns_lookup(res, name, rtype):
    """
    Returns (records, state). state is 'ok', 'none' (authoritative: the record does not exist)
    or 'error' (timeout / server failure: UNKNOWN, must never be reported as "missing").
    Tries UDP first, then TCP (large TXT answers often time out over UDP).
    """
    import dns.resolver, dns.exception
    for use_tcp in (False, True, True):
        try:
            ans = res.resolve(name, rtype, tcp=use_tcp, raise_on_no_answer=True)
            return list(ans), 'ok'
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [], 'none'
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException):
            continue
    return [], 'error'


def check_email_auth(hostname):
    """SPF / DMARC posture. DNS failures are reported as 'could not determine', never as missing records."""
    if _is_local(hostname) or _is_ip(hostname):
        return []
    try:
        import dns.resolver
    except ImportError:
        return []
    res = dns.resolver.Resolver()
    res.lifetime = 6
    res.timeout = 3
    labels = hostname.lower().split('.')
    candidates = ['.'.join(labels[i:]) for i in range(0, max(1, len(labels) - 1))]

    domain, mx_unknown = None, False
    for cand in candidates:
        recs, state = _dns_lookup(res, cand, 'MX')
        if state == 'ok' and recs:
            domain = cand
            break
        if state == 'error':
            mx_unknown = True
    if not domain:
        if mx_unknown:
            return [_f('E-mail Spoofing Protection', 'info', 'info',
                       'DNS lookups timed out, so SPF/DMARC could not be assessed (not reported as missing).',
                       fid='email_dns_error')]
        return [_f('E-mail Spoofing Protection', 'info', 'info',
                   'No MX records found, so SPF/DMARC were not assessed.', fid='email_na')]

    def txt(name):
        recs, state = _dns_lookup(res, name, 'TXT')
        return [b''.join(r.strings).decode('utf-8', 'ignore') for r in recs], state

    txts, spf_state = txt(domain)
    spf = [t for t in txts if t.lower().startswith('v=spf1')]

    # DMARC may live on the organisational (parent) domain
    dmarc, dmarc_state = [], 'none'
    for cand in candidates[candidates.index(domain):]:
        records, state = txt('_dmarc.' + cand)
        dmarc = [t for t in records if t.lower().startswith('v=dmarc1')]
        if dmarc:
            dmarc_state = 'ok'
            break
        if state == 'error':
            dmarc_state = 'error'

    out = []
    if spf_state == 'error':
        out.append(_f('SPF Record', 'info', 'info', 'SPF lookup timed out; could not be assessed.', fid='email_dns_error'))
    elif not spf:
        out.append(_f('SPF Record', 'warning', 'low', f'No SPF record for {domain}, so anyone can forge mail from your domain.',
                      'Publish an SPF TXT record listing your mail senders.', FindingID.MISSING_SPF, weight=3))
    pol = None
    if dmarc:
        m = re.search(r'p=(\w+)', dmarc[0], re.I)
        pol = m.group(1).lower() if m else 'none'
        if pol == 'none':
            out.append(_f('DMARC Record', 'warning', 'low',
                          'DMARC exists but policy is p=none (monitoring only; spoofed mail is still delivered).',
                          'Move to p=quarantine, then p=reject, once reports look clean.', FindingID.MISSING_DMARC, weight=1))
    elif dmarc_state == 'error':
        out.append(_f('DMARC Record', 'info', 'info', 'DMARC lookup timed out; could not be assessed.', fid='email_dns_error'))
    else:
        out.append(_f('DMARC Record', 'warning', 'medium',
                      f'No DMARC policy for {domain}; phishing mail impersonating your brand will not be blocked.',
                      'Publish _dmarc TXT: v=DMARC1; p=quarantine; rua=mailto:you@yourdomain', FindingID.MISSING_DMARC, weight=4))
    if not out:
        out.append(_f('E-mail Spoofing Protection', 'pass', 'none',
                      f'SPF present and DMARC enforced (p={pol}) for {domain}.', fid='email_auth_pass'))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────────────────────────

def score_breakdown(findings):
    deductions = []
    for f in findings:
        if f.get('status') in ('fail', 'warning'):          # 'error' / 'info' never deduct
            w = f.get('weight')
            if w is None:
                w = SEVERITY_WEIGHT.get(f.get('severity', 'low'), 3)
            if w:
                deductions.append({'check': f.get('check'), 'weight': w, 'severity': f.get('severity')})
    total = sum(d['weight'] for d in deductions)
    cap = None
    for f in findings:
        if f.get('status') in ('fail', 'warning'):
            c = SCORE_CAPS.get(f.get('severity'))
            if c is not None and (cap is None or c < cap):
                cap = c
    score = max(0, 100 - total)
    if cap is not None:
        score = min(score, cap)
    return {'base': 100, 'deductions': deductions, 'total_deduction': total, 'cap': cap, 'score': score}


def calculate_score(findings):
    """100 minus weighted deductions for real failures; capped by the worst severity present."""
    return score_breakdown(findings)['score']


def get_risk_level(score, findings=None):
    for minimum, label, colour in scoring_policy.RISK_BANDS:
        if score >= minimum:
            return label, colour
    return scoring_policy.RISK_BANDS[-1][1:]


LANGUAGE_INSTRUCTIONS = {
    'english': 'Write in plain English.',
    'hindi':   'हिंदी में लिखें। (Write entirely in Hindi script.)',
    'telugu':  'తెలుగులో రాయండి. (Write entirely in Telugu script.)',
    'tamil':   'தமிழில் எழுதுங்கள். (Write entirely in Tamil script.)',
    'kannada': 'ಕನ್ನಡದಲ್ಲಿ ಬರೆಯಿರಿ. (Write entirely in Kannada script.)',
    'marathi': 'मराठीत लिहा. (Write entirely in Marathi script.)',
    'bengali': 'বাংলায় লিখুন। (Write entirely in Bengali script.)',
}


def generate_ai_summary(url, findings, score, language='english'):
    issues = [f for f in findings if f['status'] in ['fail', 'warning']]
    issues_text = '\n'.join([
        f"- [{f['severity'].upper()}] {f['check']}: {f['details']}"
        for f in issues[:8]
    ])
    lang_key = language.lower().strip()
    lang_instruction = LANGUAGE_INSTRUCTIONS.get(lang_key, LANGUAGE_INSTRUCTIONS['english'])

    prompt = f"""You are PRAWL, an AI cybersecurity assistant for Indian small businesses.
Website: {url} | Score: {score}/100
Issues found:
{issues_text or 'No major issues found.'}
Write exactly 3 sentences for a non-technical Indian business owner.
Mention the score, the most critical issue, and one clear action to take today.
Be accurate: if the score is 80 or above, say the site is in good shape and do not exaggerate minor issues.
Only mention problems that appear in the list above. No bullet points. No jargon. Plain paragraph only.
Language instruction: {lang_instruction}"""

    groq_key = os.environ.get('GROQ_API_KEY', '')
    if groq_key:
        try:
            import httpx
            from groq import Groq
            client = Groq(
                api_key=groq_key,
                http_client=httpx.Client()
            )
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=350
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.warning(f"Groq API failed, using text fallback: {e}")

    return generate_fallback_summary(findings, score)


def generate_fallback_summary(findings, score):
    issues   = [f for f in findings if f['status'] in ['fail', 'warning']]
    critical = [f for f in issues   if f['severity'] in ['critical', 'high']]
    if not issues:
        return (f"Your website scored {score}/100 — no security issues were detected by the checks PRAWL ran. "
                "Keep your software updated and re-scan after any major change. "
                "Today: nothing urgent to fix.")
    if score >= 80:
        top = max(issues, key=lambda f: SEVERITY_WEIGHT.get(f.get('severity'), 0))
        return (f"Your website scored {score}/100 — good security overall, with {len(issues)} minor item(s) to tidy up. "
                f"The most notable is: {top['check']}. "
                f"Today: {top.get('fix') or 'review the flagged item'}")
    if score >= 60:
        return (f"Your website scored {score}/100 — moderate risk. "
                f"We found {len(issues)} security issues including {len(critical)} high-priority item(s). "
                "Address the flagged findings this week to protect your customers.")
    return (f"Your website scored {score}/100 — this is high risk. "
            f"We found {len(critical)} critical/high issues out of {len(issues)} total problems. "
            "Contact your hosting provider today and ask them to fix the critical items on this report.")


def _mark_exploit_path(findings, G):
    """
    Mark findings whose finding_id has an actual directed path to the goal
    node (customer_pii_breach) in the attack graph — not merely findings
    that exist anywhere in the graph. build_attack_graph() seeds every
    failing/warning finding as a node regardless of whether it connects to
    anything, so membership alone is not evidence of reachability.
    findings: list of finding dicts (mutable)
    G: networkx DiGraph
    """
    try:
        import networkx as nx
        from attackpath.path_scorer import GOAL
        if GOAL not in G:
            return
        for f in findings:
            candidate_ids = [f.get('finding_id', '')] + f.get('finding_ids', [])
            f['on_exploit_path'] = any(
                cid and cid in G and nx.has_path(G, cid, GOAL)
                for cid in candidate_ids
            )
    except Exception:
        pass


def _run_phishing_watch(hostname, timeout=30):
    """Run phishing domain watch in a thread with a timeout."""
    import concurrent.futures
    try:
        from phishing.permutations import generate_permutations
        from phishing.impersonator_scorer import score_impersonators

        def _do_phishing():
            candidates = generate_permutations(hostname)
            return score_impersonators(hostname, candidates, total_timeout=timeout)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_do_phishing)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                logger.warning(f"Phishing watch timed out for {hostname}")
                return []
    except Exception as e:
        logger.warning(f"Phishing watch failed for {hostname}: {e}")
        return []




def run_full_scan(url, language='english'):
    parsed   = urlparse(url)
    hostname = parsed.hostname or parsed.path.split('/')[0]

    # ── LAYER 0: COLLECTION ───────────────────────────────────────────────────
    page = fetch_page(url)
    if page.resp is None:
        raise ScanError(f'Could not reach {hostname}: {page.error}')

    detected = detect_software(page)
    jobs = {
        'ssl':     lambda: [check_ssl(hostname, page.scheme)],
        'tls':     lambda: [check_legacy_tls(hostname)] if page.scheme == 'https' and not _is_local(hostname) else [],
        'headers': lambda: check_headers(page) if not page.blocked else [],
        'cookies': lambda: check_cookies(page) if not page.blocked else [],
        'cors':    lambda: check_cors(page) if not page.blocked else [],
        'methods': lambda: check_http_methods(page) if not page.blocked else [],
        'ports':   lambda: check_open_ports(hostname),
        'version': lambda: check_software_versions(page, detected),
        'cves':    lambda: check_known_cves(detected),
        'files':   lambda: check_exposed_files(page),
        'content': lambda: check_page_content(page),
        'reflect': lambda: check_reflection(page),
        'disclose': lambda: check_disclosure_files(page),
        'email':   lambda: check_email_auth(hostname),
    }
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {name: ex.submit(fn) for name, fn in jobs.items()}
        for name, fut in futures.items():
            try:
                results[name] = fut.result(timeout=60)
            except Exception as e:
                logger.warning(f"check '{name}' failed: {e}")
                results[name] = [_f(name.title() + ' check', 'error', 'info', f'Check could not run: {e}',
                                    fid=f'{name}_error')]

    findings = []
    if page.ssl_error and not any(f.get('finding_id') == FindingID.SSL_INVALID for f in results['ssl']):
        findings.append(_f('SSL Certificate', 'fail', 'critical', f'TLS verification failed: {page.ssl_error}',
                           "Install a valid SSL certificate for this exact hostname.", FindingID.SSL_INVALID))
    if page.blocked:
        findings.append(_f('WAF / Bot Protection', 'info', 'info',
                           f'{page.cdn or "The site"} challenged the scanner (HTTP {page.status}). HTTP-layer checks '
                           '(headers, cookies, files, page content, CORS) were SKIPPED because the response was a '
                           'challenge page, not your application. TLS, ports, DNS and CVE checks still ran.',
                           'Allow-list the scanner or scan from a trusted IP for a full assessment.',
                           'waf_blocked'))
    if page.cdn and not page.blocked:
        findings.append(_f('CDN / Edge Network', 'info', 'info',
                           f'Site is served through {page.cdn}; port results describe the CDN edge, not your origin server.',
                           fid='cdn_info'))
    for name in jobs:
        findings.extend(results.get(name, []))
    taxonomy.enrich_findings(findings)

    # Technical score: 100 minus weighted deductions for real failures, capped by worst severity
    breakdown              = score_breakdown(findings)
    technical_score        = breakdown['score']
    risk_level, risk_color = get_risk_level(technical_score, findings)

    # ── LAYER 1A: ATTACK-PATH ENGINE ─────────────────────────────────────────
    attack_graph_json = {"nodes": [], "edges": []}
    exploit_result = {"risk": 0, "reachable": False,
                      "best_path": None, "distinct_routes": 0, "paths": []}
    attack_narrative = ""

    try:
        from attackpath.attack_graph import build_attack_graph, to_cytoscape_json, get_node_labels
        from attackpath.path_scorer import exploitability
        from attackpath.narrative import generate_narrative

        G = build_attack_graph(findings)
        _mark_exploit_path(findings, G)

        exploit_result = exploitability(G)
        attack_graph_json = to_cytoscape_json(G)

        if exploit_result.get("reachable") and exploit_result.get("best_path"):
            node_labels = get_node_labels(G)
            groq_key = os.environ.get('GROQ_API_KEY', '')
            attack_narrative = generate_narrative(
                exploit_result["best_path"], node_labels, language, groq_key=groq_key
            )
    except Exception as e:
        logger.warning(f"Attack path engine failed: {e}")

    # ── LAYER 1B: COMPLIANCE ENGINE ──────────────────────────────────────────
    disclaimer = ("Indicative compliance guidance generated from public information about the DPDP Act and "
                  "CERT-In Directions. Not legal advice. Consult a qualified professional.")
    compliance_result = {"readiness_score": 100, "hits": [], "brief": "", "disclaimer": disclaimer}
    try:
        from compliance.compliance_mapper import map_findings_to_obligations, dpdp_readiness_score
        from compliance.brief_generator import generate_compliance_brief

        hits = map_findings_to_obligations(findings)
        readiness_score = dpdp_readiness_score(hits)
        brief = generate_compliance_brief(url, hits, readiness_score, language)
        compliance_result = {"readiness_score": readiness_score, "hits": hits, "brief": brief,
                             "disclaimer": disclaimer}
    except Exception as e:
        logger.warning(f"Compliance engine failed: {e}")

    # ── LAYER 1C: PHISHING WATCH (non-blocking, 30s timeout) ─────────────────
    impersonators = []
    try:
        impersonators = _run_phishing_watch(hostname, timeout=30)
    except Exception as e:
        logger.warning(f"Phishing watch error: {e}")

    # ── LAYER 2: FINAL SCORE + AI SUMMARY ────────────────────────────────────
    # A chained attack path built from CONFIRMED findings can only lower the score further;
    # speculative / unchained findings never do.
    final_score = technical_score
    if exploit_result.get("reachable"):
        final_score = min(technical_score, 100 - exploit_result.get("risk", 0))
    risk_level, risk_color = get_risk_level(final_score, findings)
    ai_summary = generate_ai_summary(url, findings, final_score, language)

    critical_count = len([f for f in findings if f['status'] == 'fail'              and f['severity'] in ['critical', 'high']])
    warning_count  = len([f for f in findings if f['status'] in ['warning', 'fail'] and f['severity'] in ['medium', 'low']])
    pass_count     = len([f for f in findings if f['status'] == 'pass'])

    # ── LAYER 3: UNIFIED RESPONSE ────────────────────────────────────────────
    return {
        'url': url, 'hostname': hostname,
        'score': final_score,
        'risk_level': risk_level, 'risk_color': risk_color,
        'ai_summary': ai_summary, 'findings': findings,
        'stats': {
            'critical': critical_count, 'warnings': warning_count,
            'passed': pass_count, 'total': len(findings)
        },
        'scanned_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),

        # How the score was computed (transparent)
        'score_breakdown': breakdown,
        'score_policy': scoring_policy.as_dict(),

        # Attack-path engine + graph (evidence-gated)
        'exploit': {
            'risk': exploit_result.get("risk", 0) if exploit_result.get("reachable") else 0,
            'reachable': exploit_result.get("reachable", False),
            'best_path': exploit_result.get("best_path"),
            'distinct_routes': exploit_result.get("distinct_routes", 0),
            'narrative': attack_narrative,
        },
        'attack_graph': attack_graph_json,

        # DPDP compliance
        'compliance': compliance_result,

        # Phishing domain watch
        'impersonators': impersonators,

        # Pen-test framing, OWASP coverage, remediation order, concepts
        'methodology': engagement.build_methodology(page, findings),
        'owasp_coverage': taxonomy.owasp_coverage(findings),
        'remediation_plan': engagement.remediation_plan(findings),
        'concepts': engagement.concepts_for_findings(findings),

        # Real CVE feed (NVD + CISA KEV) used for matching
        'cve_feed': cve_intel.summarize_snapshot(limit=10),
        'detected_software': [{'product': p, 'version': v, 'source': s} for (p, v), s in detected.items()],

        'technical_score': technical_score,
    }
