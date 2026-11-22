"""
Headless tests for the evidence-based scanner (no real network traffic).
They pin the behaviours that matter:
  * a hardened, CDN-fronted site (think chatgpt.com) scores GREEN
  * a leaked .env scores RED
  * a WAF challenge page is reported as "not assessed", never as passed or failed
  * checks that error out never lower the score
  * CVE matching uses real NVD version ranges from the October 2026 snapshot
Run: pytest test_scanner_scoring.py -v
"""
from types import SimpleNamespace

import pytest

import scanner
from scanner import _f, calculate_score, get_risk_level, score_breakdown
import cve_intel


# ── helpers ─────────────────────────────────────────────────────────────────

HARDENED_HEADERS = {
    'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
    'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc123' 'strict-dynamic'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=()',
    'server': 'cloudflare',
    'cf-ray': '8a1b2c3d4e5f-BOM',
}


def make_page(headers=None, status=200, body='<html><body>hi</body></html>', cookies=None, blocked=False,
              scheme='https', host='example.com'):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    return SimpleNamespace(
        url=f'{scheme}://{host}', hostname=host, scheme=scheme, origin=f'{scheme}://{host}',
        resp=object(), error=None, ssl_error=None, status=status, headers=headers,
        cookies=cookies or [], body=body, content_type='text/html; charset=utf-8',
        final_url=f'{scheme}://{host}/', cdn=scanner._detect_cdn(headers), blocked=blocked,
    )


class FakeResp:
    def __init__(self, url):
        self.url = url


@pytest.fixture
def offline(monkeypatch):
    """Replace every function that would touch the network with a clean, deterministic stub."""
    monkeypatch.setattr(scanner, 'check_ssl', lambda h, s='https': _f('SSL Certificate', 'pass', 'none', 'ok', fid='ssl_valid'))
    monkeypatch.setattr(scanner, 'check_legacy_tls', lambda h: _f('Legacy TLS Protocols', 'pass', 'none', 'ok', fid='tls_pass'))
    monkeypatch.setattr(scanner, 'check_open_ports', lambda h: [
        _f('Other Open Ports', 'info', 'info', '8080, 8443', fid='open_ports_info'),
        _f('Dangerous Open Ports', 'pass', 'none', 'none exposed', fid='open_ports_pass')])
    monkeypatch.setattr(scanner, 'check_cors', lambda p: [_f('CORS Configuration', 'pass', 'none', 'ok', fid='cors_pass')])
    monkeypatch.setattr(scanner, 'check_http_methods', lambda p: [])
    monkeypatch.setattr(scanner, 'check_disclosure_files', lambda p: [])
    monkeypatch.setattr(scanner, 'check_reflection', lambda p: [_f('Reflected Input', 'pass', 'none', 'ok', fid='reflection_pass')])
    monkeypatch.setattr(scanner, 'check_email_auth', lambda h: [_f('E-mail Spoofing Protection', 'pass', 'none', 'ok', fid='email_auth_pass')])
    monkeypatch.setattr(scanner, 'check_exposed_files', lambda p: [_f('Sensitive Files Exposure', 'pass', 'none', 'ok', fid='exposed_files_pass')])
    monkeypatch.setattr(scanner.requests, 'get', lambda url, **kw: FakeResp(url.replace('http://', 'https://')))
    monkeypatch.setattr(scanner, '_run_phishing_watch', lambda h, timeout=30: [])
    monkeypatch.setattr(scanner, 'generate_ai_summary', lambda *a, **k: 'summary')
    monkeypatch.setattr('compliance.brief_generator.generate_compliance_brief', lambda *a, **k: '')
    monkeypatch.setattr('attackpath.narrative.generate_narrative', lambda *a, **k: '')


# ── scoring ──────────────────────────────────────────────────────────────────

def test_hardened_cdn_site_scores_green(offline, monkeypatch):
    """The 'scan chatgpt.com' scenario: modern headers, hidden versions, CDN edge ports -> green."""
    monkeypatch.setattr(scanner, 'fetch_page', lambda url: make_page(HARDENED_HEADERS))
    r = scanner.run_full_scan('https://example.com')
    assert r['score'] >= 90
    assert r['risk_level'] == 'LOW' and r['risk_color'] == '#00d4aa'
    assert r['stats']['critical'] == 0 and r['stats']['warnings'] == 0
    assert r['exploit']['reachable'] is False
    assert r['compliance']['readiness_score'] == 100


def test_few_minor_issues_stay_green():
    findings = [
        _f('Header: Permissions-Policy', 'fail', 'low', 'missing', fid='missing_permissions_policy', weight=1),
        _f('Header: Referrer-Policy', 'fail', 'low', 'missing', fid='missing_referrer_policy', weight=2),
        _f('Software Version Disclosure', 'warning', 'low', 'nginx/1.2', fid='software_version_disclosure', weight=3),
    ]
    score = calculate_score(findings)
    assert score == 94
    assert get_risk_level(score)[0] == 'LOW'


def test_all_six_headers_missing_is_only_medium():
    findings = [_f(n, 'fail', s, 'missing', fid=n, weight=w) for n, s, w in [
        ('a', 'medium', 6), ('b', 'medium', 6), ('c', 'medium', 4), ('d', 'low', 2), ('e', 'low', 2), ('f', 'low', 1)]]
    assert calculate_score(findings) == 79
    assert get_risk_level(79)[0] == 'MEDIUM'


def test_critical_finding_cannot_hide_in_green_score():
    findings = [_f('.env', 'fail', 'critical', 'exposed', fid='exposed_env_file', weight=1)]
    assert calculate_score(findings) <= 35
    assert get_risk_level(calculate_score(findings))[0] == 'CRITICAL'


def test_high_finding_caps_at_orange():
    s = calculate_score([_f('db', 'fail', 'high', 'mysql open', fid='open_port_mysql', weight=15)])
    assert s <= 59
    assert get_risk_level(s)[0] == 'HIGH'


def test_errors_and_info_never_reduce_score():
    findings = [_f('x', 'error', 'high', 'timeout'), _f('y', 'info', 'info', 'note'),
                _f('z', 'pass', 'none', 'ok')]
    assert calculate_score(findings) == 100
    assert score_breakdown(findings)['deductions'] == []


# ── individual checks ────────────────────────────────────────────────────────

def test_header_check_passes_hardened_headers():
    res = scanner.check_headers(make_page(HARDENED_HEADERS, host='localhost', scheme='https'))
    assert not [f for f in res if f['status'] in ('fail', 'warning')]


def test_frame_ancestors_satisfies_clickjacking_check():
    h = dict(HARDENED_HEADERS)  # no X-Frame-Options, but CSP has frame-ancestors
    res = scanner.check_headers(make_page(h, host='localhost'))
    xfo = [f for f in res if f['check'] == 'Header: X-Frame-Options'][0]
    assert xfo['status'] == 'pass'


def test_short_hsts_and_unsafe_inline_are_low_severity_warnings():
    h = dict(HARDENED_HEADERS)
    h['strict-transport-security'] = 'max-age=300'
    h['content-security-policy'] = "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    res = scanner.check_headers(make_page(h, host='localhost'))
    issues = {f['finding_id']: f for f in res if f['status'] == 'warning'}
    assert 'weak_hsts' in issues and 'csp_unsafe_inline' in issues
    assert all(f['severity'] == 'low' for f in issues.values())


def test_cookie_check_is_per_cookie_and_ignores_benign_analytics():
    page = make_page(cookies=['_ga=1; Path=/; Max-Age=3600; Secure', 'sessionid=abc; Path=/; Secure; HttpOnly'])
    assert scanner.check_cookies(page)[0]['status'] == 'pass'
    bad = make_page(cookies=['sessionid=abc; Path=/; Secure'])
    r = scanner.check_cookies(bad)[0]
    assert r['status'] == 'warning' and 'HttpOnly' in r['details']


def test_software_disclosure_only_flags_real_versions():
    p = make_page({'server': 'cloudflare'})
    assert scanner.check_software_versions(p, scanner.detect_software(p))[0]['status'] == 'pass'
    p2 = make_page({'server': 'nginx/1.18.0 (Ubuntu)', 'x-powered-by': 'PHP/8.1.2'})
    det = scanner.detect_software(p2)
    assert ('nginx', '1.18.0') in det and ('php', '8.1.2') in det
    assert scanner.check_software_versions(p2, det)[0]['status'] == 'warning'


def test_waf_challenge_is_not_assessed_not_passed_or_failed(offline, monkeypatch):
    blocked = make_page({'server': 'cloudflare', 'cf-ray': 'x', 'cf-mitigated': 'challenge'}, status=403,
                        body='Just a moment...', blocked=True)
    monkeypatch.setattr(scanner, 'fetch_page', lambda url: blocked)
    monkeypatch.setattr(scanner, 'check_exposed_files', lambda p: scanner.check_exposed_files.__wrapped__(p)
                        if hasattr(scanner.check_exposed_files, '__wrapped__') else [])
    r = scanner.run_full_scan('https://example.com')
    ids = [f['finding_id'] for f in r['findings']]
    assert 'waf_blocked' in ids
    assert not any(i.startswith('missing_') for i in ids)       # no guessing from the challenge page
    assert r['methodology']['http_layer_assessed'] is False


# ── evidence-gated attack paths ──────────────────────────────────────────────

def test_missing_csp_or_open_rdp_alone_never_creates_attack_path():
    from attackpath.attack_graph import build_attack_graph
    from attackpath.path_scorer import exploitability
    f = [_f('csp', 'fail', 'medium', 'x', fid='missing_csp'), _f('rdp', 'fail', 'high', 'x', fid='open_port_rdp'),
         _f('mongo', 'fail', 'high', 'x', fid='open_port_mongodb')]
    assert exploitability(build_attack_graph(f))['reachable'] is False


def test_unauthenticated_redis_creates_real_path():
    from attackpath.attack_graph import build_attack_graph
    from attackpath.path_scorer import exploitability
    G = build_attack_graph([_f('redis', 'fail', 'critical', 'x', fid='redis_unauthenticated')])
    assert exploitability(G)['reachable'] is True


def test_exposed_env_with_credentials_plus_mysql_chain():
    from attackpath.attack_graph import build_attack_graph
    from attackpath.path_scorer import exploitability
    f = [_f('env', 'fail', 'critical', 'x', fid='exposed_env_file', evidence={'credential_pattern': True}),
         _f('db', 'fail', 'high', 'x', fid='open_port_mysql')]
    assert exploitability(build_attack_graph(f))['reachable'] is True


def test_leaked_env_is_red_and_secrets_are_masked(monkeypatch):
    class R:
        status_code = 200
        headers = {'Content-Type': 'text/plain'}
        def iter_content(self, n):
            yield b'APP_KEY=base64:supersecretvalue\nDB_PASSWORD=hunter2\n'
        def close(self): pass
    monkeypatch.setattr(scanner.requests, 'get', lambda url, **kw: R() if url.endswith('/.env') else
                        SimpleNamespace(status_code=404, headers={}, iter_content=lambda n: iter(()), close=lambda: None))
    res = scanner.check_exposed_files(make_page())
    env = [f for f in res if f['finding_id'] == 'exposed_env_file'][0]
    assert env['severity'] == 'critical'
    assert 'hunter2' not in env['evidence']['leaked_source']       # never echo secrets back
    assert env['evidence']['credential_pattern'] is True
    assert calculate_score(res) <= 35


def test_spa_html_200_is_not_reported_as_env_file(monkeypatch):
    class R:
        status_code = 200
        headers = {'Content-Type': 'text/html'}
        def iter_content(self, n):
            yield b'<!doctype html><html>APP_NAME=Shop</html>'
        def close(self): pass
    monkeypatch.setattr(scanner.requests, 'get', lambda url, **kw: R())
    res = scanner.check_exposed_files(make_page())
    assert [f['status'] for f in res] == ['pass']


# ── CVE intelligence (real October 2026 data) ───────────────────────────────

def _snap():
    s = cve_intel.load_snapshot()
    assert s is not None, 'run: python backend/cve_intel.py refresh'
    return s


def test_snapshot_is_real_october_2026_data():
    s = _snap()
    assert s['window']['start'].startswith('2026-10-01') and s['window']['end'].startswith('2026-10-31')
    assert s['sources']['nvd'].startswith('https://services.nvd.nist.gov')
    assert s['kev_added_in_window'], 'CISA KEV additions for October 2026 expected'
    assert all(c['published'].startswith('2026-10') for c in s['cves'])
    assert all(c['id'].startswith('CVE-') for c in s['cves'])


def test_version_matching_uses_ranges_not_guesses():
    s = _snap()
    php_cves = [c for c in s['cves'] if c['watched'] and any(a['product'] == 'php' for a in c['affects'])]
    assert php_cves, 'expected PHP CVEs in the October 2026 snapshot'
    ids = {h['id'] for h in cve_intel.match_software([('php', '8.1.2')], s)}
    assert {c['id'] for c in php_cves} & ids                    # old PHP is flagged
    assert not cve_intel.match_software([('php', '9.9.9')], s)  # far-future version is not
    assert not cve_intel.match_software([('nginx', '99.0.0')], s)


def test_cve_findings_for_vulnerable_banner_and_clean_banner():
    res = scanner.check_known_cves({('php', '8.1.2'): 'x-powered-by header'})
    cves = [f for f in res if f['finding_id'] == 'known_cve_software']
    assert cves and all(f['cve'].startswith('CVE-') for f in cves)
    assert any(f['status'] == 'fail' for f in cves)
    clean = scanner.check_known_cves({})
    assert clean[0]['status'] == 'pass'


def test_taxonomy_tags_every_failure_with_owasp_and_cwe():
    f = [_f('x', 'fail', 'high', 'x', fid='open_port_mysql'), _f('y', 'fail', 'medium', 'x', fid='missing_csp')]
    from taxonomy import enrich_findings
    enrich_findings(f)
    assert all(x['owasp'].startswith('A0') or x['owasp'].startswith('A1') for x in f)
    assert all(x['cwe'].startswith('CWE-') for x in f)
