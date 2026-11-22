"""
Edge-case and regression tests (no external network).
Run: pytest test_edge_cases.py -v
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

import scanner
import advanced_scanner as adv
import engagement
import scoring_policy
from scanner import _f


# ── DNS: a timeout is UNKNOWN, never "missing" ──────────────────────────────

def test_dns_timeout_is_not_reported_as_missing_records(monkeypatch):
    pytest.importorskip('dns.resolver')
    monkeypatch.setattr(scanner, '_dns_lookup', lambda res, name, rtype: ([], 'error'))
    out = scanner.check_email_auth('example.com')
    assert all(f['status'] == 'info' for f in out)
    assert not any(f['finding_id'] in ('missing_spf', 'missing_dmarc') for f in out)


def test_authoritative_missing_dmarc_is_reported(monkeypatch):
    pytest.importorskip('dns.resolver')

    class Rec:
        def __init__(self, s): self.strings = [s.encode()]

    def fake(res, name, rtype):
        if rtype == 'MX':
            return [object()], 'ok'
        if name == 'example.com':
            return [Rec('v=spf1 -all')], 'ok'
        return [], 'none'                       # _dmarc.* does not exist (NXDOMAIN / no answer)
    monkeypatch.setattr(scanner, '_dns_lookup', fake)
    out = scanner.check_email_auth('example.com')
    assert [f['finding_id'] for f in out] == ['missing_dmarc'] and out[0]['status'] == 'warning'


def test_ip_and_localhost_skip_email_checks():
    assert scanner.check_email_auth('127.0.0.1') == [] and scanner.check_email_auth('localhost') == []


# ── TLS: not testable != passed ─────────────────────────────────────────────

def test_legacy_tls_network_error_is_untested_not_pass(monkeypatch):
    def boom(*a, **k): raise OSError('network down')
    monkeypatch.setattr(scanner.socket, 'create_connection', boom)
    r = scanner.check_legacy_tls('example.com')
    assert r['status'] == 'info' and r['finding_id'] == 'tls_untested'


# ── CVE matching edge cases ─────────────────────────────────────────────────

def test_upper_bound_only_range_is_marked_approximate():
    import cve_intel
    snap = {'cves': [{'id': 'CVE-2026-1', 'published': '2026-10-01', 'score': 9.8, 'severity': 'CRITICAL',
                      'description': 'x', 'kev': False, 'watched': True,
                      'affects': [{'vendor': 'nodejs', 'product': 'node.js', 'exact': '*', 'start_incl': None,
                                   'start_excl': None, 'end_incl': None, 'end_excl': '22.23.4'}]}]}
    hit = cve_intel.match_software([('node.js', '20.1.0')], snap)[0]
    assert hit['approximate'] is True
    snap['cves'][0]['affects'][0]['start_incl'] = '22.0.0'
    assert cve_intel.match_software([('node.js', '20.1.0')], snap) == []          # outside the bounded range
    assert cve_intel.match_software([('node.js', '22.5.0')], snap)[0]['approximate'] is False


def test_approximate_cve_cannot_cap_score_as_critical(monkeypatch):
    monkeypatch.setattr(scanner.cve_intel, 'match_software', lambda d: [{
        'id': 'CVE-2026-1', 'published': '2026-10-01', 'score': 9.8, 'severity': 'CRITICAL',
        'description': 'x', 'kev': False, 'product': 'node.js', 'detected_version': '20.1.0', 'approximate': True}])
    monkeypatch.setattr(scanner.cve_intel, 'load_snapshot',
                        lambda: {'window': {'start': '2026-10-01', 'end': '2026-10-31'}, 'cves': [1]})
    res = scanner.check_known_cves({('node.js', '20.1.0'): 'x'})
    assert res[0]['severity'] == 'medium' and res[0]['status'] == 'warning' and res[0]['weight'] <= 6
    assert scanner.calculate_score(res) >= 90


def test_version_parsing_edge_cases():
    import cve_intel
    assert cve_intel.parse_banner('Apache/2.4.49 (Unix) PHP/7.4.3 OpenSSL/1.1.1k') == \
        [('apache', '2.4.49'), ('php', '7.4.3'), ('openssl', '1.1.1k')]
    assert cve_intel.parse_banner('cloudflare') == [] and cve_intel.parse_banner('') == [] \
        and cve_intel.parse_banner(None) == []
    assert cve_intel._cmp('8.1', '8.1.0') == 0 and cve_intel._cmp('2.4.9', '2.4.10') < 0
    assert cve_intel._cmp('abc', '1.0') is None


# ── advanced scanner regressions ────────────────────────────────────────────

def test_sqlmap_negative_output_is_not_reported_as_injectable():
    neg = "[WARNING] GET parameter 'id' does not seem to be injectable\n[CRITICAL] all tested parameters do not appear to be injectable"
    assert adv._parse_sqlmap_output(neg, 'http://x')['injectable'] is False


def test_sqlmap_positive_output_is_reported():
    pos = "sqlmap identified the following injection point(s)\nParameter: id (GET)\n    Type: boolean-based blind"
    assert adv._parse_sqlmap_output(pos, 'http://x')['injectable'] is True


def test_nikto_header_notes_are_not_critical():
    assert adv._classify_nikto('The X-XSS-Protection header is not defined. protect against some forms of XSS') == 'info'
    assert adv._classify_nikto('Reflected cross-site scripting (CVE-2020-1)') == 'critical'


# ── fetch_page against real local servers: odd responses ────────────────────

class _H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        if self.server.server_address[1] == getattr(_H, 'redirect_port', -1) and self.path == '/':
            self.send_response(302); self.send_header('Location', '/final'); self.end_headers(); return
        if self.path == '/redir':
            self.send_response(302); self.send_header('Location', '/final'); self.end_headers(); return
        if self.path == '/final':
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers()
            self.wfile.write(b'{"ok":true}'); return
        self.send_response(404); self.send_header('Content-Type', 'text/html'); self.end_headers()
        self.wfile.write(b'<html>not found</html>')


@pytest.fixture(scope='module')
def server():
    srv = HTTPServer(('127.0.0.1', 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_404_root_is_still_assessed_not_blocked(server):
    p = scanner.fetch_page(f'http://127.0.0.1:{server}')
    assert p.status == 404 and p.blocked is False and p.resp is not None


def test_redirect_followed_and_non_html_skips_html_checks():
    srv = HTTPServer(('127.0.0.1', 0), _H)
    _H.redirect_port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    p = scanner.fetch_page(f'http://127.0.0.1:{srv.server_address[1]}')
    srv.shutdown()
    assert p.status == 200 and 'json' in p.content_type
    assert scanner.check_page_content(p) == []          # no HTML analysis on JSON
    assert scanner.check_reflection(p) is not None


def test_unreachable_target_raises_scan_error():
    with pytest.raises(scanner.ScanError):
        scanner.run_full_scan('http://127.0.0.1:1')


def test_http_only_target_has_no_hsts_or_redirect_penalty():
    page = SimpleNamespace(scheme='http', hostname='127.0.0.1', origin='http://127.0.0.1', headers={
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'", 'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=()'}, cookies=[], body='', content_type='text/html',
        final_url='http://127.0.0.1/', blocked=False, resp=object(), cdn=None)
    res = scanner.check_headers(page)
    assert not [f for f in res if f['status'] in ('fail', 'warning')]


# ── policy / concepts / reports ─────────────────────────────────────────────

def test_score_policy_is_exposed_and_matches_scoring():
    pol = scoring_policy.as_dict()
    assert pol['kind'] == 'policy_choice_not_statistical'
    assert scanner.get_risk_level(80)[0] == 'LOW' and scanner.get_risk_level(79)[0] == 'MEDIUM'
    assert scanner.get_risk_level(59)[0] == 'HIGH' and scanner.get_risk_level(39)[0] == 'CRITICAL'
    assert scanner.get_risk_level(0)[0] == 'CRITICAL' and scanner.get_risk_level(100)[0] == 'LOW'


def test_every_concept_cites_a_textbook_chapter():
    cs = engagement.load_concepts()
    assert len(cs) >= 14
    for c in cs:
        assert c['source']['book'] and c['source']['chapter'].startswith(('Ch.', 'Gray Hat', 'Dummies'))


def test_pdf_report_builds_with_new_sections_english_and_hindi(tmp_path):
    reportlab = pytest.importorskip('reportlab')
    from report_generator import generate_pdf_report
    scan = {
        'url': 'https://example.com', 'hostname': 'example.com', 'score': 91, 'risk_level': 'LOW', 'risk_color': '#00d4aa',
        'ai_summary': 'ok', 'scanned_at': '2026-11-22 12:00 UTC',
        'findings': [_f('Header: Permissions-Policy', 'fail', 'low', 'Missing header', 'Add it', 'missing_permissions_policy', weight=1)],
        'stats': {'critical': 0, 'warnings': 1, 'passed': 3, 'total': 4},
        'score_breakdown': {'deductions': [{'check': 'Header: Permissions-Policy', 'weight': 1}], 'cap': None},
        'remediation_plan': [{'priority': 'P3: fix this month', 'check': 'Permissions-Policy', 'fix': 'Add it',
                              'owasp': 'A05:2021 Security Misconfiguration', 'cwe': 'CWE-693'}],
        'owasp_coverage': [{'id': 'A05', 'category': 'A05:2021 Security Misconfiguration', 'issues': 1, 'assessed': True}],
        'cve_feed': {'available': True, 'window': {'start': '2026-10-01T00', 'end': '2026-10-31T23'}, 'fetched_at': 'x',
                     'nvd_total_published_in_window': 17481, 'kev_count': 36},
        'methodology': {'phases': [{'phase': '1. Planning', 'status': 'done', 'detail': 'd'}], 'out_of_scope': ['x <b>& y']},
    }
    for lang in ('english', 'hindi'):
        scan['language'] = lang
        name = generate_pdf_report(scan, str(tmp_path))
        assert name and (tmp_path / name).stat().st_size > 2000
