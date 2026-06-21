import ssl, socket, requests, os, sys, logging
from urllib.parse import urlparse
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Ensure the backend directory is on the path so sub-packages can be imported
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from core.finding_ids import FindingID

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy',
]

# Map header names to their FindingID slugs (for missing/fail cases)
_HEADER_MISSING_ID = {
    'Strict-Transport-Security': FindingID.MISSING_HSTS,
    'Content-Security-Policy':   FindingID.MISSING_CSP,
    'X-Frame-Options':           FindingID.MISSING_XFO,
    'X-Content-Type-Options':    FindingID.MISSING_XCTO,
    'Referrer-Policy':           FindingID.MISSING_RP,
    'Permissions-Policy':        FindingID.MISSING_PP,
}

_HEADER_PASS_ID = {
    'Strict-Transport-Security': 'hsts_pass',
    'Content-Security-Policy':   'csp_pass',
    'X-Frame-Options':           'xfo_pass',
    'X-Content-Type-Options':    'xcto_pass',
    'Referrer-Policy':           'rp_pass',
    'Permissions-Policy':        'pp_pass',
}

# Map risky port numbers to their FindingID slugs
_PORT_FINDING_IDS = {
    21:    FindingID.OPEN_PORT_FTP,
    22:    FindingID.OPEN_PORT_SSH,
    23:    FindingID.OPEN_PORT_TELNET,
    3306:  FindingID.OPEN_PORT_MYSQL,
    5432:  FindingID.OPEN_PORT_POSTGRES,
    27017: FindingID.OPEN_PORT_MONGODB,
    6379:  FindingID.OPEN_PORT_REDIS,
    3389:  FindingID.OPEN_PORT_RDP,
}

# Severity ordering for picking "most severe" port
_PORT_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'none']


def check_ssl(hostname):
    result = {
        'check': 'SSL Certificate',
        'status': 'unknown',
        'details': '',
        'severity': 'info',
        'fix': '',
        'finding_id': 'ssl_unknown',
        'on_exploit_path': False,
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        expire_str = cert.get('notAfter', '')
        expire_dt  = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z') if expire_str else None

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        days_left = (expire_dt - now).days if expire_dt else None

        if days_left is not None and days_left < 0:
            result.update({
                'status': 'fail', 'severity': 'critical',
                'details': 'SSL certificate has EXPIRED.',
                'fix': "Renew your SSL certificate now. An expired cert scares away customers and exposes data.",
                'finding_id': FindingID.SSL_EXPIRED,
            })
        elif days_left is not None and days_left < 30:
            result.update({
                'status': 'warning', 'severity': 'medium',
                'details': f'SSL certificate expires in {days_left} days.',
                'fix': "Renew your SSL certificate immediately using your hosting provider or Let's Encrypt (free).",
                'finding_id': FindingID.SSL_EXPIRING,
            })
        else:
            result.update({
                'status': 'pass', 'severity': 'none',
                'details': f'SSL certificate is valid. Expires in {days_left} days.' if days_left else 'SSL valid.',
                'fix': '',
                'finding_id': 'ssl_valid',
            })
    except ssl.SSLError as e:
        result.update({
            'status': 'fail', 'severity': 'critical',
            'details': f'SSL error: {str(e)}',
            'fix': "Install a valid SSL certificate. Use Let's Encrypt for free SSL.",
            'finding_id': FindingID.SSL_INVALID,
        })
    except Exception as e:
        logger.warning(f"SSL check failed for {hostname}: {e}")
        result.update({
            'status': 'fail', 'severity': 'high',
            'details': f'Could not connect over HTTPS: {str(e)}',
            'fix': 'Ensure your site uses HTTPS. Most hosting providers offer free SSL.',
            'finding_id': FindingID.SSL_INVALID,
        })
    return result


def check_headers(url):
    results = []
    try:
        parsed    = urlparse(url)
        hostname  = parsed.hostname or parsed.path.split('/')[0]
        scheme    = parsed.scheme if parsed.scheme in ('http', 'https') else 'https'
        target_url = f'{scheme}://{hostname}'

        r = requests.get(
            target_url, timeout=8, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; PRAWL/1.0)'}
        )
        headers = {k.lower(): v for k, v in r.headers.items()}

        for h in SECURITY_HEADERS:
            found = h.lower() in headers
            results.append({
                'check':    f'Header: {h}',
                'status':   'pass' if found else 'fail',
                'severity': 'none' if found else 'medium',
                'details':  f'Present: {headers[h.lower()]}' if found else f'Missing header: {h}',
                'fix':      '' if found else get_header_fix(h),
                'finding_id': _HEADER_PASS_ID.get(h, f'header_{h.lower().replace("-","_")}_pass') if found
                              else _HEADER_MISSING_ID.get(h, f'missing_header_{h.lower().replace("-","_")}'),
                'on_exploit_path': False,
            })

        # HTTPS redirect check
        try:
            http_r = requests.get(
                f'http://{hostname}', timeout=5, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; PRAWL/1.0)'}
            )
            if http_r.url.startswith('https://'):
                results.append({
                    'check': 'HTTPS Redirect', 'status': 'pass', 'severity': 'none',
                    'details': 'HTTP correctly redirects to HTTPS.', 'fix': '',
                    'finding_id': 'https_redirect_pass', 'on_exploit_path': False,
                })
            else:
                results.append({
                    'check': 'HTTPS Redirect', 'status': 'fail', 'severity': 'medium',
                    'details': 'HTTP traffic is not redirected to HTTPS.',
                    'fix': 'Configure your web server to redirect all HTTP traffic to HTTPS.',
                    'finding_id': FindingID.NO_HTTPS_REDIRECT, 'on_exploit_path': False,
                })
        except Exception as e:
            logger.debug(f"HTTP redirect check: {e} — assuming HTTPS-only (good)")
            results.append({
                'check': 'HTTPS Redirect', 'status': 'pass', 'severity': 'none',
                'details': 'HTTP port not accessible — site is HTTPS only.', 'fix': '',
                'finding_id': 'https_redirect_pass', 'on_exploit_path': False,
            })

    except Exception as e:
        logger.warning(f"Header check failed for {url}: {e}")
        err_msg = "Connection failed or refused. Target may be unreachable." if "Max retries exceeded" in str(e) else str(e)
        results.append({
            'check': 'Security Headers', 'status': 'error', 'severity': 'high',
            'details': err_msg, 'fix': 'Check that your website is reachable on this port.',
            'finding_id': 'security_headers_error', 'on_exploit_path': False,
        })
    return results


def get_header_fix(header):
    fixes = {
        'Strict-Transport-Security': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        'Content-Security-Policy':   'Add Content-Security-Policy header to prevent XSS attacks.',
        'X-Frame-Options':           'Add X-Frame-Options: DENY to block clickjacking attacks.',
        'X-Content-Type-Options':    'Add X-Content-Type-Options: nosniff to prevent MIME sniffing.',
        'Referrer-Policy':           'Add Referrer-Policy: strict-origin-when-cross-origin to stop data leaking.',
        'Permissions-Policy':        'Add Permissions-Policy header to control camera/mic/location access.',
    }
    return fixes.get(header, f'Add the {header} header to your server configuration.')


def check_open_ports(hostname):
    common_ports = {
        21: 'FTP',  22: 'SSH',         23: 'Telnet',   25: 'SMTP',
        3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB',
        6379: 'Redis',  8080: 'HTTP Alt',  8443: 'HTTPS Alt',
        3389: 'RDP',
    }
    risky_ports = [21, 23, 3306, 5432, 27017, 6379, 22, 3389]
    open_ports  = []

    for port, service in common_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            r1 = s.connect_ex((hostname, port))
            s.close()
            if r1 == 0:
                # Double-verify to eliminate false positives
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(1.5)
                r2 = s2.connect_ex((hostname, port))
                s2.close()
                if r2 == 0:
                    open_ports.append({'port': port, 'service': service, 'risky': port in risky_ports})
        except Exception as e:
            logger.debug(f"Port {port} check error on {hostname}: {e}")

    if not open_ports:
        return [{'check': 'Open Ports', 'status': 'pass', 'severity': 'none',
                 'details': 'No unexpected open ports detected.', 'fix': '',
                 'finding_id': 'open_ports_pass', 'on_exploit_path': False}]

    results = []
    risky = [p for p in open_ports if p['risky']]
    safe  = [p for p in open_ports if not p['risky']]

    if risky:
        port_list = ', '.join([f"{p['port']} ({p['service']})" for p in risky])

        # Collect all finding_ids for risky ports
        risky_finding_ids = []
        for p in risky:
            fid = _PORT_FINDING_IDS.get(p['port'])
            if fid:
                risky_finding_ids.append(fid)

        # Pick the most severe port's finding_id as the primary finding_id
        # Port priority: DB ports > RDP > SSH > FTP > Telnet
        primary_priority = [
            FindingID.OPEN_PORT_MONGODB, FindingID.OPEN_PORT_MYSQL,
            FindingID.OPEN_PORT_POSTGRES, FindingID.OPEN_PORT_REDIS,
            FindingID.OPEN_PORT_RDP, FindingID.OPEN_PORT_SSH,
            FindingID.OPEN_PORT_FTP, FindingID.OPEN_PORT_TELNET,
        ]
        primary_id = next(
            (fid for fid in primary_priority if fid in risky_finding_ids),
            risky_finding_ids[0] if risky_finding_ids else 'open_port_risky'
        )

        results.append({
            'check': 'Dangerous Open Ports', 'status': 'fail', 'severity': 'high',
            'details': f'Risky ports exposed to internet: {port_list}',
            'fix': 'Close these ports in your firewall immediately. Database ports should NEVER be public.',
            'finding_id': primary_id,
            'finding_ids': risky_finding_ids,
            'on_exploit_path': False,
        })

    if safe:
        port_list = ', '.join([f"{p['port']} ({p['service']})" for p in safe])
        results.append({
            'check': 'Open Service Ports', 'status': 'warning', 'severity': 'low',
            'details': f'Additional ports open: {port_list}.',
            'fix': 'Check with your hosting provider whether these ports need to be publicly accessible.',
            'finding_id': 'open_ports_safe', 'on_exploit_path': False,
        })
    return results


def check_software_versions(url):
    results = []
    try:
        parsed   = urlparse(url)
        hostname = parsed.hostname or parsed.path.split('/')[0]
        scheme   = parsed.scheme if parsed.scheme in ('http', 'https') else 'https'
        r = requests.get(
            f'{scheme}://{hostname}', timeout=8,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; PRAWL/1.0)'}
        )
        disclosed = []
        for h in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']:
            if h in r.headers:
                disclosed.append(f'{h}: {r.headers[h]}')
        if disclosed:
            results.append({
                'check': 'Software Version Disclosure', 'status': 'warning', 'severity': 'low',
                'details': f'Server discloses software info: {"; ".join(disclosed)}',
                'fix': 'Hide version info. Apache: ServerTokens Prod. Nginx: server_tokens off.',
                'finding_id': FindingID.SOFTWARE_DISCLOSURE, 'on_exploit_path': False,
            })
        else:
            results.append({
                'check': 'Software Version Disclosure', 'status': 'pass', 'severity': 'none',
                'details': 'No software version information leaked in headers.', 'fix': '',
                'finding_id': 'software_version_pass', 'on_exploit_path': False,
            })
    except Exception as e:
        logger.warning(f"Version check failed for {url}: {e}")
        err_msg = "Connection failed or refused." if "Max retries exceeded" in str(e) else str(e)
        results.append({
            'check': 'Software Version Check', 'status': 'error',
            'severity': 'info', 'details': err_msg, 'fix': '',
            'finding_id': 'software_version_error', 'on_exploit_path': False,
        })
    return results


def check_cookies_secure(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=False)
        cookies_header = response.headers.get('set-cookie', '').lower()
        if not cookies_header:
            return [{'check': 'Cookie Security', 'status': 'pass', 'severity': 'none',
                     'details': 'No session cookies are exposed directly on initialization.', 'fix': 'N/A',
                     'finding_id': 'cookies_pass', 'on_exploit_path': False}]

        missing_secure = 'secure' not in cookies_header
        missing_httponly = 'httponly' not in cookies_header

        if missing_secure and url.startswith('https://'):
            return [{'check': 'Cookie Security', 'status': 'warning', 'severity': 'medium',
                     'details': 'Cookies are missing the Secure flag, making them vulnerable to interception over unencrypted connections.',
                     'fix': 'Set the Secure flag on all session cookies.',
                     'finding_id': FindingID.INSECURE_COOKIES, 'on_exploit_path': False}]
        if missing_httponly:
            return [{'check': 'Cookie Security', 'status': 'warning', 'severity': 'medium',
                     'details': 'Cookies are missing the HttpOnly flag, increasing risk of Cross-Site Scripting (XSS) token theft.',
                     'fix': 'Set the HttpOnly flag on all sensitive cookies.',
                     'finding_id': FindingID.INSECURE_COOKIES, 'on_exploit_path': False}]

        return [{'check': 'Cookie Security', 'status': 'pass', 'severity': 'none',
                 'details': 'Cookies are configured securely.', 'fix': '',
                 'finding_id': 'cookies_pass', 'on_exploit_path': False}]
    except Exception as e:
        return [{'check': 'Cookie Security', 'status': 'error', 'severity': 'info',
                 'details': f'Failed to check cookies: {str(e)}', 'fix': '',
                 'finding_id': 'cookies_error', 'on_exploit_path': False}]


def check_cors(url):
    try:
        headers = {'Origin': 'https://evil.com'}
        response = requests.get(url, headers=headers, timeout=10)
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        if acao == '*' or acao == 'https://evil.com':
            return [{'check': 'CORS Configuration', 'status': 'warning', 'severity': 'medium',
                     'details': f"Overly permissive CORS policy detected (Access-Control-Allow-Origin: {acao}).",
                     'fix': "Restrict CORS headers to trusted domains only instead of a wildcard.",
                     'finding_id': FindingID.CORS_WILDCARD, 'on_exploit_path': False}]
        return [{'check': 'CORS Configuration', 'status': 'pass', 'severity': 'none',
                 'details': 'CORS policy appears restrictive.', 'fix': '',
                 'finding_id': 'cors_pass', 'on_exploit_path': False}]
    except Exception as e:
        return [{'check': 'CORS Configuration', 'status': 'error', 'severity': 'info',
                 'details': f'Failed to check CORS: {str(e)}', 'fix': '',
                 'finding_id': 'cors_error', 'on_exploit_path': False}]


def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=False)
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        results = []

        if 'x-frame-options' not in headers and 'content-security-policy' not in headers:
            results.append({
                'check': 'Clickjacking Protection', 'status': 'warning', 'severity': 'medium',
                'details': 'Missing X-Frame-Options or CSP frame-ancestors. Site may be vulnerable to Clickjacking.',
                'fix': 'Add X-Frame-Options: DENY or SAMEORIGIN.',
                'finding_id': FindingID.CLICKJACKING, 'on_exploit_path': False,
            })
        else:
            results.append({
                'check': 'Clickjacking Protection', 'status': 'pass', 'severity': 'none',
                'details': 'Anti-clickjacking headers are present.', 'fix': '',
                'finding_id': 'clickjacking_pass', 'on_exploit_path': False,
            })

        if 'x-content-type-options' not in headers:
            results.append({
                'check': 'MIME Sniffing', 'status': 'warning', 'severity': 'low',
                'details': 'Missing X-Content-Type-Options header.',
                'fix': 'Add X-Content-Type-Options: nosniff.',
                'finding_id': FindingID.MIME_SNIFFING, 'on_exploit_path': False,
            })
        else:
            results.append({
                'check': 'MIME Sniffing', 'status': 'pass', 'severity': 'none',
                'details': 'MIME-sniffing protection enabled.', 'fix': '',
                'finding_id': 'mime_sniffing_pass', 'on_exploit_path': False,
            })

        if url.startswith('https://'):
            if 'strict-transport-security' not in headers:
                results.append({
                    'check': 'HSTS Check', 'status': 'warning', 'severity': 'medium',
                    'details': 'HTTP Strict-Transport-Security (HSTS) is not enabled.',
                    'fix': 'Add Strict-Transport-Security header to enforce secure connections.',
                    'finding_id': FindingID.MISSING_HSTS, 'on_exploit_path': False,
                })
            else:
                results.append({
                    'check': 'HSTS Check', 'status': 'pass', 'severity': 'none',
                    'details': 'HSTS is enabled.', 'fix': '',
                    'finding_id': 'hsts_pass', 'on_exploit_path': False,
                })

        return results
    except Exception as e:
        return [{'check': 'Advanced Security Headers', 'status': 'error', 'severity': 'info',
                 'details': f'Failed to verify headers: {str(e)}', 'fix': '',
                 'finding_id': 'adv_headers_error', 'on_exploit_path': False}]


def check_exposed_files(url):
    base_url = url.rstrip('/')
    results = []

    try:
        env_resp = requests.get(base_url + '/.env', timeout=5, allow_redirects=False)
        if env_resp.status_code == 200 and 'DB_' in env_resp.text:
            results.append({
                'check': 'Exposed Secrets (.env)', 'status': 'fail', 'severity': 'critical',
                'details': '.env configuration file is publicly exposed!',
                'fix': 'Deny access to dotfiles located in the root web directory.',
                'finding_id': FindingID.EXPOSED_ENV, 'on_exploit_path': False,
                'evidence': {'leaked_source': env_resp.text[:500]},
            })
    except Exception:
        pass

    try:
        git_resp = requests.get(base_url + '/.git/config', timeout=5, allow_redirects=False)
        if git_resp.status_code == 200 and '[core]' in git_resp.text:
            results.append({
                'check': 'Exposed Codebase (.git)', 'status': 'fail', 'severity': 'critical',
                'details': 'Git configuration folder is publicly exposed!',
                'fix': 'Deny access to the .git directory immediately.',
                'finding_id': FindingID.EXPOSED_GIT, 'on_exploit_path': False,
                'evidence': {'leaked_source': git_resp.text[:500]},
            })
    except Exception:
        pass

    if not results:
        results.append({
            'check': 'Sensitive Files Exposure', 'status': 'pass', 'severity': 'none',
            'details': 'No common sensitive configuration files (.env, .git) exposed.', 'fix': '',
            'finding_id': 'exposed_files_pass', 'on_exploit_path': False,
        })

    return results


def calculate_score(findings):
    """Legacy additive score — kept for backwards compatibility."""
    score        = 100
    deductions   = {'critical': 15, 'high': 10, 'medium': 5, 'low': 2, 'info': 0, 'none': 0}
    per_check_cap = 15
    per_check_totals = {}

    for f in findings:
        if f['status'] in ['fail', 'warning', 'error']:
            sev = f.get('severity', 'medium')
            key = f.get('check', 'Unknown')
            per_check_totals[key] = per_check_totals.get(key, 0) + deductions.get(sev, 5)

    for total in per_check_totals.values():
        score -= min(total, per_check_cap)

    return max(0, min(score, 95))


def get_risk_level(score, findings):
    if score >= 75: return 'LOW',      '#00d4aa'
    if score >= 60: return 'MEDIUM',   '#f59e0b'
    if score >= 40: return 'HIGH',     '#f97316'
    return                 'CRITICAL', '#ef4444'


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
No bullet points. No jargon. Plain paragraph only.
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
    if score >= 75:
        return (f"Your website scored {score}/100 — good security overall. "
                f"We found {len(issues)} minor issue(s) to address. "
                "Add the missing security headers to fully protect your customers.")
    elif score >= 60:
        return (f"Your website scored {score}/100 — moderate risk. "
                f"We found {len(issues)} security issues including {len(critical)} high-priority item(s). "
                "Address the red-flagged findings this week to protect your customers.")
    else:
        return (f"Your website scored {score}/100 — this is high risk. "
                f"We found {len(critical)} critical issues out of {len(issues)} total problems. "
                "Contact your hosting provider today and ask them to fix the critical items on this report.")


def _mark_exploit_path(findings, G):
    """
    Mark findings that appear as nodes on the attack graph.
    findings: list of finding dicts (mutable)
    G: networkx DiGraph
    """
    try:
        graph_node_ids = set(G.nodes())
        for f in findings:
            fid = f.get('finding_id', '')
            if fid in graph_node_ids:
                f['on_exploit_path'] = True
            # Also check finding_ids list (for multi-port findings)
            for extra_fid in f.get('finding_ids', []):
                if extra_fid in graph_node_ids:
                    f['on_exploit_path'] = True
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
    findings = []
    findings.append(check_ssl(hostname))
    findings.extend(check_headers(url))
    findings.extend(check_open_ports(hostname))
    findings.extend(check_software_versions(url))
    findings.extend(check_cookies_secure(url))
    findings.extend(check_cors(url))
    findings.extend(check_security_headers(url))
    findings.extend(check_exposed_files(url))

    # Legacy technical score (kept for backwards compatibility)
    technical_score        = calculate_score(findings)
    risk_level, risk_color = get_risk_level(technical_score, findings)

    # ── LAYER 1A: ATTACK-PATH ENGINE ─────────────────────────────────────────
    attack_graph_json = {"nodes": [], "edges": []}
    exploit_result = {"risk": 100 - technical_score, "reachable": False,
                      "best_path": None, "distinct_routes": 0, "paths": []}
    attack_narrative = ""

    try:
        from attackpath.attack_graph import build_attack_graph, to_cytoscape_json, get_node_labels
        from attackpath.path_scorer import exploitability
        from attackpath.narrative import generate_narrative

        G = build_attack_graph(findings)

        # Mark findings that appear on the attack graph
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
    compliance_result = {
        "readiness_score": 100,
        "hits": [],
        "brief": "",
        "disclaimer": "Indicative compliance guidance generated from public information about the DPDP Act and CERT-In Directions. Not legal advice. Consult a qualified professional."
    }

    try:
        from compliance.compliance_mapper import map_findings_to_obligations, dpdp_readiness_score
        from compliance.brief_generator import generate_compliance_brief

        hits = map_findings_to_obligations(findings)
        readiness_score = dpdp_readiness_score(hits)
        brief = generate_compliance_brief(url, hits, readiness_score, language)

        compliance_result = {
            "readiness_score": readiness_score,
            "hits": hits,
            "brief": brief,
            "disclaimer": "Indicative compliance guidance generated from public information about the DPDP Act and CERT-In Directions. Not legal advice. Consult a qualified professional."
        }
    except Exception as e:
        logger.warning(f"Compliance engine failed: {e}")

    # ── LAYER 1C: PHISHING WATCH (non-blocking, 30s timeout) ─────────────────
    impersonators = []
    try:
        impersonators = _run_phishing_watch(hostname, timeout=30)
    except Exception as e:
        logger.warning(f"Phishing watch error: {e}")

    # ── LAYER 2: AI SUMMARY ──────────────────────────────────────────────────
    # Convert exploit risk (0-100 where higher is worse) to security score (100 - risk where higher is better)
    final_score = 100 - exploit_result.get("risk", 100 - technical_score)
    risk_level, risk_color = get_risk_level(final_score, findings)
    ai_summary = generate_ai_summary(url, findings, final_score, language)

    critical_count = len([f for f in findings if f['status'] == 'fail'              and f['severity'] in ['critical', 'high']])
    warning_count  = len([f for f in findings if f['status'] in ['warning', 'fail'] and f['severity'] in ['medium', 'low']])
    pass_count     = len([f for f in findings if f['status'] == 'pass'])

    # ── LAYER 3: UNIFIED RESPONSE ────────────────────────────────────────────
    return {
        'url': url, 'hostname': hostname,
        # Primary score is now exploit-based (or technical if no graph)
        'score': final_score,
        'risk_level': risk_level, 'risk_color': risk_color,
        'ai_summary': ai_summary, 'findings': findings,
        'stats': {
            'critical': critical_count, 'warnings': warning_count,
            'passed': pass_count, 'total': len(findings)
        },
        'scanned_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),

        # Feature 2 — attack-path engine
        'exploit': {
            'risk': exploit_result.get("risk", 100 - technical_score),
            'reachable': exploit_result.get("reachable", False),
            'best_path': exploit_result.get("best_path"),
            'distinct_routes': exploit_result.get("distinct_routes", 0),
            'narrative': attack_narrative,
        },

        # Feature 3 — attack-path graph (Cytoscape JSON)
        'attack_graph': attack_graph_json,

        # Feature 1 — DPDP compliance
        'compliance': compliance_result,

        # Feature 4 — phishing domain watch
        'impersonators': impersonators,

        # Backwards compatibility
        'technical_score': technical_score,
    }
