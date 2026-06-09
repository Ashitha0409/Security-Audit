"""
validation.py — target sanitisation for PRAWL.

Every value that ends up as a command-line argument to nmap / nikto / sqlmap,
or as a network target, passes through here first.

subprocess list-form already blocks *shell* injection, but it does NOT block
*argument* injection — a token like "--script=..." would be read by the tool
as a FLAG, not a host. These helpers reject anything that isn't a plain
hostname / IP / CIDR (in particular, anything starting with "-").

NOTE: localhost and RFC-1918 private ranges are intentionally allowed — PRAWL
is used for on-prem / internal testing, not hosted publicly.
"""
import ipaddress
import re
from urllib.parse import urlparse

# Hostname per RFC 1123 (labels of letters/digits/hyphen, not starting/ending
# with a hyphen). Underscores tolerated for internal hosts.
_HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}$)'
    r'([A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?)'
    r'(\.[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?)*$'
)

_PRIVATE_PREFIX_RE = re.compile(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)')


class TargetValidationError(ValueError):
    """Raised when a user-supplied target is missing or unsafe."""


def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def _is_valid_host(host: str) -> bool:
    host = host.strip()
    if not host or host.startswith('-'):
        return False
    # IPv6 literals may arrive bracketed: [::1]
    bare = host[1:-1] if host.startswith('[') and host.endswith(']') else host
    if _is_ip(bare):
        return True
    return bool(_HOSTNAME_RE.match(host))


def _extract_host(raw: str) -> str:
    """Strip scheme / path / query / fragment and return the bare host."""
    raw = raw.strip()
    for prefix in ('https://', 'http://'):
        if raw.lower().startswith(prefix):
            raw = raw[len(prefix):]
            break
    # host is everything before the first /, ?, # or whitespace
    return re.split(r'[/?#\s]', raw, 1)[0]


def normalize_web_target(raw: str):
    """
    Validate a user-supplied website target and return (url, hostname).

    Adds a scheme if missing — http:// for localhost/private addresses,
    https:// otherwise. Raises TargetValidationError on anything unsafe.
    """
    if not raw or not raw.strip():
        raise TargetValidationError('No URL provided')

    candidate = raw.strip().split()[0].rstrip('/')
    if candidate.startswith('-'):
        raise TargetValidationError('Invalid target.')

    url = candidate
    if not url.startswith(('http://', 'https://')):
        host_only = _extract_host(url)
        if host_only.startswith('localhost') or _PRIVATE_PREFIX_RE.match(host_only):
            url = 'http://' + url
        else:
            url = 'https://' + url

    hostname = urlparse(url).hostname or ''
    if not _is_valid_host(hostname):
        raise TargetValidationError('Please enter a valid website URL or host.')
    return url, hostname


def safe_url(raw: str) -> str:
    """Validated URL (with scheme) — for tools that need a full URL (nikto, sqlmap)."""
    url, _ = normalize_web_target(raw)
    return url


def safe_hostname(raw: str) -> str:
    """Validated bare hostname/IP — for tools that take a host (nmap, crt.sh)."""
    if not raw or not raw.strip():
        raise TargetValidationError('No target provided')
    host = _extract_host(raw)
    if not _is_valid_host(host):
        raise TargetValidationError(f'Invalid or unsafe target: {raw!r}')
    # Return bare host without IPv6 brackets for socket/CLI use
    if host.startswith('[') and host.endswith(']'):
        return host[1:-1]
    return host


def safe_cidr_targets(raw: str):
    """
    Validate a CIDR block / comma- or space-separated list of IPs/hosts.
    Returns a list of normalised tokens safe to append to an nmap argv.
    Raises TargetValidationError on anything unsafe.
    """
    if not raw or not raw.strip():
        raise TargetValidationError('No CIDR or IP range provided')

    tokens = [t for t in re.split(r'[,\s]+', raw.strip()) if t]
    if not tokens:
        raise TargetValidationError('No targets provided')

    cleaned = []
    for tok in tokens:
        if tok.startswith('-'):
            raise TargetValidationError(f'Invalid target: {tok!r}')
        if '/' in tok:
            try:
                cleaned.append(str(ipaddress.ip_network(tok, strict=False)))
            except ValueError:
                raise TargetValidationError(f'Invalid CIDR: {tok!r}')
        elif _is_ip(tok) or _is_valid_host(tok):
            cleaned.append(tok)
        else:
            raise TargetValidationError(f'Invalid host/IP: {tok!r}')
    return cleaned
