"""Tests for validation.py — the argument-injection / target-sanitisation layer.

These are security-critical: every value that becomes a CLI argument to
nmap/nikto/sqlmap, or a network target, passes through here first.
"""
import pytest

from validation import (
    normalize_web_target,
    safe_url,
    safe_hostname,
    safe_cidr_targets,
    TargetValidationError,
)


# ── normalize_web_target ──────────────────────────────────────────────────

def test_adds_https_for_public_host():
    url, host = normalize_web_target("example.com")
    assert url == "https://example.com"
    assert host == "example.com"


def test_adds_http_for_localhost():
    url, host = normalize_web_target("localhost:8080")
    assert url == "http://localhost:8080"
    assert host == "localhost"


def test_adds_http_for_private_ip():
    url, host = normalize_web_target("192.168.1.10")
    assert url == "http://192.168.1.10"
    assert host == "192.168.1.10"


def test_preserves_explicit_http_scheme():
    url, host = normalize_web_target("http://example.com/path?q=1")
    assert url == "http://example.com/path?q=1"
    assert host == "example.com"


def test_empty_input_rejected():
    with pytest.raises(TargetValidationError):
        normalize_web_target("")
    with pytest.raises(TargetValidationError):
        normalize_web_target("   ")


@pytest.mark.parametrize("hostile", [
    "-oN/tmp/pwn",          # nmap output flag
    "--script=http-shellshock",
    "-Pn",
])
def test_argument_injection_tokens_rejected(hostile):
    """A target starting with '-' would be read by the tool as a FLAG."""
    with pytest.raises(TargetValidationError):
        normalize_web_target(hostile)


# ── safe_url / safe_hostname ──────────────────────────────────────────────

def test_safe_url_returns_scheme_url():
    assert safe_url("example.com") == "https://example.com"


def test_safe_hostname_strips_scheme_and_path():
    assert safe_hostname("https://example.com/admin") == "example.com"


def test_safe_hostname_strips_ipv6_brackets():
    assert safe_hostname("[::1]") == "::1"


def test_safe_hostname_rejects_flag():
    with pytest.raises(TargetValidationError):
        safe_hostname("-oG")


def test_safe_hostname_rejects_empty():
    with pytest.raises(TargetValidationError):
        safe_hostname("")


# ── safe_cidr_targets ─────────────────────────────────────────────────────

def test_cidr_normalised():
    assert safe_cidr_targets("192.168.1.0/24") == ["192.168.1.0/24"]


def test_cidr_host_bits_normalised_to_network():
    # 192.168.1.55/24 -> network address form
    assert safe_cidr_targets("192.168.1.55/24") == ["192.168.1.0/24"]


def test_cidr_accepts_comma_and_space_separated_list():
    result = safe_cidr_targets("10.0.0.1, 10.0.0.2  example.com")
    assert result == ["10.0.0.1", "10.0.0.2", "example.com"]


def test_cidr_rejects_flag_token():
    with pytest.raises(TargetValidationError):
        safe_cidr_targets("192.168.1.0/24, -sS")


def test_cidr_rejects_garbage_cidr():
    with pytest.raises(TargetValidationError):
        safe_cidr_targets("999.999.0.0/24")


def test_cidr_rejects_invalid_host():
    with pytest.raises(TargetValidationError):
        safe_cidr_targets("not a valid host!!")


def test_cidr_empty_rejected():
    with pytest.raises(TargetValidationError):
        safe_cidr_targets("")
