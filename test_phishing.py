"""
Headless unit tests for backend/phishing/impersonator_scorer.py (Feature 4).
All network calls (CT lookups, DNS resolution) are mocked -- no live network use.
Run: pytest test_phishing.py -v
"""
import phishing.impersonator_scorer as scorer_mod
from phishing.impersonator_scorer import score_impersonators


def test_unregistered_candidates_are_filtered_out(monkeypatch):
    # Neither a certificate nor a DNS hit -> must not appear in results (the core filter
    # that keeps dnstwist's hundreds of permutations from becoming noise).
    monkeypatch.setattr(scorer_mod, 'domain_exists_in_ct', lambda c: False)
    monkeypatch.setattr(scorer_mod, 'resolves', lambda c: False)
    results = score_impersonators('real.com', ['nobody-registered-this.com'])
    assert results == []


def test_existing_candidate_is_kept_and_scored(monkeypatch):
    monkeypatch.setattr(scorer_mod, 'domain_exists_in_ct', lambda c: True)
    monkeypatch.setattr(scorer_mod, 'resolves', lambda c: True)
    results = score_impersonators('real.com', ['fake-real.com'])
    assert len(results) == 1
    assert results[0]['domain'] == 'fake-real.com'
    assert results[0]['has_cert'] is True
    assert results[0]['resolves'] is True


def test_threat_score_composition(monkeypatch):
    monkeypatch.setattr(scorer_mod, 'domain_exists_in_ct', lambda c: True)
    monkeypatch.setattr(scorer_mod, 'resolves', lambda c: False)
    results = score_impersonators('real.com', ['cert-only.com'])
    assert results[0]['threat'] == 40  # cert only

    monkeypatch.setattr(scorer_mod, 'domain_exists_in_ct', lambda c: False)
    monkeypatch.setattr(scorer_mod, 'resolves', lambda c: True)
    results = score_impersonators('real.com', ['dns-only.com'])
    assert results[0]['threat'] == 30  # dns only

    monkeypatch.setattr(scorer_mod, 'domain_exists_in_ct', lambda c: True)
    monkeypatch.setattr(scorer_mod, 'resolves', lambda c: True)
    results = score_impersonators('real.com', ['real-login-secure.com'])
    assert results[0]['threat'] == 100  # cert + dns + phishing keyword, capped at 100


def test_real_domain_is_excluded_from_candidates(monkeypatch):
    monkeypatch.setattr(scorer_mod, 'domain_exists_in_ct', lambda c: True)
    monkeypatch.setattr(scorer_mod, 'resolves', lambda c: True)
    results = score_impersonators('real.com', ['real.com', 'fake-real.com'])
    domains = [r['domain'] for r in results]
    assert 'real.com' not in domains
    assert 'fake-real.com' in domains


def test_results_sorted_by_threat_descending(monkeypatch):
    monkeypatch.setattr(scorer_mod, 'domain_exists_in_ct', lambda c: 'high' in c)
    monkeypatch.setattr(scorer_mod, 'resolves', lambda c: True)
    results = score_impersonators('real.com', ['low-threat.com', 'high-threat-login.com'])
    assert results[0]['domain'] == 'high-threat-login.com'
    assert results[0]['threat'] >= results[-1]['threat']


def test_empty_candidate_list_returns_empty():
    assert score_impersonators('real.com', []) == []
