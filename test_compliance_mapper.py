"""
Headless unit tests for backend/compliance/compliance_mapper.py (Feature 1).
No network, no browser -- pure functions over synthetic finding lists.
Run: pytest test_compliance_mapper.py -v
"""
from compliance.compliance_mapper import map_findings_to_obligations, dpdp_readiness_score


def _finding(finding_id, status='fail', on_exploit_path=False):
    return {'finding_id': finding_id, 'status': status, 'on_exploit_path': on_exploit_path}


def test_empty_findings_gives_perfect_score():
    hits = map_findings_to_obligations([])
    assert hits == []
    assert dpdp_readiness_score(hits) == 100


def test_passing_findings_are_ignored():
    hits = map_findings_to_obligations([_finding('open_port_mysql', status='pass')])
    assert hits == []
    assert dpdp_readiness_score(hits) == 100


def test_low_weight_finding_off_path_is_partial_not_gap():
    # missing_hsts is "low" weight under dpdp_reasonable_safeguards and not on an exploit path
    hits = map_findings_to_obligations([_finding('missing_hsts', on_exploit_path=False)])
    safeguard = next(h for h in hits if h['obligation_id'] == 'dpdp_reasonable_safeguards')
    assert safeguard['status'] == 'partial'


def test_high_weight_finding_is_a_gap_regardless_of_exploit_path():
    # exposed_env_file is "high" weight -> gap even without exploit-path confirmation
    hits = map_findings_to_obligations([_finding('exposed_env_file', on_exploit_path=False)])
    safeguard = next(h for h in hits if h['obligation_id'] == 'dpdp_reasonable_safeguards')
    assert safeguard['status'] == 'gap'


def test_low_weight_finding_amplified_to_gap_when_on_exploit_path():
    # Same low-weight finding as above, but now confirmed reachable to a breach
    hits = map_findings_to_obligations([_finding('missing_hsts', on_exploit_path=True)])
    safeguard = next(h for h in hits if h['obligation_id'] == 'dpdp_reasonable_safeguards')
    assert safeguard['status'] == 'gap'


def test_penalty_ceiling_is_the_documented_band_not_a_fabricated_figure():
    hits = map_findings_to_obligations([_finding('exposed_env_file')])
    safeguard = next(h for h in hits if h['obligation_id'] == 'dpdp_reasonable_safeguards')
    # Must equal the documented ceiling (Rs.250 crore) exactly -- never a derived "precise" number
    assert safeguard['penalty_ceiling_inr'] == 2_500_000_000


def test_readiness_score_drops_for_unmitigated_gaps():
    clean_score = dpdp_readiness_score(map_findings_to_obligations(
        [_finding('open_port_mysql', status='pass')]
    ))
    breached_score = dpdp_readiness_score(map_findings_to_obligations(
        [_finding('exposed_env_file', on_exploit_path=True)]
    ))
    assert clean_score == 100
    assert 0 <= breached_score < clean_score


def test_unmapped_finding_id_triggers_no_obligation():
    hits = map_findings_to_obligations([_finding('totally_unknown_finding_id')])
    assert hits == []
