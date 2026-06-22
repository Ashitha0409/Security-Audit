"""
Headless unit tests for backend/attackpath/attack_graph.py and path_scorer.py (Feature 2).
No network, no browser -- pure functions over synthetic finding lists.
Run: pytest test_attack_path.py -v
"""
from attackpath.attack_graph import build_attack_graph, to_cytoscape_json
from attackpath.path_scorer import exploitability, GOAL


def _finding(finding_id, status='fail', evidence=None):
    return {'finding_id': finding_id, 'check': finding_id, 'status': status,
            'severity': 'high', 'evidence': evidence or {}}


def test_no_findings_means_no_path():
    G = build_attack_graph([])
    result = exploitability(G)
    assert result['reachable'] is False
    assert result['risk'] == 0
    assert result['paths'] == []


def test_isolated_finding_has_no_path_to_goal():
    # missing_hsts has no transition defined in attack_transitions.json -> must stay isolated
    G = build_attack_graph([_finding('missing_hsts')])
    assert 'missing_hsts' in G.nodes()
    assert G.in_degree('missing_hsts') == 0
    assert G.out_degree('missing_hsts') == 0

    result = exploitability(G)
    assert result['reachable'] is False
    # un-chained findings can never score "critical" risk (spec's structural-risk cap)
    assert result['risk'] <= 60


def test_sql_injection_alone_reaches_customer_pii_breach():
    G = build_attack_graph([_finding('sql_injection')])
    result = exploitability(G)
    assert result['reachable'] is True
    assert result['best_path']['path'][0] == 'sql_injection'
    assert result['best_path']['path'][-1] == GOAL
    assert 0 < result['risk'] <= 100


def test_source_to_creds_requires_evidence_gate():
    # exposed_git_dir alone gives source_code_disclosure but NOT leaked_db_credentials --
    # that edge only fires if a credential pattern is actually found in the leaked source.
    G_no_evidence = build_attack_graph([_finding('exposed_git_dir')])
    assert 'source_code_disclosure' in G_no_evidence.nodes()
    assert 'leaked_db_credentials' not in G_no_evidence.nodes()

    G_with_evidence = build_attack_graph([
        _finding('exposed_git_dir', evidence={'leaked_source': 'DB_PASSWORD=supersecret123'})
    ])
    assert 'leaked_db_credentials' in G_with_evidence.nodes()


def test_converging_paths_score_higher_than_a_single_path():
    single = build_attack_graph([_finding('sql_injection')])
    converging = build_attack_graph([_finding('sql_injection'), _finding('open_port_mongodb')])

    risk_single = exploitability(single)['risk']
    result_converging = exploitability(converging)
    assert result_converging['distinct_routes'] >= exploitability(single)['distinct_routes']
    assert result_converging['risk'] >= risk_single


def test_to_cytoscape_json_shape():
    G = build_attack_graph([_finding('sql_injection')])
    graph_json = to_cytoscape_json(G)
    assert 'nodes' in graph_json and 'edges' in graph_json
    assert all('id' in n['data'] for n in graph_json['nodes'])
    assert all('source' in e['data'] and 'target' in e['data'] for e in graph_json['edges'])
