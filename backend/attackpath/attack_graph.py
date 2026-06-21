import json
import networkx as nx
from pathlib import Path

_TRANSITIONS = json.loads(
    (Path(__file__).parent.parent / "data" / "attack_transitions.json").read_text()
)["transitions"]

IMPACT_PENALTY = {
    "customer_pii_breach": 2_500_000_000,   # ties to DPDP reasonable-safeguards ceiling
}


def _credential_pattern_present(findings):
    """Cheap evidence gate for the source->creds transition."""
    import re
    pat = re.compile(r"(DB_PASSWORD|password\s*=|mysqli_connect|mongodb\+srv|AKIA[0-9A-Z]{16})", re.I)
    for f in findings:
        # findings may be dicts or dataclass objects
        evidence = f.get("evidence", {}) if isinstance(f, dict) else getattr(f, "evidence", {})
        blob = (evidence or {}).get("leaked_source", "")
        if pat.search(blob or ""):
            return True
    return False


def _get_status(f):
    """Get status from a finding dict or dataclass."""
    if isinstance(f, dict):
        return f.get("status", "")
    return getattr(f, "status", "")


def _get_finding_id(f):
    """Get finding_id from a finding dict or dataclass."""
    if isinstance(f, dict):
        return f.get("finding_id", "")
    return getattr(f, "finding_id", "")


def _get_check(f):
    """Get human check label from a finding dict or dataclass."""
    if isinstance(f, dict):
        return f.get("check", "")
    return getattr(f, "check", "")


def _get_severity(f):
    """Get severity value from a finding dict or dataclass."""
    if isinstance(f, dict):
        return f.get("severity", "info")
    sev = getattr(f, "severity", "info")
    # Handle Severity enum
    return sev.value if hasattr(sev, "value") else sev


def build_attack_graph(findings):
    """
    Build a networkx DiGraph from a list of findings.
    findings: list of Finding dicts or dataclass objects.
    Returns: nx.DiGraph
    """
    present_finding_ids = {
        _get_finding_id(f) for f in findings
        if _get_status(f) in ("fail", "warning")
    }
    G = nx.DiGraph()

    # Seed finding nodes from failing/warning findings
    for f in findings:
        status = _get_status(f)
        fid = _get_finding_id(f)
        if status in ("fail", "warning") and fid:
            G.add_node(
                fid,
                layer="finding",
                label=_get_check(f) or fid.replace("_", " ").title(),
                severity=_get_severity(f)
            )

    # Iteratively instantiate transitions whose preconditions are satisfied
    have_creds_evidence = _credential_pattern_present(findings)
    changed = True
    satisfied = set(present_finding_ids)

    while changed:
        changed = False
        for t in _TRANSITIONS:
            pre = t["precondition"]
            ok = False
            if pre["type"] == "finding":
                ok = pre["id"] in satisfied
            elif pre["type"] == "capability":
                ok = pre["id"] in satisfied
            elif pre["type"] == "all_of":
                ok = all(i in satisfied for i in pre["ids"])

            # Evidence gate: only instantiate if credential pattern was found in leaked source
            if t.get("requires_evidence") == "credential_pattern_in_source" and not have_creds_evidence:
                ok = False

            yld = t["yields"]["id"]
            if ok and yld not in satisfied:
                satisfied.add(yld)
                layer = t["yields"]["type"]   # "capability" | "impact"
                G.add_node(
                    yld,
                    layer=layer,
                    label=yld.replace("_", " ").title(),
                    penalty_ceiling_inr=IMPACT_PENALTY.get(yld),
                    severity="critical" if layer == "impact" else "high"
                )
                changed = True

            if ok:
                # Add the edge(s) into the yielded node
                sources = pre["ids"] if pre["type"] == "all_of" else [pre["id"]]
                for s in sources:
                    if s in satisfied and G.has_node(s) and G.has_node(yld):
                        if not G.has_edge(s, yld):
                            G.add_edge(
                                s, yld,
                                confidence=t["confidence"],
                                transition_id=t["transition_id"],
                                rationale=t["rationale"],
                                capec=t.get("capec"),
                                attack=t.get("attack")
                            )
    return G


def to_cytoscape_json(G):
    """Export the graph to Cytoscape.js-compatible JSON."""
    nodes = []
    for n, d in G.nodes(data=True):
        node_data = {"id": n}
        node_data.update({k: v for k, v in d.items() if v is not None})
        nodes.append({"data": node_data})

    edges = []
    for u, v, d in G.edges(data=True):
        edge_data = {"id": f"{u}->{v}", "source": u, "target": v}
        edge_data.update({k: v2 for k, v2 in d.items() if v2 is not None})
        edges.append({"data": edge_data})

    return {"nodes": nodes, "edges": edges}


def get_node_labels(G):
    """Return a dict of node_id -> human label for narrative generation."""
    return {n: d.get("label", n.replace("_", " ").title()) for n, d in G.nodes(data=True)}
