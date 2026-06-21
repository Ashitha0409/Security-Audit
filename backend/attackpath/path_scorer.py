import networkx as nx

GOAL = "customer_pii_breach"


def exploitability(G):
    """
    Returns dict: 0-100 risk, plus the evidence behind it.
    Keys: risk (int), reachable (bool), best_path (dict|None),
          distinct_routes (int), paths (list)
    """
    if GOAL not in G:
        return {"risk": _structural_risk(G), "reachable": False,
                "best_path": None, "distinct_routes": 0, "paths": []}

    entry_nodes = [
        n for n, d in G.nodes(data=True)
        if d.get("layer") == "finding" and G.in_degree(n) == 0
    ]

    all_paths = []
    for src in entry_nodes:
        try:
            for path in nx.all_simple_paths(G, src, GOAL, cutoff=8):
                conf = 1.0
                for a, b in zip(path, path[1:]):
                    edge_data = G[a][b]
                    conf *= edge_data.get("confidence", 1.0)
                all_paths.append({
                    "path": path,
                    "length": len(path) - 1,
                    "confidence": round(conf, 3)
                })
        except nx.NetworkXNoPath:
            continue
        except Exception:
            continue

    if not all_paths:
        return {"risk": _structural_risk(G), "reachable": False,
                "best_path": None, "distinct_routes": 0, "paths": []}

    best = max(all_paths, key=lambda p: p["confidence"])
    distinct_routes = len({tuple(p["path"]) for p in all_paths})

    # Risk rises with best-path confidence, shortness, and number of converging routes.
    base = best["confidence"] * 100
    shortness_bonus = max(0, (5 - best["length"])) * 3
    convergence_bonus = min(15, (distinct_routes - 1) * 5)
    risk = min(100, round(base + shortness_bonus + convergence_bonus))

    return {
        "risk": risk,
        "reachable": True,
        "best_path": best,
        "distinct_routes": distinct_routes,
        "paths": all_paths
    }


def _structural_risk(G):
    """No path to goal: fall back to weighted finding severities, capped low."""
    weights = {"critical": 12, "high": 8, "medium": 4, "low": 1, "info": 0, "none": 0}
    s = sum(
        weights.get(d.get("severity", "none"), 0)
        for _, d in G.nodes(data=True)
        if d.get("layer") == "finding"
    )
    return min(60, s)   # un-chained findings can never score "critical" risk
