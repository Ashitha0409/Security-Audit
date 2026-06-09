"""
graph_mapper.py — Graph-based threat mapping for PRAWL.

Turns scan results and network-sweep data into a property graph of
Hosts, Services, Vulnerabilities, Technologies, Subdomains and Breaches,
then derives ranked ATTACK PATHS (Internet → exposed service → host → impact).

Neo4j is the backing store when reachable (set NEO4J_URI / NEO4J_USER /
NEO4J_PASSWORD) — the graph is MERGEd in so it can be explored in the Neo4j
Browser. The same graph is always built in-memory, so visualisation and
attack-path detection work even when Neo4j is not running, matching PRAWL's
graceful-fallback design.
"""
import os
import logging

logger = logging.getLogger(__name__)

# Severity → numeric weight, used for ranking attack paths.
SEV_WEIGHT = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1, 'none': 0}

# Services that are dangerous entry points when exposed to a network.
RISKY_PORTS = {21, 23, 25, 53, 3306, 3389, 5432, 5900, 6379, 9200, 27017}

# Whitelisted node-type → Neo4j label (avoids dynamic-label injection).
_LABELS = {
    'host': 'Host', 'service': 'Service', 'vulnerability': 'Vulnerability',
    'technology': 'Technology', 'subdomain': 'Subdomain', 'breach': 'Breach',
}


def _sev_of(score):
    """Map a 0–100 score to a node severity for host colouring."""
    if score is None:
        return 'info'
    try:
        score = int(score)
    except (TypeError, ValueError):
        return 'info'
    if score < 40:
        return 'critical'
    if score < 60:
        return 'high'
    if score < 80:
        return 'medium'
    return 'none'


# ──────────────────────────────────────────────
# IN-MEMORY GRAPH MODEL
# ──────────────────────────────────────────────

class ThreatGraph:
    def __init__(self):
        self.nodes = {}   # id -> {id, label, type, severity, meta}
        self._edges = {}  # (source, target, rel) -> edge dict

    def add_node(self, node_id, label, ntype, severity='info', **meta):
        existing = self.nodes.get(node_id)
        if existing is None:
            self.nodes[node_id] = {
                'id': node_id, 'label': str(label)[:80],
                'type': ntype, 'severity': severity, 'meta': meta,
            }
        elif SEV_WEIGHT.get(severity, 0) > SEV_WEIGHT.get(existing['severity'], 0):
            existing['severity'] = severity  # escalate to the worst seen
        return node_id

    def add_edge(self, source, target, rel):
        self._edges[(source, target, rel)] = {'source': source, 'target': target, 'rel': rel}

    @property
    def edges(self):
        return list(self._edges.values())


# ──────────────────────────────────────────────
# GRAPH BUILDERS
# ──────────────────────────────────────────────

def build_from_scan(graph: ThreatGraph, scan: dict):
    host = scan.get('hostname') or scan.get('url') or 'target'
    hid = f"host:{host}"
    graph.add_node(hid, host, 'host', severity=_sev_of(scan.get('score')),
                   score=scan.get('score'), risk=scan.get('risk_level'))

    for f in scan.get('findings', []) or []:
        check = f.get('check', '')
        sev = f.get('severity', 'info')
        status = f.get('status')

        if check == 'Data Breach History' and status == 'fail':
            bid = f"breach:{host}"
            graph.add_node(bid, 'Data Breach', 'breach', severity='high',
                           details=f.get('details', ''))
            graph.add_edge(hid, bid, 'BREACHED_IN')
            continue

        if status in ('fail', 'warning') and sev in ('critical', 'high', 'medium', 'low'):
            vid = f"vuln:{host}:{check}"
            graph.add_node(vid, check, 'vulnerability', severity=sev,
                           details=f.get('details', ''), fix=f.get('fix', ''))
            graph.add_edge(hid, vid, 'HAS_FINDING')

    adv = scan.get('advanced_scan') or {}
    if isinstance(adv, dict):
        nmap = adv.get('nmap') or {}
        for r in (nmap.get('risk_findings', []) if isinstance(nmap, dict) else []):
            port = r.get('port')
            sid = f"svc:{host}:{port}"
            graph.add_node(sid, f"{r.get('service')} :{port}", 'service',
                           severity=r.get('severity', 'medium'), port=port)
            graph.add_edge(hid, sid, 'EXPOSES')
            vid = f"vuln:{host}:port{port}"
            graph.add_node(vid, r.get('description', f'Exposed port {port}'),
                           'vulnerability', severity=r.get('severity', 'medium'))
            graph.add_edge(sid, vid, 'HAS_VULN')

        nikto = adv.get('nikto') or {}
        for i, v in enumerate((nikto.get('vulnerabilities', []) if isinstance(nikto, dict) else [])[:20]):
            vid = f"vuln:{host}:nikto{i}"
            graph.add_node(vid, v.get('description', 'Nikto finding'),
                           'vulnerability', severity=v.get('severity', 'info'))
            graph.add_edge(hid, vid, 'HAS_FINDING')

        sql = adv.get('sqlmap') or {}
        if isinstance(sql, dict) and sql.get('injectable'):
            vid = f"vuln:{host}:sqli"
            graph.add_node(vid, f"SQL Injection ({sql.get('dbms') or 'DB'})",
                           'vulnerability', severity='critical')
            graph.add_edge(hid, vid, 'HAS_FINDING')

        ww = adv.get('whatweb') or {}
        for p in (ww.get('plugins', []) if isinstance(ww, dict) else [])[:15]:
            name = p.get('name', '')
            label = f"{name} {p.get('version')}".strip() if p.get('version') else name
            tid = f"tech:{host}:{name}"
            graph.add_node(tid, label, 'technology', severity='info')
            graph.add_edge(hid, tid, 'RUNS')

        crt = adv.get('crt_sh') or {}
        for s in (crt.get('subdomains', []) if isinstance(crt, dict) else [])[:25]:
            sdid = f"sub:{s}"
            graph.add_node(sdid, s, 'subdomain', severity='info')
            graph.add_edge(hid, sdid, 'HAS_SUBDOMAIN')


def build_from_sweep(graph: ThreatGraph, sweep: dict):
    for h in sweep.get('hosts', []) or []:
        ip = h.get('ip') or 'unknown'
        label = f"{ip} ({h['hostname']})" if h.get('hostname') else ip
        hid = f"host:{ip}"
        graph.add_node(hid, label, 'host', severity='info', ip=ip)
        for p in h.get('open_ports', []) or []:
            try:
                port = int(p.get('port', 0) or 0)
            except (TypeError, ValueError):
                port = 0
            sev = 'high' if port in RISKY_PORTS else 'low'
            sid = f"svc:{ip}:{port}"
            graph.add_node(sid, f"{p.get('service', 'unknown')} :{port}", 'service',
                           severity=sev, port=port)
            graph.add_edge(hid, sid, 'EXPOSES')


# ──────────────────────────────────────────────
# ATTACK-PATH DETECTION
# ──────────────────────────────────────────────

def _make_path(items):
    """items: list of literal entry strings and/or node dicts → a ranked path."""
    steps, score, worst, sig = [], 0, 'info', []
    for it in items:
        if isinstance(it, str):
            steps.append({'label': it, 'type': 'entry', 'severity': 'info'})
            sig.append(it)
        else:
            steps.append({'label': it['label'], 'type': it['type'], 'severity': it['severity']})
            score += SEV_WEIGHT.get(it['severity'], 0)
            sig.append(it['id'])
            if SEV_WEIGHT.get(it['severity'], 0) > SEV_WEIGHT.get(worst, 0):
                worst = it['severity']
    return {'steps': steps, 'score': score, 'severity': worst, 'signature': '>'.join(sig)}


def compute_attack_paths(graph: ThreatGraph, limit=10):
    out = {}
    for e in graph.edges:
        out.setdefault(e['source'], []).append((e['rel'], e['target']))

    paths = []
    for hid, host in graph.nodes.items():
        if host['type'] != 'host':
            continue

        services = [graph.nodes[t] for r, t in out.get(hid, []) if r == 'EXPOSES']
        impacts = sorted(
            [graph.nodes[t] for r, t in out.get(hid, []) if r in ('HAS_FINDING', 'BREACHED_IN')],
            key=lambda v: SEV_WEIGHT.get(v['severity'], 0), reverse=True,
        )
        risky = [s for s in services
                 if s['meta'].get('port') in RISKY_PORTS or SEV_WEIGHT.get(s['severity'], 0) >= 7]

        # 1. exposed service → its own vulnerability
        for s in services:
            for r, t in out.get(s['id'], []):
                if r == 'HAS_VULN':
                    paths.append(_make_path(['🌐 Internet', s, host, graph.nodes[t]]))

        # 2. risky exposed service → host → highest-severity impact on that host
        for s in risky:
            chain = ['🌐 Internet', s, host]
            if impacts:
                chain.append(impacts[0])
            paths.append(_make_path(chain))

        # 3. web-reachable critical/high vuln with no risky port (e.g. SQLi over 443)
        if not risky:
            for v in impacts:
                if SEV_WEIGHT.get(v['severity'], 0) >= 7:
                    paths.append(_make_path(['🌐 Internet', host, v]))

    # dedupe by signature (keep highest score), then rank
    best = {}
    for p in paths:
        if p['signature'] not in best or p['score'] > best[p['signature']]['score']:
            best[p['signature']] = p
    ranked = sorted(best.values(), key=lambda p: p['score'], reverse=True)
    for p in ranked:
        p.pop('signature', None)
    return ranked[:limit]


# ──────────────────────────────────────────────
# NEO4J STORE (optional)
# ──────────────────────────────────────────────

class Neo4jStore:
    def __init__(self, uri, user, password):
        from neo4j import GraphDatabase
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.driver.verify_connectivity()

    def write(self, graph: ThreatGraph, reset=True):
        with self.driver.session() as session:
            if reset:
                session.run("MATCH (n:Asset) DETACH DELETE n")
            for n in graph.nodes.values():
                label = _LABELS.get(n['type'], 'Asset')
                session.run(
                    f"MERGE (x:Asset:{label} {{id:$id}}) "
                    "SET x.label=$label, x.ntype=$ntype, x.severity=$sev",
                    id=n['id'], label=n['label'], ntype=n['type'], sev=n['severity'],
                )
            for e in graph.edges:
                session.run(
                    "MATCH (a:Asset {id:$s}), (b:Asset {id:$t}) "
                    "MERGE (a)-[r:CONNECTS {rel:$rel}]->(b)",
                    s=e['source'], t=e['target'], rel=e['rel'],
                )

    def close(self):
        try:
            self.driver.close()
        except Exception:
            pass


_STORE = 'uninitialised'


def _get_store():
    """Lazy Neo4j connection. Returns a Neo4jStore or None (fallback to memory)."""
    global _STORE
    if _STORE == 'uninitialised':
        uri = os.environ.get('NEO4J_URI')
        if not uri:
            _STORE = None
        else:
            try:
                _STORE = Neo4jStore(
                    uri,
                    os.environ.get('NEO4J_USER', 'neo4j'),
                    os.environ.get('NEO4J_PASSWORD', 'neo4j'),
                )
                logger.info("Connected to Neo4j threat-graph store.")
            except Exception as e:
                logger.warning(f"Neo4j unavailable, using in-memory graph: {e}")
                _STORE = None
    return _STORE


# ──────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────

def build_threat_map(scan=None, sweep=None, reset=True):
    """
    Build the threat graph from a scan result and/or a network sweep.
    Returns {backend, nodes, edges, attack_paths, stats}.
    """
    graph = ThreatGraph()
    if scan:
        build_from_scan(graph, scan)
    if sweep:
        build_from_sweep(graph, sweep)

    backend = 'memory'
    store = _get_store()
    if store is not None:
        try:
            store.write(graph, reset=reset)
            backend = 'neo4j'
        except Exception as e:
            logger.warning(f"Neo4j write failed, serving in-memory graph: {e}")

    attack_paths = compute_attack_paths(graph)
    return {
        'backend': backend,
        'nodes': list(graph.nodes.values()),
        'edges': graph.edges,
        'attack_paths': attack_paths,
        'stats': {
            'nodes': len(graph.nodes),
            'edges': len(graph.edges),
            'attack_paths': len(attack_paths),
        },
    }
