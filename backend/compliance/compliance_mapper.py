import json
from pathlib import Path

_OBLIGATIONS = json.loads(
    (Path(__file__).parent.parent / "data" / "dpdp_obligations.json").read_text()
)["obligations"]

_WEIGHT_SCORE = {"high": 3, "medium": 2, "low": 1}


def _get_finding_id(f):
    """Get finding_id from a finding dict or dataclass."""
    if isinstance(f, dict):
        return f.get("finding_id", "")
    return getattr(f, "finding_id", "")


def _get_status(f):
    """Get status from a finding dict or dataclass."""
    if isinstance(f, dict):
        return f.get("status", "")
    status = getattr(f, "status", "")
    return status.value if hasattr(status, "value") else status


def _get_on_exploit_path(f):
    """Get on_exploit_path from a finding dict or dataclass."""
    if isinstance(f, dict):
        return f.get("on_exploit_path", False)
    return getattr(f, "on_exploit_path", False)


def map_findings_to_obligations(findings):
    """
    findings: List[Finding dict or dataclass].
    Returns List[dict] of obligation hits for failing/warning findings.
    Only returns obligations that have at least one trigger matched.
    """
    failing = {}
    for f in findings:
        status = _get_status(f)
        if status in ("fail", "warning"):
            fid = _get_finding_id(f)
            if fid:
                failing[fid] = f

    hits = []

    for ob in _OBLIGATIONS:
        # Skip advisory-only obligations with no triggers (e.g. certin_log_retention, dpdp_children_data)
        # unless they have triggers that matched
        triggered = [fid for fid in ob.get("triggers", {}) if fid in failing]
        if not triggered:
            continue

        worst_weight = max(
            _WEIGHT_SCORE.get(ob["triggers"][fid]["weight"], 1)
            for fid in triggered
        )
        on_path = any(_get_on_exploit_path(failing[fid]) for fid in triggered)

        if on_path and ob.get("amplified_if_on_exploit_path"):
            status = "gap"            # confirmed reachable -> hard gap
        elif worst_weight >= 3:
            status = "gap"
        else:
            status = "partial"

        hits.append({
            "obligation_id": ob["obligation_id"],
            "law": ob["law"],
            "clause": ob["clause"],
            "status": status,
            "penalty_ceiling_inr": ob["penalty_ceiling_inr"],
            "rationale": "; ".join(ob["triggers"][fid]["note"] for fid in triggered),
            "triggering_finding_ids": triggered,
        })

    return hits


def dpdp_readiness_score(hits, all_obligation_count=None):
    """
    0-100 readiness score. Penalizes gaps more than partials; weights by penalty ceiling.
    100 = no compliance gaps detected.
    0 = all high-penalty obligations are hard gaps.
    """
    if not hits:
        return 100

    total_penalty = sum(h["penalty_ceiling_inr"] for h in hits)
    if total_penalty == 0:
        return 100

    gap_penalty = sum(
        h["penalty_ceiling_inr"] * (1.0 if h["status"] == "gap" else 0.4)
        for h in hits
    )

    # Normalize: ratio of weighted gaps to total mapped exposure, inverted.
    ratio = gap_penalty / total_penalty
    score = round(100 * (1 - ratio))
    return max(0, min(100, score))
