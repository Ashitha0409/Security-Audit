from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
    NONE     = "none"


class FindingStatus(str, Enum):
    PASS    = "pass"
    FAIL    = "fail"
    WARNING = "warning"
    ERROR   = "error"


@dataclass
class Finding:
    finding_id: str              # stable slug, e.g. "open_port_mysql"
    check: str                   # human display label
    status: FindingStatus
    severity: Severity
    details: str
    fix: str = ""
    evidence: dict = field(default_factory=dict)   # raw data: port, header value, leaked snippet
    on_exploit_path: bool = False                  # set by Feature 2, read by Feature 1


@dataclass
class ObligationHit:
    obligation_id: str
    law: str                     # "DPDP Act 2023" | "CERT-In Directions 2022"
    clause: str                  # "Section 8(4) — reasonable security safeguards"
    status: str                  # "gap" | "partial" | "met"
    penalty_ceiling_inr: int     # in rupees, e.g. 2_500_000_000 for Rs. 250 crore
    rationale: str
    triggering_finding_ids: list = field(default_factory=list)


@dataclass
class GraphNode:
    node_id: str
    label: str
    layer: str                   # "entry" | "finding" | "capability" | "impact"
    severity: Severity
    finding_id: Optional[str] = None
    penalty_ceiling_inr: Optional[int] = None      # only on impact nodes


@dataclass
class GraphEdge:
    source: str
    target: str
    confidence: float            # 0.0 - 1.0, from the transition KB
    transition_id: str
    rationale: str
