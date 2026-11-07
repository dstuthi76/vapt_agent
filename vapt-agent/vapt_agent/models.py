"""Common data model shared by all adapters, the correlator, risk engine and report."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class Evidence:
    """One observation from one tool. Never edited after creation."""
    source_tool: str                 # nmap | nikto | zap | openvas | nessus | burp | metasploit
    asset: str                       # host / IP
    port: Optional[int]
    url: Optional[str]
    observed_at: str                 # timestamp of observation (tool or ingestion time)
    raw_ref: str                     # relative path to the raw tool output file
    raw_sha256: str                  # hash of that raw file (tamper evidence)
    job_id: str                      # job (or import) that produced it
    excerpt: str                     # verbatim snippet from the raw output
    tool_title: str                  # title as the tool named it
    tool_severity: str               # normalized severity as the tool rated it
    tool_confidence: Optional[str] = None  # tool's own confidence / QoD if it gives one
    tool_ref_id: Optional[str] = None      # plugin id / NVT OID / alertRef / nikto id
    mode: str = "live"               # live | import
    id: str = field(default_factory=lambda: new_id("EV"))

    def to_dict(self):
        return asdict(self)


@dataclass
class RawFinding:
    """What an adapter emits: a tool-specific finding before correlation."""
    title: str
    severity: str                    # critical/high/medium/low/info (tool's rating, normalized)
    asset: str
    port: Optional[int] = None
    protocol: Optional[str] = "tcp"
    service: Optional[str] = None
    url: Optional[str] = None
    description: str = ""
    solution: str = ""
    cves: list = field(default_factory=list)
    cwes: list = field(default_factory=list)
    cvss_score: Optional[float] = None       # only if the TOOL provided it
    cvss_vector: Optional[str] = None
    cvss_source: Optional[str] = None        # e.g. "nessus cvss3_base_score"
    exploit_available: Optional[bool] = None # only if the TOOL said so
    references: list = field(default_factory=list)
    evidence: Optional[Evidence] = None
    tool_confidence_score: Optional[float] = None  # 0..1, derived from tool's own field
    version_inferred: bool = False           # finding derived only from a banner/version


@dataclass
class Host:
    address: str
    hostnames: list = field(default_factory=list)
    os_guess: Optional[str] = None
    services: list = field(default_factory=list)   # list of dicts: port, proto, state, name, product, version, tunnel
    sources: list = field(default_factory=list)    # job ids that observed it

    def to_dict(self):
        return asdict(self)


@dataclass
class Action:
    """A planned unit of work. Created by the planner, executed by the orchestrator."""
    tool: str
    target: str                      # host, url
    params: dict
    rationale: str                   # WHY (references evidence ids / job ids)
    phase: str                       # recon | enumeration | vuln-scan | validation | import
    intrusive: bool = False
    requires_approval: bool = False  # validation & intrusive actions
    triggered_by: list = field(default_factory=list)   # evidence / job ids that motivated it
    status: str = "proposed"         # proposed|approved|rejected|blocked|queued|running|done|failed|skipped
    decided_by: Optional[str] = None
    id: str = field(default_factory=lambda: new_id("ACT"))
    created_at: str = field(default_factory=now_iso)
    reasoning_source: str = "rules" # rules | llm+rules

    def key(self) -> str:
        import hashlib, json
        return hashlib.sha1(json.dumps([self.tool, self.target, self.params], sort_keys=True).encode()).hexdigest()[:16]

    def to_dict(self):
        d = asdict(self)
        d["key"] = self.key()
        return d


@dataclass
class Job:
    action_id: str
    tool: str
    target: str
    status: str = "queued"           # queued|running|succeeded|failed|timeout|unavailable|blocked
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    command: Optional[str] = None    # exact command / API call executed (for transparency)
    mode: str = "live"
    raw_files: list = field(default_factory=list)
    error: Optional[str] = None
    attempts: int = 0
    findings_count: int = 0
    id: str = field(default_factory=lambda: new_id("JOB"))

    def to_dict(self):
        return asdict(self)


@dataclass
class Finding:
    """A correlated finding: one vulnerability identity, possibly on several assets,
    supported by one or more pieces of evidence from one or more tools."""
    id: str
    identity: str                    # correlation key
    title: str
    category: str
    description: str
    severity: str
    cves: list
    cwes: list
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cvss_source: Optional[str]
    affected: list                   # list of {asset, port, url, service}
    evidence: list                   # list of Evidence dicts
    source_tools: list
    confidence: float
    confidence_factors: list
    status: str                      # suspected | confirmed | false_positive | not_validated
    validation: list                 # list of validation records
    risk_score: float = 0.0
    risk_breakdown: dict = field(default_factory=dict)
    priority: str = "P4"
    solution: str = ""
    references: list = field(default_factory=list)
    owasp: list = field(default_factory=list)
    attack: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    exploit_available: Optional[bool] = None
    version_inferred: bool = False
    ai_impact: Optional[str] = None  # AI-generated inference, clearly labelled

    def to_dict(self):
        return asdict(self)
