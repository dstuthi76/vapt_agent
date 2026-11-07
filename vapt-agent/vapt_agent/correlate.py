"""Normalization + cross-tool correlation + confidence calibration.

Grouping rules (per asset — findings on different assets are NEVER merged, so no
affected asset is hidden):
  two raw findings on the same asset are the same issue if they
    (a) share at least one CVE, or
    (b) map to the same canonical category (except OTHER / OUTDATED_SW), or
    (c) have near-identical normalized titles (token Jaccard >= 0.6).
Every piece of evidence is kept on the merged finding with its own source, port/URL,
timestamp and raw reference.
"""
from __future__ import annotations

import hashlib
import re

from .knowledge import (SEV_ORDER, categorize, owasp_for, references_for, CATEGORY_ATTACK,
                        REMEDIATION, sev_from_cvss)
from .models import Finding

STOP = {"the", "a", "an", "is", "not", "of", "on", "in", "to", "header", "detected", "found", "present", "set", "missing"}


def _tokens(s: str) -> set:
    return {w for w in re.findall(r"[a-z0-9\-]+", (s or "").lower()) if w not in STOP and len(w) > 1}


def _jacc(a, b):
    return len(a & b) / max(1, len(a | b))


class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


TOOL_TITLE_PRIORITY = ["nessus", "openvas", "burp", "zap", "nmap", "nikto", "metasploit"]


def correlate(raw_findings: list, hosts: dict, scope, overrides: dict, validations: dict) -> list[Finding]:
    # 1. normalize asset identity (hostname -> IP) so tools that report names and IPs line up
    items = []
    for rf in raw_findings:
        ip = scope._resolve(rf.asset) if rf.asset else None
        cat, ctitle, ccwe = categorize(rf.title, rf.description)
        items.append({"rf": rf, "asset": ip or rf.asset, "cat": cat, "ctitle": ctitle, "ccwe": ccwe,
                      "tok": _tokens(rf.title)})

    # 2. union-find grouping, per asset
    uf = _UF(len(items))
    by_asset = {}
    for i, it in enumerate(items):
        by_asset.setdefault(it["asset"], []).append(i)
    for idxs in by_asset.values():
        for x in range(len(idxs)):
            for y in range(x + 1, len(idxs)):
                a, b = items[idxs[x]], items[idxs[y]]
                ra, rb = a["rf"], b["rf"]
                same = bool(set(ra.cves) & set(rb.cves)) \
                    or (a["cat"] == b["cat"] and a["cat"] not in ("OTHER", "OUTDATED_SW")) \
                    or _jacc(a["tok"], b["tok"]) >= 0.6
                if same:
                    uf.union(idxs[x], idxs[y])
    groups = {}
    for i in range(len(items)):
        groups.setdefault(uf.find(i), []).append(items[i])

    findings = []
    for members in groups.values():
        findings.append(_build(members, hosts, overrides, validations))
    return findings


def _build(members, hosts, overrides, validations) -> Finding:
    asset = members[0]["asset"]
    rfs = [m["rf"] for m in members]
    cats = {m["cat"] for m in members}
    cat = next((c for c in cats if c != "OTHER"), "OTHER")
    cves = sorted({c for r in rfs for c in r.cves})
    cwes = sorted({c for r in rfs for c in r.cwes} | {m["ccwe"] for m in members if m["ccwe"]})
    tools = sorted({r.evidence.source_tool for r in rfs if r.evidence}, key=TOOL_TITLE_PRIORITY.index)

    # identity (stable across re-correlation)
    if cat not in ("OTHER", "OUTDATED_SW"):
        key = cat
    elif cves:
        key = cves[0]
    else:
        key = " ".join(sorted(_tokens(rfs[0].title)))[:80]
    identity = f"{asset}|{key}"
    fid = "F-" + hashlib.sha1(identity.encode()).hexdigest()[:6].upper()

    # title: canonical category title, otherwise the title from the most authoritative tool
    best = sorted(rfs, key=lambda r: TOOL_TITLE_PRIORITY.index(r.evidence.source_tool) if r.evidence else 99)[0]
    title = members[0]["ctitle"] if cat not in ("OTHER", "OUTDATED_SW") else best.title

    # CVSS only if a tool supplied it
    scored = [r for r in rfs if r.cvss_score is not None]
    top = max(scored, key=lambda r: r.cvss_score) if scored else None
    tool_sevs = {(r.evidence.source_tool if r.evidence else "?"): r.severity for r in rfs}
    notes = []
    if top:
        severity = sev_from_cvss(top.cvss_score)
    else:
        severity = max((r.severity for r in rfs), key=lambda s: SEV_ORDER.get(s, 0))
    if len(set(tool_sevs.values())) > 1:
        notes.append("Severity disagreement between tools: " + ", ".join(f"{t}={s}" for t, s in tool_sevs.items())
                     + (f"; CVSS {top.cvss_score} from {top.cvss_source} used." if top else "; highest rating retained."))

    affected, seen = [], set()
    for r in rfs:
        k = (asset, r.port, r.url)
        if k not in seen:
            seen.add(k)
            affected.append({"asset": asset, "hostname": r.asset if r.asset != asset else None,
                             "port": r.port, "url": r.url, "service": r.service})

    # ---------------- confidence calibration (explainable) ----------------
    factors = []
    base = max((r.tool_confidence_score or 0.5) for r in rfs)
    factors.append(f"highest tool-reported confidence {base:.2f}")
    conf = base
    if len(tools) >= 2:
        bonus = 0.15 if len(tools) == 2 else 0.2
        conf += bonus
        factors.append(f"+{bonus} corroborated by {len(tools)} independent tools ({', '.join(tools)})")
    if all(r.version_inferred for r in rfs):
        conf -= 0.15
        factors.append("-0.15 inferred from version/banner only (not behaviourally verified)")
    h = hosts.get(asset)
    if h and any(s.get("evidence_ref") for s in h.get("services", [])):
        open_ports = {s["port"] for s in h["services"] if s.get("state") == "open"}
        ports = {r.port for r in rfs if r.port}
        if ports and not (ports & open_ports):
            conf -= 0.25
            factors.append(f"-0.25 port(s) {sorted(ports)} not observed open by Nmap (possible stale/false result)")
        elif ports & open_ports:
            factors.append("port observed open by Nmap (asset/port corroborated)")
    if any((r.evidence.tool_confidence or "").lower() == "false positive" for r in rfs if r.evidence):
        conf = min(conf, 0.1)
        factors.append("tool itself flagged this alert as a false positive")

    status = "suspected"
    vrecs = validations.get(identity, [])
    if any(v["outcome"] == "confirmed" for v in vrecs):
        status, conf = "confirmed", max(conf, 0.97)
        factors.append("validated by approved active check (see validation record)")
    elif any(v["outcome"] == "not_confirmed" for v in vrecs):
        conf -= 0.2
        factors.append("-0.2 approved active check did not confirm")
    conf = round(min(0.99, max(0.03, conf)), 2)
    if conf < 0.2 and status != "confirmed":
        status = "likely_false_positive"
    ov = overrides.get(identity)
    if ov:
        status = ov["status"]
        factors.append(f"analyst override -> {ov['status']} by {ov['by']}: {ov['reason']}")

    solution = next((r.solution for r in sorted(rfs, key=lambda r: -len(r.solution or "")) if r.solution), "") \
        or REMEDIATION.get(cat, "Review the finding and apply vendor guidance.")
    desc = max((r.description for r in rfs), key=lambda d: len(d or "")) or title
    refs = sorted({x for r in rfs for x in r.references} | set(references_for(cwes, cves)))

    return Finding(
        id=fid, identity=identity, title=title, category=cat, description=desc, severity=severity,
        cves=cves, cwes=cwes, cvss_score=top.cvss_score if top else None,
        cvss_vector=top.cvss_vector if top else None, cvss_source=top.cvss_source if top else None,
        affected=affected, evidence=[r.evidence.to_dict() for r in rfs if r.evidence], source_tools=tools,
        confidence=conf, confidence_factors=factors, status=status, validation=vrecs,
        solution=solution, references=refs[:12], owasp=owasp_for(cwes), attack=CATEGORY_ATTACK.get(cat, []),
        notes=notes, exploit_available=True if any(r.exploit_available for r in rfs) else None,
        version_inferred=all(r.version_inferred for r in rfs),
    )
