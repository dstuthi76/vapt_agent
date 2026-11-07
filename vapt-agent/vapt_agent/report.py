"""Unified VAPT report (PDF via ReportLab + JSON export). Sections follow the problem statement §7."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle, Preformatted)

from .adapters import INTEGRATION_MATRIX
from .llm import ground_text, llm

SEV_COLORS = {"critical": colors.HexColor("#7a0019"), "high": colors.HexColor("#c0392b"),
              "medium": colors.HexColor("#d68910"), "low": colors.HexColor("#2874a6"), "info": colors.HexColor("#7f8c8d")}
SEVS = ["critical", "high", "medium", "low", "info"]

IMPACT = {
    "SQLI": "An attacker may read or modify database contents, bypass authentication or, depending on DB privileges, execute commands.",
    "XSS": "Attackers can run script in users' browsers, steal sessions, or perform actions as the victim.",
    "CMD_INJECTION": "Remote command execution on the server, typically leading to full host compromise.",
    "PATH_TRAVERSAL": "Disclosure of arbitrary server files such as configuration and credentials.",
    "DEFAULT_CREDS": "Unauthorised administrative access using publicly known credentials.",
    "FTP_ANON": "Unauthenticated users can read (and possibly write) files on the FTP server.",
    "TLS_WEAK": "Traffic may be downgraded or decrypted by a network-positioned attacker.",
    "TLS_CERT": "Users cannot reliably authenticate the server, enabling interception.",
    "HDR_XFO": "Pages can be framed by a malicious site to trick users into unintended clicks (clickjacking).",
    "HDR_XCTO": "Browsers may MIME-sniff responses, which can turn uploads into script execution.",
    "HDR_HSTS": "Users can be downgraded to HTTP and have traffic intercepted.",
    "HDR_CSP": "No browser-side mitigation limits the impact of injected script.",
    "COOKIE_FLAGS": "Session cookies may be stolen via script or sent over unencrypted channels.",
    "INFO_SERVER_BANNER": "Precise software versions help attackers select working exploits.",
    "DIR_LISTING": "Directory contents are exposed, revealing files not intended for publication.",
    "SENSITIVE_FILE": "Exposed files may contain credentials, source code or internal details.",
    "SMB_SIGNING": "SMB traffic can be relayed to authenticate as victims (NTLM relay).",
    "SMB_MS17_010": "Unauthenticated remote code execution with SYSTEM privileges.",
    "OUTDATED_SW": "Unsupported versions accumulate known, publicly documented vulnerabilities.",
    "HTTP_METHODS": "Unneeded methods widen attack surface (e.g. TRACE for cross-site tracing, PUT for file upload).",
    "CORS": "Other origins may read authenticated responses.",
    "CSRF": "Attackers can make authenticated users perform unwanted state-changing actions.",
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1x", parent=ss["Heading1"], fontSize=16, spaceBefore=8, spaceAfter=6, textColor=colors.HexColor("#1b2631")))
    ss.add(ParagraphStyle("H2x", parent=ss["Heading2"], fontSize=12.5, spaceBefore=8, spaceAfter=4, textColor=colors.HexColor("#1b4f72")))
    ss.add(ParagraphStyle("H3x", parent=ss["Heading3"], fontSize=10.5, spaceBefore=6, spaceAfter=2))
    ss.add(ParagraphStyle("B", parent=ss["BodyText"], fontSize=9, leading=12))
    ss.add(ParagraphStyle("Small", parent=ss["BodyText"], fontSize=7.5, leading=9.5))
    ss.add(ParagraphStyle("Cell", parent=ss["BodyText"], fontSize=7.5, leading=9))
    ss.add(ParagraphStyle("AI", parent=ss["BodyText"], fontSize=9, leading=12, backColor=colors.HexColor("#f4ecf7"),
                          borderColor=colors.HexColor("#8e44ad"), borderWidth=0.5, borderPadding=4))
    ss.add(ParagraphStyle("Codex", parent=ss["Code"], fontSize=6.8, leading=8.2, backColor=colors.HexColor("#f4f6f7")))
    ss.add(ParagraphStyle("Cover", parent=ss["Title"], fontSize=24, alignment=TA_CENTER, spaceAfter=14))
    return ss


def _ts(x):
    return (x or "-")[5:19].replace("T", " ")


def P(t, st):
    return Paragraph(escape(str(t if t is not None else "")).replace("\n", "<br/>"), st)


def _table(rows, widths, ss, head_bg="#1b4f72", zebra=True):
    hdr = ParagraphStyle("hdr", parent=ss["Cell"], textColor=colors.white, fontName="Helvetica-Bold")
    data = [[P(c, hdr if ri == 0 else ss["Cell"]) if not hasattr(c, "wrap") else c for c in r] for ri, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(head_bg)),
             ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#aab7b8")),
             ("VALIGN", (0, 0), (-1, -1), "TOP")]
    if zebra:
        for i in range(1, len(rows)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f4f6f7")))
    t.setStyle(TableStyle(style))
    return t


def _chart(counts):
    d = Drawing(170 * mm, 55 * mm)
    ch = VerticalBarChart()
    ch.x, ch.y, ch.width, ch.height = 15 * mm, 8 * mm, 145 * mm, 42 * mm
    ch.data = [[counts.get(s, 0) for s in SEVS]]
    ch.categoryAxis.categoryNames = [s.capitalize() for s in SEVS]
    ch.valueAxis.valueMin = 0
    mx = max([counts.get(s, 0) for s in SEVS] + [1])
    ch.valueAxis.valueStep = max(1, round(mx / 5))
    ch.bars.strokeColor = None
    for i, s in enumerate(SEVS):
        ch.bars[(0, i)].fillColor = SEV_COLORS[s]
    ch.barLabelFormat = "%d"
    ch.barLabels.nudge = 6
    d.add(ch)
    return d


def _ai_exec_summary(state, findings):
    if not llm.enabled or not findings:
        return None
    top = [{"id": f["id"], "title": f["title"], "severity": f["severity"], "risk": f["risk_score"],
            "status": f["status"], "assets": [a["asset"] for a in f["affected"]], "cves": f["cves"]} for f in findings[:12]]
    txt = llm.chat("Write a concise (max 170 words) executive summary of a penetration test for non-technical "
                   "management, using ONLY the findings JSON. Do not add vulnerabilities, CVEs, numbers or assets "
                   "that are not present. Plain prose, no markdown.", json.dumps(top), 500)
    if not txt:
        return None
    txt, _ = ground_text(txt, {c for f in findings for c in f["cves"]})
    return txt


def build_report(state: dict, audit_check: dict, out_pdf, synthetic: bool = False) -> dict:
    ss = _styles()
    scope = state["scope"]
    gen = datetime.now(timezone.utc).isoformat(timespec="seconds")
    fs_all = state["findings"]
    fs = [f for f in fs_all if f["status"] != "false_positive"]
    fps = [f for f in fs_all if f["status"] == "false_positive"]
    vulns = [f for f in fs if f["severity"] != "info"]
    infos = [f for f in fs if f["severity"] == "info"]
    counts = Counter(f["severity"] for f in fs)
    jobs = state["jobs"]
    numbering = {f["id"]: f"VAPT-{i + 1:03d}" for i, f in enumerate(vulns + infos)}

    story = []
    # ------------------------------------------------------------------ cover
    story += [Spacer(1, 40 * mm), Paragraph("Vulnerability Assessment &amp; Penetration Test Report", ss["Cover"]),
              P(scope.get("engagement", "Authorized lab assessment"), ss["Title"]), Spacer(1, 10 * mm)]
    story.append(_table([["Field", "Value"],
                         ["Assessment ID", state["id"]], ["Analyst", state["analyst"]],
                         ["Authorization reference", scope.get("authorization_ref", "-")],
                         ["Authorized by", scope.get("authorized_by", "-")],
                         ["Assessment started", state["created_at"]], ["Report generated", gen],
                         ["Agent reasoning engine", state.get("llm", "-")],
                         ["Classification", "CONFIDENTIAL — client use only"]], [55 * mm, 110 * mm], ss))
    if synthetic:
        story += [Spacer(1, 8 * mm), P("NOTICE: this report was generated from SYNTHETIC TEST FIXTURES to demonstrate the "
                                       "report format. It does not describe a real system.", ss["AI"])]
    story += [Spacer(1, 8 * mm), P("Legend: text on a purple background is AI-generated inference. All other statements are "
                                   "derived deterministically from tool evidence referenced by job ID, raw file and SHA-256.", ss["Small"]),
              PageBreak()]

    # ------------------------------------------------------------------ 1 exec summary
    story.append(Paragraph("1. Executive Summary", ss["H1x"]))
    hosts = state["hosts"]
    story.append(P(f"Scope: {', '.join(t['value'] for t in scope.get('targets', []))}. "
                   f"Request: “{state['request']}”. {len(hosts)} host(s) were enumerated and "
                   f"{len(jobs)} tool job(s) executed or imported. After correlation, {len(vulns)} vulnerability finding(s) "
                   f"and {len(infos)} informational observation(s) remain; {len(fps)} were triaged as false positives.", ss["B"]))
    sev_line = ", ".join(f"{counts.get(s, 0)} {s}" for s in SEVS)
    story.append(P(f"Severity distribution: {sev_line}.", ss["B"]))
    if vulns:
        top = vulns[:3]
        story.append(P("Highest-priority issues: " + "; ".join(
            f"{numbering[f['id']]} {f['title']} on {', '.join(sorted({a['asset'] for a in f['affected']}))} "
            f"({f['priority']}, risk {f['risk_score']}, {f['status']})" for f in top) + ".", ss["B"]))
        posture = "HIGH" if counts.get("critical") or counts.get("high") else "MODERATE" if counts.get("medium") else "LOW"
        story.append(P(f"Overall risk posture (rule-based): {posture}.", ss["B"]))
    ai = _ai_exec_summary(state, vulns)
    if ai:
        story += [Spacer(1, 3 * mm), Paragraph("<b>AI-generated management summary (inference):</b><br/>" + escape(ai), ss["AI"])]

    # ------------------------------------------------------------------ 2 methodology
    story.append(Paragraph("2. Assessment Methodology", ss["H1x"]))
    story.append(P("The assessment followed the NIST SP 800-115 phases — planning, discovery (reconnaissance and "
                   "enumeration), vulnerability analysis, controlled validation and reporting — with findings classified "
                   "against CVE, CVSS (as supplied by tools), CWE, OWASP Top 10 (2021) and MITRE ATT&CK. Tool selection "
                   "was adaptive: each follow-up action was planned only after evidence (e.g. an open HTTP port) was observed. "
                   "Use of these frameworks does not by itself establish formal compliance.", ss["B"]))
    story.append(Paragraph("2.1 Rules of engagement", ss["H2x"]))
    w = scope.get("window") or {}
    story.append(_table([["Rule", "Value"],
                         ["Registered targets", "; ".join(f"{t['value']} ({t.get('label', '')}, criticality {t.get('criticality', 'medium')}, {t.get('exposure', 'internal')})" for t in scope.get("targets", []))],
                         ["Exclusions", ", ".join(map(str, scope.get("exclusions", []))) or "none"],
                         ["Allowed ports / tools", f"{scope.get('allowed_ports', '1-65535')} / {', '.join(scope.get('allowed_tools', [])) or 'all'}"],
                         ["Rate limit", f"{scope.get('max_rate_pps', '-')} packets/s (nmap --max-rate)"],
                         ["Engagement window", f"{w.get('start') or 'unbounded'} → {w.get('end') or 'unbounded'}"],
                         ["Public / third-party systems", "Refused by the scope guard" if not scope.get("allow_non_private") else "Allowed by scope file"],
                         ["Active validation", "Only after explicit analyst approval; non-destructive checks only; no payloads"],
                         ["Rejected targets from request", "; ".join(f"{r['target']}: {r['reason']}" for r in state.get("rejected_targets", [])) or "none"]],
                        [45 * mm, 125 * mm], ss))
    story.append(Paragraph("2.2 Assets tested", ss["H2x"]))
    rows = [["Host", "Hostnames", "Open services (port/service product version)", "Observed by"]]
    for ip, h in sorted(hosts.items()):
        svcs = [f"{s['port']}/{s.get('name') or '?'} {s.get('product') or ''} {s.get('version') or ''}".strip()
                for s in h["services"] if s.get("state") == "open"]
        rows.append([ip, ", ".join(h["hostnames"]) or "-", "; ".join(svcs) or "(none / not enumerated)", ", ".join(sorted(set(h["sources"])))])
    story.append(_table(rows, [28 * mm, 30 * mm, 82 * mm, 30 * mm], ss))
    story.append(Paragraph("2.3 Tool execution summary", ss["H2x"]))
    rows = [["Job", "Tool", "Mode", "Target", "Status", "Start / end (UTC)", "#"]]
    for j in jobs:
        rows.append([j["id"], j["tool"], j.get("mode", "live"), j["target"], j["status"] + (f": {j['error'][:80]}" if j.get("error") else ""),
                     f"{_ts(j.get('started_at'))}\n{_ts(j.get('finished_at'))}", str(j.get("findings_count", 0))])
    story.append(_table(rows, [23 * mm, 16 * mm, 12 * mm, 38 * mm, 44 * mm, 26 * mm, 11 * mm], ss))
    cs = state.get("correlation_stats", {})
    story.append(P(f"Correlation: {cs.get('raw', 0)} raw tool findings were normalised into {cs.get('correlated', 0)} "
                   f"findings ({cs.get('merged_duplicates', 0)} duplicates merged, {cs.get('multi_tool', 0)} corroborated by "
                   f"more than one tool). Findings on different assets are never merged.", ss["B"]))

    # ------------------------------------------------------------------ 3 severity
    story.append(PageBreak())
    story.append(Paragraph("3. Severity Distribution and Prioritized Findings", ss["H1x"]))
    story.append(_chart(counts))
    story.append(P("Risk score = base (tool CVSS, or severity midpoint when no CVSS) × exposure × exploitability "
                   "× asset criticality × (0.5 + 0.5 × confidence), capped at 10. It is a contextual "
                   "priority, reported separately from CVSS. P1 ≥ 8.5, P2 ≥ 6.5, P3 ≥ 4.0, P4 > 0.", ss["Small"]))
    rows = [["ID", "Finding", "Asset(s)", "Sev.", "CVSS", "Risk", "Prio", "Conf.", "Status", "Sources"]]
    for f in vulns + infos:
        rows.append([numbering[f["id"]], f["title"], ", ".join(sorted({a["asset"] for a in f["affected"]})), f["severity"],
                     f"{f['cvss_score']}" if f["cvss_score"] is not None else "n/a", f"{f['risk_score']}", f["priority"],
                     f"{f['confidence']}", f["status"], ", ".join(f["source_tools"])])
    story.append(_table(rows, [18 * mm, 40 * mm, 21 * mm, 15 * mm, 10 * mm, 10 * mm, 9 * mm, 10 * mm, 19 * mm, 18 * mm], ss))

    # ------------------------------------------------------------------ 4 details
    story.append(PageBreak())
    story.append(Paragraph("4. Detailed Vulnerability Findings", ss["H1x"]))
    for f in vulns + infos:
        story += _finding_block(f, numbering[f["id"]], ss)

    # ------------------------------------------------------------------ 5 remediation
    story.append(PageBreak())
    story.append(Paragraph("5. Impact and Remediation Roadmap", ss["H1x"]))
    rows = [["Priority", "ID", "Business / technical impact", "Remediation", ]]
    for f in vulns:
        rows.append([f["priority"], numbering[f["id"]], IMPACT.get(f["category"], f["description"][:220]), f["solution"][:500]])
    story.append(_table(rows, [13 * mm, 18 * mm, 64 * mm, 75 * mm], ss))
    story.append(P("Per-finding references (NVD, CWE, vendor and tool references) are listed in section 4.", ss["Small"]))

    # ------------------------------------------------------------------ 6 limitations
    story.append(Paragraph("6. Assessment Limitations", ss["H1x"]))
    lim = ["Testing was unauthenticated unless stated; authenticated application areas were not covered.",
           "Only TCP services were scanned; UDP services were not assessed.",
           "Findings marked 'suspected' were not actively validated; findings inferred from version banners may be false positives where vendors back-port fixes.",
           "Severity for Nikto and Nmap-script findings is agent-classified because those tools do not rate severity.",
           "CVSS values appear only where a scanner supplied them; no CVSS or CVE was generated by the agent."]
    imported = sorted({j["tool"] for j in jobs if j.get("mode") == "import"})
    if imported:
        lim.append(f"Results for {', '.join(imported)} were IMPORTED from recorded exports, not executed live by the agent.")
    for x in lim:
        story.append(P("• " + x, ss["B"]))
    story.append(Paragraph("6.1 Assumptions", ss["H2x"]))
    for x in ["The registered scope and exclusions accurately reflect the authorization provided.",
              "Asset criticality and exposure values come from the scope file and were supplied by the engagement owner.",
              "Lab systems are intentionally vulnerable; business impact statements describe a production-equivalent system."]:
        story.append(P("• " + x, ss["B"]))
    story.append(Paragraph("6.2 Scan failures and unavailable integrations", ss["H2x"]))
    bad = [j for j in jobs if j["status"] not in ("succeeded",)]
    if bad:
        story.append(_table([["Job", "Tool", "Target", "Status", "Reason"]] +
                            [[j["id"], j["tool"], j["target"], j["status"], j.get("error") or "-"] for j in bad],
                            [23 * mm, 18 * mm, 40 * mm, 20 * mm, 69 * mm], ss))
    else:
        story.append(P("No job failed.", ss["B"]))
    story.append(Paragraph("6.3 Human approvals", ss["H2x"]))
    ap = state.get("approvals", [])
    story.append(_table([["Time (UTC)", "Type", "Action", "Decision", "By", "Reason"]] +
                        [[a["ts"], a["type"], f"{a.get('tool', '')} {a.get('target', '')} {a.get('detail', '')}".strip(),
                          a["decision"], a["by"], a.get("reason", "")] for a in ap] or [["-"] * 6],
                        [30 * mm, 14 * mm, 62 * mm, 18 * mm, 20 * mm, 26 * mm], ss))
    val = [v for vs in state.get("validations", {}).values() for v in vs]
    if val:
        story.append(Paragraph("6.4 Validation outcomes", ss["H2x"]))
        story.append(_table([["Finding", "Module / method", "Outcome", "Approved by", "Raw evidence"]] +
                            [[numbering.get(v["finding_id"], v["finding_id"]), f"{v['module']} ({v['method']})", v["outcome"],
                              v["approved_by"], f"{v['raw_ref']} sha256:{v['raw_sha256'][:16]}"] for v in val],
                            [18 * mm, 55 * mm, 20 * mm, 27 * mm, 50 * mm], ss))
    story.append(Paragraph("6.5 Assessment timestamps", ss["H2x"]))
    starts = [j["started_at"] for j in jobs if j.get("started_at")]
    ends = [j["finished_at"] for j in jobs if j.get("finished_at")]
    story.append(_table([["Event", "UTC"], ["Assessment created", state["created_at"]],
                         ["First tool activity", min(starts) if starts else "-"], ["Last tool activity", max(ends) if ends else "-"],
                         ["Report generated", gen]], [60 * mm, 110 * mm], ss))

    # ------------------------------------------------------------------ appendices
    story.append(PageBreak())
    story.append(Paragraph("Appendix A — Integration Status Matrix", ss["H1x"]))
    story.append(_table([["Tool", "Status", "How", "Known limitations"]] +
                        [[m["tool"], m["status"], m["how"], m["limits"]] for m in INTEGRATION_MATRIX],
                        [28 * mm, 35 * mm, 55 * mm, 52 * mm], ss))
    story.append(Paragraph("Appendix B — Agent decision trace (excerpt)", ss["H1x"]))
    story.append(_table([["Time", "Type", "Decision / rationale"]] +
                        [[d["ts"], d["type"], d["text"][:400]] for d in state["decisions"][-40:]],
                        [30 * mm, 20 * mm, 120 * mm], ss))
    if fps:
        story.append(Paragraph("Appendix C — Findings triaged as false positive", ss["H1x"]))
        story.append(_table([["Finding", "Asset", "Sources", "Reason"]] +
                            [[f["title"], ", ".join(a["asset"] for a in f["affected"]), ", ".join(f["source_tools"]),
                              "; ".join(x for x in f["confidence_factors"] if "override" in x)] for f in fps],
                            [55 * mm, 25 * mm, 25 * mm, 65 * mm], ss))
    story.append(Paragraph("Appendix D — Audit trail integrity", ss["H1x"]))
    story.append(P(f"Hash-chained audit log: {'VALID' if audit_check.get('valid') else 'INVALID'} "
                   f"({audit_check.get('entries', '?')} entries). File: data/assessments/{state['id']}/audit.jsonl", ss["B"]))

    def on_page(c, doc):
        c.saveState()
        c.setFont("Helvetica", 7)
        c.setFillColor(colors.grey)
        c.drawString(15 * mm, 10 * mm, f"CONFIDENTIAL — {state['id']} — generated {gen}")
        c.drawRightString(195 * mm, 10 * mm, f"Page {doc.page}")
        if synthetic:
            c.setFont("Helvetica-Bold", 40)
            c.setFillColor(colors.Color(0.8, 0.1, 0.1, alpha=0.12))
            c.translate(105 * mm, 150 * mm)
            c.rotate(45)
            c.drawCentredString(0, 0, "SYNTHETIC TEST DATA")
        c.restoreState()

    doc = SimpleDocTemplate(str(out_pdf), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=16 * mm, title="VAPT Report", author="VAPT-Agent")
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return {"generated_at": gen, "findings": len(vulns), "informational": len(infos), "numbering": numbering}


def _finding_block(f, num, ss):
    sev_c = SEV_COLORS.get(f["severity"], colors.grey)
    head = Table([[Paragraph(f"<font color='white'><b>{num} ({f['id']}) — {escape(f['title'])}</b></font>", ss["B"]),
                   Paragraph(f"<font color='white'><b>{f['severity'].upper()} | {f['priority']} | risk {f['risk_score']}</b></font>", ss["B"])]],
                 colWidths=[130 * mm, 40 * mm])
    head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), sev_c), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    aff = "; ".join(f"{a['asset']}{':' + str(a['port']) if a.get('port') else ''}{' ' + a['url'] if a.get('url') else ''}"
                    for a in f["affected"][:12]) + (f" (+{len(f['affected']) - 12} more)" if len(f["affected"]) > 12 else "")
    meta = [["Affected asset(s)", aff],
            ["Severity / CVSS", f"{f['severity']} / " + (f"{f['cvss_score']} {f['cvss_vector'] or ''} (source: {f['cvss_source']})"
                                                         if f["cvss_score"] is not None else "no CVSS supplied by any tool")],
            ["CVE / CWE", f"{', '.join(f['cves']) or 'none reported'} / {', '.join('CWE-' + str(c) for c in f['cwes']) or 'n/a'}"],
            ["OWASP / ATT&CK", f"{'; '.join(f['owasp']) or 'n/a'} / {'; '.join(f['attack']) or 'n/a'}"],
            ["Confidence", f"{f['confidence']} — " + "; ".join(f["confidence_factors"])],
            ["Validation status", f["status"] + ("" if f["validation"] else " (no active validation performed)")],
            ["Risk calculation", f["risk_breakdown"].get("formula", "") + f"  [{f['risk_breakdown'].get('base_source', '')}; "
                                 f"exploitability: {f['risk_breakdown'].get('exploitability_source', '')}]"],
            ["Source tools", ", ".join(f["source_tools"])]]
    t = Table([[P(a, ss["Cell"]), P(b, ss["Cell"])] for a, b in meta], colWidths=[32 * mm, 138 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#aab7b8")),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eaf2f8")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    out = [Spacer(1, 4 * mm), KeepTogether([head, t]), Paragraph("<b>Description (from tool output)</b>", ss["H3x"]),
           P(f["description"][:1500], ss["B"])]
    out.append(Paragraph("<b>Supporting evidence (observed)</b>", ss["H3x"]))
    for e in f["evidence"][:6]:
        out.append(P(f"[{e['source_tool']} | {e['mode']} | job {e['job_id']} | {e['observed_at']} | tool severity: "
                     f"{e['tool_severity']}{' | tool confidence: ' + str(e['tool_confidence']) if e.get('tool_confidence') else ''}"
                     f" | ref {e.get('tool_ref_id') or '-'}]  raw: {e['raw_ref']} (sha256 {e['raw_sha256'][:16]}…)", ss["Small"]))
        out.append(Preformatted((e["excerpt"] or "")[:700], ss["Codex"], maxLineLength=150))
    if len(f["evidence"]) > 6:
        out.append(P(f"+ {len(f['evidence']) - 6} further evidence item(s) in the JSON export.", ss["Small"]))
    for v in f["validation"]:
        out.append(P(f"Validation: {v['module']} ({v['method']}) -> {v['outcome']}; approved by {v['approved_by']}; "
                     f"raw {v['raw_ref']}", ss["Small"]))
        if v.get("excerpt"):
            out.append(Preformatted(v["excerpt"][:600], ss["Codex"], maxLineLength=150))
    if f["notes"]:
        out.append(P("Notes: " + " ".join(f["notes"]), ss["Small"]))
    out.append(Paragraph("<b>Impact</b>", ss["H3x"]))
    out.append(P(IMPACT.get(f["category"], "Impact depends on the affected component; see description."), ss["B"]))
    if f.get("ai_impact"):
        out.append(Paragraph("<b>AI inference:</b> " + escape(f["ai_impact"]), ss["AI"]))
    out.append(Paragraph("<b>Remediation</b>", ss["H3x"]))
    out.append(P(f["solution"][:1200], ss["B"]))
    if f["references"]:
        out.append(P("References: " + " | ".join(f["references"][:8]), ss["Small"]))
    return out


def export_json(state: dict, path):
    keep = {k: state[k] for k in ("id", "created_at", "analyst", "request", "scope", "intent", "hosts", "actions", "jobs",
                                  "findings", "approvals", "validations", "decisions", "rejected_targets", "correlation_stats")
            if k in state}
    keep["integration_matrix"] = INTEGRATION_MATRIX
    path.write_text(json.dumps(keep, indent=1, default=str))
