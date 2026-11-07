"""Adaptive planner.

The rule engine generates *candidate* actions only from observed evidence (open ports,
service banners, correlated findings). Each candidate carries an evidence-based rationale.
If an LLM is configured, it may re-order or drop candidates and add reasoning, but it can
only choose from the candidate list (it cannot invent tools, targets or parameters)."""
from __future__ import annotations

import json

from .knowledge import MSF_VALIDATION
from .llm import llm
from .models import Action, now_iso

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 9000, 9090}
SMB_NAMES = {"microsoft-ds", "netbios-ssn", "smb"}


def is_web(svc: dict) -> bool:
    n = (svc.get("name") or "").lower()
    return "http" in n or (svc.get("port") in WEB_PORTS and n in ("", "unknown", "tcpwrapped", "ssl"))


def is_tls(svc: dict) -> bool:
    n = (svc.get("name") or "").lower()
    return svc.get("tunnel") == "ssl" or n in ("https", "ssl", "ssl/http", "imaps", "pop3s", "smtps") or svc.get("port") in (443, 8443)


def web_url(host: str, svc: dict) -> str:
    scheme = "https" if is_tls(svc) else "http"
    return f"{scheme}://{host}:{svc['port']}"


# ---------------------------------------------------------------------------
def initial_plan(intent: dict, scope, decisions: list) -> tuple[list[Action], list[dict]]:
    """Return (actions, rejected_targets)."""
    actions, rejected = [], []
    for t in intent["targets"]:
        dec = scope.check(t)
        if not dec.allowed:
            rejected.append({"target": t, "reason": dec.reason})
            continue
        host, port = scope.split_target(t)
        if "/" in host and "://" not in t:
            actions.append(Action(tool="nmap", target=host, params={"profile": "discovery"}, phase="recon",
                                  rationale=f"{t} is a network range: a ping sweep (-sn) identifies live hosts first so "
                                            "port scans are only spent on hosts that exist (NIST SP 800-115 discovery phase)."))
            continue
        if "://" in t:
            actions.append(Action(tool="nmap", target=host, params={"profile": "services", "ports": f"{port},22,21,80,443,445,3306,8080,8443"},
                                  phase="recon",
                                  rationale=f"Web target {t}: confirm port {port} is open and fingerprint the server (-sV) "
                                            "before choosing web scanners; also checks a few common adjacent services."))
            continue
        top = {"quick": 100, "standard": 1000, "thorough": 3000}[intent["intensity"]]
        actions.append(Action(tool="nmap", target=host, params={"profile": "services", "top_ports": top}, phase="recon",
                              rationale=f"Host {t}: service/version discovery on the top {top} TCP ports is the minimum "
                                        "evidence needed to decide which network and web tools are relevant."))
    decisions.append({"ts": now_iso(), "type": "plan", "text": f"Initial plan: {len(actions)} reconnaissance action(s); "
                      "follow-up tools are chosen only after recon evidence arrives.", "refs": []})
    return actions, rejected


def anticipated_steps(intent):
    s = ["IF HTTP/HTTPS found -> Nikto (server misconfig) + ZAP spider/passive (app issues)" if "web" in intent["focus"] else None,
         "IF TLS found -> Nmap ssl-enum-ciphers/ssl-cert",
         "IF FTP/SMB found -> Nmap ftp-anon / smb-security-mode / smb-vuln-ms17-010" if "network" in intent["focus"] else None,
         "IF analyst uploads Nessus/OpenVAS/Burp exports -> import & correlate",
         "Correlate -> calibrate confidence -> prioritise risk",
         "IF a suspected finding maps to a non-destructive Metasploit check -> REQUEST HUMAN APPROVAL",
         "ZAP active scan only if intensity=thorough AND analyst approves" if not intent["no_intrusive"] else "Intrusive actions disabled by request",
         "Analyst review -> PDF report"]
    return [x for x in s if x]


# ---------------------------------------------------------------------------
def next_actions(state: dict, scope, existing_keys: set) -> tuple[list[Action], list[dict]]:
    intent = state["intent"]
    cands, decisions = [], []
    for ip, h in state["hosts"].items():
        open_svcs = [s for s in h["services"] if s.get("state") == "open"]
        if not open_svcs and h.get("services") == [] and h.get("discovered_only"):
            cands.append(Action(tool="nmap", target=ip, params={"profile": "services",
                         "top_ports": {"quick": 100, "standard": 1000, "thorough": 3000}[intent["intensity"]]},
                         phase="recon", triggered_by=h["sources"][:1],
                         rationale=f"Host {ip} answered the discovery sweep ({h['sources'][0]}); enumerate its services."))
            continue
        scripts, sports = set(), set()
        for s in open_svcs:
            banner = f"{s['port']}/{s['proto']} {s.get('name') or '?'} {s.get('product') or ''} {s.get('version') or ''}".strip()
            src = h["sources"][0] if h["sources"] else "?"
            if is_web(s) and "web" in intent["focus"]:
                url = web_url(ip, s)
                cands.append(Action(tool="nikto", target=url, params={}, phase="vuln-scan", triggered_by=[src],
                                    rationale=f"Nmap ({src}) observed '{banner}'. Nikto checks this web server for "
                                              "misconfigurations, dangerous files and outdated server software."))
                cands.append(Action(tool="zap", target=url, params={"active": False}, phase="vuln-scan", triggered_by=[src],
                                    rationale=f"Nmap ({src}) observed '{banner}'. ZAP spider + passive scan covers "
                                              "application-layer issues (headers, cookies, info leaks) Nikto does not."))
                sports.add(s["port"]); scripts.add("http-methods")
                if intent["intensity"] == "thorough" and not intent["no_intrusive"]:
                    cands.append(Action(tool="zap", target=url, params={"active": True}, phase="vuln-scan",
                                        intrusive=True, requires_approval=True, triggered_by=[src],
                                        rationale=f"Thorough assessment requested: ZAP active scan sends attack payloads "
                                                  f"(SQLi/XSS probes) to {url}. Intrusive -> needs explicit approval."))
            if is_tls(s):
                scripts |= {"ssl-enum-ciphers", "ssl-cert"}; sports.add(s["port"])
            n = (s.get("name") or "").lower()
            if n == "ftp" and "network" in intent["focus"]:
                scripts.add("ftp-anon"); sports.add(s["port"])
            if (n in SMB_NAMES or s["port"] in (139, 445)) and "network" in intent["focus"]:
                scripts |= {"smb-security-mode", "smb2-security-mode", "smb-vuln-ms17-010"}; sports.add(s["port"])
        if scripts:
            cands.append(Action(tool="nmap", target=ip, params={"profile": "scripts", "ports": ",".join(map(str, sorted(sports))),
                                "scripts": sorted(scripts)}, phase="enumeration", triggered_by=h["sources"][:1],
                                rationale=f"Targeted safe NSE checks ({', '.join(sorted(scripts))}) on ports "
                                          f"{sorted(sports)} because those services were observed open; this verifies "
                                          "configuration directly rather than guessing from banners."))

    # validation candidates (ALWAYS require approval)
    if not intent["no_intrusive"]:
        for f in state.get("findings", []):
            if f["status"] not in ("suspected",) or f["severity"] == "info":
                continue
            module = next((MSF_VALIDATION[c] for c in f["cves"] if c in MSF_VALIDATION), None) or MSF_VALIDATION.get(f["category"])
            if not module:
                continue
            aff = f["affected"][0]
            cands.append(Action(tool="metasploit", target=aff["asset"], phase="validation", intrusive=True,
                                requires_approval=True, triggered_by=[e["id"] for e in f["evidence"]][:3],
                                params={"module": module, "rhost": aff["asset"], "rport": aff.get("port"),
                                        "finding_id": f["id"], "identity": f["identity"]},
                                rationale=f"{f['id']} '{f['title']}' is SUSPECTED (confidence {f['confidence']}, sources: "
                                          f"{', '.join(f['source_tools'])}). Non-destructive module {module} can confirm or refute it; "
                                          "confirmation raises exploitability in the risk score, refutation lowers confidence."))

    fresh, seen = [], set()
    for a in cands:
        k = a.key()
        if k in existing_keys or k in seen:
            continue
        dec = scope.check(a.target, tool=a.tool)
        if not dec.allowed:
            decisions.append({"type": "scope-block", "text": f"Did not plan {a.tool} on {a.target}: {dec.reason}", "refs": []})
            continue
        seen.add(k)
        fresh.append(a)
    if fresh:
        fresh = _llm_review(fresh, state, decisions)
    return fresh, decisions


def _llm_review(cands: list[Action], state: dict, decisions: list) -> list[Action]:
    if not llm.enabled:
        return cands
    summary = {
        "intent": state["intent"],
        "hosts": {ip: [f"{s['port']}/{s.get('name')} {s.get('product') or ''} {s.get('version') or ''}"
                       for s in h["services"] if s.get("state") == "open"] for ip, h in state["hosts"].items()},
        "top_findings": [{"id": f["id"], "title": f["title"], "sev": f["severity"], "conf": f["confidence"]}
                         for f in state.get("findings", [])[:15]],
        "candidates": [{"id": a.id, "tool": a.tool, "target": a.target, "params": a.params, "rule_rationale": a.rationale}
                       for a in cands],
    }
    out = llm.chat_json(
        "You are the planning component of an AUTHORIZED, lab-only penetration-testing agent. Given observed "
        "evidence and candidate actions produced by a rule engine, decide which candidates are worth running now, "
        "in what order, avoiding redundant work. You may only select candidate ids. For each kept candidate give a "
        "one-sentence evidence-based reason. JSON: {\"keep\": [{\"id\": str, \"reason\": str}], "
        "\"drop\": [{\"id\": str, \"reason\": str}]}",
        json.dumps(summary)[:12000], 900)
    if not out or not isinstance(out.get("keep"), list):
        if llm.last_error:
            decisions.append({"type": "llm-error", "text": f"LLM review unavailable ({llm.last_error}); rule plan used.", "refs": []})
        return cands
    byid = {a.id: a for a in cands}
    kept = []
    for k in out["keep"]:
        a = byid.get(k.get("id"))
        if a and a not in kept:
            a.rationale += f"  [LLM reasoning: {str(k.get('reason', ''))[:300]}]"
            a.reasoning_source = "llm+rules"
            kept.append(a)
    for d in out.get("drop", []):
        a = byid.get(d.get("id"))
        if a and a not in kept:
            if a.requires_approval:          # the LLM cannot silently hide a validation option from the analyst
                kept.append(a)
                continue
            a.status, a.decided_by, a.reasoning_source = "skipped", "agent:llm", "llm+rules"
            a.rationale += f"  [LLM decided to skip: {str(d.get('reason', ''))[:300]}]"
            kept.append(a)        # recorded as 'skipped' so it is visible and never re-proposed
            decisions.append({"type": "llm-drop", "text": f"Skipped {a.tool} on {a.target}: {str(d.get('reason', ''))[:300]}",
                              "refs": a.triggered_by})
    # anything the LLM neither kept nor dropped is retained (fail-safe for coverage)
    kept += [a for a in cands if a not in kept and not any(d.get("id") == a.id for d in out.get("drop", []))]
    return kept
