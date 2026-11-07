"""Turn a natural-language analyst request into a structured, scope-checked intent."""
from __future__ import annotations

import re

from .llm import llm

URL_RE = re.compile(r"https?://[^\s,;'\"<>]+", re.I)
CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOSTPORT_RE = re.compile(r"\b([a-z0-9][a-z0-9\-\.]*[a-z0-9]):(\d{2,5})\b", re.I)

SYSTEM = """You are the request-understanding component of an authorized penetration-testing agent.
Extract the analyst's intent. Never add targets that are not literally written in the request.
JSON schema: {"targets": [str], "focus": ["web"|"network"], "intensity": "quick"|"standard"|"thorough",
"no_intrusive": bool, "summary": str}"""


def parse_request(text: str, scope) -> dict:
    t = text.strip()
    targets = []
    for u in URL_RE.findall(t):
        targets.append(u.rstrip(".)"))
    rest = URL_RE.sub(" ", t)
    for c in CIDR_RE.findall(rest):
        targets.append(c)
    rest = CIDR_RE.sub(" ", rest)
    for h, p in HOSTPORT_RE.findall(rest):      # host:port is treated as a web endpoint
        targets.append(f"http://{h}:{p}")
    rest = HOSTPORT_RE.sub(" ", rest)
    targets += IP_RE.findall(rest)
    # registered hostnames mentioned by name
    for hn in scope.hostnames:
        if re.search(rf"(?<![\w\-\.]){re.escape(hn)}(?![\w\-])", rest, re.I):
            targets.append(hn)
    low = t.lower()
    focus = []
    if re.search(r"\b(web|app|application|http|owasp|api|site|zap|burp|nikto)\b", low):
        focus.append("web")
    if re.search(r"\b(network|infra|infrastructure|ports?|services?|host|nmap|nessus|openvas|smb|ftp)\b", low):
        focus.append("network")
    if not focus or re.search(r"\b(full|complete|end[- ]to[- ]end|everything|comprehensive)\b", low):
        focus = ["network", "web"]
    intensity = "quick" if re.search(r"\b(quick|quickly|fast|light|lightweight)\b", low) else \
        "thorough" if re.search(r"\b(thorough|deep|full|comprehensive|in[- ]depth)\b", low) else "standard"
    no_intr = bool(re.search(r"\b(passive|non[- ]intrusive|no active|safe only|read[- ]only)\b", low))
    intent = {"targets": list(dict.fromkeys(targets)), "focus": focus, "intensity": intensity,
              "no_intrusive": no_intr, "summary": t[:300], "parser": "rules"}

    out = llm.chat_json(SYSTEM, t, 400)
    if out:
        # LLM may refine focus/intensity; targets only accepted if literally present in the request
        llm_targets = [x for x in out.get("targets", []) if isinstance(x, str) and x.lower() in low]
        intent["targets"] = list(dict.fromkeys(intent["targets"] + [x for x in llm_targets if x not in intent["targets"]
                                                                    and not any(x in y for y in intent["targets"])]))
        if out.get("focus") and set(out["focus"]) <= {"web", "network"}:
            intent["focus"] = out["focus"]
        if out.get("intensity") in ("quick", "standard", "thorough"):
            intent["intensity"] = out["intensity"]
        intent["no_intrusive"] = bool(out.get("no_intrusive", no_intr)) or no_intr
        intent["summary"] = str(out.get("summary", intent["summary"]))[:300]
        intent["parser"] = f"rules+{llm.describe()}"
    return intent
