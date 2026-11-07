"""Nikto adapter — LIVE (CLI, XML output) + IMPORT (XML or JSON).

Nikto does not rate severity. The agent assigns a severity from the finding category and
labels it 'agent-classified' in the evidence so it is never presented as Nikto's own rating."""
from __future__ import annotations

import json
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from .. import config
from ..knowledge import categorize, extract_cves
from ..models import RawFinding
from .base import Adapter, AdapterResult, RunContext, ToolError, cmd_str, evidence, run_cmd, which

CATEGORY_SEVERITY = {
    "OUTDATED_SW": "medium", "SENSITIVE_FILE": "medium", "DIR_LISTING": "medium",
    "DEFAULT_CREDS": "high", "HTTP_METHODS": "low", "HDR_XFO": "low", "HDR_XCTO": "low",
    "HDR_HSTS": "low", "HDR_CSP": "low", "COOKIE_FLAGS": "low", "INFO_SERVER_BANNER": "info",
    "CORS": "low", "INFO_DISCLOSURE": "low", "TLS_CERT": "low", "TLS_WEAK": "medium",
}


class NiktoAdapter(Adapter):
    name = "nikto"
    supports_live = True
    supports_import = True
    import_extensions = (".xml", ".json")

    def availability(self):
        p = which(config.NIKTO_BIN)
        return (True, f"live: {p}") if p else (False, "nikto not on PATH (imports still work)")

    def run(self, action, ctx: RunContext) -> AdapterResult:
        url = action.target
        maxtime = int(action.params.get("maxtime", min(ctx.timeout - 30, 600)))
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "nikto.xml")
            cmd = [config.NIKTO_BIN, "-h", url, "-Format", "xml", "-o", out,
                   "-nointeractive", "-maxtime", f"{maxtime}s", "-Tuning", "x6"]   # x6 = never run DoS checks
            ctx.note(f"exec: {cmd_str(cmd)}")
            rc, so, se = run_cmd(cmd, ctx.timeout)
            if not Path(out).exists() or Path(out).stat().st_size == 0:
                raise ToolError(f"nikto produced no output (exit {rc}): {(se or so).strip()[-400:]}")
            content = Path(out).read_bytes()
        raw_ref, sha = ctx.save_raw("nikto.xml", content)
        res = self.parse(content, ctx, raw_ref, sha)
        res.command = cmd_str(cmd)
        return res

    def parse(self, content: bytes, ctx: RunContext, raw_ref: str, sha: str) -> AdapterResult:
        text = content.decode("utf-8", "replace").lstrip()
        items = []   # (ip, host, port, item_id, method, uri, msg, refs)
        if text.startswith("{") or text.startswith("["):
            data = json.loads(text)
            for scan in (data if isinstance(data, list) else [data]):
                for v in scan.get("vulnerabilities", []):
                    items.append((scan.get("ip"), scan.get("host"), int(scan.get("port", 80)),
                                  str(v.get("id")), v.get("method"), v.get("url"), v.get("msg"),
                                  v.get("references") or ""))
        else:
            # Nikto's XML may contain a DOCTYPE; strip it before parsing.
            text = re.sub(r"<!DOCTYPE[^>]*>", "", text)
            root = ET.fromstring(text)
            for sd in root.iter("scandetails"):
                ip, hn, port = sd.get("targetip"), sd.get("targethostname"), int(sd.get("targetport") or 80)
                for it in sd.findall("item"):
                    refs = (it.findtext("references") or "")
                    items.append((ip, hn, port, it.get("id"), it.get("method"),
                                  it.findtext("uri"), (it.findtext("description") or "").strip(), refs))
        res = AdapterResult(raw_files=[(raw_ref, sha)])
        for ip, hn, port, iid, method, uri, msg, refs in items:
            if not msg:
                continue
            cat, _, cwe = categorize(msg)
            sev = CATEGORY_SEVERITY.get(cat, "low")
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{hn or ip}:{port}{uri or '/'}"
            rf = RawFinding(title=msg.split(": ", 1)[-1][:200], severity=sev, asset=ip or hn, port=port,
                            service="http", url=url, description=msg, cves=extract_cves(msg + " " + refs),
                            cwes=[cwe] if cwe else [], references=[r for r in re.split(r"[\s,]+", refs) if r.startswith("http")])
            rf.version_inferred = cat == "OUTDATED_SW"
            rf.evidence = evidence(ctx, "nikto", raw_ref, sha, asset=ip or hn, port=port, url=url,
                                   excerpt=f"{method or 'GET'} {uri} -> {msg}", title=msg,
                                   severity=f"unrated (agent-classified {sev})", ref_id=f"nikto/{iid}")
            rf.tool_confidence_score = 0.55
            res.findings.append(rf)
        return res
