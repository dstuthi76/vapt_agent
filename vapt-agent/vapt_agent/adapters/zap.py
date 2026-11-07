"""OWASP ZAP adapter — LIVE (ZAP REST API, daemon mode) + IMPORT (traditional JSON / XML report).

Live flow: accessUrl -> spider -> wait for passive scan -> [active scan only if the action
was explicitly approved as intrusive] -> fetch alerts for the target base URL."""
from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import requests

from .. import config
from ..knowledge import norm_sev
from ..models import RawFinding
from .base import Adapter, AdapterResult, RunContext, ToolError, ToolTimeout, ToolUnavailable, evidence

CONF_MAP = {"confirmed": 0.95, "high": 0.85, "medium": 0.65, "low": 0.4, "false positive": 0.05,
            "4": 0.95, "3": 0.85, "2": 0.65, "1": 0.4, "0": 0.05}
RISK_MAP = {"3": "high", "2": "medium", "1": "low", "0": "info"}


class ZapAdapter(Adapter):
    name = "zap"
    supports_live = True
    supports_import = True
    import_extensions = (".json", ".xml")

    def _get(self, path, **params):
        params["apikey"] = config.ZAP_API_KEY
        try:
            r = requests.get(f"{config.ZAP_URL}{path}", params=params, timeout=30, proxies={"http": None, "https": None})
        except requests.RequestException as e:
            raise ToolUnavailable(f"ZAP API not reachable at {config.ZAP_URL} ({type(e).__name__})") from e
        if r.status_code != 200:
            raise ToolError(f"ZAP API {path} -> HTTP {r.status_code}: {r.text[:200]}")
        return r.json()

    def availability(self):
        try:
            v = self._get("/JSON/core/view/version/")
            return True, f"live: ZAP {v.get('version')} at {config.ZAP_URL}"
        except Exception as e:
            return False, str(e)[:160]

    def _wait(self, status_path, scan_id, deadline, label, ctx):
        while True:
            st = int(self._get(status_path, scanId=scan_id).get("status", 0))
            if st >= 100:
                return
            if time.time() > deadline:
                raise ToolTimeout(f"ZAP {label} did not finish before timeout")
            ctx.note(f"zap {label} {st}%")
            time.sleep(3)

    def run(self, action, ctx: RunContext) -> AdapterResult:
        url = action.target
        deadline = time.time() + ctx.timeout
        calls = []
        self._get("/JSON/core/action/accessUrl/", url=url, followRedirects="true"); calls.append("core/action/accessUrl")
        sid = self._get("/JSON/spider/action/scan/", url=url, maxChildren="25", recurse="true",
                        subtreeOnly="true")["scan"]; calls.append("spider/action/scan")
        self._wait("/JSON/spider/view/status/", sid, deadline, "spider", ctx)
        while int(self._get("/JSON/pscan/view/recordsToScan/").get("recordsToScan", 0)) > 0:
            if time.time() > deadline:
                raise ToolTimeout("ZAP passive scan queue did not drain")
            time.sleep(2)
        if action.params.get("active"):
            if not action.intrusive or action.status not in ("approved", "running", "queued"):
                raise ToolError("ZAP active scan requires an explicitly approved intrusive action")
            aid = self._get("/JSON/ascan/action/scan/", url=url, recurse="true")["scan"]; calls.append("ascan/action/scan")
            self._wait("/JSON/ascan/view/status/", aid, deadline, "active scan", ctx)
        alerts = self._get("/JSON/core/view/alerts/", baseurl=url, start="0", count="5000")
        content = json.dumps(alerts, indent=1).encode()
        raw_ref, sha = ctx.save_raw("zap_alerts.json", content)
        res = self.parse(content, ctx, raw_ref, sha)
        res.command = f"ZAP API {config.ZAP_URL}: " + " -> ".join(calls) + " -> core/view/alerts"
        return res

    # ------------------------------------------------------------------ parse
    def _mk(self, ctx, raw_ref, sha, *, name, risk, conf, url, param, ev, desc, sol, refs, cwe, plugin, other=""):
        u = urlparse(url or "")
        port = u.port or (443 if u.scheme == "https" else 80)
        rf = RawFinding(title=name, severity=risk, asset=u.hostname or "", port=port, service="http", url=url,
                        description=(desc or "").strip(), solution=(sol or "").strip(),
                        cwes=[int(cwe)] if str(cwe).isdigit() and int(cwe) > 0 else [],
                        references=[r for r in (refs or "").split() if r.startswith("http")])
        rf.tool_confidence_score = CONF_MAP.get(str(conf).lower(), 0.5)
        excerpt = f"{url} param={param or '-'}\nevidence: {ev or '-'}"
        if other:
            excerpt += f"\nother: {other[:300]}"
        rf.evidence = evidence(ctx, "zap", raw_ref, sha, asset=rf.asset, port=port, url=url, excerpt=excerpt,
                               title=name, severity=risk, tool_confidence=str(conf), ref_id=f"zap/{plugin}")
        return rf

    def parse(self, content: bytes, ctx: RunContext, raw_ref: str, sha: str) -> AdapterResult:
        res = AdapterResult(raw_files=[(raw_ref, sha)])
        text = content.decode("utf-8", "replace").lstrip()
        if text.startswith("<"):
            root = ET.fromstring(text)
            for site in root.iter("site"):
                for a in site.iter("alertitem"):
                    risk = RISK_MAP.get(a.findtext("riskcode", "0"), "info")
                    for inst in a.iter("instance") or []:
                        res.findings.append(self._mk(ctx, raw_ref, sha, name=a.findtext("alert") or a.findtext("name"),
                            risk=risk, conf=a.findtext("confidence"), url=inst.findtext("uri"),
                            param=inst.findtext("param"), ev=inst.findtext("evidence"), desc=a.findtext("desc"),
                            sol=a.findtext("solution"), refs=a.findtext("reference"), cwe=a.findtext("cweid"),
                            plugin=a.findtext("pluginid")))
            return res
        data = json.loads(text)
        if "alerts" in data and isinstance(data["alerts"], list):        # live API format
            for a in data["alerts"]:
                res.findings.append(self._mk(ctx, raw_ref, sha, name=a.get("alert") or a.get("name"),
                    risk=norm_sev(a.get("risk")), conf=a.get("confidence"), url=a.get("url"), param=a.get("param"),
                    ev=a.get("evidence"), desc=a.get("description"), sol=a.get("solution"), refs=a.get("reference"),
                    cwe=a.get("cweid"), plugin=a.get("pluginId"), other=a.get("other", "")))
        for site in data.get("site", []):                                  # traditional-json report
            for a in site.get("alerts", []):
                risk = RISK_MAP.get(str(a.get("riskcode")), "info")
                for inst in a.get("instances", []) or [{"uri": site.get("@name")}]:
                    res.findings.append(self._mk(ctx, raw_ref, sha, name=a.get("alert") or a.get("name"),
                        risk=risk, conf=a.get("confidence"), url=inst.get("uri"), param=inst.get("param"),
                        ev=inst.get("evidence"), desc=a.get("desc"), sol=a.get("solution"), refs=a.get("reference"),
                        cwe=a.get("cweid"), plugin=a.get("pluginid"), other=a.get("otherinfo", "")))
        return res
