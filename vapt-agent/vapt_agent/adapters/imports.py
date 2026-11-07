"""Import adapters for tools whose live use is licence- or edition-restricted:

* Nessus  — IMPORT of .nessus (v2) exports. Live scan launch via the API is not available in
            Nessus Essentials/Professional, so we do not claim it.
* OpenVAS — IMPORT of Greenbone XML reports. Optional EXPERIMENTAL live mode via python-gvm
            (see openvas_live.py) when GVM_SOCKET is configured.
* Burp    — IMPORT of the XML "Report issues" export (Community & Pro). Burp Pro's REST API
            is listed as *planned* in the integration matrix.
"""
from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from ..knowledge import extract_cves, norm_sev, CWE_RE
from ..models import RawFinding
from .base import Adapter, AdapterResult, RunContext, evidence


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


class NessusAdapter(Adapter):
    name = "nessus"
    supports_import = True
    import_extensions = (".nessus", ".xml")

    def availability(self):
        return True, "import-only (.nessus v2 export)"

    def parse(self, content, ctx: RunContext, raw_ref, sha):
        root = ET.fromstring(content)
        res = AdapterResult(raw_files=[(raw_ref, sha)])
        for rh in root.iter("ReportHost"):
            props = {t.get("name"): t.text for t in rh.findall("HostProperties/tag")}
            ip = props.get("host-ip") or rh.get("name")
            ts = props.get("HOST_END") or props.get("HOST_START")
            for it in rh.findall("ReportItem"):
                sev = norm_sev(it.get("severity"))
                port = int(it.get("port") or 0) or None
                cvss3 = _f(it.findtext("cvss3_base_score"))
                cvss2 = _f(it.findtext("cvss_base_score"))
                score, vector, src = (cvss3, it.findtext("cvss3_vector"), "Nessus cvss3_base_score") if cvss3 is not None \
                    else (cvss2, it.findtext("cvss_vector"), "Nessus cvss_base_score") if cvss2 is not None else (None, None, None)
                cves = sorted({c.text.strip().upper() for c in it.findall("cve") if c.text})
                cwes = [int(c.text) for c in it.findall("cwe") if c.text and c.text.strip().isdigit()]
                expl = it.findtext("exploit_available")
                out = it.findtext("plugin_output") or ""
                rf = RawFinding(
                    title=it.get("pluginName"), severity=sev, asset=ip, port=port, protocol=it.get("protocol"),
                    service=it.get("svc_name"), description=(it.findtext("description") or it.findtext("synopsis") or "").strip(),
                    solution=(it.findtext("solution") or "").strip(), cves=cves, cwes=cwes,
                    cvss_score=score, cvss_vector=vector, cvss_source=src,
                    exploit_available=(expl.strip().lower() == "true") if expl else None,
                    references=[r for r in (it.findtext("see_also") or "").split() if r.startswith("http")])
                rf.tool_confidence_score = 0.8 if sev != "info" else 0.9
                rf.version_inferred = "version" in (it.get("pluginName") or "").lower() and "<" in (it.get("pluginName") or "")
                rf.evidence = evidence(ctx, "nessus", raw_ref, sha, asset=ip, port=port,
                                       excerpt=f"Plugin {it.get('pluginID')} {it.get('pluginName')}\n{out.strip()[:1000]}",
                                       title=it.get("pluginName"), severity=sev, ref_id=f"nessus/{it.get('pluginID')}",
                                       observed_at=ts)
                res.findings.append(rf)
        return res


class OpenVASAdapter(Adapter):
    name = "openvas"
    supports_import = True
    import_extensions = (".xml",)

    def availability(self):
        from .. import config
        if config.GVM_SOCKET:
            return True, f"import + experimental live via python-gvm ({config.GVM_SOCKET})"
        return True, "import-only (Greenbone XML report); set GVM_SOCKET for experimental live mode"

    @property
    def supports_live(self):
        from .. import config
        return bool(config.GVM_SOCKET)

    def run(self, action, ctx: RunContext) -> AdapterResult:
        """EXPERIMENTAL live scan through python-gvm over the gvmd unix socket."""
        import time
        from .. import config
        from .base import ToolUnavailable, ToolTimeout, ToolError
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
        except ImportError as e:
            raise ToolUnavailable("python-gvm not installed (pip install python-gvm)") from e
        FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
        OPENVAS_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"
        ALL_IANA_TCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
        XML_FORMAT = "a994b278-1f62-11e1-96ac-406186ea4fc5"
        deadline = time.time() + ctx.timeout
        with Gmp(UnixSocketConnection(path=config.GVM_SOCKET)) as gmp:
            gmp.authenticate(config.GVM_USER, config.GVM_PASS)
            tgt = gmp.create_target(name=f"vapt-{ctx.job_id}", hosts=[action.target], port_list_id=ALL_IANA_TCP)
            task = gmp.create_task(name=f"vapt-{ctx.job_id}", config_id=FULL_AND_FAST,
                                   target_id=tgt.get("id"), scanner_id=OPENVAS_SCANNER)
            started = gmp.start_task(task.get("id"))
            report_id = started.findtext("report_id")
            while True:
                st = gmp.get_task(task.get("id")).findtext("task/status")
                ctx.note(f"openvas task status: {st}")
                if st == "Done":
                    break
                if st in ("Stopped", "Interrupted") or time.time() > deadline:
                    raise (ToolTimeout if time.time() > deadline else ToolError)(f"OpenVAS task ended: {st}")
                time.sleep(15)
            rep = gmp.get_report(report_id, report_format_id=XML_FORMAT, details=True, ignore_pagination=True)
            content = ET.tostring(rep)
        raw_ref, sha = ctx.save_raw("openvas_report.xml", content)
        res = self.parse(content, ctx, raw_ref, sha)
        res.command = f"python-gvm {config.GVM_SOCKET}: create_target/create_task(Full and fast)/start_task/get_report"
        return res

    def parse(self, content, ctx: RunContext, raw_ref, sha):
        root = ET.fromstring(content)
        res = AdapterResult(raw_files=[(raw_ref, sha)])
        for r in root.iter("result"):
            nvt = r.find("nvt")
            if nvt is None:
                continue
            host_el = r.find("host")
            ip = (host_el.text or "").strip() if host_el is not None else ""
            port_txt = r.findtext("port") or ""
            m = re.match(r"(\d+)/(\w+)", port_txt)
            port = int(m.group(1)) if m else None
            score = _f(r.findtext("severity")) or _f(nvt.findtext("cvss_base"))
            tags = dict(kv.split("=", 1) for kv in (nvt.findtext("tags") or "").split("|") if "=" in kv)
            threat = (r.findtext("threat") or "").lower()
            sev = norm_sev(threat) if threat else "info"
            cves = sorted({ref.get("id").upper() for ref in nvt.findall("refs/ref") if ref.get("type") == "cve"})
            cves = cves or extract_cves(nvt.findtext("cve") or "")
            cwes = sorted({int(x) for x in CWE_RE.findall(nvt.findtext("tags") or "")})
            qod = _f(r.findtext("qod/value"))
            desc = (r.findtext("description") or "").strip()
            rf = RawFinding(
                title=r.findtext("name") or nvt.findtext("name"), severity=sev, asset=ip, port=port,
                protocol=m.group(2) if m else None,
                description=tags.get("summary") or desc, solution=(nvt.findtext("solution") or tags.get("solution") or "").strip(),
                cves=cves, cwes=cwes, cvss_score=score if score and score > 0 else None,
                cvss_vector=tags.get("cvss_base_vector"), cvss_source="OpenVAS severity/cvss_base" if score else None,
                references=[ref.get("id") for ref in nvt.findall("refs/ref") if ref.get("type") == "url"])
            rf.tool_confidence_score = (qod / 100.0) if qod is not None else 0.7
            rf.version_inferred = qod is not None and qod <= 80   # QoD 80 = remote banner check
            rf.evidence = evidence(ctx, "openvas", raw_ref, sha, asset=ip, port=port,
                                   excerpt=f"NVT {nvt.get('oid')} | QoD {qod}\n{desc[:1000]}",
                                   title=rf.title, severity=sev, tool_confidence=f"QoD {qod}",
                                   ref_id=f"nvt/{nvt.get('oid')}", observed_at=r.findtext("creation_time"))
            res.findings.append(rf)
        return res


class BurpAdapter(Adapter):
    name = "burp"
    supports_import = True
    import_extensions = (".xml",)
    CONF = {"certain": 0.95, "firm": 0.75, "tentative": 0.4}

    def availability(self):
        return True, "import-only (Burp 'Report issues' XML export); Pro REST API planned"

    def parse(self, content, ctx: RunContext, raw_ref, sha):
        root = ET.fromstring(content)
        res = AdapterResult(raw_files=[(raw_ref, sha)])
        for i in root.iter("issue"):
            host_el = i.find("host")
            base = (host_el.text or "").strip() if host_el is not None else ""
            u = urlparse(base)
            ip = host_el.get("ip") if host_el is not None and host_el.get("ip") else u.hostname
            port = u.port or (443 if u.scheme == "https" else 80)
            path = i.findtext("path") or "/"
            sev = norm_sev(i.findtext("severity"))
            conf = (i.findtext("confidence") or "").lower()
            classif = i.findtext("vulnerabilityClassifications") or ""
            cwes = sorted({int(x) for x in CWE_RE.findall(classif)})
            req = i.find("requestresponse/request")
            req_txt = ""
            if req is not None and req.text:
                req_txt = base64.b64decode(req.text).decode("utf-8", "replace") if req.get("base64") == "true" else req.text
            detail = re.sub(r"<[^>]+>", " ", i.findtext("issueDetail") or "")
            rf = RawFinding(
                title=i.findtext("name"), severity=sev, asset=ip, port=port, service="http", url=base + path,
                description=re.sub(r"<[^>]+>", " ", i.findtext("issueBackground") or detail).strip(),
                solution=re.sub(r"<[^>]+>", " ", i.findtext("remediationBackground") or "").strip(),
                cves=extract_cves(detail), cwes=cwes)
            rf.tool_confidence_score = self.CONF.get(conf, 0.5)
            rf.evidence = evidence(ctx, "burp", raw_ref, sha, asset=ip, port=port, url=base + path,
                                   excerpt=(detail.strip()[:600] + ("\n--- request ---\n" + req_txt[:600] if req_txt else "")),
                                   title=rf.title, severity=sev, tool_confidence=conf,
                                   ref_id=f"burp/{i.findtext('type')}/{i.findtext('serialNumber')}")
            res.findings.append(rf)
        return res
