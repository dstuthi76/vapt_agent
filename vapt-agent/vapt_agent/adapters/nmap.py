"""Nmap adapter — LIVE (CLI) + IMPORT (-oX XML)."""
from __future__ import annotations

import os
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .. import config
from ..knowledge import extract_cves
from ..models import RawFinding, Host
from .base import (Adapter, AdapterResult, RunContext, ToolError, cmd_str, evidence,
                   run_cmd, which)

# Safe (non-intrusive) NSE scripts the planner may request.
SAFE_SCRIPTS = {
    "ssl-enum-ciphers", "ssl-cert", "http-headers", "http-methods", "http-title",
    "http-server-header", "ftp-anon", "smb-security-mode", "smb2-security-mode",
    "smb-protocols", "smb-vuln-ms17-010", "ssh2-enum-algos", "mysql-info",
    "rdp-enum-encryption", "vnc-info", "banner",
}

CLEARTEXT_ADMIN = {"telnet": 23, "login": 513, "shell": 514, "exec": 512}


class NmapAdapter(Adapter):
    name = "nmap"
    supports_live = True
    supports_import = True
    import_extensions = (".xml",)

    def availability(self):
        p = which(config.NMAP_BIN)
        return (True, f"live: {p}") if p else (False, "nmap binary not on PATH (imports still work)")

    def build_cmd(self, action, ctx: RunContext, out_file: str) -> list[str]:
        p = action.params
        profile = p.get("profile", "services")
        rate = str(ctx.scope.scope.get("max_rate_pps", 300))
        cmd = [config.NMAP_BIN, "-oX", out_file, "--max-rate", rate, "-T4", "-Pn"]
        if profile == "discovery":
            cmd = [config.NMAP_BIN, "-oX", out_file, "--max-rate", rate, "-T4", "-sn"]
        elif profile == "services":
            cmd += ["-sV", "--version-light"]
            cmd += (["-p", p["ports"]] if p.get("ports") else ["--top-ports", str(p.get("top_ports", 1000))])
        elif profile == "scripts":
            scripts = [s for s in p.get("scripts", []) if s in SAFE_SCRIPTS]
            if not scripts:
                raise ToolError("no permitted NSE scripts requested")
            cmd += ["-sV", "--version-light", "-p", p["ports"], "--script", ",".join(scripts)]
        else:
            raise ToolError(f"unknown nmap profile {profile}")
        if os.geteuid() != 0 and profile != "discovery":
            cmd.insert(1, "-sT")      # connect scan when not root
        cmd += ctx.scope.nmap_exclude_arg()
        cmd.append(action.target)
        return cmd

    def run(self, action, ctx: RunContext) -> AdapterResult:
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "nmap.xml")
            cmd = self.build_cmd(action, ctx, out)
            ctx.note(f"exec: {cmd_str(cmd)}")
            rc, so, se = run_cmd(cmd, ctx.timeout)
            if rc != 0 or not Path(out).exists():
                raise ToolError(f"nmap exit {rc}: {se.strip()[:400]}")
            content = Path(out).read_bytes()
        raw_ref, sha = ctx.save_raw("nmap.xml", content)
        res = self.parse(content, ctx, raw_ref, sha)
        res.command = cmd_str(cmd)
        return res

    # ------------------------------------------------------------------ parse
    def parse(self, content: bytes, ctx: RunContext, raw_ref: str, sha: str) -> AdapterResult:
        root = ET.fromstring(content)
        res = AdapterResult(raw_files=[(raw_ref, sha)])
        scan_ts = root.get("startstr")
        for h in root.findall("host"):
            st = h.find("status")
            if st is not None and st.get("state") != "up":
                continue
            addr = None
            for a in h.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr")
            if not addr:
                continue
            host = Host(address=addr, sources=[ctx.job_id])
            host.hostnames = [hn.get("name") for hn in h.findall("hostnames/hostname") if hn.get("name")]
            osm = h.find("os/osmatch")
            if osm is not None:
                host.os_guess = f"{osm.get('name')} ({osm.get('accuracy')}%)"
            for p in h.findall("ports/port"):
                state = p.find("state").get("state") if p.find("state") is not None else "unknown"
                svc = p.find("service")
                port = int(p.get("portid"))
                sd = {
                    "port": port, "proto": p.get("protocol"), "state": state,
                    "name": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                    "extrainfo": svc.get("extrainfo") if svc is not None else None,
                    "tunnel": svc.get("tunnel") if svc is not None else None,
                    "cpe": [c.text for c in svc.findall("cpe")] if svc is not None else [],
                    "evidence_ref": raw_ref,
                }
                host.services.append(sd)
                if state != "open":
                    continue
                excerpt_base = f"{port}/{sd['proto']} open {sd['name'] or ''} {sd['product'] or ''} {sd['version'] or ''}".strip()
                # cleartext remote administration exposure (observed fact: service is open)
                if sd["name"] in CLEARTEXT_ADMIN:
                    rf = RawFinding(
                        title=f"Cleartext remote administration service exposed ({sd['name']})",
                        severity="medium", asset=addr, port=port, service=sd["name"],
                        description=f"Nmap observed {sd['name']} listening on {port}/tcp. Credentials and session data travel unencrypted.",
                        solution="Disable the service and use SSH for remote administration.",
                        cwes=[319],
                    )
                    rf.evidence = evidence(ctx, "nmap", raw_ref, sha, asset=addr, port=port,
                                           excerpt=excerpt_base, title=rf.title, severity="unrated",
                                           ref_id=f"port/{port}", observed_at=scan_ts)
                    rf.tool_confidence_score = 0.9
                    res.findings.append(rf)
                for s in p.findall("script"):
                    res.findings += self._script_findings(s, addr, port, sd, ctx, raw_ref, sha, scan_ts)
            res.hosts.append(host)
        return res

    def _script_findings(self, s, addr, port, sd, ctx, raw_ref, sha, ts):
        sid, out = s.get("id"), (s.get("output") or "")
        found = []

        def mk(title, sev, desc, conf=0.8, cwes=None, cves=None, solution=""):
            rf = RawFinding(title=title, severity=sev, asset=addr, port=port, service=sd["name"],
                            description=desc, cwes=cwes or [], cves=cves or extract_cves(out), solution=solution)
            rf.evidence = evidence(ctx, "nmap", raw_ref, sha, asset=addr, port=port,
                                   excerpt=f"[{sid}]\n{out.strip()}", title=title, severity="unrated",
                                   ref_id=f"nse/{sid}", observed_at=ts)
            rf.tool_confidence_score = conf
            found.append(rf)

        if sid == "ftp-anon" and "Anonymous FTP login allowed" in out:
            mk("Anonymous FTP login allowed", "medium", "Nmap ftp-anon logged in anonymously.", 0.95, [284])
        elif sid == "ssl-enum-ciphers":
            weak_proto = [v for v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1") if re.search(rf"\b{re.escape(v)}\b:", out)]
            grade = re.search(r"least strength:\s*([A-F])", out)
            if weak_proto or (grade and grade.group(1) in "CDEF"):
                mk("Weak SSL/TLS protocols or ciphers offered", "medium",
                   f"Deprecated protocols offered: {', '.join(weak_proto) or 'none'}; least cipher strength grade: {grade.group(1) if grade else 'n/a'}.",
                   0.9, [326])
        elif sid == "http-methods":
            m = re.search(r"Potentially risky methods:\s*(.+)", out)
            if m:
                mk(f"Potentially risky HTTP methods enabled: {m.group(1).strip()}", "low",
                   "Nmap http-methods reports risky methods in the OPTIONS response.", 0.7, [650])
        elif sid in ("smb-security-mode", "smb2-security-mode"):
            if re.search(r"message_signing:\s*disabled|signing enabled but not required", out, re.I):
                mk("SMB signing not required", "medium", "SMB message signing is not enforced, enabling relay attacks.", 0.9, [294])
        elif "VULNERABLE" in out:
            likely = "LIKELY VULNERABLE" in out
            title_m = re.search(r"VULNERABLE:\s*\n\s*(.+)", out)
            title = title_m.group(1).strip() if title_m else f"NSE {sid} reports VULNERABLE"
            mk(title, "medium" if likely else "high",
               f"Nmap script {sid} reported the service as {'likely ' if likely else ''}vulnerable.",
               0.6 if likely else 0.85)
        return found
