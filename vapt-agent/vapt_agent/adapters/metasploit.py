"""Metasploit adapter — LIVE, HUMAN-APPROVED, LAB-ONLY, NON-DESTRUCTIVE validation.

Hard rules enforced in code (not just policy):
  * the action must be in status 'approved' with an analyst recorded as approver;
  * the module must be in the curated allow-list (knowledge.MSF_VALIDATION);
  * exploit/* modules are only ever invoked with `check` (no payload, no `exploit`/`run`);
  * auxiliary/scanner/* modules are run as scanners; no PAYLOAD is ever set;
  * the target is re-validated against the scope immediately before execution.

Transport: msfrpcd (MessagePack RPC, needs `pip install msgpack`) if MSF_RPC_HOST is set,
otherwise the local `msfconsole` binary.
"""
from __future__ import annotations

import re
import time

import requests

from .. import config
from ..knowledge import MSF_VALIDATION
from .base import Adapter, AdapterResult, RunContext, ToolError, ToolUnavailable, cmd_str, run_cmd, which

ALLOWED_MODULES = set(MSF_VALIDATION.values())

OUTCOME_PATTERNS = [
    (r"The target is vulnerable", "confirmed"),
    (r"likely VULNERABLE|Host is likely VULNERABLE", "confirmed"),
    (r"Anonymous READ", "confirmed"),
    (r"Login Successful|Success: '", "confirmed"),
    (r"appears to be vulnerable", "likely"),
    (r"The target is not exploitable|does NOT appear vulnerable|Host does NOT appear|not vulnerable", "not_confirmed"),
    (r"Cannot reliably check|check is not supported|This module does not support check", "inconclusive"),
]


def interpret(output: str) -> str:
    for rx, outcome in OUTCOME_PATTERNS:
        if re.search(rx, output, re.I):
            return outcome
    return "inconclusive"


class MetasploitAdapter(Adapter):
    name = "metasploit"
    supports_live = True

    def availability(self):
        if config.MSF_RPC_HOST:
            try:
                import msgpack  # noqa: F401
            except ImportError:
                return False, "MSF_RPC_HOST set but python 'msgpack' not installed"
            return True, f"live (approval-gated) via msfrpcd {config.MSF_RPC_HOST}:{config.MSF_RPC_PORT}"
        p = which(config.MSFCONSOLE_BIN)
        return (True, f"live (approval-gated) via {p}") if p else (False, "msfconsole / msfrpcd not configured")

    def _commands(self, module, rhost, rport):
        verb = "check" if module.startswith("exploit/") else "run"
        cmds = [f"use {module}", f"set RHOSTS {rhost}"]
        if rport:
            cmds.append(f"set RPORT {rport}")
        if module.endswith("openssl_heartbleed"):
            cmds.append("set ACTION SCAN")
        if module.endswith("_login"):
            cmds += ["set STOP_ON_SUCCESS true", "set BLANK_PASSWORDS false", "set USER_AS_PASS false"]
        cmds.append(verb)
        return cmds, verb

    def run(self, action, ctx: RunContext) -> AdapterResult:
        p = action.params
        module = p.get("module", "")
        if action.status not in ("approved", "running", "queued") or not (action.decided_by or "").startswith("analyst"):
            raise ToolError("BLOCKED: Metasploit validation requires explicit analyst approval")
        if module not in ALLOWED_MODULES:
            raise ToolError(f"BLOCKED: module {module} is not in the non-destructive allow-list")
        dec = ctx.scope.check(p["rhost"], tool="metasploit", port=p.get("rport"))
        if not dec.allowed:
            raise ToolError(f"BLOCKED by scope: {dec.reason}")
        cmds, verb = self._commands(module, dec.resolved_ip or p["rhost"], p.get("rport"))
        ctx.note(f"validation via {verb}: {'; '.join(cmds)}")
        if config.MSF_RPC_HOST:
            output, command = self._rpc(cmds, ctx)
        else:
            cli = [config.MSFCONSOLE_BIN, "-q", "-n", "-x", "; ".join(cmds + ["exit -y"])]
            rc, so, se = run_cmd(cli, ctx.timeout)
            output, command = so + se, cmd_str(cli)
        raw_ref, sha = ctx.save_raw("msf_validation.txt", output.encode())
        outcome = interpret(output)
        res = AdapterResult(raw_files=[(raw_ref, sha)], command=command)
        res.validation = {
            "finding_id": p.get("finding_id"), "module": module, "method": verb, "outcome": outcome,
            "raw_ref": raw_ref, "raw_sha256": sha, "job_id": ctx.job_id,
            "excerpt": "\n".join(l for l in output.splitlines() if re.search(r"\[[+\-*!]\]", l))[:1200],
            "approved_by": action.decided_by,
        }
        return res

    def _rpc(self, cmds, ctx):
        import msgpack
        scheme = "https" if config.MSF_RPC_SSL else "http"
        url = f"{scheme}://{config.MSF_RPC_HOST}:{config.MSF_RPC_PORT}/api/"

        def call(*args):
            try:
                r = requests.post(url, data=msgpack.packb(list(args)), timeout=30, verify=False,
                                  headers={"Content-Type": "binary/message-pack"}, proxies={"http": None, "https": None})
            except requests.RequestException as e:
                raise ToolUnavailable(f"msfrpcd unreachable: {e}") from e
            return msgpack.unpackb(r.content, raw=False, strict_map_key=False)

        tok = call("auth.login", config.MSF_RPC_USER, config.MSF_RPC_PASS).get("token")
        if not tok:
            raise ToolError("msfrpcd authentication failed")
        cid = call("console.create", tok)["id"]
        call("console.read", tok, cid)
        out, deadline = "", time.time() + ctx.timeout
        for c in cmds:
            call("console.write", tok, cid, c + "\n")
            time.sleep(1)
            while True:
                r = call("console.read", tok, cid)
                out += r.get("data", "")
                if not r.get("busy"):
                    break
                if time.time() > deadline:
                    raise ToolError("metasploit validation timed out")
                time.sleep(1)
        call("console.destroy", tok, cid)
        return out, f"msfrpcd {url} console: " + "; ".join(cmds)
