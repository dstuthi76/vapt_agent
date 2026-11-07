"""Adapter contract shared by every tool integration."""
from __future__ import annotations

import hashlib
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..models import Evidence, RawFinding, Host, now_iso


class ToolUnavailable(Exception):
    """The tool binary / API is not installed or not reachable."""


class ToolTimeout(Exception):
    pass


class ToolError(Exception):
    pass


@dataclass
class RunContext:
    """Per-job context handed to adapters by the orchestrator."""
    job_id: str
    raw_dir: Path               # <assessment>/raw
    base_dir: Path              # <assessment>   (raw refs are relative to this)
    scope: object               # ScopeGuard
    timeout: int = 900
    mode: str = "live"
    log: list = field(default_factory=list)   # progress messages shown in the UI

    def save_raw(self, name: str, content: bytes) -> tuple[str, str]:
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        path = self.raw_dir / f"{self.job_id}_{name}"
        path.write_bytes(content)
        return str(path.relative_to(self.base_dir)), hashlib.sha256(content).hexdigest()

    def note(self, msg: str):
        self.log.append(f"{now_iso()} {msg}")


@dataclass
class AdapterResult:
    findings: list = field(default_factory=list)   # RawFinding
    hosts: list = field(default_factory=list)      # Host
    raw_files: list = field(default_factory=list)  # (relpath, sha256)
    command: str = ""
    notes: list = field(default_factory=list)
    validation: Optional[dict] = None              # metasploit validation outcome


class Adapter:
    name = "base"
    supports_live = False
    supports_import = False
    import_extensions: tuple = ()

    def availability(self) -> tuple[bool, str]:
        return False, "not implemented"

    def run(self, action, ctx: RunContext) -> AdapterResult:  # live execution
        raise ToolUnavailable(f"{self.name} has no live integration")

    def parse(self, content: bytes, ctx: RunContext, raw_ref: str, sha: str) -> AdapterResult:
        raise ToolUnavailable(f"{self.name} has no import parser")


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def run_cmd(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    if not which(cmd[0]):
        raise ToolUnavailable(f"'{cmd[0]}' not found on PATH")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise ToolTimeout(f"{cmd[0]} exceeded {timeout}s") from e
    return p.returncode, p.stdout, p.stderr


def cmd_str(cmd: list[str]) -> str:
    return " ".join(shlex.quote(c) for c in cmd)


def evidence(ctx: RunContext, tool: str, raw_ref: str, sha: str, *, asset, port=None, url=None,
             excerpt="", title="", severity="info", tool_confidence=None, ref_id=None,
             observed_at=None) -> Evidence:
    return Evidence(
        source_tool=tool, asset=asset, port=port, url=url,
        observed_at=observed_at or now_iso(), raw_ref=raw_ref, raw_sha256=sha,
        job_id=ctx.job_id, excerpt=(excerpt or "")[:1500], tool_title=title,
        tool_severity=severity, tool_confidence=tool_confidence, tool_ref_id=ref_id,
        mode=ctx.mode,
    )
