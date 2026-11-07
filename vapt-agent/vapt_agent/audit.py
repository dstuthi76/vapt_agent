"""Append-only, hash-chained audit trail. Every decision, scope check, approval and
tool execution is recorded here; `verify()` detects edits or deletions."""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from .models import now_iso

_lock = threading.Lock()


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def _last_hash(self) -> str:
        last = "GENESIS"
        with self.path.open() as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def record(self, event: str, actor: str, details: dict) -> dict:
        with _lock:
            entry = {
                "ts": now_iso(),
                "event": event,           # e.g. scope.check, plan.proposed, approval.granted, job.finished
                "actor": actor,           # agent | analyst:<name> | system
                "details": details,
                "prev": self._last_hash(),
            }
            entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            with self.path.open("a") as f:
                f.write(json.dumps(entry) + "\n")
            return entry

    def entries(self) -> list[dict]:
        with self.path.open() as f:
            return [json.loads(l) for l in f if l.strip()]

    def verify(self) -> dict:
        prev = "GENESIS"
        for i, e in enumerate(self.entries()):
            h = e.pop("hash")
            if e["prev"] != prev:
                return {"valid": False, "broken_at": i, "reason": "chain link mismatch"}
            if hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
                return {"valid": False, "broken_at": i, "reason": "entry content modified"}
            prev = h
        return {"valid": True, "entries": len(self.entries())}
