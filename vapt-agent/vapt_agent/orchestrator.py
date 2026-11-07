"""Assessment state machine + job orchestration.

  request -> intent -> scope validation -> plan (awaiting approval) -> approved scans run
  -> ingest -> correlate -> prioritise -> re-plan (adaptive) -> ... -> review -> report

State is persisted to data/assessments/<id>/state.json after every change, raw tool outputs
to data/assessments/<id>/raw/, and every decision to the hash-chained audit.jsonl."""
from __future__ import annotations

import json
import threading
import time
import traceback
from dataclasses import asdict
from pathlib import Path

from . import config
from .adapters import ADAPTERS
from .adapters.base import RunContext, ToolError, ToolTimeout, ToolUnavailable
from .audit import AuditLog
from .correlate import correlate
from .intent import parse_request
from .llm import llm
from .models import Action, Evidence, Job, RawFinding, new_id, now_iso
from .planner import anticipated_steps, initial_plan, next_actions
from .risk import prioritize
from .scope import ScopeGuard


def _rf_from_dict(d: dict) -> RawFinding:
    d = dict(d)
    ev = d.pop("evidence", None)
    rf = RawFinding(**d)
    rf.evidence = Evidence(**ev) if ev else None
    return rf


class Assessment:
    def __init__(self, aid: str, scope: ScopeGuard):
        self.id = aid
        self.dir = config.DATA_DIR / "assessments" / aid
        self.raw_dir = self.dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.audit = AuditLog(self.dir / "audit.jsonl")
        self.scope = scope
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.state: dict = {}
        self._thread = None

    # ---------------------------------------------------------------- persistence
    def save(self):
        with self.lock:
            tmp = self.dir / "state.json.tmp"
            tmp.write_text(json.dumps(self.state, indent=1, default=str))
            tmp.replace(self.dir / "state.json")

    @classmethod
    def load(cls, aid: str, scope: ScopeGuard) -> "Assessment":
        a = cls(aid, scope)
        a.state = json.loads((a.dir / "state.json").read_text())
        for j in a.state["jobs"]:          # jobs interrupted by a restart are not silently lost
            if j["status"] in ("running", "queued"):
                j["status"], j["error"] = "failed", "interrupted by agent restart"
        return a

    # ---------------------------------------------------------------- helpers
    def msg(self, role: str, text: str, **extra):
        self.state["messages"].append({"ts": now_iso(), "role": role, "text": text, **extra})

    def decide(self, dtype: str, text: str, refs=None):
        d = {"ts": now_iso(), "type": dtype, "text": text, "refs": refs or []}
        self.state["decisions"].append(d)
        self.audit.record(f"decision.{dtype}", "agent", {"text": text, "refs": refs or []})

    def action(self, aid) -> dict:
        return next(a for a in self.state["actions"] if a["id"] == aid)

    def _keys(self) -> set:
        return {a["key"] for a in self.state["actions"]}

    # ---------------------------------------------------------------- lifecycle
    @classmethod
    def create(cls, request: str, analyst: str, scope: ScopeGuard) -> "Assessment":
        a = cls(new_id("ASM"), scope)
        a.state = {
            "id": a.id, "created_at": now_iso(), "analyst": analyst, "request": request,
            "status": "planning", "llm": llm.describe(), "scope": scope.scope,
            "intent": {}, "actions": [], "jobs": [], "hosts": {}, "raw_findings": [], "findings": [],
            "overrides": {}, "validations": {}, "messages": [], "decisions": [], "approvals": [],
            "rejected_targets": [], "anticipated": [], "reports": [], "finished_at": None,
        }
        a.audit.record("assessment.created", f"analyst:{analyst}", {"request": request,
                       "authorization_ref": scope.scope.get("authorization_ref"), "llm": llm.describe()})
        a.msg("analyst", request)
        intent = parse_request(request, scope)
        a.state["intent"] = intent
        a.audit.record("intent.parsed", "agent", intent)
        acts, rejected = initial_plan(intent, scope, a.state["decisions"])
        for r in rejected:
            a.audit.record("scope.denied", "agent", r)
        for act in acts:
            a.audit.record("scope.allowed", "agent", {"target": act.target, "tool": act.tool})
        a.state["rejected_targets"] = rejected
        a.state["anticipated"] = anticipated_steps(intent)
        for act in acts:
            a.state["actions"].append(act.to_dict())
            a.audit.record("plan.proposed", "agent", {"action": act.id, "tool": act.tool, "target": act.target,
                                                      "rationale": act.rationale})
        lines = [f"Understood ({intent['parser']}): focus={'+'.join(intent['focus'])}, intensity={intent['intensity']}"
                 + (", NON-INTRUSIVE only" if intent["no_intrusive"] else "") + "."]
        if rejected:
            lines.append("REJECTED (out of scope): " + "; ".join(f"{r['target']} -> {r['reason']}" for r in rejected))
        if not intent["targets"]:
            lines.append("I could not find a target in your request. Name an IP, CIDR, hostname or URL from the registered scope.")
        if acts:
            lines.append(f"Proposed plan: {len(acts)} reconnaissance action(s). Review the rationale and click "
                         "'Approve plan' to start. Follow-up tools will be chosen from what recon actually finds.")
            a.state["status"] = "awaiting_plan_approval"
        else:
            a.state["status"] = "rejected" if intent["targets"] else "needs_input"
        a.msg("agent", "\n".join(lines))
        a.save()
        return a

    def approve_plan(self, analyst: str):
        with self.lock:
            n = 0
            for act in self.state["actions"]:
                if act["status"] == "proposed" and not act["requires_approval"]:
                    act["status"], act["decided_by"] = "approved", f"analyst:{analyst}"
                    n += 1
            self.state["plan_approved_by"] = analyst
            self.state["status"] = "running"
            self.state["approvals"].append({"ts": now_iso(), "type": "plan", "by": analyst, "decision": "approved",
                                            "detail": f"{n} non-intrusive action(s); follow-up non-intrusive scans "
                                                      f"{'auto-approved within scope' if config.AUTO_APPROVE_FOLLOWUPS else 'need approval'}"})
            self.audit.record("approval.plan", f"analyst:{analyst}", {"approved_actions": n})
            self.msg("agent", f"Plan approved by {analyst}. Executing {n} action(s).")
            self.save()
        self.start()

    def decide_action(self, action_id: str, decision: str, analyst: str, reason: str = ""):
        with self.lock:
            act = self.action(action_id)
            if act["status"] != "proposed":
                raise ValueError(f"action is {act['status']}, not awaiting a decision")
            act["status"] = "approved" if decision == "approve" else "rejected"
            act["decided_by"] = f"analyst:{analyst}"
            rec = {"ts": now_iso(), "type": "action", "action_id": action_id, "tool": act["tool"], "target": act["target"],
                   "params": act["params"], "by": analyst, "decision": act["status"], "reason": reason,
                   "intrusive": act["intrusive"]}
            self.state["approvals"].append(rec)
            self.audit.record(f"approval.{act['status']}", f"analyst:{analyst}", rec)
            self.msg("agent", f"{act['tool']} on {act['target']} {act['status']} by {analyst}" + (f" ({reason})" if reason else ""))
            if self.state["status"] in ("awaiting_review", "complete"):
                self.state["status"] = "running"
            self.save()
        self.start()

    def triage(self, finding_id: str, status: str, analyst: str, reason: str):
        with self.lock:
            f = next(f for f in self.state["findings"] if f["id"] == finding_id)
            self.state["overrides"][f["identity"]] = {"status": status, "by": analyst, "reason": reason, "ts": now_iso()}
            self.audit.record("finding.triaged", f"analyst:{analyst}", {"finding": finding_id, "status": status, "reason": reason})
            self._recorrelate()
            self.save()

    def request_validation(self, finding_id: str, analyst: str):
        from .knowledge import MSF_VALIDATION
        with self.lock:
            f = next(f for f in self.state["findings"] if f["id"] == finding_id)
            module = next((MSF_VALIDATION[c] for c in f["cves"] if c in MSF_VALIDATION), None) or MSF_VALIDATION.get(f["category"])
            if not module:
                raise ValueError("no non-destructive validation module is mapped for this finding; validate manually in Burp")
            aff = f["affected"][0]
            act = Action(tool="metasploit", target=aff["asset"], phase="validation", intrusive=True, requires_approval=True,
                         params={"module": module, "rhost": aff["asset"], "rport": aff.get("port"), "finding_id": f["id"],
                                 "identity": f["identity"]},
                         rationale=f"Analyst {analyst} requested validation of {f['id']} with {module}.")
            if act.key() in self._keys():
                raise ValueError("this validation was already proposed")
            self.state["actions"].append(act.to_dict())
            self.audit.record("plan.proposed", f"analyst:{analyst}", {"action": act.id, "tool": "metasploit", "module": module})
            self.save()
            return act.id

    # ---------------------------------------------------------------- imports
    def import_file(self, tool: str, filename: str, content: bytes, analyst: str) -> dict:
        adapter = ADAPTERS.get(tool)
        if not adapter or not adapter.supports_import:
            raise ValueError(f"no import parser for {tool}")
        with self.lock:
            act = Action(tool=tool, target=filename, params={"import": filename}, phase="import",
                         rationale=f"Analyst {analyst} supplied a recorded {tool} export; imported (not executed live).",
                         status="done", decided_by=f"analyst:{analyst}")
            self.state["actions"].append(act.to_dict())
            job = Job(action_id=act.id, tool=tool, target=filename, mode="import", status="running", started_at=now_iso(),
                      command=f"import {filename}")
            ctx = RunContext(job.id, self.raw_dir, self.dir, self.scope, mode="import")
            raw_ref, sha = ctx.save_raw(Path(filename).name, content)
            try:
                res = adapter.parse(content, ctx, raw_ref, sha)
            except Exception as e:
                job.status, job.error, job.finished_at = "failed", f"parse error: {e}", now_iso()
                self.state["jobs"].append(job.to_dict())
                self.audit.record("import.failed", f"analyst:{analyst}", {"tool": tool, "file": filename, "error": str(e)})
                self.save()
                raise ValueError(f"could not parse {filename} as {tool}: {e}")
            job.raw_files = [raw_ref]
            kept, dropped = self._ingest(res, job)
            job.status, job.finished_at, job.findings_count = "succeeded", now_iso(), kept
            self.state["jobs"].append(job.to_dict())
            self.audit.record("import.ingested", f"analyst:{analyst}", {"tool": tool, "file": filename, "sha256": sha,
                                                                        "findings": kept, "out_of_scope_dropped": dropped})
            self.msg("agent", f"Imported {filename} as {tool.upper()} (import-only, not a live scan): {kept} finding(s)"
                     + (f"; {dropped} dropped because the asset is outside the registered scope." if dropped else "."))
            self._recorrelate()
            self._replan()
            self.save()
        self.start()
        return {"findings": kept, "dropped_out_of_scope": dropped}

    # ---------------------------------------------------------------- worker
    def start(self):
        if self._thread and self._thread.is_alive():
            self.wake.set()
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name=f"worker-{self.id}")
        self._thread.start()

    def _loop(self):
        try:
            while True:
                with self.lock:
                    nxt = next((a for a in self.state["actions"] if a["status"] == "approved"), None)
                    if nxt:
                        nxt["status"] = "running"
                        if self.state["status"] in ("awaiting_review", "complete"):
                            self.state["status"] = "running"
                        self.save()
                if not nxt:
                    with self.lock:
                        pending = [a for a in self.state["actions"] if a["status"] == "proposed"]
                        if self.state["status"] == "running":
                            self.state["status"] = "awaiting_review"
                            self.msg("agent", self._review_message(pending))
                            self.save()
                    return
                self._execute(nxt)
        except Exception as e:  # never die silently
            with self.lock:
                self.state["status"] = "error"
                self.msg("agent", f"Internal error: {e}")
                self.audit.record("agent.error", "system", {"error": str(e), "trace": traceback.format_exc()[-1500:]})
                self.save()

    def _review_message(self, pending):
        fs = self.state["findings"]
        counts = {}
        for f in fs:
            if f["status"] not in ("false_positive",):
                counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        failed = [j for j in self.state["jobs"] if j["status"] in ("failed", "timeout", "unavailable")]
        order = ["critical", "high", "medium", "low", "info"]
        s = f"Scanning phase complete. {len(fs)} correlated finding(s)" + (
            ": " + ", ".join(f"{k}={counts[k]}" for k in order if k in counts) + "." if counts else ".")
        if failed:
            s += f" {len(failed)} job(s) did not complete (see Jobs; recorded as limitations)."
        if pending:
            s += f" {len(pending)} action(s) await your decision (validation / intrusive)."
        s += " Review findings, triage false positives, then generate the report."
        return s

    def _execute(self, act: dict):
        adapter = ADAPTERS[act["tool"]]
        job = Job(action_id=act["id"], tool=act["tool"], target=act["target"], status="running", started_at=now_iso())
        with self.lock:
            self.state["jobs"].append(job.to_dict())
            self.save()
        a_obj = Action(**{k: v for k, v in act.items() if k != "key"})
        a_obj.status = "approved"

        def upd(**kw):
            with self.lock:
                j = next(j for j in self.state["jobs"] if j["id"] == job.id)
                j.update(kw)
                self.save()

        # scope re-check at execution time (scope file could have changed; defence in depth)
        dec = self.scope.check(act["target"], tool=act["tool"])
        if not dec.allowed:
            upd(status="blocked", error=dec.reason, finished_at=now_iso())
            with self.lock:
                act["status"] = "blocked"
            self.audit.record("scope.denied", "agent", {"action": act["id"], "target": act["target"], "reason": dec.reason})
            return
        self.audit.record("job.started", "agent", {"job": job.id, "action": act["id"], "tool": act["tool"], "target": act["target"]})
        ctx = RunContext(job.id, self.raw_dir, self.dir, self.scope, timeout=config.DEFAULT_JOB_TIMEOUT)
        res, err, status = None, None, "succeeded"
        for attempt in (1, 2):
            upd(attempts=attempt)
            try:
                res = adapter.run(a_obj, ctx)
                status, err = "succeeded", None
                break
            except ToolUnavailable as e:
                status, err = "unavailable", str(e)
                break
            except ToolTimeout as e:
                status, err = "timeout", str(e)
                break
            except ToolError as e:
                status, err = "failed", str(e)
                if "BLOCKED" in str(e):
                    status = "blocked"
                    break
                if attempt == 1:
                    ctx.note(f"attempt 1 failed ({e}); retrying once in 5s")
                    time.sleep(5)
            except Exception as e:
                status, err = "failed", f"{type(e).__name__}: {e}"
                break
        with self.lock:
            j = next(j for j in self.state["jobs"] if j["id"] == job.id)
            j.update(status=status, error=err, finished_at=now_iso(), log=ctx.log[-30:])
            if res:
                j["command"] = res.command
                j["raw_files"] = [r for r, _ in res.raw_files]
                kept, dropped = self._ingest(res, Job(**{k: v for k, v in j.items() if k != "log"}))
                j["findings_count"] = kept
                if res.validation:
                    self._record_validation(res.validation, act)
            act["status"] = "done" if status == "succeeded" else "failed"
            self.audit.record("job.finished", "agent", {"job": job.id, "status": status, "error": err,
                                                        "command": res.command if res else None,
                                                        "raw": [r for r, _ in res.raw_files] if res else []})
            if status != "succeeded":
                self.decide("failure", f"{act['tool']} on {act['target']} -> {status}: {err}. "
                            + self._fallback_note(act["tool"]), [job.id])
            self._recorrelate()
            self._replan()
            self.save()

    @staticmethod
    def _fallback_note(tool):
        return {"zap": "Web application coverage now relies on Nikto (+ any Burp import); gap recorded as a limitation.",
                "nikto": "Web server coverage now relies on ZAP; gap recorded as a limitation.",
                "nmap": "Without Nmap the service inventory is incomplete; imported scanner results are still correlated.",
                "metasploit": "Finding stays 'suspected'; analyst may validate manually."}.get(tool, "Recorded as a limitation.")

    def _ingest(self, res, job) -> tuple[int, int]:
        kept = dropped = 0
        for h in res.hosts:
            dec = self.scope.check(h.address)
            if not dec.allowed:
                dropped += 1
                continue
            cur = self.state["hosts"].get(h.address)
            if not cur:
                cur = {"address": h.address, "hostnames": [], "os_guess": None, "services": [], "sources": [],
                       "discovered_only": True}
                self.state["hosts"][h.address] = cur
            cur["hostnames"] = sorted(set(cur["hostnames"]) | set(h.hostnames))
            cur["os_guess"] = h.os_guess or cur["os_guess"]
            cur["sources"].append(job.id)
            if h.services:
                cur["discovered_only"] = False
                svc = {(s["port"], s["proto"]): s for s in cur["services"]}
                for s in h.services:
                    svc[(s["port"], s["proto"])] = {**svc.get((s["port"], s["proto"]), {}), **{k: v for k, v in s.items() if v}}
                cur["services"] = sorted(svc.values(), key=lambda s: s["port"])
            elif job.tool == "nmap" and job.mode == "live":
                pass
        for rf in res.findings:
            dec = self.scope.check(rf.asset) if rf.asset else None
            if not dec or not dec.allowed:
                dropped += 1
                continue
            d = asdict(rf)
            self.state["raw_findings"].append(d)
            kept += 1
        return kept, dropped

    def _record_validation(self, v: dict, act: dict):
        ident = act["params"].get("identity")
        v["ts"] = now_iso()
        self.state["validations"].setdefault(ident, []).append(v)
        self.audit.record("validation.outcome", "agent", v)
        self.msg("agent", f"Validation of {v['finding_id']} with {v['module']} ({v['method']}): {v['outcome'].upper()}. "
                          f"Approved by {v['approved_by']}. Raw output: {v['raw_ref']}")

    def _recorrelate(self):
        raws = [_rf_from_dict(d) for d in self.state["raw_findings"]]
        fs = correlate(raws, self.state["hosts"], self.scope, self.state["overrides"], self.state["validations"])
        fs = prioritize(fs, self.scope)
        before = len(self.state["raw_findings"])
        self.state["findings"] = [f.to_dict() for f in fs]
        multi = sum(1 for f in fs if len(f.source_tools) > 1)
        self.state["correlation_stats"] = {"raw": before, "correlated": len(fs), "multi_tool": multi,
                                           "merged_duplicates": before - len(fs)}

    def _replan(self):
        if len(self.state["actions"]) >= config.MAX_ACTIONS_PER_ASSESSMENT:
            self.decide("budget", f"Action budget ({config.MAX_ACTIONS_PER_ASSESSMENT}) reached; no further actions planned.")
            return
        fresh, decisions = next_actions(self.state, self.scope, self._keys())
        for d in decisions:
            self.decide(d["type"], d["text"], d.get("refs"))
        for a in fresh:
            if a.status == "skipped":
                self.state["actions"].append(a.to_dict())
                self.audit.record("plan.skipped", "agent", {"action": a.id, "tool": a.tool, "target": a.target,
                                                            "rationale": a.rationale})
                continue
            auto = (config.AUTO_APPROVE_FOLLOWUPS and not a.requires_approval and not a.intrusive
                    and self.state.get("plan_approved_by"))
            if auto:
                a.status, a.decided_by = "approved", f"policy:auto (plan approved by {self.state['plan_approved_by']})"
            self.state["actions"].append(a.to_dict())
            self.audit.record("plan.proposed", "agent", {"action": a.id, "tool": a.tool, "target": a.target,
                                                         "params": a.params, "auto_approved": bool(auto),
                                                         "rationale": a.rationale, "source": a.reasoning_source})
            self.decide("next-step", f"{'Queued' if auto else 'Proposed (needs approval)'}: {a.tool} -> {a.target}. {a.rationale}",
                        a.triggered_by)

    # ---------------------------------------------------------------- Q&A
    def answer(self, text: str, analyst: str) -> str:
        self.msg("analyst", text)
        low = text.lower().strip()
        reply = None
        if llm.enabled:
            ctx = {
                "status": self.state["status"], "intent": self.state["intent"],
                "hosts": {ip: [f"{s['port']}/{s.get('name')} {s.get('product') or ''}" for s in h["services"] if s.get("state") == "open"]
                          for ip, h in self.state["hosts"].items()},
                "actions": [{k: a[k] for k in ("id", "tool", "target", "status", "rationale")} for a in self.state["actions"]],
                "jobs": [{k: j.get(k) for k in ("id", "tool", "status", "error")} for j in self.state["jobs"]],
                "findings": [{k: f[k] for k in ("id", "title", "severity", "risk_score", "priority", "confidence", "status",
                                                "source_tools", "cves", "confidence_factors")} for f in self.state["findings"][:25]],
                "decisions": self.state["decisions"][-15:],
            }
            out = llm.chat("You are an authorized penetration-testing assistant. Answer ONLY from the assessment state JSON. "
                           "Separate 'Observed evidence:' from 'Inference:'. If the state does not contain the answer, say so. "
                           "Never invent CVEs, scores or results. You cannot run tools; tell the analyst which button/approval to use.",
                           json.dumps(ctx, default=str)[:14000] + "\n\nAnalyst question: " + text, 700)
            if out:
                from .llm import ground_text
                allowed = {c for f in self.state["findings"] for c in f["cves"]}
                out, removed = ground_text(out, allowed)
                reply = "[AI inference, grounded on assessment state]\n" + out
        if not reply:
            reply = self._rule_answer(low)
        self.msg("agent", reply)
        self.audit.record("chat", f"analyst:{analyst}", {"q": text[:300]})
        self.save()
        return reply

    def _rule_answer(self, low: str) -> str:
        if "why" in low:
            for a in self.state["actions"]:
                if a["id"].lower() in low or a["tool"] in low:
                    return f"{a['tool']} on {a['target']} ({a['status']}): {a['rationale']}"
        for f in self.state["findings"]:
            if f["id"].lower() in low:
                return (f"{f['id']} {f['title']} [{f['severity']}, risk {f['risk_score']} {f['priority']}, "
                        f"confidence {f['confidence']}, {f['status']}]. Sources: {', '.join(f['source_tools'])}. "
                        f"Confidence factors: {'; '.join(f['confidence_factors'])}. Risk: {f['risk_breakdown'].get('formula')}")
        if "next" in low or "status" in low or "progress" in low:
            pend = [a for a in self.state["actions"] if a["status"] in ("proposed", "approved", "running")]
            return f"Status: {self.state['status']}. Open actions: " + ("; ".join(f"{a['tool']}->{a['target']} ({a['status']})" for a in pend) or "none")
        top = self.state["findings"][:5]
        return ("Top risks: " + "; ".join(f"{f['id']} {f['title']} ({f['priority']}, {f['risk_score']})" for f in top)) if top else \
            "No findings yet. Ask 'status', 'why nikto', or a finding id like F-ABC123. (Configure an LLM for free-form Q&A.)"


class Registry:
    def __init__(self):
        self.items: dict[str, Assessment] = {}
        self.scope = ScopeGuard.from_file(config.SCOPE_FILE)
        base = config.DATA_DIR / "assessments"
        base.mkdir(parents=True, exist_ok=True)
        for d in sorted(base.iterdir()):
            if (d / "state.json").exists():
                try:
                    self.items[d.name] = Assessment.load(d.name, self.scope)
                except Exception:
                    pass

    def reload_scope(self):
        self.scope = ScopeGuard.from_file(config.SCOPE_FILE)
        for a in self.items.values():
            a.scope = self.scope

    def create(self, request, analyst):
        a = Assessment.create(request, analyst, self.scope)
        self.items[a.id] = a
        return a

    def get(self, aid) -> Assessment:
        return self.items[aid]
