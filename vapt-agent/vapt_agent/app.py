"""Flask web server: REST API + single-page analyst console."""
from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file, send_from_directory

from . import config
from .adapters import ADAPTERS, INTEGRATION_MATRIX
from .llm import llm
from .orchestrator import Registry
from .report import build_report, export_json

STATIC = Path(__file__).parent / "static"
app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
REG = Registry()
API_TOKEN = os.getenv("VAPT_API_TOKEN", "")


@app.before_request
def _auth():
    if API_TOKEN and request.path.startswith("/api/") and request.headers.get("X-API-Token") != API_TOKEN:
        return jsonify({"error": "missing or invalid X-API-Token"}), 401


def body():
    return request.get_json(silent=True) or {}


def analyst():
    return (body().get("analyst") or request.form.get("analyst") or "analyst").strip()[:40]


def get_a(aid):
    try:
        return REG.get(aid)
    except KeyError:
        abort(404)


@app.errorhandler(ValueError)
def _ve(e):
    return jsonify({"error": str(e)}), 400


@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.get("/api/health")
def health():
    tools = {}
    for name, ad in ADAPTERS.items():
        ok, msg = ad.availability()
        tools[name] = {"available": ok, "detail": msg, "live": bool(ad.supports_live), "import": ad.supports_import}
    return jsonify({"llm": llm.describe(), "tools": tools, "matrix": INTEGRATION_MATRIX,
                    "auto_approve_followups": config.AUTO_APPROVE_FOLLOWUPS})


@app.get("/api/scope")
def scope_get():
    return jsonify(REG.scope.summary())


@app.post("/api/scope/reload")
def scope_reload():
    REG.reload_scope()
    return jsonify({"ok": True, "scope": REG.scope.summary()})


@app.post("/api/scope/check")
def scope_check():
    return jsonify(REG.scope.check(body().get("target", ""), tool=body().get("tool")).to_dict())


@app.get("/api/assessments")
def list_assessments():
    return jsonify([{"id": a.id, "created_at": a.state["created_at"], "request": a.state["request"],
                     "status": a.state["status"]} for a in sorted(REG.items.values(), key=lambda a: a.state["created_at"], reverse=True)])


@app.post("/api/assessments")
def create():
    req = (body().get("request") or "").strip()
    if not req:
        raise ValueError("request text is required")
    a = REG.create(req, analyst())
    return jsonify(a.state), 201


@app.get("/api/assessments/<aid>")
def get_state(aid):
    a = get_a(aid)
    with a.lock:
        s = dict(a.state)
    s["audit_verify"] = a.audit.verify()
    s["pending"] = [x for x in s["actions"] if x["status"] == "proposed"]
    return jsonify(s)


@app.post("/api/assessments/<aid>/plan/approve")
def approve_plan(aid):
    get_a(aid).approve_plan(analyst())
    return jsonify({"ok": True})


@app.post("/api/assessments/<aid>/actions/<act>/decision")
def decide(aid, act):
    d = body().get("decision")
    if d not in ("approve", "reject"):
        raise ValueError("decision must be approve or reject")
    get_a(aid).decide_action(act, d, analyst(), body().get("reason", ""))
    return jsonify({"ok": True})


@app.post("/api/assessments/<aid>/findings/<fid>/triage")
def triage(aid, fid):
    st = body().get("status")
    if st not in ("false_positive", "confirmed", "suspected"):
        raise ValueError("status must be false_positive | confirmed | suspected")
    reason = (body().get("reason") or "").strip()
    if not reason:
        raise ValueError("a reason is required for triage decisions")
    get_a(aid).triage(fid, st, analyst(), reason)
    return jsonify({"ok": True})


@app.post("/api/assessments/<aid>/findings/<fid>/validate")
def validate(aid, fid):
    return jsonify({"action_id": get_a(aid).request_validation(fid, analyst())})


@app.post("/api/assessments/<aid>/imports")
def do_import(aid):
    f = request.files.get("file")
    tool = request.form.get("tool", "")
    if not f:
        raise ValueError("file is required")
    return jsonify(get_a(aid).import_file(tool, f.filename, f.read(), analyst()))


@app.post("/api/assessments/<aid>/chat")
def chat(aid):
    return jsonify({"reply": get_a(aid).answer(body().get("text", ""), analyst())})


@app.post("/api/assessments/<aid>/report")
def report(aid):
    a = get_a(aid)
    with a.lock:
        state = dict(a.state)
    pdf = a.dir / "report.pdf"
    info = build_report(state, a.audit.verify(), pdf, synthetic=bool(state.get("synthetic")))
    export_json(state, a.dir / "report.json")
    with a.lock:
        a.state["reports"].append(info["generated_at"])
        if a.state["status"] in ("awaiting_review",):
            a.state["status"] = "complete"
        a.audit.record("report.generated", f"analyst:{analyst()}", {"findings": info["findings"]})
        a.msg("agent", f"Report generated ({info['findings']} findings, {info['informational']} informational).")
        a.save()
    return jsonify({"pdf": f"/api/assessments/{aid}/report.pdf", "json": f"/api/assessments/{aid}/report.json"})


@app.get("/api/assessments/<aid>/report.pdf")
def report_pdf(aid):
    p = get_a(aid).dir / "report.pdf"
    if not p.exists():
        abort(404)
    return send_file(p, as_attachment=True, download_name=f"VAPT_Report_{aid}.pdf")


@app.get("/api/assessments/<aid>/report.json")
def report_json(aid):
    p = get_a(aid).dir / "report.json"
    if not p.exists():
        abort(404)
    return send_file(p, as_attachment=True, download_name=f"VAPT_Report_{aid}.json")


@app.get("/api/assessments/<aid>/raw/<path:name>")
def raw(aid, name):
    a = get_a(aid)
    p = (a.dir / name).resolve()
    if not str(p).startswith(str(a.raw_dir.resolve())) or not p.exists():
        abort(404)
    return send_file(p, mimetype="text/plain")


@app.get("/api/assessments/<aid>/audit")
def audit(aid):
    a = get_a(aid)
    return jsonify({"verify": a.audit.verify(), "entries": a.audit.entries()})


def main():
    host = os.getenv("VAPT_HOST", "127.0.0.1")
    port = int(os.getenv("VAPT_PORT", "8080"))
    print(f"VAPT-Agent console: http://{host}:{port}   (LLM: {llm.describe()}, scope: {config.SCOPE_FILE})")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
