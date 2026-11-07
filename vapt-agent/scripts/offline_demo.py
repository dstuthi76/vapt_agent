"""Offline end-to-end demo that needs NO scanners and NO network.

It drives the real agent pipeline (intent -> scope -> plan -> approval -> jobs -> import ->
correlation -> risk -> approval gate -> report) using the SYNTHETIC parser fixtures in
tests/fixtures. Live jobs whose tools are not installed are recorded honestly as
'unavailable'. The generated PDF is watermarked SYNTHETIC TEST DATA.

    python scripts/offline_demo.py
"""
import os
import sys
import time
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("VAPT_DATA_DIR", str(Path(tempfile.gettempdir()) / "vapt-offline-demo"))

from vapt_agent.orchestrator import Registry  # noqa: E402
from vapt_agent.report import build_report, export_json  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


def wait(a, timeout=60):
    t = time.time()
    while time.time() - t < timeout:
        if a._thread is None or not a._thread.is_alive():
            return
        time.sleep(0.2)


def main():
    reg = Registry()
    a = reg.create("Run a full end-to-end network and web assessment of 172.28.10.0/24 and also 8.8.8.8", "demo-analyst")
    a.state["synthetic"] = True
    print("status:", a.state["status"])
    print("rejected:", a.state["rejected_targets"])
    a.approve_plan("demo-analyst")
    wait(a)
    for tool, fn in [("nmap", "nmap_lab.xml"), ("nikto", "nikto_dvwa.xml"), ("zap", "zap_dvwa.json"),
                     ("nessus", "nessus_lab.nessus"), ("openvas", "openvas_lab.xml"), ("burp", "burp_juice.xml")]:
        print(f"import {tool}:", a.import_file(tool, fn, (FIX / fn).read_bytes(), "demo-analyst"))
        wait(a)
    # live follow-ups that the planner queued will fail as 'unavailable' if tools are not installed
    wait(a, 120)
    # analyst triage of one finding
    csrf = next((f for f in a.state["findings"] if f["category"] == "CSRF"), None)
    if csrf:
        a.triage(csrf["id"], "false_positive", "demo-analyst", "DVWA CSRF page is intentionally token-less in low security mode; out of test objective")
    # approval gate: approve one validation, reject another
    pend = [x for x in a.state["actions"] if x["status"] == "proposed"]
    print("pending approvals:", [(p["tool"], p["params"].get("module"), p["target"]) for p in pend])
    for p in pend:
        ok = p["tool"] == "metasploit"
        a.decide_action(p["id"], "approve" if ok else "reject", "demo-analyst",
                        "lab-only, non-destructive check" if ok else "intrusive active scan not needed for this demo")
        wait(a)
    wait(a, 60)
    out = a.dir / "report.pdf"
    info = build_report(a.state, a.audit.verify(), out, synthetic=True)
    export_json(a.state, a.dir / "report.json")
    a.save()
    print(f"\nfindings: {len(a.state['findings'])}  stats: {a.state['correlation_stats']}")
    for f in a.state["findings"][:12]:
        print(f"  {f['priority']:4} {f['risk_score']:4} {f['severity']:8} conf={f['confidence']:<4} {f['status']:22} "
              f"{','.join(f['source_tools']):24} {f['title'][:60]}")
    print("jobs:", [(j["tool"], j["status"]) for j in a.state["jobs"]])
    print("audit:", a.audit.verify())
    print("report:", out)


if __name__ == "__main__":
    main()
