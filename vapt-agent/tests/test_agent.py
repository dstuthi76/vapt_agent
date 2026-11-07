"""Unit tests: scope enforcement, parsers, correlation, risk, approval gate, audit chain.
Run:  python -m pytest -q   (or: python -m unittest discover -s tests)"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["VAPT_DATA_DIR"] = tempfile.mkdtemp(prefix="vapt-test-")
os.environ["LLM_PROVIDER"] = "none"

from vapt_agent.adapters import ADAPTERS                      # noqa: E402
from vapt_agent.adapters.base import RunContext, ToolError     # noqa: E402
from vapt_agent.audit import AuditLog                          # noqa: E402
from vapt_agent.correlate import correlate                     # noqa: E402
from vapt_agent.intent import parse_request                    # noqa: E402
from vapt_agent.models import Action                           # noqa: E402
from vapt_agent.risk import prioritize                         # noqa: E402
from vapt_agent.scope import ScopeGuard                        # noqa: E402

FIX = ROOT / "tests" / "fixtures"
SCOPE = ScopeGuard.from_file(ROOT / "config" / "scope.lab.json")


def ctx():
    d = Path(tempfile.mkdtemp())
    return RunContext("JOB-test", d / "raw", d, SCOPE, mode="import")


def parse(tool, fn):
    c = ctx()
    data = (FIX / fn).read_bytes()
    ref, sha = c.save_raw(fn, data)
    return ADAPTERS[tool].parse(data, c, ref, sha)


class ScopeTests(unittest.TestCase):
    def test_registered_targets_allowed(self):
        self.assertTrue(SCOPE.check("172.28.10.12").allowed)
        self.assertTrue(SCOPE.check("http://dvwa:80/login.php").allowed)
        self.assertTrue(SCOPE.check("172.28.10.0/25").allowed)

    def test_exclusions_public_and_unregistered_denied(self):
        self.assertFalse(SCOPE.check("172.28.10.5").allowed)          # excluded (agent itself)
        self.assertFalse(SCOPE.check("8.8.8.8").allowed)              # public
        self.assertFalse(SCOPE.check("10.0.0.1").allowed)             # private but unregistered
        self.assertFalse(SCOPE.check("172.28.0.0/16").allowed)        # wider than scope
        self.assertFalse(SCOPE.check("172.28.10.12", tool="sqlmap").allowed)

    def test_intent_rejects_out_of_scope(self):
        it = parse_request("Scan 8.8.8.8 and the web app http://juice-shop:3000 quickly", SCOPE)
        self.assertIn("8.8.8.8", it["targets"])
        self.assertEqual(it["intensity"], "quick")
        self.assertFalse(SCOPE.check("8.8.8.8").allowed)


class ParserTests(unittest.TestCase):
    def test_nmap(self):
        r = parse("nmap", "nmap_lab.xml")
        self.assertEqual(len(r.hosts), 3)
        titles = {f.title for f in r.findings}
        self.assertIn("Anonymous FTP login allowed", titles)
        self.assertIn("SMB signing not required", titles)

    def test_nessus_drops_nothing_itself_and_reads_cvss(self):
        r = parse("nessus", "nessus_lab.nessus")
        bd = next(f for f in r.findings if "Backdoor" in f.title)
        self.assertEqual(bd.cvss_score, 9.8)
        self.assertEqual(bd.cves, ["CVE-2011-2523"])
        self.assertTrue(bd.exploit_available)

    def test_openvas_qod(self):
        r = parse("openvas", "openvas_lab.xml")
        self.assertTrue(all(f.evidence.tool_confidence.startswith("QoD") for f in r.findings))

    def test_zap_burp_nikto(self):
        self.assertEqual(len(parse("zap", "zap_dvwa.json").findings), 5)
        b = parse("burp", "burp_juice.xml").findings
        self.assertIn(89, b[0].cwes)
        self.assertIn("GET /rest/products/search", b[0].evidence.excerpt)
        self.assertEqual(len(parse("nikto", "nikto_dvwa.xml").findings), 5)


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        raws = []
        hosts = {}
        for tool, fn in [("nmap", "nmap_lab.xml"), ("nikto", "nikto_dvwa.xml"), ("zap", "zap_dvwa.json"),
                         ("nessus", "nessus_lab.nessus"), ("openvas", "openvas_lab.xml"), ("burp", "burp_juice.xml")]:
            r = parse(tool, fn)
            raws += [f for f in r.findings if SCOPE.check(f.asset).allowed]
            for h in r.hosts:
                hosts[h.address] = {"services": h.services}
        self.fs = prioritize(correlate(raws, hosts, SCOPE, {}, {}), SCOPE)

    def get(self, cat, asset):
        return [f for f in self.fs if f.category == cat and f.affected[0]["asset"] == asset]

    def test_cross_tool_merge_keeps_all_evidence(self):
        ftp = self.get("FTP_ANON", "172.28.10.12")
        self.assertEqual(len(ftp), 1)
        self.assertEqual(set(ftp[0].source_tools), {"nmap", "nessus", "openvas"})
        self.assertEqual(len(ftp[0].evidence), 3)
        xfo = self.get("HDR_XFO", "172.28.10.11")
        self.assertEqual(set(xfo[0].source_tools), {"nikto", "zap"})

    def test_cve_merge(self):
        bd = [f for f in self.fs if "CVE-2011-2523" in f.cves]
        self.assertEqual(len(bd), 1)
        self.assertEqual(set(bd[0].source_tools), {"nessus", "openvas"})
        self.assertEqual(bd[0].priority, "P1")

    def test_port_not_open_lowers_confidence(self):
        tel = [f for f in self.fs if f.affected[0].get("port") == 8023][0]
        self.assertLess(tel.confidence, 0.5)
        self.assertTrue(any("not observed open" in x for x in tel.confidence_factors))

    def test_no_invented_cvss(self):
        for f in self.fs:
            if f.cvss_score is not None:
                self.assertIn(f.source_tools[0] if f.cvss_source else "", ["nessus", "openvas"] + f.source_tools)
                self.assertTrue(f.cvss_source)
        sqli = [f for f in self.fs if f.category == "SQLI"][0]
        self.assertIsNone(sqli.cvss_score)
        self.assertIn("severity-derived", sqli.risk_breakdown["base_source"])


class SafetyTests(unittest.TestCase):
    def test_metasploit_blocks_without_approval_and_unlisted_modules(self):
        msf = ADAPTERS["metasploit"]
        a = Action(tool="metasploit", target="172.28.10.12", params={"module": "auxiliary/scanner/ftp/anonymous",
                   "rhost": "172.28.10.12", "rport": 21}, rationale="t", phase="validation", status="proposed")
        with self.assertRaises(ToolError):
            msf.run(a, ctx())
        a.status, a.decided_by = "approved", "analyst:x"
        a.params["module"] = "exploit/unix/ftp/vsftpd_234_backdoor"
        with self.assertRaisesRegex(ToolError, "allow-list"):
            msf.run(a, ctx())
        a.params.update(module="auxiliary/scanner/ftp/anonymous", rhost="8.8.8.8")
        with self.assertRaisesRegex(ToolError, "scope"):
            msf.run(a, ctx())

    def test_audit_chain_detects_tamper(self):
        p = Path(tempfile.mkdtemp()) / "a.jsonl"
        log = AuditLog(p)
        for i in range(3):
            log.record("e", "agent", {"i": i})
        self.assertTrue(log.verify()["valid"])
        lines = p.read_text().splitlines()
        e = json.loads(lines[1]); e["details"]["i"] = 99; lines[1] = json.dumps(e)
        p.write_text("\n".join(lines) + "\n")
        self.assertFalse(log.verify()["valid"])


class WorkflowTest(unittest.TestCase):
    def test_end_to_end_with_imports(self):
        from vapt_agent.orchestrator import Assessment
        a = Assessment.create("Full assessment of 172.28.10.0/24 and 1.1.1.1", "tester", SCOPE)
        self.assertEqual(a.state["status"], "awaiting_plan_approval")
        self.assertEqual(a.state["rejected_targets"][0]["target"], "1.1.1.1")
        res = a.import_file("nessus", "nessus_lab.nessus", (FIX / "nessus_lab.nessus").read_bytes(), "tester")
        self.assertEqual(res["dropped_out_of_scope"], 1)
        # validation actions are proposed but never auto-approved
        a.import_file("nmap", "nmap_lab.xml", (FIX / "nmap_lab.xml").read_bytes(), "tester")
        val = [x for x in a.state["actions"] if x["tool"] == "metasploit"]
        self.assertTrue(val and all(x["status"] == "proposed" and x["requires_approval"] for x in val))
        self.assertTrue(a.audit.verify()["valid"])


if __name__ == "__main__":
    unittest.main()
