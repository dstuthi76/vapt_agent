# 10-minute judging demo script

Preparation (before the judges arrive):
```bash
docker compose --profile full --profile validation up -d --build
# .env: MSF_RPC_HOST=msf, LLM_PROVIDER=... (optional)
```
Open http://localhost:8080, enter your analyst name (top right), and keep the Nessus/OpenVAS/Burp exports you made of the lab ready.

| # | Checklist item | What to do / say |
|---|---|---|
| 1 | Authorized target + scope validation | Type `Scan 8.8.8.8 and 10.0.0.1` → both are rejected with reasons. Then type `Run a full end-to-end network and web assessment of the lab subnet 172.28.10.0/24`. In the Scope tab, test `172.28.10.5` → excluded (the agent itself). |
| 2 | Plan + reasoning | In Plan & Approvals, point out the discovery sweep rationale and the *anticipated adaptive steps*. Click **Approve plan**. |
| 3 | Multi-tool execution | Jobs tab: live nmap → nmap services → Nikto/ZAP queued *because* HTTP was found (Decisions tab shows the evidence reference). Open a raw XML link. Import a Nessus and an OpenVAS export in the Imports tab; the out-of-scope host is dropped. |
| 4 | Normalisation, correlation, FP, uncertainty | Findings tab: "N raw → M correlated". Open *Anonymous FTP login permitted*: three tools, three evidence items, confidence factors. Show a finding with "port not observed open by Nmap" and lowered confidence. Mark the DVWA CSRF finding as a false positive with a reason. |
| 5 | Risk + approval checkpoint | Show the risk formula on a P1. Under **⚠ Human approval required**, approve the `auxiliary/scanner/ftp/anonymous` validation and reject the ZAP active scan, giving reasons. The finding becomes **confirmed**; its risk rises because exploitability goes to 1.2. |
| 6 | Report + traceability | Report tab → Generate → open the PDF. Pick a finding in §4, read its `job / raw file / sha256`, then open the same raw file from the Jobs tab. |
| 7 | Safe failure + honest integrations | Run `docker stop vapt-zap`, then ask for `Assess http://dvwa:80`. The ZAP job is `unavailable`, the decision trace shows the fallback to Nikto, and the PDF §6.2 lists the failure. The Integrations tab shows Nessus/Burp as import-only. The Audit tab shows a valid hash chain. |
