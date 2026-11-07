"""Static security knowledge used for normalization, correlation and reporting.

Nothing here invents vulnerabilities: these tables only *classify* findings that a tool
actually reported (so that e.g. ZAP's 'Missing Anti-clickjacking Header' and Nikto's
'X-Frame-Options header is not present' are recognised as the same issue)."""
import re

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Severity midpoints used ONLY when a tool gave a qualitative severity and no CVSS.
# Shown in the report as "severity-derived (no CVSS from tool)".
SEVERITY_BASE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}


def sev_from_cvss(score):
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def norm_sev(s) -> str:
    s = str(s or "").strip().lower()
    return {
        "4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info",
        "critical": "critical", "high": "high", "medium": "medium", "moderate": "medium",
        "low": "low", "information": "info", "informational": "info", "info": "info",
        "log": "info", "none": "info", "false positive": "info",
    }.get(s, "info")


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CWE_RE = re.compile(r"CWE-(\d+)", re.I)


def extract_cves(text: str) -> list[str]:
    return sorted({c.upper() for c in CVE_RE.findall(text or "")})


# ---------------------------------------------------------------------------
# Canonical categories: (category id, title, regex over tool title/description, cwe)
# Used to correlate the same issue across tools that do not share CVE ids.
CATEGORY_RULES = [
    ("HDR_XFO", "Missing anti-clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
     r"x-frame-options|clickjacking|anti-clickjacking|frame-ancestors", 1021),
    ("HDR_XCTO", "Missing X-Content-Type-Options header",
     r"x-content-type-options", 693),
    ("HDR_HSTS", "Missing HTTP Strict-Transport-Security header",
     r"strict-transport-security|\bhsts\b", 319),
    ("HDR_CSP", "Content Security Policy header not set",
     r"content security policy|content-security-policy|\bcsp\b header", 693),
    ("COOKIE_FLAGS", "Cookie set without HttpOnly / Secure / SameSite flags",
     r"cookie.*(httponly|secure flag|samesite)|(httponly|samesite).*cookie|created without the httponly", 1004),
    ("INFO_SERVER_BANNER", "Server software / version disclosure",
     r"server leaks version|retrieved from the .*server.* header|x-powered-by|server banner|version information|banner disclos", 200),
    ("DIR_LISTING", "Directory listing / indexing enabled",
     r"directory (listing|indexing|browsing)|index of /", 548),
    ("HTTP_METHODS", "Potentially dangerous HTTP methods enabled (TRACE/PUT/DELETE)",
     r"\btrace\b.*(enabled|allowed|active)|http trace|xst|allowed http methods|put method|delete method", 650),
    ("SQLI", "SQL injection", r"sql injection|sqli\b", 89),
    ("XSS", "Cross-site scripting (XSS)", r"cross[- ]site scripting|\bxss\b", 79),
    ("CSRF", "Absence of anti-CSRF tokens", r"anti-csrf|csrf", 352),
    ("PATH_TRAVERSAL", "Path traversal", r"path traversal|directory traversal", 22),
    ("CMD_INJECTION", "OS command injection", r"command injection|remote os command", 78),
    ("CORS", "Permissive CORS configuration", r"cross-domain misconfiguration|cors|access-control-allow-origin", 942),
    ("SENSITIVE_FILE", "Sensitive file or backup exposed",
     r"backup file|\.bak\b|\.git/|\.env\b|phpinfo|server-status|config(uration)? file .* (found|exposed)", 538),
    ("DEFAULT_CREDS", "Default or weak credentials", r"default (credential|password|account)|weak password|login succeeded", 1392),
    ("FTP_ANON", "Anonymous FTP login permitted", r"anonymous ftp|ftp-anon|anonymous login allowed", 284),
    ("TLS_WEAK", "Weak SSL/TLS protocol or cipher configuration",
     r"sslv2|sslv3|tlsv1\.0|tls 1\.0|weak cipher|rc4|export cipher|ssl-enum-ciphers|deprecated (tls|ssl)|ssl medium strength|ssl weak", 326),
    ("TLS_CERT", "SSL/TLS certificate problem (self-signed/expired/untrusted)",
     r"self[- ]signed|certificate (expired|cannot be trusted|untrusted)|ssl certificate", 295),
    ("SMB_SIGNING", "SMB signing not required", r"smb signing|message signing", 294),
    ("SMB_MS17_010", "SMBv1 remote code execution (MS17-010)", r"ms17-010|eternalblue", 20),
    ("OUTDATED_SW", "Outdated / unsupported software version",
     r"outdated|unsupported (version|web server)|end of life|is out of date|appears to be outdated|obsolete", 1104),
    ("INFO_DISCLOSURE", "Information disclosure", r"information disclosure|private ip disclosure|stack trace|debug error", 200),
]
_COMPILED = [(cid, title, re.compile(rx, re.I), cwe) for cid, title, rx, cwe in CATEGORY_RULES]


def categorize(title: str, description: str = "") -> tuple[str, str, int | None]:
    """Return (category_id, canonical_title, cwe) or ('OTHER', title, None).
    Title is matched first so that a long description does not dominate."""
    for text in (title or "", (description or "")[:400]):
        for cid, ctitle, rx, cwe in _COMPILED:
            if rx.search(text):
                return cid, ctitle, cwe
    return "OTHER", title, None


# ---------------------------------------------------------------------------
# CWE -> OWASP Top 10 (2021). Partial mapping for the CWEs this agent commonly sees.
CWE_OWASP = {
    22: "A01:2021 Broken Access Control", 284: "A01:2021 Broken Access Control",
    352: "A01:2021 Broken Access Control", 538: "A01:2021 Broken Access Control",
    548: "A01:2021 Broken Access Control", 942: "A05:2021 Security Misconfiguration",
    319: "A02:2021 Cryptographic Failures", 326: "A02:2021 Cryptographic Failures",
    327: "A02:2021 Cryptographic Failures", 295: "A07:2021 Identification and Authentication Failures",
    89: "A03:2021 Injection", 79: "A03:2021 Injection", 78: "A03:2021 Injection", 20: "A03:2021 Injection",
    693: "A05:2021 Security Misconfiguration", 1021: "A05:2021 Security Misconfiguration",
    1004: "A05:2021 Security Misconfiguration", 650: "A05:2021 Security Misconfiguration",
    200: "A05:2021 Security Misconfiguration", 16: "A05:2021 Security Misconfiguration",
    1104: "A06:2021 Vulnerable and Outdated Components", 937: "A06:2021 Vulnerable and Outdated Components",
    1392: "A07:2021 Identification and Authentication Failures", 287: "A07:2021 Identification and Authentication Failures",
    294: "A07:2021 Identification and Authentication Failures", 502: "A08:2021 Software and Data Integrity Failures",
    778: "A09:2021 Security Logging and Monitoring Failures", 918: "A10:2021 Server-Side Request Forgery",
}

# Category -> MITRE ATT&CK techniques an adversary could use against the weakness.
CATEGORY_ATTACK = {
    "SQLI": ["T1190 Exploit Public-Facing Application"],
    "XSS": ["T1189 Drive-by Compromise", "T1539 Steal Web Session Cookie"],
    "CMD_INJECTION": ["T1190 Exploit Public-Facing Application", "T1059 Command and Scripting Interpreter"],
    "PATH_TRAVERSAL": ["T1190 Exploit Public-Facing Application", "T1083 File and Directory Discovery"],
    "DEFAULT_CREDS": ["T1078.001 Valid Accounts: Default Accounts", "T1110 Brute Force"],
    "FTP_ANON": ["T1078 Valid Accounts", "T1005 Data from Local System"],
    "TLS_WEAK": ["T1557 Adversary-in-the-Middle"], "TLS_CERT": ["T1557 Adversary-in-the-Middle"],
    "HDR_HSTS": ["T1557 Adversary-in-the-Middle"],
    "COOKIE_FLAGS": ["T1539 Steal Web Session Cookie"],
    "SMB_SIGNING": ["T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay"],
    "SMB_MS17_010": ["T1210 Exploitation of Remote Services"],
    "OUTDATED_SW": ["T1190 Exploit Public-Facing Application", "T1210 Exploitation of Remote Services"],
    "SENSITIVE_FILE": ["T1083 File and Directory Discovery", "T1552.001 Credentials In Files"],
    "DIR_LISTING": ["T1083 File and Directory Discovery"],
    "INFO_SERVER_BANNER": ["T1592.002 Gather Victim Host Information: Software"],
    "INFO_DISCLOSURE": ["T1592 Gather Victim Host Information"],
}

# Remediation guidance per category (used when the tool gave none, and as a summary).
REMEDIATION = {
    "HDR_XFO": "Send 'Content-Security-Policy: frame-ancestors 'self'' (and/or 'X-Frame-Options: DENY|SAMEORIGIN') on all HTML responses.",
    "HDR_XCTO": "Send 'X-Content-Type-Options: nosniff' on all responses.",
    "HDR_HSTS": "Serve the site only over HTTPS and send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    "HDR_CSP": "Define a restrictive Content-Security-Policy (default-src 'self'; avoid 'unsafe-inline'/'unsafe-eval').",
    "COOKIE_FLAGS": "Set HttpOnly, Secure and SameSite=Lax/Strict on session and sensitive cookies.",
    "INFO_SERVER_BANNER": "Suppress version details in Server / X-Powered-By headers (e.g. Apache 'ServerTokens Prod', 'ServerSignature Off'; nginx 'server_tokens off').",
    "DIR_LISTING": "Disable automatic directory indexes (Apache 'Options -Indexes', nginx 'autoindex off').",
    "HTTP_METHODS": "Disable TRACE and any unused methods (PUT/DELETE) at the web server.",
    "SQLI": "Use parameterised queries / prepared statements everywhere; validate input; apply least privilege to the DB account.",
    "XSS": "Context-aware output encoding, input validation and a restrictive CSP.",
    "CSRF": "Use synchronizer tokens or SameSite cookies plus origin checks on state-changing requests.",
    "PATH_TRAVERSAL": "Canonicalise paths and enforce an allow-list of accessible files/directories.",
    "CMD_INJECTION": "Never pass user input to shell commands; use safe APIs with argument arrays and strict allow-lists.",
    "CORS": "Restrict Access-Control-Allow-Origin to trusted origins; never reflect arbitrary origins with credentials.",
    "SENSITIVE_FILE": "Remove backups, VCS folders, debug pages and configuration files from the web root; block them at the server.",
    "DEFAULT_CREDS": "Change all default credentials, enforce strong unique passwords and MFA where supported.",
    "FTP_ANON": "Disable anonymous FTP (vsftpd 'anonymous_enable=NO'); prefer SFTP.",
    "TLS_WEAK": "Allow only TLS 1.2/1.3 with modern AEAD cipher suites; disable SSLv2/3, TLS 1.0/1.1, RC4, 3DES and export ciphers.",
    "TLS_CERT": "Install a certificate from a trusted CA with correct hostname and validity.",
    "SMB_SIGNING": "Require SMB signing on servers and clients (GPO: 'Digitally sign communications (always)').",
    "SMB_MS17_010": "Apply MS17-010 updates and disable SMBv1.",
    "OUTDATED_SW": "Upgrade the component to a vendor-supported version and subscribe to its security advisories.",
    "INFO_DISCLOSURE": "Disable verbose errors and remove internal details from responses.",
}

# Curated *non-destructive* Metasploit validation mapping: category / CVE -> module.
# Only auxiliary scanners or exploit modules run with the `check` method are allowed.
MSF_VALIDATION = {
    "CVE-2017-0143": "auxiliary/scanner/smb/smb_ms17_010",
    "CVE-2017-0144": "auxiliary/scanner/smb/smb_ms17_010",
    "SMB_MS17_010": "auxiliary/scanner/smb/smb_ms17_010",
    "FTP_ANON": "auxiliary/scanner/ftp/anonymous",
    "CVE-2004-2687": "exploit/unix/misc/distcc_exec",           # check only
    "CVE-2014-0160": "auxiliary/scanner/ssl/openssl_heartbleed",  # run with ACTION=SCAN
    "TOMCAT_MGR": "auxiliary/scanner/http/tomcat_mgr_login",
}


def owasp_for(cwes) -> list[str]:
    return sorted({CWE_OWASP[c] for c in cwes if c in CWE_OWASP})


def references_for(cwes, cves) -> list[str]:
    refs = [f"https://cwe.mitre.org/data/definitions/{c}.html" for c in cwes]
    refs += [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves]
    return refs
