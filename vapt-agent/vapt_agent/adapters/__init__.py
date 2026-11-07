from .nmap import NmapAdapter
from .nikto import NiktoAdapter
from .zap import ZapAdapter
from .imports import NessusAdapter, OpenVASAdapter, BurpAdapter
from .metasploit import MetasploitAdapter

ADAPTERS = {a.name: a for a in (NmapAdapter(), NiktoAdapter(), ZapAdapter(), NessusAdapter(),
                                OpenVASAdapter(), BurpAdapter(), MetasploitAdapter())}

# Truthful integration matrix (also rendered in the UI and the report appendix).
INTEGRATION_MATRIX = [
    {"tool": "Nmap", "key": "nmap", "status": "Live + Import",
     "how": "CLI subprocess, XML (-oX) parsing; safe NSE scripts only", "limits": "No OS detection by default; UDP not scanned."},
    {"tool": "Nikto", "key": "nikto", "status": "Live + Import",
     "how": "CLI subprocess, XML output; DoS tuning excluded (-Tuning x6)", "limits": "Nikto does not rate severity: agent classifies and labels it."},
    {"tool": "OWASP ZAP", "key": "zap", "status": "Live + Import",
     "how": "ZAP REST API (daemon): spider + passive; active scan only after explicit approval", "limits": "No authenticated scanning contexts configured."},
    {"tool": "OpenVAS / Greenbone", "key": "openvas", "status": "Import (Live: experimental)",
     "how": "Greenbone XML report import; optional python-gvm live mode", "limits": "Live mode untested outside a GVM container; import is the supported path."},
    {"tool": "Nessus", "key": "nessus", "status": "Import-only",
     "how": ".nessus v2 export import", "limits": "Nessus Essentials/Pro do not permit API scan launch; we do not claim live scans."},
    {"tool": "Burp Suite", "key": "burp", "status": "Import-only (Pro REST API: Planned)",
     "how": "Burp 'Report issues' XML export import", "limits": "Community edition has no API; analyst-driven testing stays in Burp."},
    {"tool": "Metasploit", "key": "metasploit", "status": "Live (approval-gated, check/scanner only)",
     "how": "msfrpcd RPC or msfconsole; curated non-destructive modules; `check` for exploit modules", "limits": "Never runs payloads or autonomous exploitation."},
]
