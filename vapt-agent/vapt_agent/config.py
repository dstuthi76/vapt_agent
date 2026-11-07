"""Runtime configuration, read from environment variables (see .env.example)."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Minimal .env loader (no extra dependency). Real environment variables win.
_env = BASE_DIR / ".env"
if _env.exists():
    for _line in _env.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            if _v.strip():
                os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))
DATA_DIR = Path(os.getenv("VAPT_DATA_DIR", BASE_DIR / "data"))
SCOPE_FILE = Path(os.getenv("VAPT_SCOPE_FILE", BASE_DIR / "config" / "scope.lab.json"))
if not SCOPE_FILE.is_absolute():
    SCOPE_FILE = BASE_DIR / SCOPE_FILE

# --- LLM -------------------------------------------------------------------
# none | anthropic | openai | ollama
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none").lower()
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "60"))

# --- Tools -------------------------------------------------------------------
NMAP_BIN = os.getenv("NMAP_BIN", "nmap")
NIKTO_BIN = os.getenv("NIKTO_BIN", "nikto")
MSFCONSOLE_BIN = os.getenv("MSFCONSOLE_BIN", "msfconsole")
ZAP_URL = os.getenv("ZAP_URL", "http://localhost:8090")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
MSF_RPC_HOST = os.getenv("MSF_RPC_HOST", "")          # e.g. msf (docker) or 127.0.0.1
MSF_RPC_PORT = int(os.getenv("MSF_RPC_PORT", "55553"))
MSF_RPC_USER = os.getenv("MSF_RPC_USER", "msf")
MSF_RPC_PASS = os.getenv("MSF_RPC_PASS", "")
MSF_RPC_SSL = os.getenv("MSF_RPC_SSL", "false").lower() == "true"
GVM_SOCKET = os.getenv("GVM_SOCKET", "")              # optional live OpenVAS (python-gvm)
GVM_USER = os.getenv("GVM_USER", "admin")
GVM_PASS = os.getenv("GVM_PASS", "")

# --- Behaviour ---------------------------------------------------------------
DEFAULT_JOB_TIMEOUT = int(os.getenv("VAPT_JOB_TIMEOUT", "900"))
# Follow-up *non-intrusive* scans inside an approved plan run without a new click.
# Intrusive scans and all validation actions ALWAYS need explicit approval.
AUTO_APPROVE_FOLLOWUPS = os.getenv("VAPT_AUTO_APPROVE_FOLLOWUPS", "true").lower() == "true"
MAX_ACTIONS_PER_ASSESSMENT = int(os.getenv("VAPT_MAX_ACTIONS", "40"))

DATA_DIR.mkdir(parents=True, exist_ok=True)
