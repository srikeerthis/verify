"""Single source of config. Every module reads settings from here, never from
os.environ directly.

Loads .env from the repo root if present. Real environment variables always win,
so Render's dashboard config overrides whatever is in a local .env file.

No dependency on python-dotenv — the parser below is fifteen lines and this repo
has enough moving parts already.
"""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_env(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        os.environ.setdefault(key, value)  # real env wins


_load_env(ROOT / ".env")


def _get(key: str, default: str = "") -> str:
    """An empty value falls back to the default — a bare `DB_PATH=` in .env
    means "unset", not "the empty string"."""
    return os.environ.get(key, "").strip() or default


# --- core ---------------------------------------------------------------
PUBLIC_BASE_URL = _get("PUBLIC_BASE_URL", "http://localhost:8000")
DB_PATH = Path(_get("DB_PATH", str(ROOT / "verify.db")))
TEMPLATE_DIR = ROOT / "templates"

# --- linq (notify.py) ---------------------------------------------------
LINQ_API_KEY = _get("LINQ_API_KEY")
LINQ_API_BASE = _get("LINQ_API_BASE", "https://api.linqapp.com/api/partner/v3")
# Optional: Linq picks the best sender line when this is empty.
LINQ_SENDER_ID = _get("LINQ_SENDER_ID")
# whsec_... — handed back when the webhook subscription is created. Without it
# inbound webhooks are rejected rather than trusted.
LINQ_WEBHOOK_SECRET = _get("LINQ_WEBHOOK_SECRET")

# --- test handsets ---
# Used by scripts to drive a live test. Nothing in the request path reads these;
# real recipients always come from the packages row.
TEST_COMPANY_PHONE = _get("TEST_COMPANY_PHONE")
TEST_CANDIDATE_PHONE = _get("TEST_CANDIDATE_PHONE")

# --- agent (agent.py) ---------------------------------------------------
ANTHROPIC_API_KEY = _get("ANTHROPIC_API_KEY")
AGENT_MODEL = _get("AGENT_MODEL", "claude-sonnet-5")

# --- terac (escalate.py) ------------------------------------------------
TERAC_API_KEY = _get("TERAC_API_KEY")
TERAC_MCP_URL = _get("TERAC_MCP_URL")

# --- scan service (scan_client.py) ---------------------------------------
# The Node service that replaces ingest/static_scan/agent/escalate: real
# OSV.dev CVE checks, secret/typosquat static scan, GPT verdict, Superserve
# sandbox execution, and Terac human escalation on an ambiguous verdict.
SCAN_SERVICE_URL = _get("SCAN_SERVICE_URL", "http://localhost:3000")
SCAN_TIMEOUT_SECONDS = int(_get("SCAN_TIMEOUT_SECONDS", "300"))

# --- stripe (pay.py) ----------------------------------------------------
STRIPE_SECRET_KEY = _get("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = _get("STRIPE_PRICE_ID")


def is_configured(*keys: str) -> bool:
    """True when every named setting has a non-empty value.

    Lets a leaf module no-op cleanly instead of half-running:
        if not config.is_configured("LINQ_API_KEY", "LINQ_API_BASE"): ...
    """
    return all(globals().get(k) for k in keys)
