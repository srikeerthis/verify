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

# --- agent (agent.py) ---------------------------------------------------
ANTHROPIC_API_KEY = _get("ANTHROPIC_API_KEY")
AGENT_MODEL = _get("AGENT_MODEL", "claude-sonnet-5")

# --- terac (escalate.py) ------------------------------------------------
TERAC_API_KEY = _get("TERAC_API_KEY")
TERAC_MCP_URL = _get("TERAC_MCP_URL")

# --- stripe (pay.py) ----------------------------------------------------
STRIPE_SECRET_KEY = _get("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = _get("STRIPE_PRICE_ID")


def is_configured(*keys: str) -> bool:
    """True when every named setting has a non-empty value.

    Lets a leaf module no-op cleanly instead of half-running:
        if not config.is_configured("LINQ_API_KEY", "LINQ_API_BASE"): ...
    """
    return all(globals().get(k) for k in keys)
