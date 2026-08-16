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
UPLOAD_DIR = ROOT / "uploads"

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
# Any Anthropic-compatible /v1/messages gateway works: set ANTHROPIC_API_KEY
# + ANTHROPIC_API_URL (+ AGENT_MODEL) and the tool loop runs there. Default
# is Anthropic direct; .env points at Pioneer with DeepSeek-V4-Flash.
ANTHROPIC_API_KEY = _get("ANTHROPIC_API_KEY")
AGENT_MODEL = _get("AGENT_MODEL", "claude-sonnet-5")
ANTHROPIC_API_URL = _get("ANTHROPIC_API_URL", "https://api.anthropic.com/v1/messages")
ANTHROPIC_API_VERSION = _get("ANTHROPIC_API_VERSION", "2023-06-01")
# Tool-use loop knobs. Six turns is enough for verify_zip + one message.
AGENT_MAX_TOKENS = int(_get("AGENT_MAX_TOKENS", "1024"))
AGENT_MAX_TURNS = int(_get("AGENT_MAX_TURNS", "6"))
# How many prior SMS the agent sees as conversation history per run.
AGENT_HISTORY_TURNS = int(_get("AGENT_HISTORY_TURNS", "10"))

# --- terac (escalate.py) ------------------------------------------------
TERAC_API_KEY = _get("TERAC_API_KEY")
TERAC_MCP_URL = _get("TERAC_MCP_URL")
# Optional: reuse an existing Terac project instead of creating one on first
# escalation.
TERAC_PROJECT_ID = _get("TERAC_PROJECT_ID")

# --- scan (static_scan.py LLM review, agent.py judge) --------------------
# Deliberately separate from ANTHROPIC_API_KEY/AGENT_MODEL above, which are
# Vera's (the SMS coordination agent), so the two LLM roles never fight over
# one config var.
#
# Runs on DeepSeek through Pioneer's OpenAI-compatible endpoint. The reviewers
# read every file in a submission across three parallel agents, so this is by
# far the most token-hungry thing in the product, and DeepSeek-V4-Flash is a
# fraction of the price with a context window that fits a whole take-home.
# Point SCAN_API_URL at https://api.openai.com/v1 to go back to OpenAI.
SCAN_API_URL = _get("SCAN_API_URL", "https://api.pioneer.ai/v1")
SCAN_MODEL = _get("SCAN_MODEL", "deepseek-ai/DeepSeek-V4-Flash-0731")
# SCAN_API_KEY is the name to use; OPENAI_API_KEY still works so an existing
# .env keeps running.
SCAN_API_KEY = _get("SCAN_API_KEY") or _get("OPENAI_API_KEY")
OPENAI_API_KEY = SCAN_API_KEY  # legacy alias, referenced by older call sites

# --- superserve (sandbox_scan.py) ----------------------------------------
# The `superserve` Python SDK reads this from the environment itself; also
# exposed here so sandbox_scan.py can check it's set before creating a
# sandbox, rather than failing partway through a run.
SUPERSERVE_API_KEY = _get("SUPERSERVE_API_KEY")

# --- stripe (pay.py) ----------------------------------------------------
# Dynamic scanning is paid: the recruiter unlocks it per package through a
# Stripe Payment Link (hosted page — we never see a card). The secret key
# verifies payments server-side; no webhook is needed. Leave either empty and
# the front page shows the free static-only tier.
STRIPE_SECRET_KEY = _get("STRIPE_SECRET_KEY")
STRIPE_PAYMENT_LINK_URL = _get("STRIPE_PAYMENT_LINK_URL")

# --- webapp handoff (handoff.py) ----------------------------------------
# The Verify web app (zipsign/ in this repo): the human-friendly front end that
# serves signed packages and verify pages. The pipeline publishes each
# delivered package there so Linq texts carry a real download link instead
# of a JSON endpoint. Leave WEBAPP_API_KEY empty to disable the handoff.
WEBAPP_BASE_URL = _get("WEBAPP_BASE_URL", "http://localhost:3000")
WEBAPP_API_KEY = _get("WEBAPP_API_KEY")
# The ed25519 signing identity the web app files the package under.
WEBAPP_SIGNER_EMAIL = _get("WEBAPP_SIGNER_EMAIL", "agents@verify.app")


def is_configured(*keys: str) -> bool:
    """True when every named setting has a non-empty value.

    Lets a leaf module no-op cleanly instead of half-running:
        if not config.is_configured("LINQ_API_KEY", "LINQ_API_BASE"): ...
    """
    return all(globals().get(k) for k in keys)
