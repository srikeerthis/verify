"""SQLite. No migration framework — the schema is edited in place.

Adding a column is safe: init_db reconciles an existing database against
SCHEMA on every startup. Removing or retyping one still means deleting
verify.db.
"""

import logging
import re
import sqlite3

from app.config import DB_PATH

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS packages (
    package_id      TEXT PRIMARY KEY,
    parent_id       TEXT,               -- submission -> the challenge it answers
    direction       TEXT NOT NULL,      -- to_candidate | to_company
    source_url      TEXT NOT NULL,      -- github or zip link, as given to us
    status          TEXT NOT NULL,      -- see STATUSES below

    -- contacts, captured once on intake and copied onto the submission row
    company_email   TEXT,
    company_phone   TEXT,
    candidate_phone TEXT,

    -- 1 when a Stripe payment unlocked the dynamic (sandbox) scan for this
    -- package. 0 is the free tier: static scan only.
    dynamic         INTEGER NOT NULL DEFAULT 0,

    -- filled in by the pipeline
    sha256          TEXT,
    verdict         TEXT,               -- CLEAN | SUSPICIOUS | MALICIOUS
    confidence      REAL,
    findings_json   TEXT,
    human_reviewed  INTEGER NOT NULL DEFAULT 0,
    human_verdict   TEXT,
    signature       TEXT,
    signed_at       TEXT,

    -- web app handoff (handoff.py): links to the signed package pages the
    -- Linq texts carry. NULL until the package is published there.
    webapp_id            TEXT,
    webapp_verify_url    TEXT,
    webapp_download_url  TEXT,
    webapp_signature_url TEXT,
    webapp_publickey_url TEXT,

    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_packages_candidate
    ON packages (candidate_phone, created_at DESC);

CREATE TABLE IF NOT EXISTS notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id  TEXT NOT NULL,
    event       TEXT NOT NULL,
    recipient   TEXT,
    status      TEXT NOT NULL,           -- sent | skipped | failed
    error       TEXT,
    message_id  TEXT,                    -- Linq message id, once sent
    sent_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (package_id, event)
);

-- One row per paid Stripe Checkout Session (pay.py). The PRIMARY KEY makes a
-- payment spendable exactly once: INSERT succeeds only the first time.
CREATE TABLE IF NOT EXISTS paid_sessions (
    session_id  TEXT PRIMARY KEY,    -- cs_test_... / cs_live_...
    package_id  TEXT,                -- the package that spent it
    unlocked_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Linq retries a webhook up to 10 times over ~25 minutes. This is what stops
-- one candidate reply from creating ten submissions.
CREATE TABLE IF NOT EXISTS webhook_events (
    event_id    TEXT PRIMARY KEY,
    event_type  TEXT,
    package_id  TEXT,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The coordination agent's memory. Every SMS in or out lands here, so the
-- agent can read the thread before replying and announce() can dedupe.
CREATE TABLE IF NOT EXISTS agent_messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id  TEXT,               -- NULL for texts from unknown numbers
    event       TEXT,               -- announce() dedupe key, NULL for free-form
    phone       TEXT,               -- who sent it (inbound) / got it (outbound)
    role        TEXT,               -- recruiter | candidate
    direction   TEXT NOT NULL,      -- inbound | outbound
    body        TEXT NOT NULL,
    message_id  TEXT,               -- Linq message id, for outbound
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_agent_messages_package
    ON agent_messages (package_id, id);

-- One row per agent turn, for the demo ("watch it think") and for debugging.
CREATE TABLE IF NOT EXISTS agent_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id  TEXT,
    task        TEXT NOT NULL,
    result      TEXT,
    tool_calls  TEXT,               -- JSON array of {name, input}
    fallback    INTEGER NOT NULL DEFAULT 0,  -- 1 when the stub path ran
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

# Package lifecycle. Only DELIVERED and VERIFIED are terminal-happy.
STATUSES = (
    "received",     # intake row written, nothing scanned yet
    "scanning",     # ingest + static scan running
    "escalated",    # SUSPICIOUS, waiting on a human via Terac
    "signed",       # verdict CLEAN and signed, ready to hand on
    "delivered",    # candidate (or company) has been texted the link
    "blocked",      # MALICIOUS, nobody gets it
    "failed",       # pipeline error — see logs
)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _declared_columns(table: str) -> list[tuple[str, str]]:
    """(name, type) for each column SCHEMA declares on `table`."""
    match = re.search(
        rf"CREATE TABLE IF NOT EXISTS {table} \((.*?)\n\);", SCHEMA, re.S
    )
    if not match:
        return []

    columns = []
    for line in match.group(1).splitlines():
        line = line.split("--")[0].strip().rstrip(",")
        if not line or line.upper().startswith(
            ("PRIMARY", "UNIQUE", "FOREIGN", "CHECK", "CONSTRAINT")
        ):
            continue
        parts = line.split()
        if len(parts) >= 2:
            columns.append((parts[0], parts[1]))
    return columns


def _add_missing_columns(conn: sqlite3.Connection) -> None:
    """Bring an existing db up to the current SCHEMA.

    CREATE TABLE IF NOT EXISTS silently does nothing when the table already
    exists, so adding a column to SCHEMA leaves every db created before that
    change broken — inserts fail with "no column named x" at runtime, which is
    a 500 in the middle of a demo rather than an error at startup.

    Only additive: columns are added with their type and nothing else. A NOT
    NULL or a non-constant DEFAULT cannot be applied to an existing table
    anyway, and dropping or retyping a column still means deleting the file.
    """
    for table in re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA):
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if not existing:
            continue  # brand new table — executescript just made it correctly
        for name, column_type in _declared_columns(table):
            if name not in existing:
                log.warning("db: adding missing column %s.%s", table, name)
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {column_type}")
    conn.commit()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _add_missing_columns(conn)


def get_package(conn: sqlite3.Connection, package_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM packages WHERE package_id = ?", (package_id,)
    ).fetchone()


def set_status(conn: sqlite3.Connection, package_id: str, status: str) -> None:
    conn.execute(
        "UPDATE packages SET status = ? WHERE package_id = ?", (status, package_id)
    )
    conn.commit()
