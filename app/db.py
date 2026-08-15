"""SQLite. No migrations — schema is created on startup and edited in place.

If you change a column while the demo db exists, delete verify.db and restart.
"""

import sqlite3

from app.config import DB_PATH

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

-- Linq retries a webhook up to 10 times over ~25 minutes. This is what stops
-- one candidate reply from creating ten submissions.
CREATE TABLE IF NOT EXISTS webhook_events (
    event_id    TEXT PRIMARY KEY,
    event_type  TEXT,
    package_id  TEXT,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
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


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def get_package(conn: sqlite3.Connection, package_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM packages WHERE package_id = ?", (package_id,)
    ).fetchone()


def set_status(conn: sqlite3.Connection, package_id: str, status: str) -> None:
    conn.execute(
        "UPDATE packages SET status = ? WHERE package_id = ?", (status, package_id)
    )
    conn.commit()
