"""SQLite. No migrations — schema is created on startup and edited in place."""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "verify.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS packages (
    package_id      TEXT PRIMARY KEY,
    sha256          TEXT,
    direction       TEXT NOT NULL,
    verdict         TEXT,
    confidence      REAL,
    human_reviewed  INTEGER NOT NULL DEFAULT 0,
    human_verdict   TEXT,
    signature       TEXT,
    signed_at       TEXT,
    company_contact TEXT,
    candidate_contact TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id  TEXT NOT NULL,
    event       TEXT NOT NULL,
    recipient   TEXT,
    status      TEXT NOT NULL,           -- sent | skipped | failed
    error       TEXT,
    sent_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (package_id, event)
);
"""


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)
