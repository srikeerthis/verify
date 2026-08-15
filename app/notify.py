"""Linq notifications.

Leaf module. Nothing imports from here except call sites, and every entry point
swallows its own exceptions — a Linq outage must never turn a CLEAN verdict into
a 500. Delete this file and the pipeline still works. That is the point: Linq is
first on the cut list.

Set LINQ_API_KEY to go live. Unset, every send logs as `skipped` and the pipeline
runs green.
"""

import logging
import sqlite3
from typing import Literal

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app import config
from app.db import get_conn

log = logging.getLogger(__name__)


class NotConfigured(Exception):
    """No Linq credentials. Not an error — notifications are simply off."""


Event = Literal[
    "package_received",
    "package_ready",
    "package_blocked",
    "escalation_resolved",
    "submission_verified",
]

# event -> (recipient column, subject line)
EVENTS: dict[str, tuple[str, str]] = {
    "package_received": ("company_contact", "Take-home package received"),
    "package_ready": ("candidate_contact", "Your take-home is verified and ready"),
    "package_blocked": ("company_contact", "Take-home package blocked"),
    "escalation_resolved": ("company_contact", "Human review complete"),
    "submission_verified": ("company_contact", "Candidate submission verified"),
}

_env = Environment(
    loader=FileSystemLoader(config.TEMPLATE_DIR),
    autoescape=select_autoescape(default=False),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _send(recipient: str, subject: str, body: str) -> None:
    """The only Linq-specific code in the repo.

    Raises on failure; `notify` decides what that means. Fill this in once we
    have the API docs — base URL, auth header, send endpoint, and what Linq
    addresses a recipient by.
    """
    if not config.is_configured("LINQ_API_KEY", "LINQ_API_BASE"):
        raise NotConfigured

    raise NotImplementedError(
        "Linq transport not wired up — need API base, auth scheme, send endpoint"
    )
    # import httpx
    # r = httpx.post(
    #     f"{config.LINQ_API_BASE}/messages",
    #     headers={"Authorization": f"Bearer {config.LINQ_API_KEY}"},
    #     json={"to": recipient, "from": config.LINQ_SENDER_ID,
    #           "subject": subject, "body": body},
    #     timeout=5.0,
    # )
    # r.raise_for_status()


def _already_sent(conn: sqlite3.Connection, package_id: str, event: str) -> bool:
    row = conn.execute(
        "SELECT status FROM notifications WHERE package_id = ? AND event = ?",
        (package_id, event),
    ).fetchone()
    return row is not None and row["status"] == "sent"


def _record(
    conn: sqlite3.Connection,
    package_id: str,
    event: str,
    recipient: str | None,
    status: str,
    error: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO notifications (package_id, event, recipient, status, error)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (package_id, event) DO UPDATE SET
            recipient = excluded.recipient,
            status    = excluded.status,
            error     = excluded.error,
            sent_at   = datetime('now')
        """,
        (package_id, event, recipient, status, error),
    )
    conn.commit()


def notify(event: Event, package_id: str) -> None:
    """Fire-and-forget. Never raises."""
    try:
        if event not in EVENTS:
            log.warning("notify: unknown event %r", event)
            return

        recipient_col, subject = EVENTS[event]

        with get_conn() as conn:
            if _already_sent(conn, package_id, event):
                return

            pkg = conn.execute(
                "SELECT * FROM packages WHERE package_id = ?", (package_id,)
            ).fetchone()
            if pkg is None:
                log.warning("notify: no package %s", package_id)
                return

            recipient = pkg[recipient_col]
            if not recipient:
                _record(conn, package_id, event, None, "skipped", "no recipient")
                return

            body = _env.get_template(f"notify/{event}.txt").render(
                pkg=dict(pkg),
                verify_url=f"{config.PUBLIC_BASE_URL}/verify/{package_id}",
            )

            try:
                _send(recipient, subject, body)
            except Exception as exc:  # noqa: BLE001 — status is the return value
                configured = not isinstance(exc, NotConfigured)
                status = "failed" if configured else "skipped"
                detail = str(exc) if configured else "linq not configured"
                _record(conn, package_id, event, recipient, status, detail)
                log.info("notify %s/%s: %s", package_id, event, status)
                return

            _record(conn, package_id, event, recipient, "sent")
            log.info("notify %s/%s: sent", package_id, event)

    except BaseException:  # noqa: BLE001 — notifications never break the pipeline
        log.exception("notify %s/%s crashed", package_id, event)
