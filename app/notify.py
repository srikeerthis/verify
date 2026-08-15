"""Linq notifications.

Leaf module. Nothing imports from here except call sites, and every entry point
swallows its own exceptions — a Linq outage must never turn a CLEAN verdict into
a 500. Delete this file and the pipeline still works. That is the point: Linq is
first on the cut list.

Set LINQ_API_KEY to go live. Unset, every send logs as `skipped` and the pipeline
runs green.
"""

import json
import logging
import re
import sqlite3
import urllib.error
import urllib.request
from typing import Literal

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app import config
from app.db import get_conn

log = logging.getLogger(__name__)


class NotConfigured(Exception):
    """No Linq credentials. Not an error — notifications are simply off."""


class LinqError(Exception):
    """A send Linq refused or could not complete."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


# https://docs.linqapp.com/error — 1007 rate limit, all 3xxx server errors, and
# the transient half of 4xxx delivery. Everything else is permanent and retrying
# it just burns quota.
_RETRYABLE_CODES = {1007, 4001, 4004, 4006, 4007, 4010, 5001, 5003}


def _is_retryable(code: int | None, http_status: int) -> bool:
    if code is None:
        return http_status >= 500
    return 3000 <= code < 4000 or code in _RETRYABLE_CODES

E164 = re.compile(r"^\+[1-9]\d{7,14}$")

Event = Literal[
    "package_received",
    "package_ready",
    "package_blocked",
    "escalation_resolved",
    "submission_verified",
]

# event -> which packages column holds the recipient.
# Linq is SMS, so there is no subject line — the whole message is the body.
EVENTS: dict[str, str] = {
    "package_received": "company_phone",
    "package_ready": "candidate_phone",
    "package_blocked": "company_phone",
    "escalation_resolved": "company_phone",
    "submission_verified": "company_phone",
}

_env = Environment(
    loader=FileSystemLoader(config.TEMPLATE_DIR),
    autoescape=select_autoescape(default=False),
    trim_blocks=True,
    lstrip_blocks=True,
)


def send_raw(recipient: str, body: str, idempotency_key: str) -> str:
    """Send arbitrary text through Linq. Returns the Linq message id.

    The agent tools (app/tools.py) compose their own messages, so they need
    the pipe without the template/event bookkeeping `notify` does. Raises
    NotConfigured / LinqError — callers handle both.
    """
    return _send(recipient, body, idempotency_key)


def _send(recipient: str, body: str, idempotency_key: str) -> str:
    """The only Linq-specific code in the repo. Returns the Linq message id.

    POST {base}/messages — https://docs.linqapp.com/guides/messaging/sending-messages/

    urllib rather than httpx on purpose: this is the one outbound call in a
    module that is first on the cut list, and it does not justify a dependency.
    Swapping in httpx later is a five-line change.
    """
    if not config.is_configured("LINQ_API_KEY", "LINQ_API_BASE"):
        raise NotConfigured

    if not E164.match(recipient):
        raise LinqError(f"recipient {recipient!r} is not E.164 (+15551234567)")

    payload: dict = {
        "to": [recipient],
        "message": {
            "parts": [{"type": "text", "value": body}],
            # Same key for the same (package, event) forever, so a retry after a
            # timeout returns the original send instead of texting someone twice.
            "idempotency_key": idempotency_key[:255],
        },
    }
    if config.LINQ_SENDER_ID:
        payload["from"] = config.LINQ_SENDER_ID

    req = urllib.request.Request(
        f"{config.LINQ_API_BASE.rstrip('/')}/messages",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {config.LINQ_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return _message_id(json.loads(resp.read() or b"{}"))
    except urllib.error.HTTPError as exc:
        raise _linq_error(exc) from exc
    except Exception as exc:  # network, DNS, timeout — all transient
        raise LinqError(f"{type(exc).__name__}: {exc}", retryable=True) from exc


def _message_id(body: dict) -> str:
    """Pull the message id out of a send response.

    The live API returns the whole chat — {chat_id, handles, message: {...}} —
    with the id at `message.id`, not the flat {"id": ...} the docs example
    shows. Checked against a real send on 2026-08-15. Both shapes are accepted
    so a docs-shaped response does not silently lose the id.
    """
    message = body.get("message")
    if isinstance(message, dict) and message.get("id"):
        return str(message["id"])
    return str(body.get("id") or "")


def _linq_error(exc: urllib.error.HTTPError) -> LinqError:
    """Turn Linq's error envelope into something a human can read in the log."""
    code, message, trace = None, exc.reason, None
    try:
        err = json.loads(exc.read() or b"{}").get("error", {})
        code, message = err.get("code"), err.get("message", message)
        trace = err.get("trace_id")
    except Exception:  # noqa: BLE001 — a bad error body is still an error
        pass

    detail = f"HTTP {exc.code}"
    if code is not None:
        detail += f" code {code}"
    detail += f": {message}"
    if trace:
        detail += f" (trace {trace})"

    return LinqError(detail, retryable=_is_retryable(code, exc.code))


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
    message_id: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO notifications
            (package_id, event, recipient, status, error, message_id)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (package_id, event) DO UPDATE SET
            recipient  = excluded.recipient,
            status     = excluded.status,
            error      = excluded.error,
            message_id = excluded.message_id,
            sent_at    = datetime('now')
        """,
        (package_id, event, recipient, status, error, message_id),
    )
    conn.commit()


def notify(event: Event, package_id: str) -> None:
    """Fire-and-forget. Never raises."""
    try:
        if event not in EVENTS:
            log.warning("notify: unknown event %r", event)
            return

        recipient_col = EVENTS[event]

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
                # Web app pages (may be NULL when the handoff is off or
                # failed) — templates fall back to verify_url.
                download_page=pkg["webapp_verify_url"],
                signature_link=pkg["webapp_signature_url"],
                pubkey_link=pkg["webapp_publickey_url"],
            ).strip()

            try:
                message_id = _send(recipient, body, f"{package_id}:{event}")
            except NotConfigured:
                _record(
                    conn, package_id, event, recipient, "skipped",
                    "linq not configured",
                )
                return
            except LinqError as exc:  # noqa: BLE001 — status is the return value
                detail = f"{'retryable' if exc.retryable else 'permanent'}: {exc}"
                _record(conn, package_id, event, recipient, "failed", detail)
                log.warning("notify %s/%s failed — %s", package_id, event, detail)
                return

            _record(
                conn, package_id, event, recipient, "sent", message_id=message_id
            )
            log.info("notify %s/%s: sent (%s)", package_id, event, message_id)

    except BaseException:  # noqa: BLE001 — notifications never break the pipeline
        log.exception("notify %s/%s crashed", package_id, event)
