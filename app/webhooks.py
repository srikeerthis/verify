"""Inbound Linq webhooks — the candidate's reply coming back.

https://docs.linqapp.com/guides/webhooks/ — Standard Webhooks: three headers,
HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{body}`, base64 signature
prefixed `v1,`, reject anything older than five minutes.

Linq retries a failed delivery up to 10 times over ~25 minutes, so the same
reply *will* arrive more than once. Dedupe on `webhook-id` before doing any
work — that is what `webhook_events` is for.

Verification is stdlib hmac rather than the SDK. It is twenty lines and it is
the boundary where an attacker would try to inject a package, so it is worth
reading rather than importing.
"""

import base64
import hashlib
import hmac
import logging
import re
import sqlite3
import time

from app import config

log = logging.getLogger(__name__)

TOLERANCE_SECONDS = 5 * 60

# First http(s) URL in the message body. Candidates text things like
# "here you go! https://github.com/me/solution" so we take the link, not the line.
URL_RE = re.compile(r"https?://[^\s<>\"']+")


class WebhookError(Exception):
    """Rejected before any work happened. Caller returns 4xx."""


def verify_signature(body: bytes, headers: dict[str, str]) -> None:
    """Raise WebhookError unless this really came from Linq.

    `headers` must be case-insensitively accessible; FastAPI's request.headers
    already is.
    """
    if not config.LINQ_WEBHOOK_SECRET:
        raise WebhookError("LINQ_WEBHOOK_SECRET not set — refusing to trust webhook")

    webhook_id = headers.get("webhook-id", "")
    timestamp = headers.get("webhook-timestamp", "")
    signature = headers.get("webhook-signature", "")
    if not (webhook_id and timestamp and signature):
        raise WebhookError("missing webhook-id/timestamp/signature headers")

    try:
        sent_at = int(timestamp)
    except ValueError as exc:
        raise WebhookError(f"bad webhook-timestamp {timestamp!r}") from exc

    if abs(time.time() - sent_at) > TOLERANCE_SECONDS:
        raise WebhookError("webhook timestamp outside the 5 minute window")

    secret = config.LINQ_WEBHOOK_SECRET
    if secret.startswith("whsec_"):
        secret = secret[len("whsec_"):]
    try:
        key = base64.b64decode(secret)
    except Exception as exc:  # noqa: BLE001
        raise WebhookError("LINQ_WEBHOOK_SECRET is not valid base64") from exc

    signed = f"{webhook_id}.{timestamp}.".encode() + body
    expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()

    # The header may carry several space-separated versioned signatures during a
    # secret rotation; any one matching is a pass.
    for candidate in signature.split():
        version, _, value = candidate.partition(",")
        if version == "v1" and hmac.compare_digest(value, expected):
            return

    raise WebhookError("signature mismatch")


def already_handled(conn: sqlite3.Connection, event_id: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM webhook_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        is not None
    )


def mark_handled(
    conn: sqlite3.Connection,
    event_id: str,
    event_type: str,
    package_id: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO webhook_events (event_id, event_type, package_id)
        VALUES (?, ?, ?)
        ON CONFLICT (event_id) DO UPDATE SET package_id = excluded.package_id
        """,
        (event_id, event_type, package_id),
    )
    conn.commit()


def parse_inbound(payload: dict) -> tuple[str, str] | None:
    """Pull (sender phone, message text) out of a message.received event.

    Returns None for anything that is not an inbound text — delivery receipts,
    reactions, typing indicators all hit the same endpoint.
    """
    if payload.get("event_type") != "message.received":
        return None

    data = payload.get("data") or {}
    if data.get("direction") != "inbound":
        return None

    sender = (data.get("sender_handle") or {}).get("handle", "")
    text = " ".join(
        part.get("value", "")
        for part in data.get("parts") or []
        if part.get("type") == "text"
    ).strip()

    if not sender:
        return None
    return sender, text


def extract_link(text: str) -> str | None:
    match = URL_RE.search(text)
    return match.group(0).rstrip(".,;)") if match else None


def find_open_challenge(conn: sqlite3.Connection, phone: str) -> sqlite3.Row | None:
    """Which challenge is this candidate replying to?

    An inbound SMS carries a phone number, not a package id, so we match on the
    most recent challenge delivered to that number.

    Known limitation: a candidate with two open take-homes gets matched to the
    newer one. Fixing that means putting a short code in the outbound message and
    asking candidates to quote it — worth doing if this ever ships, overkill for
    the demo.
    """
    return conn.execute(
        """
        SELECT * FROM packages
         WHERE candidate_phone = ?
           AND direction = 'to_candidate'
           AND status IN ('delivered', 'signed')
         ORDER BY created_at DESC, rowid DESC
         LIMIT 1
        """,
        (phone,),
    ).fetchone()
