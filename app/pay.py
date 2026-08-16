"""Stripe paywall for dynamic scanning.

Static scanning is free. Running the package in the sandbox costs real money
per run, so it is unlocked per package with a one-time Stripe payment through
a Payment Link — a hosted Stripe page, so no card ever touches us.

No webhook and no publishable key are needed: verification is a server-side
list of Checkout Sessions on the link, using the secret key. One fewer moving
part for the demo, and it fails closed — no paid session, no sandbox.

Contract the rest of the code depends on:

    is_configured() -> bool
    payment_link_url() -> str            the buy.stripe.com URL, or ""
    verify() -> str | None               a paid-but-unused session id, or None
    consume(session_id, package_id) -> bool   tie a session to a package, once
"""

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

from app import config
from app.db import get_conn

log = logging.getLogger(__name__)

STRIPE_API = "https://api.stripe.com/v1"

# How far back a payment can count as an unlock. Generous, because a demo
# payment made over lunch should still open the door that afternoon.
_WINDOW_SECONDS = 6 * 60 * 60
_MAX_SESSIONS = 25

# payment link id (plink_...), resolved from the URL on first use.
_cached_link_id: str | None = None


class PayError(Exception):
    """Stripe is unreachable or rejected the call."""


def is_configured() -> bool:
    return config.is_configured("STRIPE_SECRET_KEY")


def payment_link_url() -> str:
    """The public buy.stripe.com URL to send the payer to (may be empty)."""
    return config.STRIPE_PAYMENT_LINK_URL


def _stripe_get(path: str, params: dict | None = None) -> dict:
    if not is_configured():
        raise PayError("STRIPE_SECRET_KEY is not set")

    url = STRIPE_API + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {config.STRIPE_SECRET_KEY}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise PayError(
            f"Stripe {path} failed: {exc.code} {exc.read().decode(errors='replace')}"
        ) from exc
    except urllib.error.URLError as exc:
        raise PayError(f"Stripe unreachable: {exc.reason}") from exc


def _link_id() -> str | None:
    """The plink_... id behind our configured URL, or None.

    Sessions carry a payment_link id, the .env only has the URL, so this
    bridges them once per process. A miss just means verification falls back
    to "any recent paid session on the account" — fine for a test account.
    """
    global _cached_link_id
    if _cached_link_id is not None:
        return _cached_link_id or None

    link_id = ""
    if config.STRIPE_PAYMENT_LINK_URL:
        try:
            links = _stripe_get("/payment_links", {"limit": 100})["data"]
            for link in links:
                if link.get("url") == config.STRIPE_PAYMENT_LINK_URL:
                    link_id = link["id"]
                    break
            if not link_id:
                log.warning("pay: payment link URL not found on this Stripe account")
        except PayError as exc:
            log.warning("pay: could not resolve payment link id — %s", exc)

    _cached_link_id = link_id
    return link_id or None


def _paid_sessions() -> list[dict]:
    """Recent Checkout Sessions on our link that completed and were paid."""
    link_id = _link_id()
    params: dict = {"limit": _MAX_SESSIONS}
    if link_id:
        params["payment_link"] = link_id
    try:
        data = _stripe_get("/checkout/sessions", params)
    except PayError:
        if not link_id:
            raise
        # Older API versions reject the payment_link filter; fall back to a
        # plain list and match client-side.
        data = _stripe_get("/checkout/sessions", {"limit": _MAX_SESSIONS})

    return [
        s for s in data["data"]
        if s.get("status") == "complete"
        and s.get("payment_status") == "paid"
        and (not link_id or s.get("payment_link") == link_id)
    ]


def _used(session_id: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM paid_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    return row is not None


def verify() -> str | None:
    """A paid-but-unused session id within the window, or None.

    Does NOT consume it — the recruiter may verify before they even pick a
    file. The session is spent only when a package actually uses it.
    """
    cutoff = time.time() - _WINDOW_SECONDS
    for session in _paid_sessions():
        if session.get("created", 0) < cutoff:
            continue
        if _used(session["id"]):
            continue
        return session["id"]
    return None


def consume(unlock_code: str, package_id: str) -> bool:
    """Bind one payment to one package. True exactly once per session.

    Re-checks the session against Stripe rather than trusting the form field,
    so a made-up or already-spent code buys nothing.
    """
    if not unlock_code:
        return False

    try:
        session = _stripe_get(f"/checkout/sessions/{urllib.parse.quote(unlock_code)}")
    except PayError as exc:
        log.warning("pay: consume %s failed — %s", unlock_code, exc)
        return False

    link_id = _link_id()
    paid = (
        session.get("status") == "complete"
        and session.get("payment_status") == "paid"
        and (not link_id or session.get("payment_link") == link_id)
    )
    if not paid:
        log.warning("pay: %s is not a paid session on our link", unlock_code)
        return False

    with get_conn() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO paid_sessions (session_id, package_id) VALUES (?, ?)",
            (unlock_code, package_id),
        )
        conn.commit()
    if cur.rowcount != 1:
        log.warning("pay: %s already used — keeping package on the free tier", unlock_code)
        return False

    log.info("pay: dynamic scan unlocked for %s via %s", package_id, unlock_code)
    return True
