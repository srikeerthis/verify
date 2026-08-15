"""Client for the Node scan service — replaces the local ingest / static_scan /
agent / escalate stubs with a real implementation: OSV.dev dependency-CVE
lookups, secret/typosquat static scanning, a GPT verdict, dynamic execution in
an isolated Superserve sandbox, and — on an ambiguous verdict — a real Terac
human escalation, all behind one call.

One outbound call, so stdlib urllib — same rule notify.py follows for Linq.

Contract: POST {SCAN_SERVICE_URL}/external/scan with
    {packageId, sourceUrl, direction}
returns
    {sha256, verdict, confidence, findings, signature, humanReviewed, humanVerdict}

`verdict` is always CLEAN or MALICIOUS by the time this returns — an ambiguous
result is resolved via Terac inside the scan service before it responds, so
SUSPICIOUS never comes back here. `humanReviewed` tells the caller whether that
happened, for the `escalation_resolved` notification.

The `signature` field in the response is signed with the scan service's own key,
not ours, and is not verifiable against our /pubkey — callers should keep using
this repo's `signing.sign()` for the signature that ships to recruiters and
candidates, and treat this response as verdict + findings only.
"""

import json
import logging
import urllib.error
import urllib.request

from app import config

log = logging.getLogger(__name__)


class ScanError(Exception):
    """The scan service could not be reached, or returned an error."""


def scan(package_id: str, source_url: str, direction: str) -> dict:
    """Runs the real pipeline and blocks until fully resolved.

    May take a while on an ambiguous verdict — a human has to actually respond
    via Terac before this returns. Safe to call from a BackgroundTask; do not
    call this from a request handler that needs to return quickly.
    """
    body = json.dumps(
        {"packageId": package_id, "sourceUrl": source_url, "direction": direction}
    ).encode()

    req = urllib.request.Request(
        f"{config.SCAN_SERVICE_URL}/external/scan",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=config.SCAN_TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise ScanError(f"scan service returned {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ScanError(f"scan service unreachable: {exc.reason}") from exc
    except TimeoutError as exc:
        raise ScanError(f"scan service timed out after {config.SCAN_TIMEOUT_SECONDS}s") from exc
