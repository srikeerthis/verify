"""Web app handoff — publish a finalized package to the Verify web app.

Leaf module, same deal as notify.py: every entry point swallows its own
exceptions — a web app outage must never turn a CLEAN verdict into a 500.
Delete this file (and the call in pipeline) and the pipeline still works;
texts just fall back to the report link.

The web app (zipsign/ in this repo) is the human-friendly front end: it signs
the package bytes with ed25519 and serves a verify page plus download,
signature, and public key links. `publish` builds a package zip from the
verdict data (the exact verdict schema from CLAUDE.md), posts it to
POST /api/integration/packages, and stores the returned links on the
package row so notify templates can use them.

Called from _finalize AFTER signing and BEFORE notify — same rule as the
texts themselves: no download link until a signature exists.
"""

import io
import json
import logging
import urllib.error
import urllib.request
import uuid
import zipfile
from typing import Any

from app import config
from app.db import get_conn, get_package

log = logging.getLogger(__name__)


class HandoffError(Exception):
    """The web app refused the package or could not be reached."""


def _report_zip(pkg: Any) -> bytes:
    """The zip the candidate/company actually downloads.

    Carries the signed verdict in machine form (verdict.json, the schema
    every consumer builds on) and a plain-English report a non-expert can
    read on a phone. When ingest becomes real this is where the original
    package bytes should go instead.
    """
    findings = json.loads(pkg["findings_json"] or "[]")
    verdict = {
        "package_id": pkg["package_id"],
        "sha256": pkg["sha256"],
        "direction": pkg["direction"],
        "verdict": pkg["human_verdict"] or pkg["verdict"],
        "confidence": pkg["confidence"],
        "findings": findings,
        "human_reviewed": bool(pkg["human_reviewed"]),
        "human_verdict": pkg["human_verdict"],
        "signature": pkg["signature"],
        "signed_at": pkg["signed_at"],
    }

    lines = [
        "Verify — package report",
        "=======================",
        f"Package   : {pkg['package_id']}",
        f"Direction : {pkg['direction']}",
        f"Verdict   : {verdict['verdict']}"
        + (" (human reviewed)" if verdict["human_reviewed"] else ""),
        f"Signed at : {pkg['signed_at']}",
        f"SHA-256   : {pkg['sha256']}",
        "",
        f"Findings ({len(findings)}):",
    ]
    for f in findings:
        lines.append(
            f"  [{f['severity']}] {f['rule']} — {f['file']}:{f['line']}\n"
            f"    {f['why']}\n    {f['snippet'][:200]}"
        )
    if not findings:
        lines.append("  none")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("verdict.json", json.dumps(verdict, indent=2))
        zf.writestr("report.txt", "\n".join(lines) + "\n")
    return buf.getvalue()


def _multipart(fields: dict[str, str], filename: str, blob: bytes) -> tuple[bytes, str]:
    """multipart/form-data with stdlib only — one file plus text fields."""
    boundary = f"----verifyhandoff{uuid.uuid4().hex}"
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n".encode()
        )
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/zip\r\n\r\n".encode()
        + blob
        + f"\r\n--{boundary}--\r\n".encode()
    )
    return b"".join(parts), boundary


def _post_package(pkg: Any) -> dict:
    if not config.is_configured("WEBAPP_API_KEY", "WEBAPP_BASE_URL"):
        raise HandoffError("web app not configured")

    blob = _report_zip(pkg)
    direction = "challenge" if pkg["direction"] == "to_candidate" else "submission"
    filename = f"{pkg['package_id'].split('-')[0]}-{direction}-report.zip"
    body, boundary = _multipart(
        {"email": config.WEBAPP_SIGNER_EMAIL}, filename, blob
    )

    req = urllib.request.Request(
        f"{config.WEBAPP_BASE_URL.rstrip('/')}/api/integration/packages",
        data=body,
        headers={
            "X-API-Key": config.WEBAPP_API_KEY,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:200].decode(errors="replace")
        raise HandoffError(f"web app returned HTTP {exc.code}: {detail}") from exc
    except Exception as exc:  # noqa: BLE001 — network, DNS, timeout
        raise HandoffError(f"{type(exc).__name__}: {exc}") from exc


def publish(package_id: str) -> bool:
    """Push the signed package to the web app, store the links.

    Fire-and-forget like notify: never raises, returns True when the
    package now has web app links on its row (idempotent — an existing
    webapp_id short-circuits rather than double-publishing).
    """
    try:
        with get_conn() as conn:
            pkg = get_package(conn, package_id)
            if pkg is None:
                log.warning("handoff: no package %s", package_id)
                return False
            if pkg["webapp_id"]:
                return True

            if not pkg["signature"]:
                log.warning("handoff %s: refusing to publish unsigned package", package_id)
                return False

            try:
                result = _post_package(pkg)
                webapp_id = result.get("id")
                if not webapp_id:
                    raise HandoffError(f"web app response missing id: {result}")
            except HandoffError as exc:
                log.warning("handoff %s failed — %s", package_id, exc)
                return False

            conn.execute(
                """
                UPDATE packages SET
                    webapp_id = ?, webapp_verify_url = ?, webapp_download_url = ?,
                    webapp_signature_url = ?, webapp_publickey_url = ?
                 WHERE package_id = ?
                """,
                (
                    webapp_id,
                    result.get("verifyUrl"),
                    result.get("downloadUrl"),
                    result.get("signatureUrl"),
                    result.get("publicKeyUrl"),
                    package_id,
                ),
            )
            conn.commit()

        log.info("handoff %s: published as %s", package_id, webapp_id)
        return True

    except BaseException:  # noqa: BLE001 — the handoff never breaks the pipeline
        log.exception("handoff %s crashed", package_id)
        return False
