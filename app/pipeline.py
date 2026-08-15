"""Orchestration. The only place that knows the order of operations.

    intake  -> scan_client.scan (ingest+scan+judge+escalate, real) -> sign -> notify

One rule holds the whole product together: **nothing is texted to anyone until a
signature exists.** The message says "here is a verified package" and links to
proof — sending it before signing would make that a lie. `_finalize` is the only
function that both signs and notifies, and it does them in that order.

Everything here is direction-agnostic. `to_candidate` is a challenge going out,
`to_company` is a submission coming back; same code path, different `direction`,
exactly as CLAUDE.md specifies.

`process` used to call the local ingest/static_scan/agent/escalate stubs
directly. It now calls out to scan_client, which hits a real scan service
(OSV.dev CVE checks, secret/typosquat static scan, GPT verdict, Superserve
sandbox execution, and — on an ambiguous verdict — a real Terac human
escalation) and blocks until fully resolved. What comes back is always a final
CLEAN or MALICIOUS; SUSPICIOUS is resolved on the other side before it ever
reaches here. `_finalize` (signing + notify) is unchanged — the scan service
never touches this repo's signing key.

`on_human_verdict` and app/escalate.py are no longer called from this path —
Terac escalation now happens inside the scan service — but are left in place
rather than deleted, in case a caller still depends on them.

For zip sources, `process` also runs app/sandbox_scan.py — a second, native
Superserve invocation, independent of the scan service's own internal sandbox
run. Findings from it are merged into findings_json before it's stored;
best-effort, never blocks or overrides the verdict already returned by
scan_client.
"""

import json
import logging
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

from app import sandbox_scan, scan_client, signing
from app.db import get_conn, get_package, set_status
from app.notify import notify

log = logging.getLogger(__name__)


def _download_if_zip(source_url: str) -> bytes | None:
    """Downloads source_url and returns the bytes if it looks like a zip
    (magic bytes or .zip suffix), else None. Best-effort — any failure here
    just skips the native sandbox scan rather than failing the pipeline.
    """
    try:
        with urllib.request.urlopen(source_url, timeout=30) as resp:
            data = resp.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        log.warning("sandbox_scan: could not download %s — %s", source_url, exc)
        return None

    looks_like_zip = source_url.endswith(".zip") or data[:2] == b"PK"
    return data if looks_like_zip else None


def create_challenge(
    *,
    source_url: str,
    company_email: str,
    company_phone: str,
    candidate_phone: str,
) -> str:
    """Recruiter intake. Called by the frontend form. Returns the package id.

    Writes the row and returns immediately — run `process` in a background task
    so the form response is not waiting on a scan.
    """
    package_id = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO packages (package_id, direction, source_url, status,
                                  company_email, company_phone, candidate_phone)
            VALUES (?, 'to_candidate', ?, 'received', ?, ?, ?)
            """,
            (package_id, source_url, company_email, company_phone, candidate_phone),
        )
        conn.commit()

    log.info("intake %s: challenge from %s for %s", package_id, company_phone,
             candidate_phone)
    notify("package_received", package_id)
    return package_id


def create_submission(*, parent_id: str, source_url: str) -> str:
    """Candidate reply. Called by the Linq webhook when a link comes back.

    Copies the contacts off the challenge row so the submission can notify
    without another lookup.
    """
    package_id = str(uuid.uuid4())
    with get_conn() as conn:
        parent = get_package(conn, parent_id)
        if parent is None:
            raise ValueError(f"no such challenge package: {parent_id}")

        conn.execute(
            """
            INSERT INTO packages (package_id, parent_id, direction, source_url,
                                  status, company_email, company_phone,
                                  candidate_phone)
            VALUES (?, ?, 'to_company', ?, 'received', ?, ?, ?)
            """,
            (package_id, parent_id, source_url, parent["company_email"],
             parent["company_phone"], parent["candidate_phone"]),
        )
        conn.commit()

    log.info("intake %s: submission answering %s", package_id, parent_id)
    return package_id


def process(package_id: str) -> None:
    """Run the real pipeline via scan_client, then finalize.

    Safe to run in a BackgroundTask. Never raises — a failure marks the package
    `failed` and stops, rather than taking the request down with it. May block
    for a while if the scan service escalates to Terac internally.
    """
    try:
        with get_conn() as conn:
            pkg = get_package(conn, package_id)
            if pkg is None:
                log.warning("process: no package %s", package_id)
                return
            set_status(conn, package_id, "scanning")

        try:
            result = scan_client.scan(package_id, pkg["source_url"], pkg["direction"])
        except scan_client.ScanError as exc:
            log.warning("process %s: scan failed — %s", package_id, exc)
            with get_conn() as conn:
                set_status(conn, package_id, "failed")
            return

        findings = result["findings"]

        # Independent, native dynamic scan in this repo's own code (the scan
        # service already ran its own sandbox scan internally as part of
        # `result`; this is a second, visible Superserve invocation). Only
        # runs for zip sources today; best-effort — never blocks the verdict
        # already returned by scan_client.
        zip_bytes = _download_if_zip(pkg["source_url"])
        if zip_bytes is not None:
            try:
                sandbox_findings, run_summary = sandbox_scan.run(zip_bytes)
                findings = findings + [f.to_dict() for f in sandbox_findings]
                log.info("process %s: native sandbox scan — install=%s build=%s test=%s (%d findings)",
                         package_id, run_summary["install"], run_summary["build"],
                         run_summary["test"], len(sandbox_findings))
            except sandbox_scan.SandboxScanError as exc:
                log.warning("process %s: native sandbox scan skipped — %s", package_id, exc)

        with get_conn() as conn:
            conn.execute(
                """
                UPDATE packages
                   SET sha256 = ?, verdict = ?, confidence = ?, findings_json = ?,
                       human_reviewed = ?, human_verdict = ?
                 WHERE package_id = ?
                """,
                (
                    result["sha256"], result["verdict"], result["confidence"],
                    json.dumps(findings),
                    1 if result["humanReviewed"] else 0, result["humanVerdict"],
                    package_id,
                ),
            )
            conn.commit()

        log.info("process %s: %s (%d findings, human_reviewed=%s)", package_id,
                 result["verdict"], len(findings), result["humanReviewed"])

        # scan_client always returns a resolved CLEAN or MALICIOUS — an
        # ambiguous verdict is escalated to Terac and resolved on the other
        # side before the call returns, so there's no separate "escalated"
        # branch here anymore. `escalated` just controls whether _finalize
        # sends the "a human looked at this" notification.
        _finalize(package_id, result["verdict"], escalated=result["humanReviewed"])

    except BaseException:  # noqa: BLE001 — a background task must not die loudly
        log.exception("process %s crashed", package_id)
        try:
            with get_conn() as conn:
                set_status(conn, package_id, "failed")
        except Exception:  # noqa: BLE001
            pass


def on_human_verdict(package_id: str, human_verdict: str) -> None:
    """Terac's answer came back. Record it, then finalize on that verdict."""
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE packages SET human_reviewed = 1, human_verdict = ?
             WHERE package_id = ?
            """,
            (human_verdict, package_id),
        )
        conn.commit()

    log.info("human verdict %s: %s", package_id, human_verdict)
    _finalize(package_id, human_verdict, escalated=True)


def _finalize(package_id: str, verdict: str, *, escalated: bool = False) -> None:
    """Sign, then notify. Never the other way round.

    MALICIOUS is signed too — a signed "we blocked this" is still a verifiable
    claim, and the recruiter gets told either way.
    """
    with get_conn() as conn:
        pkg = get_package(conn, package_id)
        if pkg is None:
            return

        signed_at = datetime.now(timezone.utc).isoformat()
        signature = signing.sign(
            pkg["sha256"] or "", verdict, pkg["direction"], signed_at
        )
        conn.execute(
            "UPDATE packages SET signature = ?, signed_at = ? WHERE package_id = ?",
            (signature, signed_at, package_id),
        )
        conn.commit()
        set_status(conn, package_id, "signed")
        direction = pkg["direction"]

    if escalated:
        # The recruiter asked a human and deserves to hear the answer, whatever
        # it was. The delivery notification below still follows on CLEAN.
        notify("escalation_resolved", package_id)

    if verdict == "MALICIOUS":
        with get_conn() as conn:
            set_status(conn, package_id, "blocked")
        notify("package_blocked", package_id)
        return

    # Signature exists — safe to hand the link on.
    if direction == "to_candidate":
        notify("package_ready", package_id)
    else:
        notify("submission_verified", package_id)

    with get_conn() as conn:
        set_status(conn, package_id, "delivered")
