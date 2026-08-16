"""Orchestration. The only place that knows the order of operations.

    intake -> ingest -> scan (static + LLM review + sandbox, zip sources) ->
    judge -> [escalate] -> sign -> announce

One rule holds the whole product together: **nothing is texted to anyone until a
signature exists.** The message says "here is a verified package" and links to
proof — sending it before signing would make that a lie. `_finalize` is the only
function that both signs and announces, and it does them in that order.

Announcements are agent-composed (app/workflow.py): a prompt plus the package
facts, with tools to text either side. The static templates survive as the
fallback when no model key is set.

Everything here is direction-agnostic. `to_candidate` is a challenge going out,
`to_company` is a submission coming back; same code path, different `direction`,
exactly as CLAUDE.md specifies.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from app import agent, escalate, handoff, ingest, sandbox_scan, signing, static_scan, workflow
from app.db import get_conn, get_package, set_status

log = logging.getLogger(__name__)


def create_challenge(
    *,
    source_url: str,
    company_email: str,
    company_phone: str,
    candidate_phone: str,
    webapp: dict | None = None,
) -> str:
    """Recruiter intake. Called by the frontend form. Returns the package id.

    Writes the row and returns immediately — run `process` in a background task
    so the form response is not waiting on a scan.

    `webapp` carries links the web app already minted when it signed the upload.
    Passing them means handoff.publish sees the package as already published and
    skips it — otherwise we would download our own zip and upload a duplicate
    copy straight back.
    """
    package_id = str(uuid.uuid4())
    webapp = webapp or {}
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO packages (package_id, direction, source_url, status,
                                  company_email, company_phone, candidate_phone,
                                  webapp_id, webapp_verify_url, webapp_download_url,
                                  webapp_signature_url, webapp_publickey_url)
            VALUES (?, 'to_candidate', ?, 'received', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (package_id, source_url, company_email, company_phone, candidate_phone,
             webapp.get("id"), webapp.get("verify_url"), webapp.get("download_url"),
             webapp.get("signature_url"), webapp.get("publickey_url")),
        )
        conn.commit()

    log.info("intake %s: challenge from %s for %s", package_id, company_phone,
             candidate_phone)
    workflow.announce("package_received", package_id)
    return package_id


def create_submission(
    *, parent_id: str, source_url: str, webapp: dict | None = None
) -> str:
    """Candidate reply. From the Linq webhook, or the submit page.

    Copies the contacts off the challenge row so the submission can notify
    without another lookup. `webapp` carries links for a zip that came in
    through the submit form and is already stored in the web app.
    """
    package_id = str(uuid.uuid4())
    webapp = webapp or {}
    with get_conn() as conn:
        parent = get_package(conn, parent_id)
        if parent is None:
            raise ValueError(f"no such challenge package: {parent_id}")

        conn.execute(
            """
            INSERT INTO packages (package_id, parent_id, direction, source_url,
                                  status, company_email, company_phone,
                                  candidate_phone, webapp_id, webapp_verify_url,
                                  webapp_download_url, webapp_signature_url,
                                  webapp_publickey_url)
            VALUES (?, ?, 'to_company', ?, 'received', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (package_id, parent_id, source_url, parent["company_email"],
             parent["company_phone"], parent["candidate_phone"],
             webapp.get("id"), webapp.get("verify_url"), webapp.get("download_url"),
             webapp.get("signature_url"), webapp.get("publickey_url")),
        )
        conn.commit()

    log.info("intake %s: submission answering %s", package_id, parent_id)
    # No ack from here — main.py dispatches workflow.ack_submission once the
    # row exists, which texts the candidate that their link landed.
    return package_id


def process(package_id: str) -> None:
    """Ingest, scan, judge, then either finalize or escalate.

    Safe to run in a BackgroundTask. Never raises — a failure marks the package
    `failed` and stops, rather than taking the request down with it.
    """
    try:
        with get_conn() as conn:
            pkg = get_package(conn, package_id)
            if pkg is None:
                log.warning("process: no package %s", package_id)
                return
            set_status(conn, package_id, "scanning")

        try:
            ingested = ingest.fetch(pkg["source_url"])
        except ingest.IngestError as exc:
            log.warning("process %s: ingest failed — %s", package_id, exc)
            with get_conn() as conn:
                set_status(conn, package_id, "failed")
            return

        try:
            findings = static_scan.scan(ingested)

            # Dynamic scan only covers zip sources today. ingest.fetch already
            # unpacked the source locally either way; for a zip source we
            # just re-pack what's on disk rather than re-download, since
            # sandbox_scan.run() takes a zip buffer.
            if pkg["source_url"].endswith(".zip"):
                try:
                    zip_bytes = _rezip(ingested)
                    sandbox_findings, run_summary = sandbox_scan.run(zip_bytes)
                    findings += sandbox_findings
                    log.info("process %s: sandbox scan — install=%s build=%s test=%s (%d findings)",
                             package_id, run_summary["install"], run_summary["build"],
                             run_summary["test"], len(sandbox_findings))
                except sandbox_scan.SandboxScanError as exc:
                    log.warning("process %s: sandbox scan skipped — %s", package_id, exc)
        finally:
            if ingested.cleanup:
                ingested.cleanup()

        verdict = agent.judge(findings)

        with get_conn() as conn:
            conn.execute(
                """
                UPDATE packages
                   SET sha256 = ?, verdict = ?, confidence = ?, findings_json = ?
                 WHERE package_id = ?
                """,
                (ingested.sha256, verdict.verdict, verdict.confidence,
                 json.dumps([f.to_dict() for f in findings]), package_id),
            )
            conn.commit()

        log.info("process %s: %s (%d findings)", package_id, verdict.verdict,
                 len(findings))

        # CLEAN and MALICIOUS finalize automatically. SUSPICIOUS goes to Terac
        # and comes back through on_human_verdict.
        if verdict.verdict == "SUSPICIOUS":
            with get_conn() as conn:
                set_status(conn, package_id, "escalated")
            # Tell whoever sent it that it is not going anywhere yet. Without
            # this the sender hears nothing at all between "we have it" and a
            # human verdict that may be hours away — and with no Terac key set,
            # may never come. Silence here reads as a broken pipeline.
            workflow.announce(
                "package_flagged" if pkg["direction"] == "to_candidate"
                else "submission_flagged",
                package_id,
            )
            escalate.escalate(package_id, findings)
            return

        _finalize(package_id, verdict.verdict)

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
        workflow.announce("escalation_resolved", package_id)

    if verdict == "MALICIOUS":
        with get_conn() as conn:
            set_status(conn, package_id, "blocked")
        workflow.announce("package_blocked", package_id)
        return

    # Signature exists — publish to the web app so the text can carry a real
    # download page, then hand the link on. Handoff failure degrades to the
    # report link rather than blocking delivery.
    handoff.publish(package_id)

    if direction == "to_candidate":
        workflow.announce("package_ready", package_id)
        # Tell the recruiter it cleared. Without this they only ever hear from
        # us when something is wrong, so silence has to carry the good news.
        workflow.announce("package_cleared", package_id)
    else:
        workflow.announce("submission_verified", package_id)

    with get_conn() as conn:
        set_status(conn, package_id, "delivered")


def _rezip(ingested) -> bytes:  # type: ignore[no-untyped-def]
    """Re-packs the already-unpacked source tree into zip bytes for
    sandbox_scan.run(), which expects a zip buffer (it's built to accept
    exactly what a recruiter/candidate would upload)."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_path in ingested.files:
            zf.write(ingested.root / rel_path, rel_path)
    return buf.getvalue()
