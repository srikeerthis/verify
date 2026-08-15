"""FastAPI routes.

Two of these are contracts other people build against:

  POST /packages       the recruiter form posts here (frontend developer)
  POST /webhooks/linq  Linq posts candidate replies here (mine)

Everything else is the verify surface from CLAUDE.md.
"""

import logging

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app import config, pipeline, signing, tools, webhooks, workflow
from app.db import get_conn, get_package, init_db
from app.notify import E164

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = FastAPI(title="Verify")


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.post("/packages")
def create_package(
    background: BackgroundTasks,
    source_url: str = Form(...),
    company_email: str = Form(...),
    company_phone: str = Form(...),
    candidate_phone: str = Form(...),
    webapp_id: str = Form(""),
    webapp_verify_url: str = Form(""),
    webapp_download_url: str = Form(""),
    webapp_signature_url: str = Form(""),
    webapp_publickey_url: str = Form(""),
) -> JSONResponse:
    """Recruiter intake. Accepts a form post or JSON with the same field names.

    Returns as soon as the row is written; scanning runs in the background. The
    candidate is texted only once the package is scanned and signed, so a 200
    here means "accepted", not "delivered".

    The webapp_* fields are optional and only sent by the web app, which has
    already signed the upload and minted these links. Anyone posting a bare
    source_url still works exactly as before.
    """
    for label, phone in (("company_phone", company_phone),
                         ("candidate_phone", candidate_phone)):
        if not E164.match(phone):
            raise HTTPException(422, f"{label} must be E.164, e.g. +15551234567")

    if not source_url.startswith(("http://", "https://")):
        raise HTTPException(422, "source_url must be an http(s) link")

    package_id = pipeline.create_challenge(
        source_url=source_url,
        company_email=company_email,
        company_phone=company_phone,
        candidate_phone=candidate_phone,
        webapp={
            "id": webapp_id,
            "verify_url": webapp_verify_url,
            "download_url": webapp_download_url,
            "signature_url": webapp_signature_url,
            "publickey_url": webapp_publickey_url,
        } if webapp_verify_url else None,
    )
    background.add_task(pipeline.process, package_id)

    return JSONResponse(
        {
            "package_id": package_id,
            "status": "received",
            "verify_url": f"{config.PUBLIC_BASE_URL}/verify/{package_id}",
        },
        status_code=202,
    )


@app.post("/webhooks/linq")
async def linq_webhook(request: Request, background: BackgroundTasks) -> JSONResponse:
    """Candidate and recruiter replies land here.

    Always 200 once the signature checks out, even when we ignore the message.
    A 4xx or 5xx makes Linq retry for 25 minutes, and there is nothing to retry
    when a candidate texts "thanks!".

    A link from a candidate with an open challenge is a submission — the
    pipeline runs on it. Everything else goes to the coordination agent
    (app/workflow.py), which reads the thread and decides whether to answer,
    and can text either side.
    """
    body = await request.body()

    try:
        webhooks.verify_signature(body, dict(request.headers))
    except webhooks.WebhookError as exc:
        log.warning("webhook rejected: %s", exc)
        raise HTTPException(401, str(exc)) from exc

    payload = await request.json()
    event_id = payload.get("event_id", "")
    event_type = payload.get("event_type", "")

    with get_conn() as conn:
        if event_id and webhooks.already_handled(conn, event_id):
            return JSONResponse({"status": "duplicate"})

        inbound = webhooks.parse_inbound(payload)
        if inbound is None:
            webhooks.mark_handled(conn, event_id, event_type)
            return JSONResponse({"status": "ignored", "reason": "not an inbound text"})

        sender, text = inbound
        ctx = webhooks.find_context(conn, sender)
        if ctx is not None:
            # Memory first, agent second: record what came in before anything
            # replies to it, so the thread stays in order.
            tools.record_inbound(sender, text, ctx[0]["package_id"], ctx[1])

        link = webhooks.extract_link(text)
        submission_id = None
        if (
            link is not None
            and ctx is not None
            and ctx[1] == "candidate"
            and (challenge := webhooks.find_open_challenge(conn, sender)) is not None
        ):
            submission_id = pipeline.create_submission(
                parent_id=challenge["package_id"], source_url=link
            )

        webhooks.mark_handled(conn, event_id, event_type, submission_id)

    if submission_id is not None:
        background.add_task(pipeline.process, submission_id)
        background.add_task(workflow.ack_submission, submission_id)
        return JSONResponse({"status": "accepted", "package_id": submission_id})

    if ctx is None and link is None:
        log.info("webhook: text from %s matches no package", sender)
        background.add_task(workflow.handle_inbound, sender, text)
        return JSONResponse({"status": "handled_by_agent", "known_sender": False})

    # Free text (question, nudge, "thanks") — the agent answers or stays quiet.
    # A recruiter's link also lands here: the agent may run verify_zip on it.
    background.add_task(workflow.handle_inbound, sender, text)
    return JSONResponse({"status": "handled_by_agent", "known_sender": True})


@app.get("/verify/{package_id}")
def verify_package(package_id: str) -> JSONResponse:
    """The link every text points at. JSON for now; the template comes later."""
    with get_conn() as conn:
        pkg = get_package(conn, package_id)
    if pkg is None:
        raise HTTPException(404, "no such package")

    return JSONResponse(
        {
            "package_id": pkg["package_id"],
            "sha256": pkg["sha256"],
            "direction": pkg["direction"],
            "status": pkg["status"],
            "verdict": pkg["human_verdict"] or pkg["verdict"],
            "confidence": pkg["confidence"],
            "human_reviewed": bool(pkg["human_reviewed"]),
            "human_verdict": pkg["human_verdict"],
            "signature": pkg["signature"],
            "signed_at": pkg["signed_at"],
        }
    )


@app.get("/pubkey", response_class=PlainTextResponse)
def pubkey() -> str:
    return signing.public_key()


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"
