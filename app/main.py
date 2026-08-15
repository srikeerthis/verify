"""FastAPI routes.

Two of these are contracts other people build against:

  POST /packages       the recruiter form posts here (frontend developer)
  POST /webhooks/linq  Linq posts candidate replies here (mine)

Everything else is the verify surface from CLAUDE.md.
"""

import logging

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from app import config, escalate, pipeline, signing, webhooks
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
) -> JSONResponse:
    """Recruiter intake. Accepts a form post or JSON with the same field names.

    Returns as soon as the row is written; scanning runs in the background. The
    candidate is texted only once the package is scanned and signed, so a 200
    here means "accepted", not "delivered".
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
    """Candidate replies land here.

    Always 200 once the signature checks out, even when we ignore the message.
    A 4xx or 5xx makes Linq retry for 25 minutes, and there is nothing to retry
    when a candidate texts "thanks!".
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
        link = webhooks.extract_link(text)
        if link is None:
            webhooks.mark_handled(conn, event_id, event_type)
            log.info("webhook: no link in reply from %s", sender)
            return JSONResponse({"status": "ignored", "reason": "no link in message"})

        challenge = webhooks.find_open_challenge(conn, sender)
        if challenge is None:
            webhooks.mark_handled(conn, event_id, event_type)
            log.warning("webhook: link from %s matches no open challenge", sender)
            return JSONResponse({"status": "ignored", "reason": "no open challenge"})

    package_id = pipeline.create_submission(
        parent_id=challenge["package_id"], source_url=link
    )

    with get_conn() as conn:
        webhooks.mark_handled(conn, event_id, event_type, package_id)

    background.add_task(pipeline.process, package_id)
    return JSONResponse({"status": "accepted", "package_id": package_id})


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


@app.get("/review/{package_id}", response_class=HTMLResponse)
def review_page(package_id: str) -> str:
    """Where a Terac-recruited reviewer lands (escalate.py's task_url). Shows
    only the snippet/file/why per finding, per CLAUDE.md — never the whole
    package.
    """
    findings = escalate.pending_reviews.get(package_id)
    if findings is None:
        return "<p>No pending review for this package (it may already be decided).</p>"

    rows = "".join(
        f"<tr><td>{f.severity}</td><td>{f.rule}</td><td>{f.file}</td>"
        f"<td><pre>{f.snippet}</pre></td><td>{f.why}</td></tr>"
        for f in findings
    )
    return f"""<!doctype html>
<html><head><title>Verify — Review</title></head>
<body style="font-family: sans-serif; max-width: 800px; margin: 2rem auto;">
  <h1>Review a flagged submission</h1>
  <table border="1" cellpadding="6" style="border-collapse: collapse; width: 100%;">
    <tr><th>Severity</th><th>Rule</th><th>File</th><th>Snippet</th><th>Why</th></tr>
    {rows}
  </table>
  <form method="POST" action="/review/{package_id}/decision" style="margin-top: 1rem;">
    <label><input type="radio" name="human_verdict" value="CLEAN" required> Safe — deliver it</label><br/>
    <label><input type="radio" name="human_verdict" value="MALICIOUS"> Malicious — block it</label><br/>
    <button type="submit">Submit decision</button>
  </form>
</body></html>"""


@app.post("/review/{package_id}/decision")
def review_decision(package_id: str, human_verdict: str = Form(...)) -> JSONResponse:
    if human_verdict not in ("CLEAN", "MALICIOUS"):
        raise HTTPException(422, "human_verdict must be CLEAN or MALICIOUS")
    escalate.resolve(package_id, human_verdict)
    return JSONResponse({"status": "recorded"})


@app.get("/pubkey", response_class=PlainTextResponse)
def pubkey() -> str:
    return signing.public_key()


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"
