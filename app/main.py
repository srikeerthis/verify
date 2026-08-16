"""FastAPI routes.

Two of these are contracts other people build against:

  POST /packages       the recruiter form posts here (frontend developer)
  POST /webhooks/linq  Linq posts candidate replies here (mine)

Everything else is the verify surface from CLAUDE.md.
"""

import json
import logging

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import config, escalate, handoff, pipeline, signing, tools, webhooks, workflow
from app.db import get_conn, get_package, init_db
from app.notify import E164

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = FastAPI(title="Verify")
templates = Jinja2Templates(directory=str(config.TEMPLATE_DIR))


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


STEPS = [
    ("received", "Package received"),
    ("scanning", "Scanning for credential-stealing code"),
    ("signed", "Verdict signed"),
    ("delivered", "Handed on"),
]

# status -> (pill class, short verdict label when there is no verdict yet)
_PILL = {"CLEAN": "ok", "SUSPICIOUS": "warn", "MALICIOUS": "bad"}


def _page_context(pkg) -> dict:
    """Everything verify.html needs, computed here so the template stays dumb."""
    verdict = pkg["human_verdict"] or pkg["verdict"]
    status = pkg["status"]
    is_challenge = pkg["direction"] == "to_candidate"

    # Where we are on the four-step track. `escalated` and `blocked` are not
    # steps — they are answers — so they colour the verdict, not the list.
    order = [s[0] for s in STEPS]
    reached = order.index(status) if status in order else (
        1 if status in ("escalated", "failed") else len(order) - 1
    )
    steps = [
        {"label": label,
         "state": "done" if i < reached else ("now" if i == reached else "")}
        for i, (_, label) in enumerate(STEPS)
    ]

    if status == "blocked":
        headline = "This package was blocked"
        subhead = "The scan found code that goes after credentials. Nobody received it."
    elif status == "escalated":
        headline = "A person is reviewing this"
        subhead = "The scan was ambiguous, so a human is looking at the flagged part."
    elif status == "failed":
        headline = "We couldn't check this"
        subhead = "The link could not be fetched. Nothing was delivered."
    elif status in ("received", "scanning"):
        headline = "Checking this package"
        subhead = "Usually takes under a minute."
    elif is_challenge:
        headline = "This take-home is verified"
        subhead = "Scanned, signed, and safe to open."
    else:
        headline = "This submission is verified"
        subhead = "Scanned and signed, ready for the company to open."

    return {
        "pkg": dict(pkg),
        "findings": json.loads(pkg["findings_json"] or "[]"),
        "steps": steps,
        "headline": headline,
        "subhead": subhead,
        "pill": _PILL.get(verdict, "warn"),
        "verdict_label": verdict or "still scanning",
        "base_url": config.PUBLIC_BASE_URL,
        "submit_url": f"{config.PUBLIC_BASE_URL}/submit/{pkg['package_id']}",
    }


# Declared before the HTML route on purpose: a path parameter happily matches
# "abc.json", so the more specific route has to be registered first.
@app.get("/verify/{package_id}.json")
def verify_json(package_id: str) -> JSONResponse:
    """The machine-readable verdict. Unchanged shape — other services read it."""
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


@app.get("/verify/{package_id}", response_class=HTMLResponse)
def verify_page(request: Request, package_id: str):
    """Tracking. Status and findings, no controls.

    People open these on a phone, from an SMS, often unsure whether we are a
    scam. A wall of JSON was the wrong answer. The JSON is still there for
    anything scripted: /verify/{id}.json, or an Accept: application/json header.

    Deliberately read-only: the package_id is the only thing guarding this URL
    and both sides are texted one, so it must not carry an action that belongs
    to only one of them. Downloading happens through the web app link in the
    candidate's own text; submitting happens at /submit/{id}.
    """
    with get_conn() as conn:
        pkg = get_package(conn, package_id)
        if pkg is None:
            raise HTTPException(404, "no such package")
        submissions = conn.execute(
            """
            SELECT package_id, status, verdict, created_at FROM packages
             WHERE parent_id = ? ORDER BY created_at DESC
            """,
            (package_id,),
        ).fetchall()

    if "application/json" in request.headers.get("accept", ""):
        return verify_json(package_id)

    ctx = _page_context(pkg)
    ctx["submissions"] = [dict(s) for s in submissions]
    return templates.TemplateResponse(request, "verify.html", ctx)


@app.get("/submit/{package_id}", response_class=HTMLResponse)
def submit_page(request: Request, package_id: str, error: str = ""):
    """Where a candidate sends their solution back.

    Replying to the SMS with a link does the same thing. This exists because a
    zip has no other way in, and because "reply to this text" is a lot to ask of
    someone who already suspects we are a scam.
    """
    with get_conn() as conn:
        pkg = get_package(conn, package_id)
    if pkg is None or pkg["direction"] != "to_candidate":
        raise HTTPException(404, "no such take-home")

    return templates.TemplateResponse(
        request, "submit.html",
        {"pkg": dict(pkg), "base_url": config.PUBLIC_BASE_URL, "error": error},
    )


@app.post("/submit/{package_id}")
async def submit_solution(
    request: Request,
    background: BackgroundTasks,
    package_id: str,
    solution_url: str = Form(""),
    file: UploadFile | None = File(None),
):
    """Accept a link or a zip, then run the same pipeline the SMS path runs."""
    with get_conn() as conn:
        pkg = get_package(conn, package_id)
    if pkg is None or pkg["direction"] != "to_candidate":
        raise HTTPException(404, "no such take-home")

    def again(message: str):
        return templates.TemplateResponse(
            request, "submit.html",
            {"pkg": dict(pkg), "base_url": config.PUBLIC_BASE_URL,
             "error": message, "prefill": solution_url},
            status_code=400,
        )

    source_url, webapp = solution_url.strip(), None

    if file is not None and file.filename:
        if not file.filename.lower().endswith(".zip"):
            return again("That doesn't look like a .zip — send a zip or paste a link.")
        data = await file.read()
        if data[:2] != b"PK":
            return again("That file isn't a zip archive.")
        # Park the bytes in the web app so the pipeline has a URL to scan and
        # the company has a signed page to open. Same route handoff uses.
        links = handoff.upload_zip(data, file.filename)
        if links is None:
            return again("We couldn't store that file. Try again, or paste a link.")
        source_url, webapp = links["download_url"], links

    if not source_url.startswith(("http://", "https://")):
        return again("Paste a link starting with http:// or https://, or upload a zip.")

    submission_id = pipeline.create_submission(
        parent_id=package_id, source_url=source_url, webapp=webapp
    )
    background.add_task(pipeline.process, submission_id)
    background.add_task(workflow.ack_submission, submission_id)

    return RedirectResponse(
        f"{config.PUBLIC_BASE_URL}/verify/{submission_id}", status_code=303
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
