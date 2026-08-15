"""Agentic messaging. Replaces the static templates as the pipe between the
pipeline and Linq:

  announce(event, package_id)      a pipeline event happened — the agent
                                   composes and sends the SMS
  handle_inbound(phone, text)      a text arrived with no link — the agent
                                   reads the thread and answers (or stays
                                   quiet)
  ack_submission(package_id)       candidate sent their solution link — the
                                   agent texts the one-line acknowledgment

Both entry points degrade the same way: no ANTHROPIC_API_KEY (or a model
failure) falls back to notify()'s templates / canned lines, and neither ever
raises into the pipeline. The one rule from pipeline.py survives intact —
nothing is announced until a signature exists, because announce is only
called from _finalize and after, exactly where notify used to be.
"""

import json
import logging

from app import agent, config, notify, tools, webhooks
from app.db import get_conn, get_package

log = logging.getLogger(__name__)

# Which role each event texts. Mirrors notify.EVENTS (the recipient column
# there, the role here) — keep the two dicts in step or the fallback and the
# agent path text different people.
EVENT_ROLES: dict[str, str] = {
    "package_received": "recruiter",
    "package_cleared": "recruiter",
    "package_ready": "candidate",
    "package_blocked": "recruiter",
    "escalation_resolved": "recruiter",
    "submission_verified": "recruiter",
}

# What each event means, in words the model can turn into an SMS. Facts
# (verdict, findings, links) are appended at runtime from the package row —
# prompts here, data there, never data baked into a prompt.
EVENT_PROMPTS: dict[str, str] = {
    "package_received": (
        "The recruiter just uploaded a take-home package. It is queued for "
        "scanning. Text the recruiter a one-line confirmation that you have "
        "it and are scanning it now. No links yet."
    ),
    "package_cleared": (
        "The recruiter's take-home scanned CLEAN, is signed, and has just been "
        "sent to the candidate. Text the recruiter the all-clear: it passed, "
        "it is on its way, and here is the report link. Without this they only "
        "ever hear from us when something is wrong."
    ),
    "package_ready": (
        "The take-home scanned CLEAN, is signed, and is published. Text the "
        "candidate it is ready. Tell them what was checked in plain English "
        "(does not read credentials, does not run code on install) and give "
        "them the download link. Calm and short — this person thinks you "
        "might be a scam."
    ),
    "package_blocked": (
        "The scan flagged this package MALICIOUS and it was blocked. Text the "
        "recruiter: blocked, why (the findings that matter, with their "
        "reasons), and the report link. Blunt is fine — they sent it, they "
        "need to know."
    ),
    "escalation_resolved": (
        "A human reviewer just resolved the escalation on this package. Text "
        "the recruiter the human's verdict and one sentence on why. If the "
        "verdict is CLEAN, say the package is being delivered now."
    ),
    "submission_verified": (
        "The candidate's solution came back, scanned, and is verified. Text "
        "the recruiter it verified and hand them the download link."
    ),
}


def _facts(package_id: str) -> str:
    """The package row as model-readable JSON. This is everything the agent
    is allowed to state as fact; anything else it must look up via tools."""
    with get_conn() as conn:
        pkg = get_package(conn, package_id)
        if pkg is None:
            return "{}"
        findings = json.loads(pkg["findings_json"] or "[]")

    facts = {
        "direction": pkg["direction"],
        "status": pkg["status"],
        "verdict": pkg["human_verdict"] or pkg["verdict"],
        "human_reviewed": bool(pkg["human_reviewed"]),
        "confidence": pkg["confidence"],
        "sha256": pkg["sha256"],
        "source_url": pkg["source_url"],
        "signed_at": pkg["signed_at"],
        "findings": [
            {k: f.get(k) for k in ("rule", "severity", "file", "why")}
            for f in findings
        ],
        "links": {
            "report": f"{config.PUBLIC_BASE_URL}/verify/{package_id}",
            "download": pkg["webapp_download_url"],
            "signature": pkg["webapp_signature_url"],
            "public_key": pkg["webapp_publickey_url"],
        },
    }
    return json.dumps(facts, indent=2)


def _record_run(package_id: str | None, task: str, result: agent.RunResult | None,
                fallback: bool) -> None:
    try:
        with get_conn() as conn:
            conn.execute(
                """
                INSERT INTO agent_runs (package_id, task, result, tool_calls,
                                        fallback)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    package_id,
                    task[:2000],
                    (result.text if result else None),
                    json.dumps(result.tool_calls) if result else None,
                    int(fallback),
                ),
            )
            conn.commit()
    except Exception:  # noqa: BLE001 — logging must never break the run
        log.exception("agent_runs insert failed")


def _agent_task(event: str, package_id: str) -> str:
    role = EVENT_ROLES[event]
    return (
        f"EVENT: {event}\n"
        f"{EVENT_PROMPTS[event]}\n\n"
        f"You must text the {role} — that is the point of this task. Use "
        f"contact_{role} exactly once.\n\n"
        f"Package facts (ground truth — do not contradict, do not invent):\n"
        f"{_facts(package_id)}"
    )


def announce(event: str, package_id: str) -> None:
    """Pipeline event -> agent-composed SMS. Never raises.

    Dedupes on (package_id, event) the same way notify() does, so a rerun or
    a retry after a crash texts once. Falls back to the static template when
    the agent is off or fails mid-run.
    """
    try:
        if event not in EVENT_ROLES:
            log.warning("announce: unknown event %r", event)
            return

        if tools.announce_already_sent(package_id, event):
            log.info("announce %s/%s: already sent", package_id, event)
            return

        task = _agent_task(event, package_id)

        if config.ANTHROPIC_API_KEY:
            try:
                schemas, executors = tools.build(package_id, event=event)
                result = agent.run(
                    task, tools=schemas, executors=executors,
                    history=tools.load_history(package_id),
                )
                _record_run(package_id, task, result, fallback=False)
                if result.tool_calls:
                    log.info("announce %s/%s: agent sent (%d tool calls)",
                             package_id, event, len(result.tool_calls))
                    return
                log.warning("announce %s/%s: agent sent nothing — falling back",
                            package_id, event)
            except agent.AgentError as exc:
                log.warning("announce %s/%s: agent failed — %s — falling back",
                            package_id, event, exc)

        _record_run(package_id, task, None, fallback=True)
        notify.notify(event, package_id)  # template fallback, never raises
    except BaseException:  # noqa: BLE001 — messaging never breaks the pipeline
        log.exception("announce %s/%s crashed", package_id, event)


INBOUND_PROMPT = """\
INBOUND SMS from the {role} ({phone}):
"{text}"

Package facts (ground truth — do not contradict, do not invent):
{facts}
{extra}
Decide what happens next. Use contact_{role} only if saying something is
genuinely useful — package_status first if they are asking about state. A
bare acknowledgment ("thanks", "ok") needs no reply at all.
"""


def handle_inbound(phone: str, text: str) -> None:
    """A text arrived that is not a submission link. Route it to the agent.

    Never raises; runs in a background task off the webhook.
    """
    try:
        with get_conn() as conn:
            ctx = webhooks.find_context(conn, phone)

        if ctx is None:
            _reply_unknown(phone)
            return

        pkg, role = ctx
        # The webhook already recorded this text in agent_messages — main.py
        # does it before dispatching, so the thread stays ordered.

        extra = ""
        if role == "candidate" and pkg["status"] in ("delivered", "signed"):
            extra = (
                "\nThey have a take-home waiting on them. If they seem stuck, "
                "the answer is: reply with a link to their solution (GitHub "
                "or zip) and you will scan it for free.\n"
            )
        if role == "recruiter" and "http" in text:
            extra = (
                "\nThe recruiter sent a link. If it looks like a take-home "
                "package, run verify_zip on it and report the result.\n"
            )

        task = INBOUND_PROMPT.format(
            role=role, phone=phone, text=text,
            facts=_facts(pkg["package_id"]), extra=extra,
        )

        if config.ANTHROPIC_API_KEY:
            try:
                schemas, executors = tools.build(pkg["package_id"])
                result = agent.run(
                    task, tools=schemas, executors=executors,
                    history=tools.load_history(pkg["package_id"]),
                )
                _record_run(pkg["package_id"], task, result, fallback=False)
                return
            except agent.AgentError as exc:
                log.warning("handle_inbound %s: agent failed — %s — falling back",
                            phone, exc)

        _record_run(pkg["package_id"], task, None, fallback=True)
        _stub_reply(pkg, role)
    except BaseException:  # noqa: BLE001
        log.exception("handle_inbound %s crashed", phone)


def ack_submission(package_id: str) -> None:
    """The candidate replied with their solution; a submission was created
    and scanning started. Agent texts the one-line ack."""
    try:
        task = (
            "EVENT: submission_received\n"
            "The candidate just texted a link to their solution. A submission "
            "package was created and the scan is running now. Text the "
            "candidate one calm line: got it, scanning, you'll hear back.\n\n"
            f"Package facts:\n{_facts(package_id)}"
        )

        if config.ANTHROPIC_API_KEY:
            try:
                schemas, executors = tools.build(package_id)
                result = agent.run(
                    task, tools=schemas, executors=executors,
                    history=tools.load_history(package_id),
                )
                _record_run(package_id, task, result, fallback=False)
                if result.tool_calls:
                    return
            except agent.AgentError as exc:
                log.warning("ack_submission %s: agent failed — %s", package_id, exc)

        _record_run(package_id, task, None, fallback=True)
        try:
            tools._send_to(
                package_id, "candidate",
                "Verify: got your submission — scanning it now. We'll text "
                "you the result.",
                event="submission_received",
            )
        except (notify.NotConfigured, notify.LinqError, ValueError) as exc:
            log.info("ack_submission %s: not sent — %s", package_id, exc)
    except BaseException:  # noqa: BLE001
        log.exception("ack_submission %s crashed", package_id)


def _reply_unknown(phone: str) -> None:
    """A number with no package. One polite line, no agent needed."""
    try:
        notify.send_raw(
            phone,
            "Verify: we don't have an open assessment for this number. If you "
            "expected one, ask your recruiter to send it through Verify.",
            f"unknown:{phone}",
        )
    except (notify.NotConfigured, notify.LinqError) as exc:
        log.info("unknown sender %s: no reply — %s", phone, exc)


def _stub_reply(pkg, role: str) -> None:
    """Deterministic fallback when the model is off. Barely smart; that is
    the point — it exists so the loop demos without keys, not to impress."""
    try:
        if role == "candidate":
            body = (
                "Verify: reply with a link to your solution (GitHub or zip) "
                "and we'll scan it and pass it on."
            )
        else:
            verdict = pkg["human_verdict"] or pkg["verdict"] or "still scanning"
            body = f"Verify: package {pkg['package_id'][:8]} — {verdict}."
        tools._send_to(pkg["package_id"], role, body)
    except (notify.NotConfigured, notify.LinqError, ValueError) as exc:
        log.info("stub reply to %s: not sent — %s", role, exc)
