"""The coordination agent's tools. Built per-run by `build(package_id)` so
every tool is bound to one package — the model can only text the two people
already on that package row, never an arbitrary number.

  contact_recruiter(message)   text the recruiter (company_phone)
  contact_candidate(message)   text the candidate (candidate_phone)
  verify_zip(source_url)       download + scan a package, STUBBED scanner
  package_status()             everything the model may claim out loud

Sends go through notify.send_raw so Linq error handling (retryable vs
permanent, idempotency keys) stays in one place. Every outbound message is
recorded in agent_messages — that table is the agent's memory and announce()'s
dedupe, so a tool that skips the insert would let the agent double-text.
"""

import json
import logging

from app import agent, config, ingest, notify, static_scan
from app.db import get_conn, get_package

log = logging.getLogger(__name__)

ROLE_TO_COLUMN = {"recruiter": "company_phone", "candidate": "candidate_phone"}


def _count_sent(package_id: str, role: str) -> int:
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS n FROM agent_messages
             WHERE package_id = ? AND role = ? AND direction = 'outbound'
            """,
            (package_id, role),
        ).fetchone()
    return row["n"]


def _send_to(package_id: str, role: str, message: str, event: str | None) -> str:
    """Shared body of contact_recruiter / contact_candidate. Returns a short
    status string for the model — it is allowed to see send failures so it
    does not claim a text went out when it did not."""
    message = (message or "").strip()
    if not message:
        raise ValueError("message is empty")

    with get_conn() as conn:
        pkg = get_package(conn, package_id)
        if pkg is None:
            raise ValueError(f"no such package: {package_id}")
        recipient = pkg[ROLE_TO_COLUMN[role]]

    if not recipient:
        return f"not sent: no {role} phone number on this package"

    # Deterministic sequence: a Linq retry after a timeout reuses the key and
    # returns the original send instead of double-texting.
    seq = _count_sent(package_id, role) + 1
    key = f"{package_id}:agent:{role}:{seq}"
    message_id = notify.send_raw(recipient, message, key)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO agent_messages
                (package_id, event, phone, role, direction, body, message_id)
            VALUES (?, ?, ?, ?, 'outbound', ?, ?)
            """,
            (package_id, event, recipient, role, message, message_id),
        )
        conn.commit()

    log.info("agent -> %s (%s): %s", role, package_id, message[:80])
    return f"sent to {role} (message id {message_id})"


def _contact_tool(package_id: str, role: str, event: str | None = None):
    def tool(input: dict) -> str:  # noqa: A002 — Anthropic tool input
        return _send_to(package_id, role, input.get("message", ""), event)

    return tool


def verify_zip(input: dict) -> str:  # noqa: A002 — Anthropic tool input
    """Download a package and scan it. STUBBED: ingest hashes the URL and
    static_scan finds nothing, so this currently always returns CLEAN — the
    plumbing is real so the scanner lands behind the same tool result shape.

    Verdict is the deterministic `judge` heuristic, not a model call: the
    agent reasons over findings but does not get to soften a high-severity
    hit.
    """
    source_url = (input.get("source_url") or "").strip()
    try:
        ingested = ingest.fetch(source_url)
    except ingest.IngestError as exc:
        return json.dumps({"error": f"could not fetch: {exc}"})

    findings = static_scan.scan(ingested)
    verdict = agent.judge(findings)
    return json.dumps(
        {
            "source_url": source_url,
            "sha256": ingested.sha256,
            "file_count": len(ingested.files),
            "verdict": verdict.verdict,
            "confidence": verdict.confidence,
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )


def _package_status(package_id: str):
    def tool(input: dict) -> str:  # noqa: A002
        with get_conn() as conn:
            pkg = get_package(conn, package_id)
            if pkg is None:
                return json.dumps({"error": f"no such package: {package_id}"})
            findings = json.loads(pkg["findings_json"] or "[]")

        return json.dumps(
            {
                "package_id": pkg["package_id"],
                "direction": pkg["direction"],
                "status": pkg["status"],
                "verdict": pkg["human_verdict"] or pkg["verdict"],
                "verdict_source": "human" if pkg["human_reviewed"] else "scanner",
                "confidence": pkg["confidence"],
                "signed": bool(pkg["signature"]),
                "signed_at": pkg["signed_at"],
                "sha256": pkg["sha256"],
                "findings": [
                    {k: f.get(k) for k in ("rule", "severity", "file", "why")}
                    for f in findings
                ],
                "links": {
                    "report": f"{config.PUBLIC_BASE_URL}/verify/{pkg['package_id']}",
                    "download": pkg["webapp_download_url"],
                    "signature": pkg["webapp_signature_url"],
                    "public_key": pkg["webapp_publickey_url"],
                },
            },
            indent=2,
        )

    return tool


def _schema(name: str, description: str, properties: dict, required: list[str]):
    return {
        "name": name,
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": required,
        },
    }


MESSAGE_PROP = {
    "type": "string",
    "description": (
        "The SMS body, under 300 characters, plain text. Links copied exactly "
        "from the task or a tool result."
    ),
}


def build(package_id: str, *, event: str | None = None):
    """Return (tools, executors) bound to one package.

    `event` tags sends for announce() dedupe: the schema the model sees is
    identical either way.
    """
    tools = [
        _schema(
            "contact_recruiter",
            "Text the recruiter (company side). Use for findings, verdicts, "
            "and anything about their take-home or the candidate's submission.",
            {"message": MESSAGE_PROP},
            ["message"],
        ),
        _schema(
            "contact_candidate",
            "Text the candidate. Outcomes only — received, checked, ready — "
            "never scanner internals or file names.",
            {"message": MESSAGE_PROP},
            ["message"],
        ),
        _schema(
            "verify_zip",
            "Download and scan a take-home package (GitHub or zip URL). "
            "Returns sha256, a verdict, and findings with plain-English "
            "reasons. Scanning is rule-based; the current rule set is a stub.",
            {
                "source_url": {
                    "type": "string",
                    "description": "http(s) URL of the zip or repo to scan",
                }
            },
            ["source_url"],
        ),
        _schema(
            "package_status",
            "Everything known about THIS package: status, verdict, signature, "
            "findings, links. Read it before claiming anything out loud.",
            {},
            [],
        ),
    ]
    executors = {
        "contact_recruiter": _contact_tool(package_id, "recruiter", event),
        "contact_candidate": _contact_tool(package_id, "candidate", event),
        "verify_zip": verify_zip,
        "package_status": _package_status(package_id),
    }
    return tools, executors


def record_inbound(phone: str, text: str, package_id: str | None, role: str | None,
                   event: str | None = None) -> None:
    """Persist an inbound SMS so future runs see it in history."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO agent_messages
                (package_id, event, phone, role, direction, body)
            VALUES (?, ?, ?, ?, 'inbound', ?)
            """,
            (package_id, event, phone, role, text),
        )
        conn.commit()


def load_history(package_id: str, limit: int | None = None) -> list[dict]:
    """The SMS thread as Messages API turns.

    Inbound texts (either party) become user turns prefixed with who sent
    them; agent sends become assistant turns. Consecutive same-role turns are
    merged — one thread, the agent in the middle.
    """
    limit = limit or config.AGENT_HISTORY_TURNS
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT role, direction, body FROM agent_messages
             WHERE package_id = ?
             ORDER BY id DESC LIMIT ?
            """,
            (package_id, limit),
        ).fetchall()

    turns: list[dict] = []
    for row in reversed(rows):
        if row["direction"] == "inbound":
            role, content = "user", f"[SMS from {row['role']}] {row['body']}"
        else:
            role, content = "assistant", row["body"]
        if turns and turns[-1]["role"] == role:
            turns[-1]["content"] += f"\n{content}"
        else:
            turns.append({"role": role, "content": content})
    return turns


def announce_already_sent(package_id: str, event: str) -> bool:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT 1 FROM agent_messages
             WHERE package_id = ? AND event = ? AND direction = 'outbound'
            """,
            (package_id, event),
        ).fetchone() is not None
