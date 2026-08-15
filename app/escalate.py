"""Real implementation: escalates a SUSPICIOUS verdict to a real human expert
via Terac.

Contract the pipeline depends on:

    escalate(package_id, findings) -> None      fire and forget, starts a review
    resolve(package_id, human_verdict) -> None  called when the human answers

Terac doesn't hand back the actual review content itself — it recruits and
verifies a human, then sends them to a task_url we host. `escalate()` creates
a Terac project/opportunity pointing at GET /review/{package_id} (see
main.py), and that page's POST /review/{package_id}/decision handler calls
`resolve()` when the reviewer submits their decision.

Escalation rules from CLAUDE.md that must survive: send only the snippet,
file path, and `why` — never the whole package.
"""

import json
import logging
import time
import urllib.error
import urllib.request

from app import config
from app.static_scan import Finding

log = logging.getLogger(__name__)

TERAC_API_URL = "https://terac.com/api/external/v2"

# In-memory: package_id -> list[Finding], while a review is pending. Read by
# the GET /review/{id} page handler in main.py.
pending_reviews: dict[str, list[Finding]] = {}

_cached_project_id: str | None = None


class EscalationError(Exception):
    pass


def _terac_request(method: str, path: str, body: dict | None = None) -> dict:
    if not config.TERAC_API_KEY:
        raise EscalationError("TERAC_API_KEY is not set")

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{TERAC_API_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {config.TERAC_API_KEY}"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise EscalationError(f"Terac {method} {path} failed: {exc.code} {exc.read().decode(errors='replace')}") from exc
    except urllib.error.URLError as exc:
        raise EscalationError(f"Terac unreachable: {exc.reason}") from exc


def _ensure_project() -> str:
    global _cached_project_id
    if config.TERAC_PROJECT_ID:
        return config.TERAC_PROJECT_ID
    if _cached_project_id:
        return _cached_project_id
    project = _terac_request("POST", "/projects", {"name": "Verify"})
    _cached_project_id = str(project["id"])
    return _cached_project_id


def _request_feasibility(task_description: str) -> str | None:
    created = _terac_request("POST", "/feasibility/requests", {
        "taskDescription": task_description,
        "panelDescription": "Software engineer capable of reviewing static/dynamic security scan findings for malicious code.",
        "submissionCount": 1,
        "timelineHours": 1,
    })
    for _ in range(12):
        status = _terac_request("GET", f"/feasibility/requests/{created['id']}")
        if status.get("status") == "RESPONDED" and status.get("costPerParticipant") is not None:
            return created["id"]
        time.sleep(5)
    return None  # proceed without a priced feasibility request rather than blocking forever


def escalate(package_id: str, findings: list[Finding]) -> None:
    """Launches a real Terac opportunity pointing at our own review page.

    Fire and forget per the contract, but Terac's API calls are themselves
    synchronous — this runs inside the same BackgroundTask as process(), so
    "fire and forget" here just means "the caller doesn't wait on the human,"
    not "this function returns instantly."
    """
    pending_reviews[package_id] = findings

    if not config.is_configured("TERAC_API_KEY") or not config.PUBLIC_BASE_URL.startswith("http"):
        log.warning("escalate %s: TERAC_API_KEY or PUBLIC_BASE_URL not set — "
                    "package will sit in `escalated` until a decision is posted manually "
                    "to POST /review/%s/decision", package_id, package_id)
        return

    try:
        project_id = _ensure_project()
        task_description = (
            "Review automated security scan findings for a code submission and decide "
            "safe or malicious.\n\n" + json.dumps([f.to_dict() for f in findings])
        )
        feasibility_id = _request_feasibility(task_description)

        _terac_request("POST", "/opportunities", {
            "title": "Review a flagged code submission",
            "project_id": project_id,
            "num_participants": 1,
            "business_type": "b2b",
            **({"feasibility_request_id": feasibility_id} if feasibility_id else {}),
            "tasks": [{
                "sequence": 1,
                "task_type": "review",
                "review_type": "auto_approve",
                "task_url": f"{config.PUBLIC_BASE_URL}/review/{package_id}",
                "title": "Verify: code submission review",
                "description": "Review the scan findings and decide safe or malicious.",
                "duration_minutes": 10,
            }],
        })
        log.info("escalate %s: %d findings sent to Terac", package_id, len(findings))
    except EscalationError:
        log.exception("escalate %s: failed to launch Terac opportunity", package_id)


def resolve(package_id: str, human_verdict: str) -> None:
    """Call this when the human answers. Drives signing and notification."""
    from app.pipeline import on_human_verdict

    pending_reviews.pop(package_id, None)
    on_human_verdict(package_id, human_verdict)
