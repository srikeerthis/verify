"""STUB — owned by the Terac developer.

Contract the pipeline depends on:

    escalate(package_id, findings) -> None      fire and forget, starts a review
    resolve(package_id, human_verdict) -> None  called when the human answers

`resolve` is the hook Linq cares about: when it lands, the pipeline signs the
package and the notification goes out. Call `pipeline.on_human_verdict` from
your side (or just call `resolve` here) and the messaging follows automatically.

Escalation rules from CLAUDE.md that must survive: send only the snippet, file
path, and `why` — never the whole package. Two independent reviewers, and
disagreement resolves to SUSPICIOUS.
"""

import logging

from app.static_scan import Finding

log = logging.getLogger(__name__)


def escalate(package_id: str, findings: list[Finding]) -> None:
    """STUB: logs and returns. The package sits in `escalated` until resolved."""
    log.info("escalate %s: %d findings would go to Terac", package_id, len(findings))


def resolve(package_id: str, human_verdict: str) -> None:
    """Call this when the human answers. Drives signing and notification."""
    from app.pipeline import on_human_verdict

    on_human_verdict(package_id, human_verdict)
