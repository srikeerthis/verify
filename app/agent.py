"""STUB — owned by the agent developer.

Contract the pipeline depends on:

    judge(findings) -> Verdict

Rule from CLAUDE.md that must survive the real implementation: every LLM call
returns strict JSON, and a parse failure defaults to SUSPICIOUS. Failing toward
human review is the correct bias.
"""

from dataclasses import dataclass

from app.static_scan import Finding


@dataclass
class Verdict:
    verdict: str        # CLEAN | SUSPICIOUS | MALICIOUS
    confidence: float


def judge(findings: list[Finding]) -> Verdict:
    """STUB: severity counting, no model call.

    Real implementation calls the model with the findings and parses strict
    JSON. Keep the thresholds — Terac results feed back into them for the
    v1-vs-v2 accuracy chart.
    """
    if any(f.severity == "high" for f in findings):
        return Verdict("MALICIOUS", 0.9)
    if findings:
        return Verdict("SUSPICIOUS", 0.5)
    return Verdict("CLEAN", 0.95)
