"""Real implementation.

Contract the pipeline depends on:

    judge(findings) -> Verdict

Rule from CLAUDE.md that must survive: every LLM call returns strict JSON,
and a parse failure defaults to SUSPICIOUS. Failing toward human review is the
correct bias.

Uses OpenAI (the key we have) rather than Anthropic — swap MODEL/the client
call if ANTHROPIC_API_KEY is what's actually configured instead.
"""

import json
import logging
from dataclasses import dataclass

from app import config
from app.static_scan import Finding

log = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a security triage agent reviewing findings from an automated \
scan of a code submission (secrets, typosquatted dependencies, known CVEs, and sandbox \
runtime behavior). Decide one of three verdicts:
- "CLEAN": no meaningful risk, deliver the submission as-is.
- "MALICIOUS": clear evidence of malicious intent (credential exfiltration, backdoors, \
destructive commands).
- "SUSPICIOUS": suspicious but ambiguous — escalate to a human reviewer.

Respond with ONLY a JSON object: {"verdict": "CLEAN"|"MALICIOUS"|"SUSPICIOUS", "confidence": \
number between 0 and 1}. Err toward "SUSPICIOUS" rather than "CLEAN" when evidence is \
ambiguous — false negatives are worse than a human review step."""


@dataclass
class Verdict:
    verdict: str        # CLEAN | SUSPICIOUS | MALICIOUS
    confidence: float


def judge(findings: list[Finding]) -> Verdict:
    if not config.OPENAI_API_KEY:
        log.warning("agent.judge: OPENAI_API_KEY not set — defaulting to SUSPICIOUS")
        return Verdict("SUSPICIOUS", 0.0)

    from openai import OpenAI

    client = OpenAI(api_key=config.OPENAI_API_KEY)

    try:
        completion = client.chat.completions.create(
            model=config.AGENT_MODEL,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps([f.to_dict() for f in findings])},
            ],
        )
        text = completion.choices[0].message.content
        if text is None:
            raise ValueError("model returned no content")
        parsed = json.loads(text)
        verdict = parsed["verdict"]
        confidence = float(parsed["confidence"])
        if verdict not in ("CLEAN", "SUSPICIOUS", "MALICIOUS"):
            raise ValueError(f"model returned invalid verdict: {verdict!r}")
        return Verdict(verdict, confidence)
    except Exception:  # noqa: BLE001 — any failure here must fail toward review, not a 500
        log.exception("agent.judge: model call failed, defaulting to SUSPICIOUS")
        return Verdict("SUSPICIOUS", 0.0)
