"""The coordination agent. Two jobs live here:

  judge(findings) -> Verdict      the scan pipeline's severity call
  run(task, ...)  -> RunResult    an LLM turn with tools (app/tools.py)

The model is called over stdlib urllib, same reasoning as notify.py: one
outbound call does not justify an SDK dependency. Without ANTHROPIC_API_KEY,
`run` raises NotConfigured and app/workflow.py falls back to the static
templates — the product must run green at a demo with no keys set.

Rule from CLAUDE.md that survives: `judge` output is data, not prose, and a
model failure fails toward SUSPICIOUS.
"""

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from app import config
from app.static_scan import Finding

log = logging.getLogger(__name__)


class NotConfigured(Exception):
    """No model credentials. Callers fall back to deterministic behavior."""


class AgentError(Exception):
    """The model call failed in a way a retry might not fix."""


@dataclass
class Verdict:
    verdict: str        # CLEAN | SUSPICIOUS | MALICIOUS
    confidence: float


@dataclass
class RunResult:
    text: str = ""                                  # final assistant text
    tool_calls: list[dict] = field(default_factory=list)  # {name, input} pairs
    turns: int = 0


def judge(findings: list[Finding]) -> Verdict:
    """Severity counting, no model call.

    The thresholds are the v1 baseline — Terac results feed back into them for
    the v1-vs-v2 accuracy chart, so keep them deterministic and logged.
    """
    if any(f.severity == "high" for f in findings):
        return Verdict("MALICIOUS", 0.9)
    if findings:
        return Verdict("SUSPICIOUS", 0.5)
    return Verdict("CLEAN", 0.95)


# --- the coordination agent ----------------------------------------------

SYSTEM_PROMPT = """\
You are Vera, the coordination agent for Verify — a trust middleman for
take-home coding assessments. Recruiters send coding tests through us;
candidates send their solutions back. Every package is scanned for
credential-stealing code before it moves between the two sides. You are the
voice of the product, over SMS, to both sides.

The two people you text:
- the recruiter (company side) — expects specifics: verdicts, findings, links
- the candidate — a developer who never asked for us, may think you are a
  scam, and is anxious about a job

House rules, in order of importance:
1. Never invent facts. A scan result exists only if you see it in verify_zip
   output or package_status. A signature exists only if package_status says
   so. Uncertainty gets hedge-free honesty: "still scanning".
2. The candidate never sees scanner internals: no rule ids, no file names, no
   severity talk. Candidates get outcomes — received, checked, ready,
   blocked — in one calm sentence.
3. The recruiter gets findings with their plain-English "why", trimmed to the
   ones that matter.
4. SMS discipline: under 300 characters, plain English, no markdown, no
   emojis, one message per person per task unless they ask a question.
5. Links are copied exactly from the task or tool output. Never shorten,
   never retype, never guess.
6. Silence is allowed. If nothing useful can be said — a bare "thanks", a
   thumbs up — reply with no tools.
7. You never claim to be human. If asked, you are the Verify agent.
"""


def _call_model(messages: list[dict], tools: list[dict]) -> dict:
    """One Anthropic Messages API call. Returns the parsed response body."""
    if not config.ANTHROPIC_API_KEY:
        raise NotConfigured

    payload = {
        "model": config.AGENT_MODEL,
        "max_tokens": config.AGENT_MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": messages,
        "tools": tools,
    }
    req = urllib.request.Request(
        config.ANTHROPIC_API_URL,
        data=json.dumps(payload).encode(),
        headers={
            "x-api-key": config.ANTHROPIC_API_KEY,
            "Authorization": f"Bearer {config.ANTHROPIC_API_KEY}",
            "anthropic-version": config.ANTHROPIC_API_VERSION,
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60.0) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:500].decode(errors="replace")
        raise AgentError(f"HTTP {exc.code}: {detail}") from exc
    except Exception as exc:  # network, DNS, timeout
        raise AgentError(f"{type(exc).__name__}: {exc}") from exc


def run(
    task: str,
    *,
    tools: list[dict] | None = None,
    executors: dict[str, object] | None = None,
    history: list[dict] | None = None,
) -> RunResult:
    """Run the tool-use loop until the model stops calling tools.

    `tools` is an Anthropic tool schema list; `executors` maps tool name to a
    callable(input: dict) -> str. Both are built per-run by app/tools.py so
    tools can be bound to a package without globals here.

    History is already in Messages API shape; the task is the user turn that
    kicks the run off. Consecutive same-role turns (merged history) are legal.
    """
    tools = tools or []
    executors = executors or {}
    messages = list(history or []) + [{"role": "user", "content": task}]
    result = RunResult()

    for _turn in range(config.AGENT_MAX_TURNS):
        body = _call_model(messages, tools)
        content = body.get("content") or []
        messages.append({"role": "assistant", "content": content})
        result.turns += 1

        tool_uses = [b for b in content if b.get("type") == "tool_use"]
        result.text = "".join(
            b.get("text", "") for b in content if b.get("type") == "text"
        ).strip()
        if not tool_uses:
            return result

        tool_results = []
        for block in tool_uses:
            name, tool_id = block.get("name", ""), block.get("id", "")
            result.tool_calls.append({"name": name, "input": block.get("input", {})})
            try:
                output = executors[name](block.get("input", {}))
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": str(output),
                })
            except Exception as exc:  # noqa: BLE001 — errors go back to the model
                log.warning("agent tool %s failed — %s", name, exc)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "is_error": True,
                    "content": f"{type(exc).__name__}: {exc}",
                })

        messages.append({"role": "user", "content": tool_results})

    log.warning("agent hit max turns (%d) — stopping", config.AGENT_MAX_TURNS)
    return result
