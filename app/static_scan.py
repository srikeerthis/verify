"""Real implementation. This is the core value of the product.

Contract the pipeline depends on:

    scan(ingested) -> list[Finding]

Findings drive everything downstream. `why` is read aloud to a non-expert
human during Terac escalation, so it's written for someone who does not know
what a postinstall hook is.

Four checks:
  1. Hardcoded secrets — regex over every file (AWS keys, PEM private keys,
     Slack tokens, high-entropy key=/token= assignments). Offline.
  2. Typosquatted dependency names — Levenshtein distance <=2 against a
     popular-package allowlist, from package.json. Offline.
  3. Known-vulnerable dependencies — package.json / requirements.txt versions
     checked against the OSV.dev API (free, no key required).
  4. LLM code review — the checks above only catch known patterns and known
     CVEs. Obfuscated payloads, novel supply-chain tricks (a postinstall hook
     that curls and execs something, a dependency that phones home), and
     anything else that doesn't match a fixed rule needs a model actually
     reading the code. Same OpenAI call agent.py uses for the final verdict,
     but here it's asked to point at *specific* suspicious code, not judge
     the findings — those are two different jobs even though they share a
     client.
"""

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

from app import config
from app.ingest import Ingested

log = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"
MAX_PACKAGES_CHECKED = 50

# LLM code review is bounded on both axes — this is a triage pass over a
# take-home-sized submission, not a full audit of an arbitrary repo.
MAX_FILES_FOR_LLM_REVIEW = 25
MAX_CHARS_PER_FILE = 4_000
MAX_TOTAL_CHARS = 60_000
_REVIEWABLE_EXTENSIONS = {
    ".js", ".ts", ".jsx", ".tsx", ".py", ".rb", ".go", ".rs", ".java",
    ".sh", ".json", ".yml", ".yaml", ".env", ".txt", ".md",
}

_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("generic private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("high-entropy assignment", re.compile(r"(api|secret|token|password)[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_\-/+]{20,}[\"']", re.I)),
]

_POPULAR_PACKAGES = [
    "express", "lodash", "react", "axios", "chalk", "moment", "requests",
    "numpy", "pandas", "django", "flask", "react-dom", "typescript",
    "webpack", "eslint", "jest", "vite", "next", "vue", "tailwindcss",
]


@dataclass
class Finding:
    rule: str
    severity: str        # high | medium
    file: str
    line: int
    snippet: str
    why: str

    def to_dict(self) -> dict:
        return asdict(self)


def _levenshtein(a: str, b: str) -> int:
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        dp[i][0] = i
    for j in range(len(b) + 1):
        dp[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    return dp[len(a)][len(b)]


def _scan_secrets(ingested: Ingested) -> list[Finding]:
    findings = []
    for rel_path in ingested.files:
        full = ingested.root / rel_path
        try:
            content = full.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, pattern in _SECRET_PATTERNS:
            if pattern.search(content):
                findings.append(Finding(
                    rule="secret", severity="high", file=rel_path, line=0,
                    snippet=f"matched pattern: {name}",
                    why=f"this file appears to contain a hardcoded {name.lower()}, "
                        "which should never be committed to source control",
                ))
    return findings


def _parse_npm_deps(package_json_text: str) -> list[tuple[str, str]]:
    try:
        manifest = json.loads(package_json_text)
    except json.JSONDecodeError:
        return []
    deps = {**manifest.get("dependencies", {}), **manifest.get("devDependencies", {})}
    out = []
    for name, version_range in deps.items():
        version = re.sub(r"^[\^~>=<\s]+", "", version_range).strip()
        if re.match(r"^\d", version):
            out.append((name, version))
    return out


def _parse_pip_deps(requirements_text: str) -> list[tuple[str, str]]:
    out = []
    for line in requirements_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(==|>=)\s*([A-Za-z0-9_.-]+)", line)
        if match:
            out.append((match.group(1), match.group(3)))
    return out


def _scan_typosquats(package_json_text: str) -> list[Finding]:
    findings = []
    try:
        manifest = json.loads(package_json_text)
    except json.JSONDecodeError:
        return findings
    deps = {**manifest.get("dependencies", {}), **manifest.get("devDependencies", {})}
    for dep_name in deps:
        for popular in _POPULAR_PACKAGES:
            if dep_name == popular:
                continue
            distance = _levenshtein(dep_name, popular)
            if 0 < distance <= 2:
                findings.append(Finding(
                    rule="typosquat", severity="medium", file="package.json", line=0,
                    snippet=f'dependency "{dep_name}"',
                    why=f'"{dep_name}" is suspiciously close to the popular package "{popular}" — '
                        "a common way to trick people into installing a malicious lookalike",
                ))
                break
    return findings


def _query_osv(name: str, version: str, ecosystem: str) -> list[dict]:
    body = json.dumps({"version": version, "package": {"name": name, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(OSV_API_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError):
        return []  # best-effort — a flaky OSV lookup shouldn't fail the whole scan
    return data.get("vulns", [])


def _scan_vulnerabilities(ingested: Ingested) -> list[Finding]:
    deps: list[tuple[str, str, str]] = []  # (name, version, ecosystem)

    package_json = ingested.root / "package.json"
    if package_json.exists():
        for name, version in _parse_npm_deps(package_json.read_text(encoding="utf-8", errors="ignore")):
            deps.append((name, version, "npm"))

    requirements_txt = ingested.root / "requirements.txt"
    if requirements_txt.exists():
        for name, version in _parse_pip_deps(requirements_txt.read_text(encoding="utf-8", errors="ignore")):
            deps.append((name, version, "PyPI"))

    findings = []
    for name, version, ecosystem in deps[:MAX_PACKAGES_CHECKED]:
        for vuln in _query_osv(name, version, ecosystem):
            findings.append(Finding(
                rule="known_vulnerability", severity="high", file="package manifest", line=0,
                snippet=f"{name}@{version}",
                why=f"{vuln.get('id', 'unknown')}: {vuln.get('summary', 'no summary available')}",
            ))
    return findings


_LLM_REVIEW_SYSTEM_PROMPT = """You are a security code reviewer looking for malicious code in a \
submitted package: credential/data exfiltration, backdoors, obfuscated payloads, destructive \
commands, postinstall/build hooks that download and execute remote code, or anything else a \
fixed rule wouldn't catch. You are NOT reviewing code quality or style — only intent to harm.

Respond with ONLY a JSON object: {"findings": [{"file": string, "line": number, "snippet": \
string, "severity": "high"|"medium", "why": string}]}. `why` is read aloud to a non-technical \
reviewer, so write it for someone who doesn't know what a postinstall hook is. Return an empty \
findings array if nothing looks malicious — most submissions are clean, and flagging ordinary \
code erodes trust in this check."""


def _collect_files_for_llm_review(ingested: Ingested) -> str:
    chunks = []
    total = 0
    for rel_path in ingested.files:
        if total >= MAX_TOTAL_CHARS or len(chunks) >= MAX_FILES_FOR_LLM_REVIEW:
            break
        full = ingested.root / rel_path
        if full.suffix not in _REVIEWABLE_EXTENSIONS:
            continue
        try:
            content = full.read_text(encoding="utf-8", errors="ignore")[:MAX_CHARS_PER_FILE]
        except OSError:
            continue
        chunk = f"--- {rel_path} ---\n{content}\n"
        chunks.append(chunk)
        total += len(chunk)
    return "\n".join(chunks)


def _scan_with_llm(ingested: Ingested) -> list[Finding]:
    if not config.OPENAI_API_KEY:
        log.warning("static_scan: OPENAI_API_KEY not set — skipping LLM code review")
        return []

    source_dump = _collect_files_for_llm_review(ingested)
    if not source_dump.strip():
        return []

    from openai import OpenAI

    client = OpenAI(api_key=config.OPENAI_API_KEY)

    try:
        completion = client.chat.completions.create(
            model=config.SCAN_MODEL,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _LLM_REVIEW_SYSTEM_PROMPT},
                {"role": "user", "content": source_dump},
            ],
        )
        text = completion.choices[0].message.content
        if text is None:
            return []
        parsed = json.loads(text)
    except Exception:  # noqa: BLE001 — best-effort, same as the OSV lookup above
        log.exception("static_scan: LLM code review call failed, skipping")
        return []

    findings = []
    for item in parsed.get("findings", []):
        findings.append(Finding(
            rule="llm_code_review",
            severity=item.get("severity", "medium"),
            file=item.get("file", "unknown"),
            line=int(item.get("line", 0)),
            snippet=item.get("snippet", ""),
            why=item.get("why", ""),
        ))
    return findings


def scan(ingested: Ingested) -> list[Finding]:
    findings = _scan_secrets(ingested)

    package_json = ingested.root / "package.json"
    if package_json.exists():
        findings += _scan_typosquats(package_json.read_text(encoding="utf-8", errors="ignore"))

    findings += _scan_vulnerabilities(ingested)
    findings += _scan_with_llm(ingested)
    return findings
