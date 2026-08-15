# CLAUDE.md

## What we are building

A trust middleman for take-home coding assessments.

Companies publish take-homes as public GitHub links or zip files. Candidates are
expected to download and run them. Fake-recruiter campaigns abuse exactly this
pattern to get developers to execute credential-stealing code. The same trust gap
exists in reverse: the company has to open a stranger's repo.

We sit in the middle. We ingest both packages, run them in sandboxes, have agents
do QA and verification, and cryptographically sign off. Ambiguous verdicts escalate
to a real human through Terac.

**One-liner:** verified handoff for take-home assessments, run by agents.

## System flow

```
1. publish          COMPANY  ──▶  MIDDLEMAN     (company uploads take-home package)
2. ingest           MIDDLEMAN                   (hash, unpack, inventory)
3. sandbox          MIDDLEMAN                   (static scan + isolated execution)
4. agents           MIDDLEMAN                   (LLM agent reads reports, issues verdict)
5. verdict = maybe  MIDDLEMAN ──▶ HUMAN (terac) (only when SUSPICIOUS)
6. deliver          MIDDLEMAN ──▶ CANDIDATE     (signed, verifiable package)
7. submit           CANDIDATE ──▶ MIDDLEMAN     (candidate's solution, signed)
8. final verdict    HUMAN     ──▶ MIDDLEMAN     (human resolves ambiguous cases)
9. verified submission        MIDDLEMAN ──▶ COMPANY
```

Both directions use the same pipeline. Steps 1–6 and 7–9 are the same code path
with a different `direction` field.

## Stack

- **Python 3.11 + FastAPI** — single language across the whole team
- **SQLite** — no migrations, no ops, good enough for today
- **Docker** — sandbox execution
- **Jinja2 templates + plain HTML** — no frontend framework, no build step
- **Render** — deploy early, deploy often
- **Stripe Checkout** — hosted page, do not build a card form
- **Linq** — coordination messaging to company and candidate
- **Terac MCP** — human escalation

## Repo layout

```
app/
  main.py            FastAPI routes
  ingest.py          unpack, hash, inventory files
  static_scan.py     rule-based detection (the core value)
  sandbox.py         Docker execution, network denied
  agent.py           LLM verdict from scan reports
  escalate.py        Terac MCP call + result handling
  signing.py         Ed25519 sign and verify
  notify.py          Linq messages
  pay.py             Stripe Checkout
  db.py              SQLite
templates/
fixtures/            test packages — INERT ONLY
keys/                dev keypair (gitignored)
```

## Verdict schema

Every scan produces exactly this. Do not add fields without updating all consumers.

```json
{
  "package_id": "uuid",
  "sha256": "hex",
  "direction": "to_candidate | to_company",
  "verdict": "CLEAN | SUSPICIOUS | MALICIOUS",
  "confidence": 0.0,
  "findings": [
    {
      "rule": "postinstall_hook",
      "severity": "high",
      "file": "package.json",
      "line": 12,
      "snippet": "...",
      "why": "runs on install, before review"
    }
  ],
  "human_reviewed": false,
  "human_verdict": null,
  "signature": "base64",
  "signed_at": "iso8601"
}
```

Routing: CLEAN and MALICIOUS finalize automatically. SUSPICIOUS goes to Terac.

## Static scan rules

This is where the real detection value is. Build these first — they catch the
actual documented attack pattern, which is credential exfiltration, not
destruction.

**High severity**

- `postinstall` / `preinstall` / `prepare` hooks in package.json
- reads of `~/.ssh`, `~/.aws`, `~/.config/gcloud`, browser cookie stores, keychain,
  crypto wallet paths
- `eval`, `exec`, `Function()` applied to fetched or decoded content
- `child_process.spawn` / `subprocess` invoking a shell with a piped download
- outbound requests to raw IPs, or to domains not in an allowlist of package registries

**Medium severity**

- base64 or hex blobs longer than 200 characters
- minified or obfuscated source in a repo that ships unminified source elsewhere
- environment variable enumeration followed by any network call
- dependency names one edit-distance from a popular package

**Output**: rule id, file, line, the snippet, and a plain-English `why`. The `why`
field is what a non-expert human reads during Terac escalation, so write it for
someone who does not know what a postinstall hook is.

## Sandbox config

```
docker run --rm
  --network=none
  --read-only
  --user 65534:65534
  --memory=512m --cpus=1 --pids-limit=128
  --cap-drop=ALL
  --security-opt=no-new-privileges
  -v /tmp/pkg:/pkg:ro
```

Capture attempted network calls, file access outside `/pkg`, and spawned processes.
Timeout at 30 seconds and treat a timeout as a finding, not an error.

## Terac escalation contract

Do not ask a general-population reviewer whether code is malware. They cannot
answer that. Ask a question they can answer from the snippet alone:

> This is code from a take-home coding test. It reads the file `~/.ssh/id_rsa`.
> Does a coding test have a legitimate reason to read this file?
> [Yes, plausible] / [No, suspicious] / [Not sure]

Send: the snippet, the file path, the rule's `why`. Never send the whole package.
Two independent reviewers per escalation; disagreement resolves to SUSPICIOUS and
we say so in the report rather than guessing.

## Signing

Ed25519 over the canonical JSON of `{sha256, verdict, direction, signed_at}`.

- `GET /verify/{package_id}` returns the verdict and signature
- `POST /verify` accepts a signature and returns valid/invalid
- Publish the public key at `/pubkey`

Keep it simple. This is twenty lines and it is the most convincing part of the demo.

## Build order

1. Upload → ingest → static scan → verdict page (no sandbox, no signing)
2. **Launch the Terac study as soon as step 1 produces findings** — recruitment
   latency is not under our control, so this gates everything downstream
3. Signing + `/verify`
4. Docker sandbox
5. Terac results fold back into thresholds, rerun, chart v1 vs v2 accuracy
6. Stripe Checkout
7. Linq notifications

## Cut list, in order

If behind schedule, drop from the top:

1. Linq notifications
2. Docker sandbox (static scan + signing + Terac escalation is already a complete product)
3. Company-side direction (scan only candidate-received packages)

Never cut: static scan, signing, Terac escalation, the before/after chart.

## Rules

- **Never write real malware.** Use the EICAR test string for the antivirus path and
  inert canaries for everything else — a postinstall that echoes a string, a fetch to
  example.com. Detection is the product; a live payload in this repo is a liability.
- Static scan is the core. Do not spend time on the sandbox until the scanner works.
- No auth, no user accounts, no admin panel. Package IDs are unguessable UUIDs.
- Every LLM call returns strict JSON. Parse defensively and default to SUSPICIOUS
  on a parse failure — failing toward human review is the correct bias here.
- Deploy to Render within the first hour and keep it deployed. A localhost demo at
  6:30 PM is a lost demo.

## Metrics for the demo

Track these from the start; they are the four numbers judges look at:

- packages scanned
- escalations sent to humans, and median time to human verdict
- scanner accuracy v1 vs v2 on the fixture set (the Terac before/after)
- Stripe revenue

## Demo script (five minutes)

1. Upload an inert malicious fixture. Findings appear with plain-English reasons.
2. Upload the ambiguous fixture. Watch it route to a real human through Terac.
3. Human verdict returns live. Package is signed.
4. Hit `/verify` from a phone — independently verifiable.
5. Show the four metrics. Close on the v1-vs-v2 accuracy chart.
