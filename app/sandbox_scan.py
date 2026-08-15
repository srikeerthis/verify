"""Real dynamic scanning: unpacks a zip package inside an isolated Superserve
sandbox and runs install/build/test there, watching for suspicious runtime
behavior (unexpected network egress, a failed install).

This runs natively in this repo via the official `superserve` Python SDK
(`pip install superserve`) — it does not depend on the Node scan service.
scan_client.py's call to the Node service already runs its own dynamic scan
internally as part of the CLEAN/SUSPICIOUS/MALICIOUS verdict; this module is a
second, independent Superserve invocation so dynamic execution is directly
visible in this repo's own code, not hidden behind another service.

Only handles zip sources for now — git sources are left to the Node service's
own sandbox scan (see scan_client.py).
"""

import logging

from superserve import NetworkConfig, Sandbox

from app import config
from app.static_scan import Finding

log = logging.getLogger(__name__)

_ALLOWED_HOSTS = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]


class SandboxScanError(Exception):
    """The sandbox could not be created or the run could not complete."""


def run(zip_bytes: bytes) -> tuple[list[Finding], dict]:
    """Uploads the zip's contents into a fresh sandbox, runs install/build/test,
    and returns (findings, run_summary). run_summary has install/build/test
    booleans. The sandbox is always killed afterward, even on error.
    """
    if not config.SUPERSERVE_API_KEY:
        raise SandboxScanError("SUPERSERVE_API_KEY is not set")

    import io
    import os
    import zipfile

    sandbox = Sandbox.create(
        name=f"verify-scan-{os.urandom(4).hex()}",
        timeout_seconds=300,
        network=NetworkConfig(allow_out=_ALLOWED_HOSTS),
    )

    findings: list[Finding] = []
    summary = {"install": True, "build": True, "test": True}

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                sandbox.files.write(f"/repo/{name}", zf.read(name))

        has_pkg_json = sandbox.commands.run(
            "test -f /repo/package.json && echo yes || echo no"
        ).stdout.strip() == "yes"
        has_requirements = sandbox.commands.run(
            "test -f /repo/requirements.txt && echo yes || echo no"
        ).stdout.strip() == "yes"

        if has_pkg_json:
            install = sandbox.commands.run(
                "cd /repo && npm install --no-audit --no-fund", timeout_ms=120_000
            )
            summary["install"] = install.exit_code == 0

            build = sandbox.commands.run(
                "cd /repo && npm run build --if-present", timeout_ms=120_000
            )
            summary["build"] = build.exit_code == 0

            test = sandbox.commands.run(
                "cd /repo && npm test --if-present", timeout_ms=120_000
            )
            summary["test"] = test.exit_code == 0
        elif has_requirements:
            install = sandbox.commands.run(
                "cd /repo && pip install -r requirements.txt", timeout_ms=120_000
            )
            summary["install"] = install.exit_code == 0

        # allow_out is a strict registry-only allowlist above, so anything the
        # sandbox itself classifies as "blocked" is exactly the signal we want:
        # a real attempted egress to a host we never permitted.
        blocked = sandbox.get_network_log(verdict="blocked", limit=100)
        for event in blocked.events:
            findings.append(
                Finding(
                    rule="network",
                    severity="high",
                    file="sandbox runtime",
                    line=0,
                    snippet=f"blocked call to {event.host}",
                    why=f"the package tried to reach {event.host} during install/build/test — "
                    "outside the allowed registry hosts, and worth a second look",
                )
            )

        if not summary["install"]:
            findings.append(
                Finding(
                    rule="process",
                    severity="medium",
                    file="sandbox runtime",
                    line=0,
                    snippet="dependency install failed",
                    why="the package's install step failed inside an isolated sandbox",
                )
            )

        return findings, summary
    finally:
        sandbox.kill()
