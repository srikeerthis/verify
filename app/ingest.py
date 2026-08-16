"""Real implementation: downloads the zip or clones the repo, hashes the
bytes, unpacks to a temp dir, and returns an inventory.

Contract the pipeline depends on:

    fetch(source_url) -> Ingested

Raises IngestError on anything a recruiter could cause — dead link, not a zip,
not a git repo. The pipeline turns that into a `failed` package, not a 500.
"""

import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024  # 100 MB — a take-home is not a monorepo


class IngestError(Exception):
    """The source link could not be turned into a package."""


@dataclass
class Ingested:
    sha256: str
    root: Path                          # unpacked tree
    files: list[str] = field(default_factory=list)
    cleanup: object = None              # call cleanup() when done with root


def _walk(root: Path) -> list[str]:
    skip = {"node_modules", ".git", "dist", "build", ".venv", "__pycache__"}
    out = []
    for path in root.rglob("*"):
        if path.is_file() and not any(part in skip for part in path.parts):
            out.append(str(path.relative_to(root)))
    return out


def _fetch_zip(source_url: str) -> Ingested:
    try:
        with urllib.request.urlopen(source_url, timeout=30) as resp:
            data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise IngestError(f"could not download {source_url!r}: {exc}") from exc

    if len(data) > MAX_DOWNLOAD_BYTES:
        raise IngestError(f"{source_url!r} is larger than {MAX_DOWNLOAD_BYTES} bytes")

    digest = sha256(data).hexdigest()
    root = Path(tempfile.mkdtemp(prefix="verify-zip-"))
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(root)
    except zipfile.BadZipFile as exc:
        shutil.rmtree(root, ignore_errors=True)
        raise IngestError(f"{source_url!r} is not a valid zip") from exc

    return Ingested(sha256=digest, root=root, files=_walk(root), cleanup=lambda: shutil.rmtree(root, ignore_errors=True))


def _fetch_git(source_url: str) -> Ingested:
    root = Path(tempfile.mkdtemp(prefix="verify-git-"))
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", source_url, str(root)],
            check=True, capture_output=True, timeout=60,
        )
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True, capture_output=True, timeout=10, text=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        shutil.rmtree(root, ignore_errors=True)
        raise IngestError(f"could not clone {source_url!r}: {exc}") from exc

    digest = sha256(head.encode()).hexdigest()
    return Ingested(sha256=digest, root=root, files=_walk(root), cleanup=lambda: shutil.rmtree(root, ignore_errors=True))


def fetch(source_url: str) -> Ingested:
    if not source_url.startswith(("http://", "https://")):
        raise IngestError(f"not a fetchable link: {source_url!r}")

    if source_url.endswith(".zip"):
        return _fetch_zip(source_url)

    try:
        with urllib.request.urlopen(source_url, timeout=10) as resp:
            content_type = resp.headers.get("Content-Type", "")
            peek = resp.read(4)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise IngestError(f"could not reach {source_url!r}: {exc}") from exc

    if "zip" in content_type or peek[:2] == b"PK":
        return _fetch_zip(source_url)

    return _fetch_git(source_url)
