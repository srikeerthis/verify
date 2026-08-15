"""STUB — owned by the ingest/scanner developer.

Contract the pipeline depends on. Keep the signature and the return shape; the
body is yours.

    fetch(source_url) -> Ingested

`fetch` downloads the zip or clones the repo, hashes the bytes, unpacks to a temp
dir, and returns an inventory. Raise IngestError on anything a recruiter could
cause — dead link, not a zip, too big. The pipeline turns that into a `failed`
package, not a 500.
"""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path


class IngestError(Exception):
    """The source link could not be turned into a package."""


@dataclass
class Ingested:
    sha256: str
    root: Path                          # unpacked tree, or a stub path
    files: list[str] = field(default_factory=list)


def fetch(source_url: str) -> Ingested:
    """STUB: hashes the URL string so the pipeline has a stable sha256 to sign.

    Real implementation: download, cap the size, reject anything that is not a
    zip or a git repo, unpack into a temp dir, walk it for the inventory.
    """
    if not source_url.startswith(("http://", "https://")):
        raise IngestError(f"not a fetchable link: {source_url!r}")

    digest = hashlib.sha256(source_url.encode()).hexdigest()
    return Ingested(sha256=digest, root=Path("/nonexistent/stub"), files=[])
