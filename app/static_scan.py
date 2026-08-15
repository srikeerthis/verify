"""STUB — owned by the scanner developer. This is the core value of the product;
see the rule list in CLAUDE.md.

Contract the pipeline depends on:

    scan(ingested) -> list[Finding]

Findings drive everything downstream. `why` is read aloud to a non-expert human
during Terac escalation, so write it for someone who does not know what a
postinstall hook is.
"""

from dataclasses import asdict, dataclass

from app.ingest import Ingested


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


def scan(ingested: Ingested) -> list[Finding]:
    """STUB: finds nothing, so every package scans CLEAN.

    That is deliberate — it lets the Linq round trip be demoed end to end before
    the scanner exists. Replace with the rule set in CLAUDE.md.
    """
    return []
