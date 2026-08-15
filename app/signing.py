"""STUB — owned by the signing developer.

Contract the pipeline depends on:

    sign(sha256, verdict, direction, signed_at) -> str   (base64 signature)
    verify(payload, signature) -> bool
    public_key() -> str

Per CLAUDE.md: Ed25519 over the canonical JSON of
{sha256, verdict, direction, signed_at}. The canonical form is already correct
below — only the crypto is stubbed — so signatures produced now stay verifiable
in shape once the real key lands.

This matters to Linq specifically: nothing is texted to a candidate until a
signature exists, because the signature is what the link in the message proves.
"""

import base64
import hashlib
import json


def canonical(sha256: str, verdict: str, direction: str, signed_at: str) -> bytes:
    """The exact bytes that get signed. Do not change without re-signing."""
    return json.dumps(
        {
            "sha256": sha256,
            "verdict": verdict,
            "direction": direction,
            "signed_at": signed_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def sign(sha256: str, verdict: str, direction: str, signed_at: str) -> str:
    """STUB: a SHA-256 digest of the canonical payload, not a signature.

    Real implementation: Ed25519 over `canonical(...)` with the key in keys/.
    Twenty lines, and the most convincing part of the demo.
    """
    payload = canonical(sha256, verdict, direction, signed_at)
    return base64.b64encode(b"stub:" + hashlib.sha256(payload).digest()).decode()


def verify(payload: bytes, signature: str) -> bool:
    """STUB: recomputes the digest. Real version verifies against the pubkey."""
    expected = base64.b64encode(b"stub:" + hashlib.sha256(payload).digest()).decode()
    return signature == expected


def public_key() -> str:
    """STUB: served at /pubkey once the real keypair exists."""
    return "stub-public-key"
