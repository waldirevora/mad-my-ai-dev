"""D1 only: verify an Orka review attestation; never authorize a merge.

The caller MUST supply bindings obtained independently from trusted MAD state,
not copied from the attestation. Key material must come from a protected
allowlist; the reviewer/worker cannot add an issuer. This verifier is stateless:
atomic one-time consumption, provider provenance and isolation are NOT supplied
here and are mandatory in later D1/D2 work before any merge integration.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_bytes, canonical_sha256, sha256_bytes, verify_canonical_artifact
from .errors import EvidenceError
from .schemas import SchemaRegistry

_DOMAIN = b"MAD-ORKA-BRIDGE/v1\x00"
_MAX_TTL_SECONDS = 900
_CLOCK_SKEW_SECONDS = 30

# All of these must come from independently verified controller/gateway data.
_REQUIRED_BINDINGS = frozenset(
    {
        "issuer",
        "repository",
        "pr",
        "source",
        "target",
        "challenge_sha256",
        "policy_sha256",
        "nonce",
        "review_generation",
        "gate",
        "reviewer",
        "review_run_id",
        "result_sha256",
        "orka",
    }
)


def _decode_signature(value: str) -> bytes:
    """Decode one canonical, unpadded base64url Ed25519 signature."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", value):
        raise EvidenceError("invalid review attestation signature encoding")
    try:
        raw = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EvidenceError("invalid review attestation signature encoding") from exc
    if len(raw) != 64 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise EvidenceError("noncanonical review attestation signature")
    return raw


class OrkaReviewAttestationVerifier:
    """Verify cryptographic integrity and exact externally supplied bindings.

    This does not establish that the producer observed a real provider run;
    that must be established separately before its key can be trusted.
    This does not make an approval decision or consume an attestation ID.
    """

    def __init__(self, schemas: SchemaRegistry, trusted_keys: Mapping[str, bytes]) -> None:
        self.schemas = schemas
        self.trusted_keys = dict(trusted_keys)

    def verify(
        self,
        attestation: dict[str, Any],
        *,
        expected: Mapping[str, Any],
        now: int,
        raw: bytes | None = None,
    ) -> str:
        """Return the attestation digest only if all verification checks pass.

        ``expected`` MUST come from protected state and authenticated provider
        capture, not from ``attestation`` or an agent-controlled ledger. All
        required bindings must be supplied. A later protected store must enforce
        atomic, durable one-time use of the returned digest/attestation ID.
        """
        self.schemas.validate("orka-review-attestation", attestation)
        if not isinstance(now, int) or isinstance(now, bool) or now < 0:
            raise EvidenceError("invalid trusted verification timestamp")
        if not isinstance(expected, Mapping) or set(expected) != _REQUIRED_BINDINGS:
            raise EvidenceError("incomplete trusted review attestation bindings")

        issued, expires = attestation["issued_at"], attestation["expires_at"]
        if issued > now + _CLOCK_SKEW_SECONDS:
            raise EvidenceError("review attestation issued in the future")
        if expires <= now or expires <= issued:
            raise EvidenceError("review attestation is expired or has invalid lifetime")
        if expires - issued > _MAX_TTL_SECONDS:
            raise EvidenceError("review attestation exceeds maximum lifetime")

        issuer = attestation["issuer"]
        signature = attestation["signature"]
        key_id = issuer["key_id"]
        if signature["key_id"] != key_id:
            raise EvidenceError("review attestation signer key ID mismatch")
        public_key_bytes = self.trusted_keys.get(key_id)
        if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
            raise EvidenceError("untrusted review attestation issuer key")
        unsigned = dict(attestation)
        unsigned.pop("signature")
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
                _decode_signature(signature["value"]), _DOMAIN + canonical_bytes(unsigned)
            )
        except (InvalidSignature, ValueError) as exc:
            raise EvidenceError("review attestation signature is invalid") from exc

        if raw is not None:
            verify_canonical_artifact(raw, attestation)
        for field in sorted(_REQUIRED_BINDINGS):
            if attestation[field] != expected[field]:
                raise EvidenceError(f"review attestation binding mismatch: {field}")
        if (
            (attestation["gate"] == "code-review" and attestation["reviewer"]["role"] != "code-reviewer")
            or (attestation["gate"] == "security-review" and attestation["reviewer"]["role"] != "security-reviewer")
        ):
            raise EvidenceError("review attestation reviewer role does not match gate")
        if attestation["verdict"] != "PASS":
            raise EvidenceError("review attestation verdict is not PASS")
        return sha256_bytes(raw) if raw is not None else canonical_sha256(attestation)
