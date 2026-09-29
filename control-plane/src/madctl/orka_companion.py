"""D3 experiment: bind a D1 attestation to simulated capture evidence.

A signed companion link establishes integrity and correspondence
between artifacts. It does NOT authenticate a real provider execution,
establish signing-key isolation, enforce one-time use, or authorize merge.
"""
from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_bytes, canonical_sha256
from .errors import EvidenceError
from .orka_attestation import OrkaReviewAttestationVerifier


LINK_DOMAIN = b"MAD-ORKA-COMPANION-LINK/prototype-v0\x00"

_CAPTURE_FIELDS = frozenset({
    "kind", "provider", "endpoint", "model", "execution_identity",
    "response_id", "review_run_id", "gate", "review_generation",
    "result_sha256", "terminal_state",
})
_LINK_FIELDS = frozenset({
    "kind", "key_id", "attestation_sha256", "capture_sha256",
    "bindings_sha256", "signature",
})
_HEX64 = re.compile(r"[0-9a-f]{64}")
_BASE64_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}")


def verify_companion_evidence(
    *,
    verifier: OrkaReviewAttestationVerifier,
    attestation: dict[str, Any],
    expected: Mapping[str, Any],
    now: int,
    capture: dict[str, Any],
    link: dict[str, Any],
    capture_keys: Mapping[str, bytes],
) -> None:
    """Verify a simulated cross-artifact link; grant no authority.

    `expected` must come from trusted MAD state. `capture_keys` must
    come from protected provisioning. This prototype does not establish
    either source or the authenticity of the simulated capture.
    """
    attestation_digest = verifier.verify(
        attestation, expected=expected, now=now
    )

    if type(capture) is not dict or set(capture) != _CAPTURE_FIELDS:
        raise EvidenceError("invalid companion capture shape")

    if capture["kind"] != "mad.orka.simulated-capture.v0":
        raise EvidenceError("unsupported companion capture kind")

    if capture["terminal_state"] != "success":
        raise EvidenceError("companion capture is not terminal success")

    for field in (
        "provider", "endpoint", "model", "execution_identity",
        "response_id", "review_run_id", "gate",
    ):
        value = capture[field]
        if type(value) is not str or not 0 < len(value) <= 255:
            raise EvidenceError(f"invalid companion capture field: {field}")

    if (
        type(capture["review_generation"]) is not int
        or capture["review_generation"] < 1
        or type(capture["result_sha256"]) is not str
        or _HEX64.fullmatch(capture["result_sha256"]) is None
    ):
        raise EvidenceError("invalid companion capture result metadata")

    reviewer = expected["reviewer"]
    required = {
        "provider": reviewer["provider"],
        "model": reviewer["model"],
        "execution_identity": reviewer["execution_identity"],
        "review_run_id": expected["review_run_id"],
        "gate": expected["gate"],
        "review_generation": expected["review_generation"],
        "result_sha256": expected["result_sha256"],
    }
    for field, trusted_value in required.items():
        if type(capture[field]) is not type(trusted_value):
            raise EvidenceError(f"companion capture binding mismatch: {field}")
        if capture[field] != trusted_value:
            raise EvidenceError(f"companion capture binding mismatch: {field}")

    if type(link) is not dict or set(link) != _LINK_FIELDS:
        raise EvidenceError("invalid companion link shape")

    if link["kind"] != "mad.orka.companion-link.prototype-v0":
        raise EvidenceError("unsupported companion link kind")

    key_id = link["key_id"]
    if type(key_id) is not str or not 0 < len(key_id) <= 128:
        raise EvidenceError("invalid companion signing key ID")

    for field in (
        "attestation_sha256", "capture_sha256", "bindings_sha256",
    ):
        value = link[field]
        if type(value) is not str or _HEX64.fullmatch(value) is None:
            raise EvidenceError(f"invalid companion link field: {field}")

    if link["attestation_sha256"] != attestation_digest:
        raise EvidenceError("companion attestation digest mismatch")
    if link["capture_sha256"] != canonical_sha256(capture):
        raise EvidenceError("companion capture digest mismatch")
    if link["bindings_sha256"] != canonical_sha256(dict(expected)):
        raise EvidenceError("companion trusted bindings digest mismatch")

    if not isinstance(capture_keys, Mapping):
        raise EvidenceError("invalid companion key registry")
    public_key = capture_keys.get(key_id)
    if type(public_key) is not bytes or len(public_key) != 32:
        raise EvidenceError("untrusted companion signing key")

    encoded = link["signature"]
    if (
        type(encoded) is not str
        or _BASE64_SIGNATURE.fullmatch(encoded) is None
    ):
        raise EvidenceError("invalid companion signature encoding")

    try:
        signature = base64.urlsafe_b64decode(encoded + "==")
    except (ValueError, binascii.Error) as exc:
        raise EvidenceError("invalid companion signature encoding") from exc

    if (
        len(signature) != 64
        or base64.urlsafe_b64encode(signature).rstrip(b"=").decode() != encoded
    ):
        raise EvidenceError("noncanonical companion signature")

    unsigned = dict(link)
    unsigned.pop("signature")

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, LINK_DOMAIN + canonical_bytes(unsigned)
        )
    except (InvalidSignature, ValueError) as exc:
        raise EvidenceError("invalid companion signature") from exc
