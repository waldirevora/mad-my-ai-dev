"""D6 mock boundary: observe before signing experimental evidence.

This is an in-process test seam, NOT an isolated signing service.
The caller that registers operations is assumed to be trusted.
A mock transport is not authenticated provider communication.
In-memory operation states are not durable one-time consumption.
"""
from __future__ import annotations

import base64
import binascii
import copy
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_bytes, canonical_sha256, sha256_bytes
from .errors import EvidenceError
from .orka_attestation import OrkaReviewAttestationVerifier
from .orka_capture import capture_simulated_review
from .orka_companion import LINK_DOMAIN, verify_companion_evidence
from .orka_durable_state import DurableCaptureStore


RECEIPT_DOMAIN = b"MAD-ORKA-MOCK-REQUEST-RECEIPT/v0\x00"

_RECEIPT_FIELDS = frozenset({
    "kind",
    "operation_id",
    "key_id",
    "request_sha256",
    "capture_sha256",
    "link_sha256",
    "signature",
})


@dataclass
class _Operation:
    attestation: dict[str, Any]
    expected: dict[str, Any]
    now: int
    context: dict[str, Any]
    request_bytes: bytes
    transport: Callable[[bytes], bytes]
    state: str = "ready"


def _operation_fingerprint(
    operation_id: str, operation: _Operation
) -> str:
    return canonical_sha256({
        "operation_id": operation_id,
        "attestation_sha256": canonical_sha256(operation.attestation),
        "bindings_sha256": canonical_sha256(operation.expected),
        "context": operation.context,
        "request_sha256": sha256_bytes(operation.request_bytes),
        "verification_time": operation.now,
    })


class MockCaptureBoundary:
    """A controlled mock workflow, without a caller-facing sign method."""

    def __init__(
        self,
        *,
        verifier: OrkaReviewAttestationVerifier,
        signing_key: Ed25519PrivateKey,
        key_id: str,
        public_key: bytes,
        allowed_endpoints: frozenset[str],
        durable_store: DurableCaptureStore | None = None,
    ) -> None:
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise EvidenceError("invalid mock signing key")
        if type(key_id) is not str or not 0 < len(key_id) <= 128:
            raise EvidenceError("invalid mock key ID")
        if type(public_key) is not bytes or len(public_key) != 32:
            raise EvidenceError("invalid mock public key")
        if type(allowed_endpoints) is not frozenset:
            raise EvidenceError("invalid mock endpoint policy")

        self._verifier = verifier
        self._signing_key = signing_key
        self._key_id = key_id
        self._public_key = public_key
        self._allowed_endpoints = allowed_endpoints
        if durable_store is not None and not isinstance(
            durable_store, DurableCaptureStore
        ):
            raise EvidenceError("invalid durable store")
        self._durable_store = durable_store
        self._operations: dict[str, _Operation] = {}

    def register_authorized_operation(
        self,
        *,
        operation_id: str,
        attestation: dict[str, Any],
        expected: dict[str, Any],
        now: int,
        context: dict[str, Any],
        request_bytes: bytes,
        transport: Callable[[bytes], bytes],
    ) -> None:
        """Test-harness-only registration; not an authorization API.

        Production registration must be restricted to MAD's trusted
        controller using an independently authenticated channel.
        """
        if (
            type(operation_id) is not str
            or not 0 < len(operation_id) <= 128
            or operation_id in self._operations
        ):
            raise EvidenceError("invalid or duplicate mock operation")

        if (
            type(attestation) is not dict
            or type(expected) is not dict
            or type(context) is not dict
            or type(now) is not int
            or type(request_bytes) is not bytes
            or not 0 < len(request_bytes) <= 262_144
            or not callable(transport)
        ):
            raise EvidenceError("invalid mock operation inputs")

        # Check D1 before invoking the simulated transport.
        self._verifier.verify(
            attestation,
            expected=expected,
            now=now,
        )

        reviewer = expected["reviewer"]
        required = {
            "provider": reviewer["provider"],
            "model": reviewer["model"],
            "execution_identity": reviewer["execution_identity"],
            "review_run_id": expected["review_run_id"],
            "gate": expected["gate"],
            "review_generation": expected["review_generation"],
        }

        for field, value in required.items():
            if (
                field not in context
                or type(context[field]) is not type(value)
                or context[field] != value
            ):
                raise EvidenceError(
                    f"mock context binding mismatch: {field}"
                )

        if (
            context.get("endpoint") not in self._allowed_endpoints
            or not context["endpoint"].startswith("https://")
        ):
            raise EvidenceError("mock endpoint is not allowed")

        operation = _Operation(
            attestation=copy.deepcopy(attestation),
            expected=copy.deepcopy(expected),
            now=now,
            context=copy.deepcopy(context),
            request_bytes=request_bytes,
            transport=transport,
        )
        if self._durable_store is not None:
            self._durable_store.register(
                operation_id,
                _operation_fingerprint(operation_id, operation),
            )
        self._operations[operation_id] = operation

    def state(self, operation_id: str) -> str:
        operation = self._operations.get(operation_id)
        if operation is None:
            raise EvidenceError("unknown mock operation")
        if self._durable_store is not None:
            return self._durable_store.state(operation_id)
        return operation.state

    def observe_and_sign(
        self,
        *,
        operation_id: str,
        presented_result: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """Sign only after this mock boundary receives a response."""
        operation = self._operations.get(operation_id)

        if operation is None or operation.state != "ready":
            raise EvidenceError("mock operation is unavailable")

        # The durable claim commits before invoking transport.
        # If execution stops afterward, no automatic retry occurs.
        binding = _operation_fingerprint(operation_id, operation)
        claim_token = (
            self._durable_store.claim(operation_id, binding)
            if self._durable_store is not None
            else None
        )
        operation.state = "needs_reconcile"

        observed = capture_simulated_review(
            context=operation.context,
            allowed_endpoints=self._allowed_endpoints,
            transport=lambda: operation.transport(
                operation.request_bytes
            ),
            presented_result=presented_result,
        )

        capture = observed.capture

        link: dict[str, Any] = {
            "kind": "mad.orka.companion-link.prototype-v1",
            "key_id": self._key_id,
            "attestation_sha256": canonical_sha256(
                operation.attestation
            ),
            "capture_sha256": canonical_sha256(capture),
            "bindings_sha256": canonical_sha256(operation.expected),
        }

        signature = self._signing_key.sign(
            LINK_DOMAIN + canonical_bytes(link)
        )
        link["signature"] = base64.urlsafe_b64encode(
            signature
        ).rstrip(b"=").decode("ascii")

        verify_companion_evidence(
            verifier=self._verifier,
            attestation=operation.attestation,
            expected=operation.expected,
            now=operation.now,
            capture=capture,
            link=link,
            capture_keys={self._key_id: self._public_key},
        )

        # D4's v1 capture does not contain the authorized request
        # commitment. This additional, separately signed mock
        # receipt binds the request bytes to that capture and link.
        receipt: dict[str, Any] = {
            "kind": "mad.orka.mock-request-receipt.v0",
            "operation_id": operation_id,
            "key_id": self._key_id,
            "request_sha256": sha256_bytes(
                operation.request_bytes
            ),
            "capture_sha256": canonical_sha256(capture),
            "link_sha256": canonical_sha256(link),
        }

        receipt_signature = self._signing_key.sign(
            RECEIPT_DOMAIN + canonical_bytes(receipt)
        )
        receipt["signature"] = base64.urlsafe_b64encode(
            receipt_signature
        ).rstrip(b"=").decode("ascii")

        evidence = {
            "capture": capture,
            "link": link,
            "receipt": receipt,
        }

        verify_mock_request_receipt(
            receipt=receipt,
            request_bytes=operation.request_bytes,
            capture=capture,
            link=link,
            public_key=self._public_key,
        )

        if self._durable_store is not None:
            if claim_token is None:
                raise EvidenceError("missing durable claim token")
            self._durable_store.complete(
                operation_id,
                binding,
                claim_token,
                canonical_sha256(evidence),
            )

        operation.state = "completed"
        return evidence


def verify_mock_request_receipt(
    *,
    receipt: dict[str, Any],
    request_bytes: bytes,
    capture: dict[str, Any],
    link: dict[str, Any],
    public_key: bytes,
) -> None:
    """Check a mock request commitment; grant no production authority."""
    if type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS:
        raise EvidenceError("invalid mock receipt shape")

    if receipt["kind"] != "mad.orka.mock-request-receipt.v0":
        raise EvidenceError("unsupported mock receipt kind")

    if type(request_bytes) is not bytes:
        raise EvidenceError("invalid mock request bytes")

    if (
        receipt["request_sha256"] != sha256_bytes(request_bytes)
        or receipt["capture_sha256"] != canonical_sha256(capture)
        or receipt["link_sha256"] != canonical_sha256(link)
    ):
        raise EvidenceError("mock receipt commitment mismatch")

    if type(public_key) is not bytes or len(public_key) != 32:
        raise EvidenceError("invalid mock receipt public key")

    encoded = receipt["signature"]
    if type(encoded) is not str or len(encoded) != 86:
        raise EvidenceError("invalid mock receipt signature")

    try:
        signature = base64.urlsafe_b64decode(encoded + "==")
    except (ValueError, binascii.Error) as exc:
        raise EvidenceError("invalid mock receipt signature") from exc

    if (
        len(signature) != 64
        or base64.urlsafe_b64encode(
            signature
        ).rstrip(b"=").decode("ascii") != encoded
    ):
        raise EvidenceError("noncanonical mock receipt signature")

    unsigned = dict(receipt)
    unsigned.pop("signature")

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            RECEIPT_DOMAIN + canonical_bytes(unsigned),
        )
    except (InvalidSignature, ValueError) as exc:
        raise EvidenceError("invalid mock receipt signature") from exc
