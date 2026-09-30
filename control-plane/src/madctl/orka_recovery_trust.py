"""D9: controller-provisioned inputs for mock evidence recovery.

This module makes the trust-input dependency explicit. It does NOT
authenticate its provisioner or isolate memory from a hostile agent.
Only a separately controlled MAD controller may provision production
trust roots; that separation is not implemented in this experiment.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .errors import EvidenceError
from .orka_attestation import OrkaReviewAttestationVerifier
from .orka_durable_state import DurableCaptureStore
from .orka_mock_boundary import recover_verified_mock_evidence
from .schemas import SchemaRegistry


@dataclass(frozen=True)
class ControllerRecoveryRecord:
    """Inputs independently authorized by the mock controller."""

    attestation: dict[str, Any]
    expected: dict[str, Any]
    request_bytes: bytes
    receipt_key_id: str


def _copy_public_keys(
    supplied: dict[str, bytes],
    label: str,
) -> dict[str, bytes]:
    if type(supplied) is not dict or not supplied:
        raise EvidenceError(f"invalid {label} registry")

    result: dict[str, bytes] = {}

    for key_id, public_key in supplied.items():
        if (
            type(key_id) is not str
            or not 0 < len(key_id) <= 128
            or type(public_key) is not bytes
            or len(public_key) != 32
        ):
            raise EvidenceError(f"invalid {label} registry entry")

        result[key_id] = public_key

    return result


class MockControllerRecoveryRegistry:
    """Snapshot trust inputs before recovery; expose no in-band overrides.

    This is a test seam, not an authorization service. The constructor
    must be called from a separately trusted control boundary.
    Python object privacy is not a protection against hostile code
    executing in the same process.
    """

    def __init__(
        self,
        *,
        schemas: SchemaRegistry,
        issuer_public_keys: dict[str, bytes],
        capture_public_keys: dict[str, bytes],
        records: Mapping[str, ControllerRecoveryRecord],
        clock: Callable[[], int],
    ) -> None:
        if not isinstance(schemas, SchemaRegistry):
            raise EvidenceError("invalid controller schema registry")

        if not callable(clock):
            raise EvidenceError("invalid controller clock")

        if type(records) is not dict or not records:
            raise EvidenceError("invalid controller recovery records")

        issuer_keys = _copy_public_keys(
            issuer_public_keys, "issuer"
        )
        capture_keys = _copy_public_keys(
            capture_public_keys, "capture"
        )

        copied_records: dict[str, ControllerRecoveryRecord] = {}

        for operation_id, record in records.items():
            if (
                type(operation_id) is not str
                or not 0 < len(operation_id) <= 128
                or type(record) is not ControllerRecoveryRecord
                or type(record.attestation) is not dict
                or type(record.expected) is not dict
                or type(record.request_bytes) is not bytes
                or not 0 < len(record.request_bytes) <= 262_144
                or type(record.receipt_key_id) is not str
                or record.receipt_key_id not in capture_keys
            ):
                raise EvidenceError(
                    "invalid controller recovery record"
                )

            copied_records[operation_id] = ControllerRecoveryRecord(
                attestation=copy.deepcopy(record.attestation),
                expected=copy.deepcopy(record.expected),
                request_bytes=record.request_bytes,
                receipt_key_id=record.receipt_key_id,
            )

        self._schemas = schemas
        self._issuer_keys = issuer_keys
        self._capture_keys = capture_keys
        self._records = copied_records
        self._clock = clock

    def recover(
        self,
        *,
        store: DurableCaptureStore,
        operation_id: str,
    ) -> dict[str, dict[str, Any]]:
        """Recover using provisioned values, never caller-supplied roots."""
        if type(operation_id) is not str:
            raise EvidenceError("invalid recovery operation ID")

        record = self._records.get(operation_id)

        if record is None:
            raise EvidenceError(
                "recovery operation not provisioned by controller"
            )

        now = self._clock()

        if type(now) is not int or now < 0:
            raise EvidenceError("invalid controller verification time")

        # Construct a verifier from this registry's pinned issuer keys.
        # Do not accept an arbitrary verifier from the recovery caller.
        verifier = OrkaReviewAttestationVerifier(
            self._schemas,
            self._issuer_keys,
        )

        return recover_verified_mock_evidence(
            store=store,
            operation_id=operation_id,
            verifier=verifier,
            attestation=copy.deepcopy(record.attestation),
            expected=copy.deepcopy(record.expected),
            now=now,
            request_bytes=record.request_bytes,
            capture_keys=dict(self._capture_keys),
            receipt_public_key=self._capture_keys[
                record.receipt_key_id
            ],
        )
