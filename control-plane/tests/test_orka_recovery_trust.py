"""D9: adversarial checks for mock recovery trust provisioning.

These tests do not authenticate the registry constructor's caller,
protect Python process memory, or prove real provider provenance.
"""
from __future__ import annotations

import copy

import pytest

from madctl.errors import EvidenceError
from madctl.orka_durable_state import DurableCaptureStore
from madctl.orka_recovery_trust import (
    ControllerRecoveryRecord,
    MockControllerRecoveryRegistry,
)

from test_orka_companion import bundle
from test_orka_mock_boundary import (
    OPERATION_ID,
    REQUEST,
    case,
    observe,
    register,
)
from test_orka_durable_state import durable_case


def make_registry(
    case,
    *,
    expected=None,
    request_bytes=REQUEST,
    issuer_keys=None,
    capture_keys=None,
    receipt_key_id="d3-capture-key",
    clock=None,
):
    trusted = case["bundle"]

    record = ControllerRecoveryRecord(
        attestation=trusted["attestation"],
        expected=(
            trusted["expected"]
            if expected is None
            else expected
        ),
        request_bytes=request_bytes,
        receipt_key_id=receipt_key_id,
    )

    return MockControllerRecoveryRegistry(
        schemas=trusted["verifier"].schemas,
        issuer_public_keys=(
            dict(trusted["verifier"].trusted_keys)
            if issuer_keys is None
            else issuer_keys
        ),
        capture_public_keys=(
            dict(trusted["capture_keys"])
            if capture_keys is None
            else capture_keys
        ),
        records={OPERATION_ID: record},
        clock=(lambda: trusted["now"]) if clock is None else clock,
    )


@pytest.fixture
def completed_case(durable_case):
    register(durable_case)
    durable_case["completed_evidence"] = observe(durable_case)
    return durable_case


def test_controller_provisioned_recovery_after_restart(completed_case):
    registry = make_registry(completed_case)

    completed_case["store"] = DurableCaptureStore(
        completed_case["database_path"]
    )

    recovered = registry.recover(
        store=completed_case["store"],
        operation_id=OPERATION_ID,
    )

    assert recovered == completed_case["completed_evidence"]
    assert completed_case["calls"] == [REQUEST]


def test_recovery_caller_cannot_override_trust_inputs(completed_case):
    registry = make_registry(completed_case)

    with pytest.raises(TypeError):
        registry.recover(
            store=completed_case["store"],
            operation_id=OPERATION_ID,
            expected=completed_case["bundle"]["expected"],
        )

    with pytest.raises(TypeError):
        registry.recover(
            store=completed_case["store"],
            operation_id=OPERATION_ID,
            capture_keys=completed_case["bundle"]["capture_keys"],
        )


def test_unknown_operation_cannot_select_arbitrary_evidence(
    completed_case,
):
    registry = make_registry(completed_case)

    with pytest.raises(EvidenceError, match="not provisioned"):
        registry.recover(
            store=completed_case["store"],
            operation_id="not-authorized",
        )


def test_mutating_original_inputs_does_not_change_pinned_snapshot(
    completed_case,
):
    registry = make_registry(completed_case)
    trusted = completed_case["bundle"]

    # Simulate modifications to the objects that were originally
    # passed into mock-controller provisioning.
    trusted["attestation"]["result_sha256"] = "f" * 64
    trusted["expected"]["result_sha256"] = "f" * 64
    trusted["capture_keys"].clear()
    trusted["verifier"].trusted_keys.clear()

    recovered = registry.recover(
        store=completed_case["store"],
        operation_id=OPERATION_ID,
    )

    assert recovered == completed_case["completed_evidence"]


def test_wrong_controller_expected_result_is_rejected(completed_case):
    changed = copy.deepcopy(
        completed_case["bundle"]["expected"]
    )
    changed["result_sha256"] = "f" * 64
    registry = make_registry(completed_case, expected=changed)

    with pytest.raises(EvidenceError, match="binding mismatch"):
        registry.recover(
            store=completed_case["store"],
            operation_id=OPERATION_ID,
        )


def test_wrong_controller_request_is_rejected(completed_case):
    registry = make_registry(
        completed_case,
        request_bytes=b'{"input":"substituted"}',
    )

    with pytest.raises(EvidenceError, match="commitment mismatch"):
        registry.recover(
            store=completed_case["store"],
            operation_id=OPERATION_ID,
        )


def test_unapproved_d1_issuer_key_is_rejected(completed_case):
    registry = make_registry(
        completed_case,
        issuer_keys={"d3-issuer": b"\x01" * 32},
    )

    with pytest.raises(EvidenceError, match="signature"):
        registry.recover(
            store=completed_case["store"],
            operation_id=OPERATION_ID,
        )


def test_unapproved_capture_key_is_rejected(completed_case):
    registry = make_registry(
        completed_case,
        capture_keys={"d3-capture-key": b"\x02" * 32},
    )

    with pytest.raises(EvidenceError, match="signature"):
        registry.recover(
            store=completed_case["store"],
            operation_id=OPERATION_ID,
        )


def test_unprovisioned_receipt_signer_is_rejected(completed_case):
    with pytest.raises(
        EvidenceError,
        match="invalid controller recovery record",
    ):
        make_registry(
            completed_case,
            receipt_key_id="agent-selected-key",
        )


def test_expired_attestation_is_rejected_at_recovery_time(
    completed_case,
):
    registry = make_registry(
        completed_case,
        clock=lambda: 1500,
    )

    with pytest.raises(EvidenceError, match="expired"):
        registry.recover(
            store=completed_case["store"],
            operation_id=OPERATION_ID,
        )


def test_invalid_controller_clock_fails_closed(completed_case):
    registry = make_registry(
        completed_case,
        clock=lambda: True,
    )

    with pytest.raises(
        EvidenceError,
        match="verification time",
    ):
        registry.recover(
            store=completed_case["store"],
            operation_id=OPERATION_ID,
        )


def test_recovery_does_not_resubmit_request(completed_case):
    registry = make_registry(completed_case)

    registry.recover(
        store=completed_case["store"],
        operation_id=OPERATION_ID,
    )
    registry.recover(
        store=completed_case["store"],
        operation_id=OPERATION_ID,
    )

    assert completed_case["calls"] == [REQUEST]


def test_provisioning_remains_an_explicit_mock_trust_assumption(
    durable_case,
):
    # Deliberate counterexample: the test harness controls the
    # transport and can return fabricated provider-looking bytes.
    # Controller-style provisioning does not authenticate the
    # transport or make the resulting signatures authoritative.
    register(
        durable_case,
        transport=lambda sent: durable_case["raw"],
    )
    evidence = observe(durable_case)
    registry = make_registry(durable_case)

    assert registry.recover(
        store=durable_case["store"],
        operation_id=OPERATION_ID,
    ) == evidence
