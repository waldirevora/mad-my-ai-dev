"""D8: atomic persistence, recovery, and tampering regressions.

Only experimental mocked evidence is used. The SQLite file and
test signing keys remain trusted inputs, not production controls.
"""
from __future__ import annotations

import copy
import sqlite3

import pytest

from madctl.canonical import canonical_bytes, sha256_bytes
from madctl.errors import EvidenceError
from madctl.orka_durable_state import DurableCaptureStore
from madctl.orka_mock_boundary import (
    recover_verified_mock_evidence,
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


def recover(case, *, operation_id=OPERATION_ID,
            request_bytes=REQUEST, expected=None, now=None):
    trusted = case["bundle"]

    return recover_verified_mock_evidence(
        store=case["store"],
        operation_id=operation_id,
        verifier=trusted["verifier"],
        attestation=trusted["attestation"],
        expected=(
            trusted["expected"]
            if expected is None
            else expected
        ),
        now=trusted["now"] if now is None else now,
        request_bytes=request_bytes,
        capture_keys=trusted["capture_keys"],
        receipt_public_key=trusted["capture_keys"][
            "d3-capture-key"
        ],
    )


def test_signed_evidence_recovers_after_store_reopening(durable_case):
    register(durable_case)
    original = observe(durable_case)

    durable_case["store"] = DurableCaptureStore(
        durable_case["database_path"]
    )

    recovered = recover(durable_case)

    assert recovered == original
    assert durable_case["store"].state(OPERATION_ID) == "completed"
    assert durable_case["calls"] == [REQUEST]


def test_recovery_does_not_invoke_transport(durable_case):
    register(durable_case)
    observe(durable_case)

    durable_case["store"] = DurableCaptureStore(
        durable_case["database_path"]
    )

    recover(durable_case)
    recover(durable_case)

    assert durable_case["calls"] == [REQUEST]


def test_legacy_digest_only_completion_is_not_recoverable(tmp_path):
    store = DurableCaptureStore(tmp_path / "legacy.sqlite3")
    store.register("legacy-operation", "a" * 64)
    token = store.claim("legacy-operation", "a" * 64)

    # D7 compatibility API: completion stores a digest only.
    store.complete(
        "legacy-operation",
        "a" * 64,
        token,
        "b" * 64,
    )

    reopened = DurableCaptureStore(store.path)

    assert reopened.state("legacy-operation") == "completed"

    with pytest.raises(
        EvidenceError,
        match="missing or invalid durable evidence",
    ):
        reopened.load_completed_evidence("legacy-operation")


def test_failed_artifact_insert_rolls_back_completion(tmp_path):
    store = DurableCaptureStore(tmp_path / "atomic.sqlite3")
    store.register("atomic-operation", "a" * 64)
    token = store.claim("atomic-operation", "a" * 64)

    with sqlite3.connect(store.path) as connection:
        connection.execute("""
            CREATE TRIGGER reject_evidence_insert
            BEFORE INSERT ON evidence_artifacts
            BEGIN
                SELECT RAISE(ABORT, 'injected insert failure');
            END
        """)

    evidence = {
        "capture": {
            "kind": "mad.orka.simulated-capture.v1",
            "provider": "fixture-provider",
            "endpoint": "https://fixture.example/v1",
            "model": "fixture-model",
            "execution_identity": "fixture-executor",
            "response_id": "fixture-response",
            "review_run_id": "fixture-run",
            "gate": "code-review",
            "review_generation": 1,
            "result_sha256": "a" * 64,
            "response_sha256": "b" * 64,
            "terminal_state": "success",
        },
        "link": {
            "kind": "mad.orka.companion-link.prototype-v1",
            "key_id": "fixture-key",
            "attestation_sha256": "a" * 64,
            "capture_sha256": "b" * 64,
            "bindings_sha256": "c" * 64,
            "signature": "x" * 86,
        },
        "receipt": {
            "kind": "mad.orka.mock-request-receipt.v0",
            "operation_id": "atomic-operation",
            "key_id": "fixture-key",
            "request_sha256": "a" * 64,
            "capture_sha256": "b" * 64,
            "link_sha256": "c" * 64,
            "signature": "x" * 86,
        },
    }

    # The store is deliberately exercised without a signing service.
    # It is transactional storage, not a cryptographic verifier.
    with pytest.raises(sqlite3.IntegrityError):
        store.complete_with_evidence(
            "atomic-operation",
            "a" * 64,
            token,
            evidence,
        )

    reopened = DurableCaptureStore(store.path)

    assert reopened.state("atomic-operation") == "needs_reconcile"
    assert reopened.evidence_sha256("atomic-operation") is None

    with pytest.raises(EvidenceError, match="not completed"):
        reopened.load_completed_evidence("atomic-operation")


def test_corrupted_artifact_bytes_are_rejected(durable_case):
    register(durable_case)
    observe(durable_case)

    with sqlite3.connect(
        durable_case["database_path"]
    ) as connection:
        connection.execute(
            """
            UPDATE evidence_artifacts
            SET artifact = ?
            WHERE operation_id = ?
            """,
            (b"{}", OPERATION_ID),
        )

    durable_case["store"] = DurableCaptureStore(
        durable_case["database_path"]
    )

    with pytest.raises(EvidenceError, match="digest mismatch"):
        recover(durable_case)


def test_rehashed_artifact_still_requires_valid_signature(
    durable_case,
):
    register(durable_case)
    observe(durable_case)

    changed = copy.deepcopy(
        durable_case["store"].load_completed_evidence(
            OPERATION_ID
        )
    )
    changed["capture"]["response_sha256"] = "e" * 64

    raw = canonical_bytes(changed)
    digest = sha256_bytes(raw)

    # Simulate privileged database tampering: update both the
    # artifact and its ordinary hash, but not the signing key.
    with sqlite3.connect(
        durable_case["database_path"]
    ) as connection:
        connection.execute(
            """
            UPDATE evidence_artifacts
            SET artifact = ?
            WHERE operation_id = ?
            """,
            (raw, OPERATION_ID),
        )
        connection.execute(
            """
            UPDATE operations
            SET evidence_sha256 = ?
            WHERE operation_id = ?
            """,
            (digest, OPERATION_ID),
        )

    durable_case["store"] = DurableCaptureStore(
        durable_case["database_path"]
    )

    assert durable_case["store"].load_completed_evidence(
        OPERATION_ID
    ) == changed

    with pytest.raises(
        EvidenceError,
        match="companion capture digest mismatch",
    ):
        recover(durable_case)


def test_wrong_request_cannot_recover_signed_receipt(durable_case):
    register(durable_case)
    observe(durable_case)

    with pytest.raises(
        EvidenceError,
        match="mock receipt commitment mismatch",
    ):
        recover(
            durable_case,
            request_bytes=b'{"input":"changed"}',
        )


def test_changed_d1_expectations_block_recovery(durable_case):
    register(durable_case)
    observe(durable_case)

    changed = copy.deepcopy(
        durable_case["bundle"]["expected"]
    )
    changed["result_sha256"] = "f" * 64

    with pytest.raises(EvidenceError):
        recover(durable_case, expected=changed)


def test_evidence_from_other_operation_is_rejected(durable_case):
    register(durable_case)
    original = observe(durable_case)

    store = durable_case["store"]
    other = "other-operation"

    # Deliberately bypass the mock boundary to test recovery's
    # operation-ID check against a signed, transplanted artifact.
    store.register(other, "a" * 64)
    token = store.claim(other, "a" * 64)
    store.complete_with_evidence(
        other,
        "a" * 64,
        token,
        original,
    )

    with pytest.raises(
        EvidenceError,
        match="recovered operation ID mismatch",
    ):
        recover(durable_case, operation_id=other)


def test_claimed_but_uncompleted_operation_cannot_recover(tmp_path):
    store = DurableCaptureStore(tmp_path / "pending.sqlite3")
    store.register("pending-operation", "a" * 64)
    store.claim("pending-operation", "a" * 64)

    reopened = DurableCaptureStore(store.path)

    with pytest.raises(EvidenceError, match="not completed"):
        reopened.load_completed_evidence("pending-operation")


def test_arbitrary_artifact_fields_are_not_persisted(tmp_path):
    store = DurableCaptureStore(tmp_path / "shape.sqlite3")
    store.register("shape-operation", "a" * 64)
    token = store.claim("shape-operation", "a" * 64)

    with pytest.raises(
        EvidenceError,
        match="invalid durable evidence artifact: capture",
    ):
        store.complete_with_evidence(
            "shape-operation",
            "a" * 64,
            token,
            {
                "capture": {"raw_response": "do not persist"},
                "link": {},
                "receipt": {},
            },
        )

    assert store.state("shape-operation") == "needs_reconcile"
    assert store.evidence_sha256("shape-operation") is None


def test_raw_request_and_response_are_not_persisted(durable_case):
    register(durable_case)
    observe(durable_case)

    database_bytes = durable_case["database_path"].read_bytes()

    assert REQUEST not in database_bytes
    assert durable_case["raw"] not in database_bytes
    assert durable_case["store"].state(OPERATION_ID) == "completed"
