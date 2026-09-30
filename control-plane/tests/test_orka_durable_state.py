"""D7: SQLite transition, restart, and replay tests.

These tests do not establish protection from filesystem tampering,
provider authenticity, or an isolated signing process.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

from madctl.canonical import canonical_sha256
from madctl.errors import EvidenceError, IndeterminateExternalResult
from madctl.orka_durable_state import DurableCaptureStore
from madctl.orka_mock_boundary import MockCaptureBoundary

from test_orka_companion import bundle
from test_orka_mock_boundary import (
    ENDPOINT,
    OPERATION_ID,
    REQUEST,
    case,
    observe,
    register,
    verify_chain,
)


def make_service(case, store):
    bundle = case["bundle"]
    return MockCaptureBoundary(
        verifier=bundle["verifier"],
        signing_key=bundle["capture_key"],
        key_id="d3-capture-key",
        public_key=bundle["capture_keys"]["d3-capture-key"],
        allowed_endpoints=frozenset({ENDPOINT}),
        durable_store=store,
    )


@pytest.fixture
def durable_case(case, tmp_path):
    path = tmp_path / "capture.sqlite3"
    store = DurableCaptureStore(path)
    case["service"] = make_service(case, store)
    case["store"] = store
    case["database_path"] = path
    return case


def test_complete_chain_survives_store_reopening(durable_case):
    register(durable_case)
    evidence = observe(durable_case)
    verify_chain(durable_case, evidence)

    assert durable_case["calls"] == [REQUEST]
    assert durable_case["store"].state(OPERATION_ID) == "completed"

    reopened = DurableCaptureStore(
        durable_case["database_path"]
    )
    assert reopened.state(OPERATION_ID) == "completed"
    assert reopened.evidence_sha256(OPERATION_ID) == (
        canonical_sha256(evidence)
    )

    durable_case["service"] = make_service(
        durable_case, reopened
    )

    with pytest.raises(EvidenceError, match="duplicate"):
        register(durable_case)

    assert durable_case["calls"] == [REQUEST]


def test_timeout_stays_indeterminate_after_restart(durable_case):
    def timeout(sent):
        durable_case["calls"].append(sent)
        raise TimeoutError("simulated network timeout")

    register(durable_case, transport=timeout)

    with pytest.raises(
        IndeterminateExternalResult,
        match="reconciliation",
    ):
        observe(durable_case)

    reopened = DurableCaptureStore(
        durable_case["database_path"]
    )

    assert reopened.state(OPERATION_ID) == "needs_reconcile"
    assert reopened.evidence_sha256(OPERATION_ID) is None

    with pytest.raises(EvidenceError, match="unavailable"):
        observe(durable_case)

    durable_case["service"] = make_service(
        durable_case, reopened
    )

    with pytest.raises(EvidenceError, match="duplicate"):
        register(durable_case)

    assert durable_case["calls"] == [REQUEST]


def test_crash_after_claim_cannot_resubmit(tmp_path):
    path = tmp_path / "capture.sqlite3"
    store = DurableCaptureStore(path)
    store.register("crash-operation", "a" * 64)

    token = store.claim("crash-operation", "a" * 64)
    assert len(token) == 32

    reopened = DurableCaptureStore(path)
    assert reopened.state("crash-operation") == "needs_reconcile"

    with pytest.raises(EvidenceError, match="unavailable"):
        reopened.claim("crash-operation", "a" * 64)


def test_atomic_claim_allows_only_one_concurrent_claim(tmp_path):
    path = tmp_path / "capture.sqlite3"
    first = DurableCaptureStore(path)
    second = DurableCaptureStore(path)
    first.register("parallel-operation", "a" * 64)

    def attempt(store):
        try:
            return store.claim("parallel-operation", "a" * 64)
        except EvidenceError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, (first, second)))

    assert sum(token is not None for token in results) == 1
    assert first.state("parallel-operation") == "needs_reconcile"


def test_wrong_claim_token_does_not_complete(tmp_path):
    store = DurableCaptureStore(
        tmp_path / "capture.sqlite3"
    )
    store.register("token-operation", "a" * 64)
    token = store.claim("token-operation", "a" * 64)

    with pytest.raises(EvidenceError, match="claim mismatch"):
        store.complete(
            "token-operation",
            "a" * 64,
            b"x" * 32,
            "b" * 64,
        )

    assert store.state("token-operation") == "needs_reconcile"

    store.complete(
        "token-operation",
        "a" * 64,
        token,
        "b" * 64,
    )

    assert store.state("token-operation") == "completed"
    assert store.evidence_sha256("token-operation") == "b" * 64


def test_changed_binding_cannot_claim(tmp_path):
    store = DurableCaptureStore(
        tmp_path / "capture.sqlite3"
    )
    store.register("binding-operation", "a" * 64)

    with pytest.raises(EvidenceError, match="binding mismatch"):
        store.claim("binding-operation", "b" * 64)

    assert store.state("binding-operation") == "ready"


def test_invalid_review_does_not_create_durable_operation(
    durable_case,
):
    changed = copy.deepcopy(durable_case["context"])
    changed["provider"] = "unauthorized-provider"

    with pytest.raises(EvidenceError, match="binding mismatch"):
        register(durable_case, context=changed)

    with pytest.raises(EvidenceError, match="unknown"):
        durable_case["store"].state(OPERATION_ID)

    assert durable_case["calls"] == []


def test_post_response_verification_failure_stays_indeterminate(
    durable_case,
):
    register(durable_case)

    # Force the mock verifier to reject the signature after the
    # simulated response has been received.
    durable_case["service"]._public_key = b"\x00" * 32

    with pytest.raises(EvidenceError):
        observe(durable_case)

    reopened = DurableCaptureStore(
        durable_case["database_path"]
    )

    assert reopened.state(OPERATION_ID) == "needs_reconcile"
    assert durable_case["calls"] == [REQUEST]


def test_store_retains_digests_not_request_or_response(
    durable_case,
):
    register(durable_case)
    observe(durable_case)

    database = durable_case["database_path"].read_bytes()

    assert REQUEST not in database
    assert durable_case["raw"] not in database


def test_repeated_completion_is_rejected(tmp_path):
    store = DurableCaptureStore(
        tmp_path / "capture.sqlite3"
    )
    store.register("completed-operation", "a" * 64)
    token = store.claim("completed-operation", "a" * 64)
    store.complete(
        "completed-operation", "a" * 64, token, "b" * 64
    )

    with pytest.raises(EvidenceError, match="unavailable"):
        store.complete(
            "completed-operation", "a" * 64, token, "b" * 64
        )


def test_untrusted_database_path_is_rejected(tmp_path):
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"not a database")
    link = tmp_path / "linked.sqlite3"
    link.symlink_to(target)

    with pytest.raises(EvidenceError, match="database path"):
        DurableCaptureStore(link)
