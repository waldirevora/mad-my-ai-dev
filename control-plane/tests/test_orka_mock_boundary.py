"""D6: test the in-process mock capture boundary and its limits."""
from __future__ import annotations

import copy
import json

import pytest

from madctl.canonical import canonical_sha256, sha256_bytes
from madctl.errors import EvidenceError, IndeterminateExternalResult
from madctl.orka_companion import verify_companion_evidence
from madctl.orka_mock_boundary import (
    MockCaptureBoundary,
    verify_mock_request_receipt,
)

from test_orka_companion import bundle, sign_attestation


OPERATION_ID = "authorized-review-0001"
ENDPOINT = "https://fixture.example/v1"
REQUEST = b'{"input":"fixture review request"}'
RESULT = {"verdict": "PASS", "findings": []}


@pytest.fixture
def case(bundle):
    result = copy.deepcopy(RESULT)
    digest = canonical_sha256(result)

    bundle["attestation"]["result_sha256"] = digest
    bundle["expected"]["result_sha256"] = digest
    sign_attestation(bundle["attestation"], bundle["issuer_key"])

    reviewer = bundle["expected"]["reviewer"]
    context = {
        "provider": reviewer["provider"],
        "endpoint": ENDPOINT,
        "model": reviewer["model"],
        "execution_identity": reviewer["execution_identity"],
        "review_run_id": bundle["expected"]["review_run_id"],
        "gate": bundle["expected"]["gate"],
        "review_generation": bundle["expected"]["review_generation"],
    }

    response = {
        "id": "fixture-response-0001",
        "status": "completed",
        "output_text": json.dumps(result),
    }

    raw_response = json.dumps(
        response, separators=(",", ":")
    ).encode("utf-8")

    service = MockCaptureBoundary(
        verifier=bundle["verifier"],
        signing_key=bundle["capture_key"],
        key_id="d3-capture-key",
        public_key=bundle["capture_keys"]["d3-capture-key"],
        allowed_endpoints=frozenset({ENDPOINT}),
    )

    return {
        "bundle": bundle,
        "service": service,
        "context": context,
        "result": result,
        "raw": raw_response,
        "calls": [],
    }


def register(case, *, transport=None, context=None, request=REQUEST):
    if transport is None:
        def transport(sent):
            case["calls"].append(sent)
            return case["raw"]

    case["service"].register_authorized_operation(
        operation_id=OPERATION_ID,
        attestation=case["bundle"]["attestation"],
        expected=case["bundle"]["expected"],
        now=case["bundle"]["now"],
        context=case["context"] if context is None else context,
        request_bytes=request,
        transport=transport,
    )


def observe(case):
    return case["service"].observe_and_sign(
        operation_id=OPERATION_ID,
        presented_result=case["result"],
    )


def verify_chain(case, evidence):
    bundle = case["bundle"]

    verify_companion_evidence(
        verifier=bundle["verifier"],
        attestation=bundle["attestation"],
        expected=bundle["expected"],
        now=bundle["now"],
        capture=evidence["capture"],
        link=evidence["link"],
        capture_keys=bundle["capture_keys"],
    )

    verify_mock_request_receipt(
        receipt=evidence["receipt"],
        request_bytes=REQUEST,
        capture=evidence["capture"],
        link=evidence["link"],
        public_key=bundle["capture_keys"]["d3-capture-key"],
    )


def test_mock_observation_to_signed_evidence(case):
    register(case)
    evidence = observe(case)

    assert case["calls"] == [REQUEST]
    assert case["service"].state(OPERATION_ID) == "completed"
    assert evidence["capture"]["response_sha256"] == sha256_bytes(
        case["raw"]
    )
    assert evidence["receipt"]["request_sha256"] == sha256_bytes(
        REQUEST
    )

    verify_chain(case, evidence)


def test_result_substitution_prevents_signing(case):
    register(case)
    case["result"]["verdict"] = "FAIL"

    with pytest.raises(EvidenceError, match="differs"):
        observe(case)

    assert case["calls"] == [REQUEST]
    assert case["service"].state(OPERATION_ID) == "needs_reconcile"

    with pytest.raises(EvidenceError, match="unavailable"):
        observe(case)


def test_response_substitution_breaks_original_signed_link(case):
    register(case)
    evidence = observe(case)
    changed = copy.deepcopy(evidence["capture"])
    changed["response_sha256"] = "a" * 64

    with pytest.raises(EvidenceError, match="capture digest mismatch"):
        verify_companion_evidence(
            verifier=case["bundle"]["verifier"],
            attestation=case["bundle"]["attestation"],
            expected=case["bundle"]["expected"],
            now=case["bundle"]["now"],
            capture=changed,
            link=evidence["link"],
            capture_keys=case["bundle"]["capture_keys"],
        )


def test_modified_request_breaks_signed_receipt(case):
    register(case)
    evidence = observe(case)

    with pytest.raises(EvidenceError, match="commitment mismatch"):
        verify_mock_request_receipt(
            receipt=evidence["receipt"],
            request_bytes=b'{"input":"substituted"}',
            capture=evidence["capture"],
            link=evidence["link"],
            public_key=case["bundle"]["capture_keys"]["d3-capture-key"],
        )


def test_modified_receipt_cannot_be_resigned_by_caller(case):
    register(case)
    evidence = observe(case)
    changed = copy.deepcopy(evidence["receipt"])
    changed["operation_id"] = "different-operation"

    with pytest.raises(EvidenceError, match="signature"):
        verify_mock_request_receipt(
            receipt=changed,
            request_bytes=REQUEST,
            capture=evidence["capture"],
            link=evidence["link"],
            public_key=case["bundle"]["capture_keys"]["d3-capture-key"],
        )


def test_mismatched_context_rejected_before_transport(case):
    changed = dict(case["context"])
    changed["provider"] = "agent-selected-provider"

    with pytest.raises(EvidenceError, match="binding mismatch"):
        register(case, context=changed)

    assert case["calls"] == []


def test_unapproved_endpoint_rejected_before_transport(case):
    changed = dict(case["context"])
    changed["endpoint"] = "https://unapproved.example/v1"

    with pytest.raises(EvidenceError, match="endpoint"):
        register(case, context=changed)

    assert case["calls"] == []


def test_invalid_d1_rejected_before_transport(case):
    case["bundle"]["attestation"]["result_sha256"] = "f" * 64

    with pytest.raises(EvidenceError):
        register(case)

    assert case["calls"] == []


def test_transport_timeout_is_indeterminate_and_not_retried(case):
    def transport(sent):
        case["calls"].append(sent)
        raise TimeoutError("simulated timeout after submission")

    register(case, transport=transport)

    with pytest.raises(
        IndeterminateExternalResult,
        match="reconciliation",
    ):
        observe(case)

    assert case["calls"] == [REQUEST]
    assert case["service"].state(OPERATION_ID) == "needs_reconcile"

    with pytest.raises(EvidenceError, match="unavailable"):
        observe(case)

    assert case["calls"] == [REQUEST]


def test_successful_operation_cannot_be_replayed_in_memory(case):
    register(case)
    observe(case)

    with pytest.raises(EvidenceError, match="unavailable"):
        observe(case)

    assert case["calls"] == [REQUEST]


def test_duplicate_operation_registration_rejected(case):
    register(case)

    with pytest.raises(EvidenceError, match="duplicate"):
        register(case)


def test_caller_cannot_submit_raw_response_to_observe_method(case):
    register(case)

    with pytest.raises(TypeError):
        case["service"].observe_and_sign(
            operation_id=OPERATION_ID,
            presented_result=case["result"],
            response_sha256="b" * 64,
        )

    assert case["calls"] == []
    assert case["service"].state(OPERATION_ID) == "ready"


def test_mock_transport_can_still_fabricate_provider_output(case):
    # Deliberate counterexample: this in-process fixture controls the
    # transport. Valid signatures do NOT prove real provider origin.
    def fabricated_transport(sent):
        case["calls"].append(sent)
        return case["raw"]

    register(case, transport=fabricated_transport)
    evidence = observe(case)

    verify_chain(case, evidence)
    assert case["calls"] == [REQUEST]
