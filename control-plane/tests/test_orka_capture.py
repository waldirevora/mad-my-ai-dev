"""Adversarial tests with an entirely simulated provider transport."""
from __future__ import annotations

import copy
import json

import pytest

from madctl.canonical import canonical_sha256, sha256_bytes
from madctl.errors import EvidenceError, IndeterminateExternalResult
from madctl.orka_capture import capture_simulated_review


@pytest.fixture
def specimen():
    result = {"verdict": "PASS", "findings": []}
    return {
        "context": {
            "provider": "fixture-provider",
            "endpoint": "https://fixture.example/v1",
            "model": "fixture-model",
            "execution_identity": "fixture-executor",
            "review_run_id": "fixture-run-0001",
            "gate": "code-review",
            "review_generation": 1,
        },
        "response": {
            "id": "fixture-response-0001",
            "status": "completed",
            "output_text": json.dumps(result),
        },
        "result": result,
        "endpoints": frozenset({"https://fixture.example/v1"}),
    }


def run(specimen, *, raw=None, transport=None):
    if raw is None:
        raw = json.dumps(specimen["response"]).encode()
    if transport is None:
        transport = lambda: raw
    return capture_simulated_review(
        context=specimen["context"],
        allowed_endpoints=specimen["endpoints"],
        transport=transport,
        presented_result=specimen["result"],
    )


def test_observed_response_matches_presented_result(specimen):
    raw = json.dumps(specimen["response"]).encode()
    observed = run(specimen, raw=raw)

    assert observed.capture["response_id"] == "fixture-response-0001"
    assert observed.capture["result_sha256"] == canonical_sha256(
        specimen["result"]
    )
    assert observed.response_sha256 == sha256_bytes(raw)
    assert observed.capture["response_sha256"] == sha256_bytes(raw)
    assert observed.capture["provider"] == "fixture-provider"


def test_changed_presented_result_rejected(specimen):
    specimen["result"]["verdict"] = "FAIL"
    with pytest.raises(EvidenceError, match="differs"):
        run(specimen)


def test_changed_observed_result_rejected(specimen):
    specimen["response"]["output_text"] = json.dumps({
        "verdict": "FAIL", "findings": [],
    })
    with pytest.raises(EvidenceError, match="differs"):
        run(specimen)


def test_nonterminal_response_rejected(specimen):
    specimen["response"]["status"] = "in_progress"
    with pytest.raises(EvidenceError, match="terminal success"):
        run(specimen)


def test_missing_response_id_rejected(specimen):
    specimen["response"]["id"] = ""
    with pytest.raises(EvidenceError, match="response ID"):
        run(specimen)


def test_unexpected_envelope_field_rejected(specimen):
    specimen["response"]["provider"] = "agent-declared-provider"
    with pytest.raises(EvidenceError, match="envelope"):
        run(specimen)


def test_duplicate_response_properties_rejected(specimen):
    raw = (
        b'{"id":"first","id":"second","status":"completed",'
        b'"output_text":"{}"}'
    )
    with pytest.raises(EvidenceError, match="duplicate"):
        run(specimen, raw=raw)


def test_duplicate_result_properties_rejected(specimen):
    specimen["response"]["output_text"] = (
        '{"verdict":"PASS","verdict":"FAIL"}'
    )
    with pytest.raises(EvidenceError, match="duplicate"):
        run(specimen)


def test_non_object_result_rejected(specimen):
    specimen["response"]["output_text"] = '["PASS"]'
    with pytest.raises(EvidenceError, match="must be an object"):
        run(specimen)


def test_disallowed_endpoint_rejected_before_transport(specimen):
    specimen["context"]["endpoint"] = "https://unapproved.example/v1"
    calls = []

    def transport():
        calls.append(True)
        return b"{}"

    with pytest.raises(EvidenceError, match="endpoint"):
        run(specimen, transport=transport)

    assert calls == []


def test_transport_error_is_indeterminate_not_success(specimen):
    def transport():
        raise TimeoutError("simulated read timeout")

    with pytest.raises(IndeterminateExternalResult, match="reconciliation"):
        run(specimen, transport=transport)


def test_invalid_json_rejected(specimen):
    with pytest.raises(EvidenceError, match="invalid observed JSON"):
        run(specimen, raw=b"not-json")


def test_oversized_response_rejected(specimen):
    with pytest.raises(EvidenceError, match="response bytes"):
        run(specimen, raw=b"x" * 262_145)


def test_new_capture_is_compatible_with_d3_capture_fields(specimen):
    from madctl.orka_companion import _CAPTURE_FIELDS

    observed = run(specimen)

    assert set(observed.capture) == _CAPTURE_FIELDS


def test_repeated_capture_does_not_implement_one_time_use(specimen):
    # Explicit limitation: persistent consumption remains future work.
    first = run(specimen)
    second = run(copy.deepcopy(specimen))

    assert first.capture == second.capture


def test_response_bytes_change_commitment_even_if_result_matches(specimen):
    compact = json.dumps(
        specimen["response"], separators=(",", ":")
    ).encode()
    indented = json.dumps(
        specimen["response"], indent=2
    ).encode()

    first = run(specimen, raw=compact)
    second = run(specimen, raw=indented)

    assert first.capture["result_sha256"] == second.capture["result_sha256"]
    assert first.capture["response_sha256"] != second.capture["response_sha256"]
    assert canonical_sha256(first.capture) != canonical_sha256(second.capture)
