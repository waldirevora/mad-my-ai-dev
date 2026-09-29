"""D5: simulated observation-to-attestation integration tests.

The fixture controls the transport, D1 issuer, trusted expectations,
and companion signer. These tests establish internal consistency,
not authentic provider provenance, key isolation, or merge authority.
"""
from __future__ import annotations

import copy
import json

import pytest

from madctl.canonical import canonical_sha256, sha256_bytes
from madctl.errors import EvidenceError, IndeterminateExternalResult
from madctl.orka_capture import capture_simulated_review
from madctl.orka_companion import verify_companion_evidence

from test_orka_companion import (
    bundle,
    sign_attestation,
    sign_link,
    verify,
)


ENDPOINT = "https://fixture.example/v1"
ALLOWED_ENDPOINTS = frozenset({ENDPOINT})


def specimen(bundle):
    """Construct a simulated response using the fixture's review context."""
    expected = bundle["expected"]
    reviewer = expected["reviewer"]

    context = {
        "provider": reviewer["provider"],
        "endpoint": ENDPOINT,
        "model": reviewer["model"],
        "execution_identity": reviewer["execution_identity"],
        "review_run_id": expected["review_run_id"],
        "gate": expected["gate"],
        "review_generation": expected["review_generation"],
    }

    result = {"verdict": "PASS", "findings": []}
    response = {
        "id": "fixture-response-0001",
        "status": "completed",
        "output_text": json.dumps(result, sort_keys=True),
    }
    raw = json.dumps(response, separators=(",", ":")).encode("utf-8")
    return context, result, raw


def observe(context, result, raw):
    return capture_simulated_review(
        context=context,
        allowed_endpoints=ALLOWED_ENDPOINTS,
        transport=lambda: raw,
        presented_result=result,
    )


def prepare_verified_chain(bundle):
    """Assemble and sign a controlled fixture, not production evidence."""
    context, result, raw = specimen(bundle)
    observed = observe(context, result, raw)

    result_digest = canonical_sha256(result)

    # In this fixture, the test controls the D1 issuer and expectations.
    # A real system must derive expected values independently.
    bundle["attestation"]["result_sha256"] = result_digest
    bundle["expected"]["result_sha256"] = result_digest
    sign_attestation(bundle["attestation"], bundle["issuer_key"])

    bundle["capture"] = observed.capture

    link = bundle["link"]
    link["attestation_sha256"] = canonical_sha256(
        bundle["attestation"]
    )
    link["capture_sha256"] = canonical_sha256(observed.capture)
    link["bindings_sha256"] = canonical_sha256(bundle["expected"])
    sign_link(link, bundle["capture_key"])

    return context, result, raw, observed


def test_complete_simulated_evidence_chain(bundle):
    context, result, raw, observed = prepare_verified_chain(bundle)

    assert observed.capture["response_sha256"] == sha256_bytes(raw)
    assert observed.capture["result_sha256"] == canonical_sha256(result)
    assert observed.capture["provider"] == context["provider"]
    assert bundle["link"]["capture_sha256"] == canonical_sha256(
        observed.capture
    )

    assert verify(bundle) is None


def test_presented_result_mismatch_stops_at_capture(bundle):
    context, result, raw = specimen(bundle)
    changed = copy.deepcopy(result)
    changed["verdict"] = "FAIL"

    with pytest.raises(EvidenceError, match="differs"):
        observe(context, changed, raw)


def test_changed_observed_review_stops_at_capture(bundle):
    context, result, raw = specimen(bundle)
    response = json.loads(raw)
    response["output_text"] = json.dumps({
        "verdict": "FAIL",
        "findings": [],
    })
    changed_raw = json.dumps(response).encode("utf-8")

    with pytest.raises(EvidenceError, match="differs"):
        observe(context, result, changed_raw)


def test_changed_response_bytes_break_original_signed_link(bundle):
    context, result, raw, original = prepare_verified_chain(bundle)

    changed_raw = json.dumps(json.loads(raw), indent=2).encode(
        "utf-8"
    )
    changed = observe(context, result, changed_raw)

    assert changed.capture["result_sha256"] == (
        original.capture["result_sha256"]
    )
    assert changed.capture["response_sha256"] != (
        original.capture["response_sha256"]
    )

    with pytest.raises(EvidenceError, match="capture digest mismatch"):
        verify_companion_evidence(
            verifier=bundle["verifier"],
            attestation=bundle["attestation"],
            expected=bundle["expected"],
            now=bundle["now"],
            capture=changed.capture,
            link=bundle["link"],
            capture_keys=bundle["capture_keys"],
        )


def test_changed_response_id_breaks_signed_link(bundle):
    prepare_verified_chain(bundle)
    bundle["capture"]["response_id"] = "different-response"

    with pytest.raises(EvidenceError, match="capture digest mismatch"):
        verify(bundle)


def test_resigned_wrong_provider_fails_trusted_binding(bundle):
    prepare_verified_chain(bundle)
    bundle["capture"]["provider"] = "substituted-provider"

    bundle["link"]["capture_sha256"] = canonical_sha256(
        bundle["capture"]
    )
    sign_link(bundle["link"], bundle["capture_key"])

    with pytest.raises(
        EvidenceError,
        match="capture binding mismatch: provider",
    ):
        verify(bundle)


def test_changed_d1_result_fails_trusted_verification(bundle):
    prepare_verified_chain(bundle)
    bundle["expected"]["result_sha256"] = "f" * 64

    with pytest.raises(EvidenceError):
        verify(bundle)


def test_transport_failure_cannot_create_capture(bundle):
    context, result, _ = specimen(bundle)

    def failing_transport():
        raise TimeoutError("simulated provider timeout")

    with pytest.raises(
        IndeterminateExternalResult,
        match="reconciliation",
    ):
        capture_simulated_review(
            context=context,
            allowed_endpoints=ALLOWED_ENDPOINTS,
            transport=failing_transport,
            presented_result=result,
        )


def test_signed_digest_does_not_prove_real_provider_origin(bundle):
    _, _, raw, _ = prepare_verified_chain(bundle)

    # Deliberate counterexample: the fixture signer can sign a
    # made-up response hash without observing corresponding bytes.
    invented_digest = "b" * 64
    assert invented_digest != sha256_bytes(raw)

    bundle["capture"]["response_sha256"] = invented_digest
    bundle["link"]["capture_sha256"] = canonical_sha256(
        bundle["capture"]
    )
    sign_link(bundle["link"], bundle["capture_key"])

    # Signature and artifact correspondence still verify.
    # This is why real transport capture and isolated signing
    # authority are required before any production trust claim.
    assert verify(bundle) is None
