"""Tests use simulated captures and ephemeral, unrelated signing keys."""
from __future__ import annotations

import base64
import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from madctl.canonical import canonical_bytes, canonical_sha256
from madctl.errors import EvidenceError
from madctl.orka_attestation import OrkaReviewAttestationVerifier
from madctl.orka_companion import LINK_DOMAIN, verify_companion_evidence
from madctl.schemas import SchemaRegistry


D1_DOMAIN = b"MAD-ORKA-BRIDGE/v1\x00"
BINDINGS = (
    "issuer", "repository", "pr", "source", "target",
    "challenge_sha256", "policy_sha256", "nonce",
    "review_generation", "gate", "reviewer",
    "review_run_id", "result_sha256", "orka",
)


def sign_attestation(document, key):
    unsigned = dict(document)
    unsigned.pop("signature", None)
    signature = key.sign(D1_DOMAIN + canonical_bytes(unsigned))
    document["signature"] = {
        "algorithm": "Ed25519",
        "key_id": document["issuer"]["key_id"],
        "value": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    }


def sign_link(link, key):
    unsigned = dict(link)
    unsigned.pop("signature", None)
    signature = key.sign(LINK_DOMAIN + canonical_bytes(unsigned))
    link["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


@pytest.fixture
def bundle():
    issuer_key = Ed25519PrivateKey.generate()
    capture_key = Ed25519PrivateKey.generate()

    document = {
        "schema_version": "mad.orka.review-attestation.v1",
        "kind": "mad-orka-review-attestation",
        "attestation_id": "9fa620d3-5b51-4660-91c2-1bbfa46eb54a",
        "issuer": {"producer_id": "fixture-issuer", "key_id": "d3-issuer"},
        "issued_at": 1000,
        "expires_at": 1500,
        "nonce": "e" * 64,
        "repository": {
            "host": "github.com", "database_id": 123,
            "name_with_owner": "example/mad",
        },
        "pr": {"database_id": 456, "number": 12},
        "source": {
            "repository_id": 123, "branch": "feature/test", "sha": "a" * 40,
        },
        "target": {
            "repository_id": 123, "branch": "main", "sha": "b" * 40,
        },
        "challenge_sha256": "c" * 64,
        "policy_sha256": "d" * 64,
        "review_generation": 1,
        "gate": "code-review",
        "reviewer": {
            "role": "code-reviewer", "provider": "fixture-provider",
            "model": "fixture-model", "execution_identity": "fixture-executor",
        },
        "review_run_id": "fixture-run-0001",
        "verdict": "PASS",
        "result_sha256": "4" * 64,
        "orka": {
            "plugin_id": "personal/orka", "version": "1.8.0",
            "runtime_sha256": "f" * 64,
            "ledger_sha256": "1" * 64,
            "permit_sha256": "2" * 64,
            "receipt_sha256": "3" * 64,
        },
    }
    expected = {field: copy.deepcopy(document[field]) for field in BINDINGS}
    sign_attestation(document, issuer_key)

    public_issuer = issuer_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    public_capture = capture_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    schemas = SchemaRegistry(Path(__file__).resolve().parents[1] / "schemas")
    verifier = OrkaReviewAttestationVerifier(
        schemas, {"d3-issuer": public_issuer}
    )

    capture = {
        "kind": "mad.orka.simulated-capture.v1",
        "provider": "fixture-provider",
        "endpoint": "https://fixture.example/v1",
        "model": "fixture-model",
        "execution_identity": "fixture-executor",
        "response_id": "fixture-response-0001",
        "review_run_id": "fixture-run-0001",
        "gate": "code-review",
        "review_generation": 1,
        "result_sha256": "4" * 64,
        "response_sha256": "a" * 64,
        "terminal_state": "success",
    }
    link = {
        "kind": "mad.orka.companion-link.prototype-v1",
        "key_id": "d3-capture-key",
        "attestation_sha256": canonical_sha256(document),
        "capture_sha256": canonical_sha256(capture),
        "bindings_sha256": canonical_sha256(expected),
    }
    sign_link(link, capture_key)

    return {
        "verifier": verifier, "attestation": document,
        "expected": expected, "now": 1200, "capture": capture,
        "link": link, "capture_keys": {"d3-capture-key": public_capture},
        "issuer_key": issuer_key, "capture_key": capture_key,
    }


def verify(bundle):
    verify_companion_evidence(**{
        name: bundle[name]
        for name in (
            "verifier", "attestation", "expected", "now",
            "capture", "link", "capture_keys",
        )
    })


def test_simulated_signed_link_matches_verified_d1(bundle):
    assert verify(bundle) is None


def test_swapped_capture_rejected(bundle):
    bundle["capture"]["response_id"] = "other-response"
    with pytest.raises(EvidenceError, match="capture digest mismatch"):
        verify(bundle)


def test_other_valid_d1_attestation_cannot_reuse_link(bundle):
    document = bundle["attestation"]
    document["attestation_id"] = "1fa620d3-5b51-4660-91c2-1bbfa46eb54a"
    sign_attestation(document, bundle["issuer_key"])
    with pytest.raises(EvidenceError, match="attestation digest mismatch"):
        verify(bundle)


def test_modified_link_signature_rejected(bundle):
    bundle["link"]["signature"] = "A" * 86
    with pytest.raises(EvidenceError, match="companion signature"):
        verify(bundle)


def test_untrusted_companion_signer_rejected(bundle):
    bundle["capture_keys"] = {}
    with pytest.raises(EvidenceError, match="untrusted companion"):
        verify(bundle)


def test_capture_metadata_mismatch_even_when_link_is_resigned(bundle):
    bundle["capture"]["model"] = "substituted-model"
    bundle["link"]["capture_sha256"] = canonical_sha256(bundle["capture"])
    sign_link(bundle["link"], bundle["capture_key"])
    with pytest.raises(EvidenceError, match="capture binding mismatch: model"):
        verify(bundle)


@pytest.mark.parametrize("terminal_state", ["failure", "indeterminate"])
def test_non_success_capture_rejected(bundle, terminal_state):
    bundle["capture"]["terminal_state"] = terminal_state
    with pytest.raises(EvidenceError, match="not terminal success"):
        verify(bundle)


@pytest.mark.parametrize("field", ["capture", "link"])
def test_unexpected_fields_rejected(bundle, field):
    bundle[field]["unexpected"] = "value"
    with pytest.raises(EvidenceError, match="shape"):
        verify(bundle)


def test_d1_result_mismatch_rejected(bundle):
    bundle["capture"]["result_sha256"] = "5" * 64
    with pytest.raises(EvidenceError, match="capture binding mismatch"):
        verify(bundle)


def test_stateless_reverification_is_not_one_time_consumption(bundle):
    # Explicit limitation: durable consumption is outside this experiment.
    verify(bundle)
    verify(bundle)


def test_changed_response_digest_rejected(bundle):
    bundle["capture"]["response_sha256"] = "b" * 64
    with pytest.raises(EvidenceError, match="capture digest mismatch"):
        verify(bundle)


def test_malformed_response_digest_rejected(bundle):
    bundle["capture"]["response_sha256"] = "b" * 63
    with pytest.raises(EvidenceError, match="capture result metadata"):
        verify(bundle)


def test_trusted_signer_cannot_be_replaced_by_digest_alone(bundle):
    bundle["capture"]["response_sha256"] = "b" * 64
    bundle["link"]["capture_sha256"] = canonical_sha256(bundle["capture"])
    with pytest.raises(EvidenceError, match="companion signature"):
        verify(bundle)


def test_simulated_signer_cannot_prove_raw_response_origin(bundle):
    # A signer with the trusted key can attest to an unverified digest.
    # Real transport observation and key isolation remain outside D4.
    bundle["capture"]["response_sha256"] = "b" * 64
    bundle["link"]["capture_sha256"] = canonical_sha256(bundle["capture"])
    sign_link(bundle["link"], bundle["capture_key"])
    verify(bundle)
