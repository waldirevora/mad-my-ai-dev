"""Adversarial D1 tests; signing keys are ephemeral and never shipped."""
from __future__ import annotations

import base64
import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from madctl.canonical import canonical_bytes, sha256_bytes
from madctl.errors import EvidenceError, SchemaError
from madctl.orka_attestation import OrkaReviewAttestationVerifier
from madctl.schemas import SchemaRegistry

_DOMAIN = b"MAD-ORKA-BRIDGE/v1\x00"
_BINDINGS = (
    "issuer", "repository", "pr", "source", "target", "challenge_sha256",
    "policy_sha256", "nonce", "review_generation", "gate", "reviewer",
    "review_run_id", "result_sha256", "orka",
)


def _sign(document: dict, private_key: Ed25519PrivateKey) -> None:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    signature = private_key.sign(_DOMAIN + canonical_bytes(unsigned))
    document["signature"] = {
        "algorithm": "Ed25519",
        "key_id": document["issuer"]["key_id"],
        "value": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }


@pytest.fixture
def specimen():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    document = {
        "schema_version": "mad.orka.review-attestation.v1",
        "kind": "mad-orka-review-attestation",
        "attestation_id": "9fa620d3-5b51-4660-91c2-1bbfa46eb54a",
        "issuer": {"producer_id": "mad-test-emitter", "key_id": "test-issuer"},
        "issued_at": 1000,
        "expires_at": 1500,
        "nonce": "e" * 64,
        "repository": {"host": "github.com", "database_id": 123, "name_with_owner": "example/mad"},
        "pr": {"database_id": 456, "number": 12},
        "source": {"repository_id": 123, "branch": "feature/test", "sha": "a" * 40},
        "target": {"repository_id": 123, "branch": "main", "sha": "b" * 40},
        "challenge_sha256": "c" * 64,
        "policy_sha256": "d" * 64,
        "review_generation": 1,
        "gate": "code-review",
        "reviewer": {
            "role": "code-reviewer",
            "provider": "fixture-provider",
            "model": "fixture-model",
            "execution_identity": "fixture-executor",
        },
        "review_run_id": "fixture-run-0001",
        "verdict": "PASS",
        "result_sha256": "4" * 64,
        "orka": {
            "plugin_id": "personal/orka",
            "version": "1.8.0",
            "runtime_sha256": "f" * 64,
            "ledger_sha256": "1" * 64,
            "permit_sha256": "2" * 64,
            "receipt_sha256": "3" * 64,
        },
    }
    expected = {field: copy.deepcopy(document[field]) for field in _BINDINGS}
    _sign(document, key)
    schemas = SchemaRegistry(Path(__file__).resolve().parents[1] / "schemas")
    verifier = OrkaReviewAttestationVerifier(schemas, {"test-issuer": public})
    return document, expected, verifier, key


def _verify(specimen, document=None, expected=None, *, now=1200, raw=None):
    base, trusted, verifier, _ = specimen
    return verifier.verify(
        base if document is None else document,
        expected=trusted if expected is None else expected,
        now=now,
        raw=raw,
    )


def test_canonical_digest_is_identical_with_and_without_raw(specimen):
    document = specimen[0]
    raw = canonical_bytes(document) + b"\n"
    expected_digest = sha256_bytes(canonical_bytes(document))
    assert _verify(specimen) == expected_digest
    assert _verify(specimen, raw=raw) == expected_digest
    assert sha256_bytes(raw) != expected_digest


@pytest.mark.parametrize("field,value", [
    ("result_sha256", "5" * 64),
    ("challenge_sha256", "f" * 64),
    ("policy_sha256", "f" * 64),
    ("nonce", "0" * 64),
    ("review_run_id", "different-run"),
    ("gate", "security-review"),
    ("review_generation", 2),
])
def test_resigned_changes_still_fail_trusted_bindings(specimen, field, value):
    document = copy.deepcopy(specimen[0])
    document[field] = value
    _sign(document, specimen[3])
    with pytest.raises(EvidenceError, match="binding mismatch"):
        _verify(specimen, document)


@pytest.mark.parametrize("field,value", [
    ("pr", {"database_id": 456, "number": 13}),
    ("source", {"repository_id": 123, "branch": "feature/test", "sha": "9" * 40}),
    ("target", {"repository_id": 123, "branch": "main", "sha": "9" * 40}),
    ("repository", {"host": "github.com", "database_id": 999, "name_with_owner": "example/mad"}),
    ("orka", {"plugin_id": "personal/orka", "version": "1.8.0", "runtime_sha256": "0" * 64,
              "ledger_sha256": "1" * 64, "permit_sha256": "2" * 64, "receipt_sha256": "3" * 64}),
])
def test_resigned_context_changes_fail(specimen, field, value):
    document = copy.deepcopy(specimen[0])
    document[field] = value
    _sign(document, specimen[3])
    with pytest.raises(EvidenceError, match="binding mismatch"):
        _verify(specimen, document)


def test_tampered_result_cannot_keep_signature(specimen):
    document = copy.deepcopy(specimen[0])
    document["result_sha256"] = "5" * 64
    with pytest.raises(EvidenceError, match="signature is invalid"):
        _verify(specimen, document)


def test_unregistered_issuer_cannot_self_enroll(specimen):
    document = copy.deepcopy(specimen[0])
    unauthorized_key = Ed25519PrivateKey.generate()
    document["issuer"]["key_id"] = "intruder"
    _sign(document, unauthorized_key)
    with pytest.raises(EvidenceError, match="untrusted"):
        _verify(specimen, document)


def test_issuer_identity_cannot_be_relabelled(specimen):
    document = copy.deepcopy(specimen[0])
    document["issuer"]["producer_id"] = "impersonated-emitter"
    _sign(document, specimen[3])
    with pytest.raises(EvidenceError, match="binding mismatch: issuer"):
        _verify(specimen, document)


def test_wrong_gate_role_rejected_even_when_expected_matches(specimen):
    document = copy.deepcopy(specimen[0])
    document["reviewer"]["role"] = "security-reviewer"
    expected = copy.deepcopy(specimen[1])
    expected["reviewer"]["role"] = "security-reviewer"
    _sign(document, specimen[3])
    with pytest.raises(EvidenceError, match="role does not match gate"):
        _verify(specimen, document, expected)


def test_signed_fail_does_not_become_approval(specimen):
    document = copy.deepcopy(specimen[0])
    document["verdict"] = "FAIL"
    _sign(document, specimen[3])
    with pytest.raises(EvidenceError, match="not PASS"):
        _verify(specimen, document)


@pytest.mark.parametrize("now,reason", [
    (1500, "expired"),
    (900, "future"),
])
def test_expiration_and_future_clock(specimen, now, reason):
    with pytest.raises(EvidenceError, match=reason):
        _verify(specimen, now=now)


def test_excessive_ttl_rejected(specimen):
    document = copy.deepcopy(specimen[0])
    document["expires_at"] = 2000
    _sign(document, specimen[3])
    with pytest.raises(EvidenceError, match="maximum lifetime"):
        _verify(specimen, document)


def test_missing_trusted_binding_rejected(specimen):
    expected = copy.deepcopy(specimen[1])
    expected.pop("nonce")
    with pytest.raises(EvidenceError, match="incomplete trusted"):
        _verify(specimen, expected=expected)


def test_noncanonical_file_rejected(specimen):
    raw = canonical_bytes(specimen[0]) + b"\n\n"
    with pytest.raises(EvidenceError, match="canonical"):
        _verify(specimen, raw=raw)


@pytest.mark.parametrize("alter", [
    lambda d: d.update({"unexpected": True}),
    lambda d: d.pop("review_run_id"),
    lambda d: d["pr"].update({"number": "12"}),
    lambda d: d["signature"].update({"algorithm": "HMAC"}),
    lambda d: d["signature"].update({"value": "not_base64"}),
])
def test_invalid_schema_rejected(specimen, alter):
    document = copy.deepcopy(specimen[0])
    alter(document)
    with pytest.raises((SchemaError, EvidenceError)):
        _verify(specimen, document)


@pytest.mark.parametrize("path", [
    ("attestation_id",),
    ("nonce",),
    ("source", "sha"),
    ("target", "sha"),
    ("challenge_sha256",),
    ("policy_sha256",),
    ("result_sha256",),
    ("orka", "runtime_sha256"),
    ("orka", "ledger_sha256"),
    ("orka", "permit_sha256"),
    ("orka", "receipt_sha256"),
    ("signature", "value"),
])
def test_schema_rejects_trailing_newline_in_fixed_length_values(specimen, path):
    document = copy.deepcopy(specimen[0])
    field = document
    for segment in path[:-1]:
        field = field[segment]
    field[path[-1]] += "\n"
    with pytest.raises(SchemaError):
        specimen[2].schemas.validate("orka-review-attestation", document)


def test_bad_cryptographic_signature_encoding(specimen):
    document = copy.deepcopy(specimen[0])
    document["signature"]["value"] = "A" * 86
    with pytest.raises(EvidenceError, match="noncanonical|invalid"):
        _verify(specimen, document)


def test_cross_challenge_reuse_rejected_by_nonce_binding(specimen):
    expected = copy.deepcopy(specimen[1])
    expected["nonce"] = "7" * 64
    with pytest.raises(EvidenceError, match="nonce"):
        _verify(specimen, expected=expected)


def test_stateless_verifier_alone_does_not_enforce_one_time_use(specimen):
    # Critical negative design test: durable replay prevention belongs to D2.
    assert _verify(specimen) == _verify(specimen)
