from __future__ import annotations

import base64
import time
import uuid
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_bytes, canonical_sha256, sha256_bytes, verify_canonical_artifact, verify_self_hash
from .errors import EvidenceError
from .policy import Policy
from .schemas import SchemaRegistry
from .state import EvidenceStore


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class HumanApprovalVerifier:
    def __init__(self, schemas: SchemaRegistry) -> None:
        self.schemas = schemas

    def verify(
        self,
        approval: dict[str, Any],
        *,
        challenge: dict[str, Any],
        repository_record: dict[str, Any],
        policy: Policy,
        operation: str,
        raw: bytes | None = None,
        now: int | None = None,
    ) -> str:
        now = int(time.time()) if now is None else now
        self.schemas.validate("human-approval", approval)
        expected_scope = "genesis" if challenge["classification"] == "genesis" else operation
        if approval["scope"] != expected_scope:
            raise EvidenceError("human approval has the wrong operation scope")
        if approval["issued_at"] > now + policy.clock_skew:
            raise EvidenceError("human approval is too far in the future")
        if approval["expires_at"] <= now or approval["expires_at"] <= approval["issued_at"]:
            raise EvidenceError("human approval is expired or has invalid lifetime")
        if approval["expires_at"] - approval["issued_at"] > policy.approval_ttl(operation):
            raise EvidenceError("human approval exceeds the trusted TTL")
        expected_repo = {key: challenge["repository"][key] for key in ("host", "database_id", "name_with_owner")}
        expected = {
            "repository": expected_repo,
            "source": challenge["source"],
            "target": challenge["target"],
            "diff": challenge["diff"],
            "policy_sha256": challenge["effective_policy_sha256"],
            "control_plane_sha256": challenge["control_plane"]["digest"],
            "risk_class": challenge["classification"],
            "nonce": challenge["nonce"],
        }
        for field, value in expected.items():
            if approval[field] != value:
                raise EvidenceError(f"human approval binding mismatch: {field}")
        key_id = approval["approver"]["key_id"]
        if approval["signature"]["key_id"] != key_id:
            raise EvidenceError("human approval signer key IDs disagree")
        matches = [item for item in repository_record["human_approvers"] if item["key_id"] == key_id]
        if len(matches) != 1 or matches[0]["subject"] != approval["approver"]["subject"]:
            raise EvidenceError("human approver is not an external registered authority")
        unsigned = dict(approval)
        unsigned.pop("signature")
        try:
            key = Ed25519PublicKey.from_public_bytes(_b64url_decode(matches[0]["ed25519_public_key"]))
            key.verify(_b64url_decode(approval["signature"]["value"]), canonical_bytes(unsigned))
        except (ValueError, InvalidSignature) as exc:
            raise EvidenceError("human approval signature is invalid") from exc
        if raw is not None:
            verify_canonical_artifact(raw, approval)
            return sha256_bytes(raw)
        return canonical_sha256(approval)


class MachineApprovalIssuer:
    def __init__(self, schemas: SchemaRegistry, store: EvidenceStore) -> None:
        self.schemas = schemas
        self.store = store

    def issue(
        self,
        *,
        operation: str,
        challenge: dict[str, Any],
        qa: dict[str, Any],
        attestation: dict[str, Any],
        policy: Policy,
        human_approval_sha256: str | None,
        qa_raw: bytes | None = None,
        attestation_raw: bytes | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        now = int(time.time()) if now is None else now
        if operation not in {"create-pr", "merge"}:
            raise EvidenceError("unsupported approval operation")
        expected_stage = "pre-pr" if operation == "create-pr" else "pre-merge"
        if challenge.get("stage") != expected_stage:
            raise EvidenceError(f"{operation} approval requires a {expected_stage} challenge")
        self.schemas.validate("challenge", challenge)
        self.schemas.validate("qa-evidence", qa)
        self.schemas.validate("codex-attestation", attestation)
        verify_self_hash(challenge, "challenge_sha256")
        verify_self_hash(qa, "qa_evidence_sha256")
        verify_self_hash(attestation, "attestation_sha256")
        if qa_raw is not None:
            verify_canonical_artifact(qa_raw, qa)
        if attestation_raw is not None:
            verify_canonical_artifact(attestation_raw, attestation)
        if challenge["expires_at"] <= now:
            raise EvidenceError("challenge preparation expired before approval")
        shared = {
            "run_id": challenge["run_id"], "nonce": challenge["nonce"],
            "challenge_sha256": challenge["challenge_sha256"],
            "source_sha": challenge["source"]["sha"], "target_sha": challenge["target"]["sha"],
        }
        for field, expected in shared.items():
            if qa.get(field) != expected or attestation.get(field) != expected:
                raise EvidenceError(f"evidence is not bound to challenge field {field}")
        if qa["merge_base_sha"] != challenge["merge_base_sha"] or qa["qa_plan_sha256"] != challenge["qa_plan_sha256"]:
            raise EvidenceError("QA evidence merge-base or plan binding is invalid")
        if attestation["stage"] != challenge["stage"] or attestation["diff_sha256"] != challenge["diff"]["sha256"]:
            raise EvidenceError("Codex attestation stage or diff binding is invalid")
        if qa["result"] == "PASS" and any(check["result"] != "PASS" or check["timed_out"] or check["exit_code"] != 0 for check in qa["checks"]):
            raise EvidenceError("QA PASS contradicts an individual check")
        if attestation["review_finished_at"] < attestation["review_started_at"]:
            raise EvidenceError("Codex review timestamps are reversed")
        if qa["result"] != "PASS" or attestation["verdict"] != "PASS":
            raise EvidenceError("failing QA or Codex evidence blocks approval")
        if any(item["blocking"] or item["severity"] in {"BLOCKER", "HIGH"} for item in attestation["findings"]):
            raise EvidenceError("blocking Codex findings block approval")
        if challenge["required_human_approval"] and human_approval_sha256 is None:
            raise EvidenceError("required human approval is missing")
        approval_id = str(uuid.uuid4())
        value = {
            "schema_version": 1,
            "kind": "mad-machine-approval",
            "approval_id": approval_id,
            "operation": operation,
            "run_id": challenge["run_id"],
            "nonce": challenge["nonce"],
            "repository_id": challenge["repository"]["database_id"],
            "source_sha": challenge["source"]["sha"],
            "target_sha": challenge["target"]["sha"],
            "diff_sha256": challenge["diff"]["sha256"],
            "policy_sha256": challenge["effective_policy_sha256"],
            "control_plane_sha256": challenge["control_plane"]["digest"],
            "challenge_sha256": challenge["challenge_sha256"],
            "qa_evidence_sha256": sha256_bytes(qa_raw) if qa_raw is not None else qa["qa_evidence_sha256"],
            "attestation_sha256": sha256_bytes(attestation_raw) if attestation_raw is not None else attestation["attestation_sha256"],
            "human_approval_sha256": human_approval_sha256,
            "issued_at": now,
            "expires_at": now + policy.approval_ttl(operation),
            "state": "approved",
            "signature": "0" * 64,
        }
        with self.store.lock(f"issue-{challenge['run_id']}-{operation}"):
            marker = self.store.run_dir(challenge["run_id"]) / f"issued-{operation}.json"
            if marker.exists():
                raise EvidenceError("an approval was already issued for this run and operation")
            self.store.write_run_json(
                challenge["run_id"], f"issued-{operation}.json",
                {"approval_id": approval_id, "nonce": challenge["nonce"]}, exclusive=True,
            )
            self.store.put_machine_approval(value)
        return self.store.load_machine_approval(value["approval_id"])
