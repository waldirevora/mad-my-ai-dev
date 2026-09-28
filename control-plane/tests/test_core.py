from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from madctl.approvals import HumanApprovalVerifier, MachineApprovalIssuer
from madctl.canonical import add_self_hash, canonical_bytes, sha256_bytes, verify_self_hash
from madctl.config import validate_orchestration_config
from madctl.errors import EvidenceError, SchemaError
from madctl.policy import classify_paths, parse_policy
from madctl.schemas import SchemaRegistry
from madctl.state import EvidenceStore, HmacSigner


ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "control-plane" / "schemas"
POLICY_RAW = (ROOT / ".mad" / "policy.yaml").read_bytes()
OID_A = "a" * 40
OID_B = "b" * 40


def release(name: str) -> dict[str, str]:
    return {"name": name, "version": "1.0", "digest": "1" * 64}


def challenge(now: int = 1_000, *, classification: str = "code", human: bool = False) -> dict:
    policy = parse_policy(POLICY_RAW)
    value = {
        "schema_version": 1, "kind": "mad-challenge", "stage": "pre-pr",
        "run_id": str(uuid.uuid4()), "nonce": "2" * 64,
        "prepared_at": now, "expires_at": now + 300,
        "repository": {"host": "github.com", "database_id": 7, "name_with_owner": "o/r", "registered_remote": "https://github.com/o/r.git"},
        "source": {"repository_id": 7, "branch": "feature", "sha": OID_A},
        "target": {"repository_id": 7, "branch": "main", "sha": OID_B},
        "merge_base_sha": OID_B, "pr": None,
        "diff": {"algorithm": "sha256", "sha256": "3" * 64, "byte_length": 9},
        "changed_paths_sha256": "4" * 64, "classification": classification,
        "risk_reasons": [],
        "trusted_policy": {"present": True, "sha256": policy.digest, "byte_length": len(POLICY_RAW)},
        "candidate_policy": {"present": True, "sha256": policy.digest, "byte_length": len(POLICY_RAW)},
        "trusted_config": {"present": True, "sha256": "5" * 64, "byte_length": 10},
        "candidate_config": {"present": True, "sha256": "5" * 64, "byte_length": 10},
        "control_plane": release("madctl"), "orka": release("orka"),
        "effective_policy_sha256": policy.digest,
        "qa_plan_sha256": policy.qa_plan_digest(classification),
        "required_human_approval": human,
    }
    return add_self_hash(value, "challenge_sha256")


def qa_evidence(item: dict) -> dict:
    return add_self_hash({
        "schema_version": 1, "kind": "mad-qa-evidence", "run_id": item["run_id"],
        "nonce": item["nonce"], "challenge_sha256": item["challenge_sha256"],
        "source_sha": item["source"]["sha"], "target_sha": item["target"]["sha"],
        "merge_base_sha": item["merge_base_sha"], "qa_plan_sha256": item["qa_plan_sha256"],
        "sandbox_profile_sha256": "6" * 64,
        "checks": [{"id": "x", "argv_sha256": "7" * 64, "started_at": 1000, "finished_at": 1000,
                    "exit_code": 0, "timed_out": False,
                    "stdout": {"sha256": sha256_bytes(b"ok\n"), "byte_length": 3},
                    "stderr": {"sha256": sha256_bytes(b""), "byte_length": 0}, "result": "PASS"}],
        "result": "PASS",
    }, "qa_evidence_sha256")


def attestation(item: dict) -> dict:
    return add_self_hash({
        "schema_version": 1, "kind": "mad-codex-attestation", "stage": item["stage"],
        "run_id": item["run_id"], "nonce": item["nonce"], "challenge_sha256": item["challenge_sha256"],
        "source_sha": item["source"]["sha"], "target_sha": item["target"]["sha"],
        "diff_sha256": item["diff"]["sha256"], "model": "gpt-5.6-sol", "reasoning_effort": "high",
        "codex_cli_version": "codex 1", "authentication_method": "Logged in using ChatGPT",
        "review_started_at": 1000, "review_finished_at": 1000, "verdict": "PASS",
        "summary": "clear", "findings": [],
    }, "attestation_sha256")


class ExactBytesAndSchemasTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schemas = SchemaRegistry(SCHEMAS)

    def test_exact_byte_hash_distinguishes_whitespace_newlines_and_binary(self) -> None:
        values = [b"x", b"x\n", b"x ", b"x\r\n", b"x\n", b"\x00x\xff"]
        hashes = [sha256_bytes(value) for value in values]
        self.assertEqual(hashes[1], hashes[4])
        self.assertEqual(len(set(hashes)), len(values) - 1)

    def test_all_evidence_schemas_are_strict(self) -> None:
        item = challenge()
        self.schemas.validate("challenge", item)
        item["unknown"] = True
        with self.assertRaises(SchemaError):
            self.schemas.validate("challenge", item)

    def test_challenge_self_hash_recomputation_detects_forgery(self) -> None:
        item = challenge()
        verify_self_hash(item, "challenge_sha256")
        item["source"]["sha"] = "c" * 40
        with self.assertRaises(EvidenceError):
            verify_self_hash(item, "challenge_sha256")

    def test_genesis_absence_is_not_empty_digest(self) -> None:
        item = challenge(classification="genesis", human=True)
        item["trusted_policy"] = {"present": False, "sha256": None, "byte_length": None}
        item["trusted_config"] = {"present": False, "sha256": None, "byte_length": None}
        item = add_self_hash(item, "challenge_sha256")
        self.schemas.validate("challenge", item)
        self.assertNotEqual(item["effective_policy_sha256"], sha256_bytes(b""))

    def test_policy_classification_is_narrow(self) -> None:
        policy = parse_policy(POLICY_RAW)
        self.assertEqual(classify_paths(["docs/a.md"], policy)[0], "documentation-only")
        self.assertEqual(classify_paths(["README.mdx"], policy)[0], "code")
        for path in ("AGENTS.md", ".codex/hooks.json", ".github/workflows/x.yml", ".orchestration/config.yaml", "control-plane/a.py", "tests/a.py", "Makefile"):
            self.assertEqual(classify_paths([path], policy)[0], "control-plane/high-risk")
        self.assertEqual(classify_paths(["app.py"], policy)[0], "code")
        with self.assertRaises(EvidenceError):
            classify_paths([], policy)

    def test_compiled_high_risk_build_release_policy_cannot_be_weakened(self) -> None:
        policy = parse_policy(POLICY_RAW)
        root_only = (
            "AGENTS.md", ".codex/hooks.json", ".github/workflows/ci.yml", ".mad/policy.yaml",
            ".orchestration/config.yaml", "control-plane/x.py", "policies/security.yml", "schemas/x.json",
        )
        families = (
            "security/policy.yml", "release/manifest.json", "packaging/spec.yml", "installer/install.sh",
            "pyproject.toml", "setup.py", "setup.cfg", "requirements-dev.txt", "requirements/base.txt",
            "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock", "tox.ini", "noxfile.py",
            "Makefile", "Dockerfile.release", "docker-compose.prod.yml", "compose.dev.yaml",
            "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
            "bun.lockb", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "Gemfile", "Gemfile.lock",
            "pom.xml", "build.gradle.kts", "gradle.properties", "settings.gradle.kts", "app.csproj",
            "solution.sln", "release-manifest.json", "installer-prod", "deploy-prod.yaml", "security.toml",
            "merge-policy.yaml", "signing-config.toml", "buildspec.yml", "Jenkinsfile",
            ".gitlab-ci.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml", ".travis.yml",
            "buildkite.pipeline.yml", ".circleci/config.yml", "gradlew", "gradlew.bat",
            "gradle/wrapper/gradle-wrapper.properties", "app.fsproj", "app.vbproj", "Directory.Build.props",
            "Directory.Build.targets", "Directory.Packages.props", "global.json", "nuget.config",
            "main.tf", "prod.tfvars", "terraform/modules/main.txt", "helm/app/values.yaml", "Chart.yaml",
            "values.yaml", "kustomization.yaml", "deployment-prod.yml", "install.ps1", "cosign.pub",
            "cosign.yaml", "provenance-config.json", "sbom-config.yaml", "release-metadata.toml",
        )
        weakened = dict(policy.value)
        weakened["protected_paths"] = []
        weakened["build_configuration_names"] = []
        weakened_policy = parse_policy(json.dumps(weakened, separators=(",", ":")).encode())
        for path in root_only:
            self.assertEqual(classify_paths([path], weakened_policy)[0], "control-plane/high-risk", path)
        for relative in families:
            for path in (relative, f"nested/deeper/{relative}"):
                self.assertEqual(
                    classify_paths([path], weakened_policy)[0], "control-plane/high-risk", path
                )
        self.assertEqual(classify_paths(["Nested/DOCKERFILE.Release"], weakened_policy)[0], "control-plane/high-risk")
        for segment in (".codex", ".github", ".mad", ".orchestration", "control-plane", "policies", "schemas"):
            path = f"nested/deeper/{segment}/authority.txt"
            self.assertEqual(classify_paths([path], weakened_policy)[0], "control-plane/high-risk", path)
        for path in ("odd/custom-security-bootstrap.conf", "tools/release-signing-step.conf", "x/install-helper.ps1"):
            self.assertEqual(classify_paths([path], weakened_policy)[0], "control-plane/high-risk", path)

        previously_missed = (
            "CMakeLists.txt", "requirements.in", "constraints.txt", "composer.json", "composer.lock",
            "deno.json", "deno.lock", "flake.nix", "flake.lock", "Podfile", "Podfile.lock",
            "mix.exs", "mix.lock", "pubspec.yaml", "WORKSPACE", "MODULE.bazel", "renovate.json",
            "ansible/playbook.yml", "ansible/site.yml", "roles/web/tasks/main.yml", "default.nix",
            "shell.nix",
        )
        for relative in previously_missed:
            for path in (relative, f"nested/deeper/{relative}"):
                self.assertEqual(classify_paths([path], weakened_policy)[0], "control-plane/high-risk", path)

    def test_orchestration_config_requires_exact_orka_pin(self) -> None:
        raw = (ROOT / ".orchestration/config.yaml").read_bytes()
        self.assertEqual(validate_orchestration_config(raw)["minimum_orka_version"], "1.8.0")
        with self.assertRaises(EvidenceError):
            validate_orchestration_config(b"schema_version: 1\nminimum_orka_version: 1.7.0\n")


class ApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.schemas = SchemaRegistry(SCHEMAS)
        self.store = EvidenceStore(Path(self.tmp.name) / "state", self.schemas, HmacSigner(b"k" * 32))
        self.policy = parse_policy(POLICY_RAW)

    def _human(self, item: dict, private: Ed25519PrivateKey, now: int = 1000) -> tuple[dict, dict]:
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_text = base64.urlsafe_b64encode(public).rstrip(b"=").decode()
        record = {"human_approvers": [{"subject": "Human One", "key_id": "human-1", "ed25519_public_key": key_text}]}
        approval = {
            "schema_version": 1, "kind": "mad-human-approval", "scope": "create-pr",
            "repository": {key: item["repository"][key] for key in ("host", "database_id", "name_with_owner")},
            "source": item["source"], "target": item["target"], "diff": item["diff"],
            "policy_sha256": item["effective_policy_sha256"],
            "control_plane_sha256": item["control_plane"]["digest"],
            "risk_class": item["classification"], "nonce": item["nonce"], "decision": "APPROVE",
            "issued_at": now, "expires_at": now + 120,
            "approver": {"subject": "Human One", "key_id": "human-1"},
        }
        signature = private.sign(canonical_bytes(approval))
        approval["signature"] = {"algorithm": "Ed25519", "key_id": "human-1", "value": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}
        return approval, record

    def test_external_human_signature_binding_and_forgery(self) -> None:
        item = challenge(classification="control-plane/high-risk", human=True)
        private = Ed25519PrivateKey.generate()
        approval, record = self._human(item, private)
        verifier = HumanApprovalVerifier(self.schemas)
        verifier.verify(approval, challenge=item, repository_record=record, policy=self.policy, operation="create-pr", now=1000)
        canonical_raw = canonical_bytes(approval) + b"\n"
        verifier.verify(approval, challenge=item, repository_record=record, policy=self.policy, operation="create-pr", raw=canonical_raw, now=1000)
        with self.assertRaises(EvidenceError):
            verifier.verify(approval, challenge=item, repository_record=record, policy=self.policy, operation="create-pr", raw=json.dumps(approval, indent=2).encode(), now=1000)
        approval["source"]["sha"] = "c" * 40
        with self.assertRaises(EvidenceError):
            verifier.verify(approval, challenge=item, repository_record=record, policy=self.policy, operation="create-pr", now=1000)

    def test_human_ttl_and_clock_skew_fail_closed(self) -> None:
        item = challenge(classification="control-plane/high-risk", human=True)
        approval, record = self._human(item, Ed25519PrivateKey.generate())
        verifier = HumanApprovalVerifier(self.schemas)
        with self.assertRaises(EvidenceError):
            verifier.verify(approval, challenge=item, repository_record=record, policy=self.policy, operation="create-pr", now=1300)
        approval, record = self._human(item, Ed25519PrivateKey.generate(), now=1200)
        with self.assertRaises(EvidenceError):
            verifier.verify(approval, challenge=item, repository_record=record, policy=self.policy, operation="create-pr", now=1000)

    def test_partial_evidence_and_expired_challenge_do_not_issue(self) -> None:
        item = challenge(now=1000)
        issuer = MachineApprovalIssuer(self.schemas, self.store)
        bad_qa = qa_evidence(item)
        bad_qa["source_sha"] = "c" * 40
        bad_qa = add_self_hash(bad_qa, "qa_evidence_sha256")
        with self.assertRaises(EvidenceError):
            issuer.issue(operation="create-pr", challenge=item, qa=bad_qa, attestation=attestation(item), policy=self.policy, human_approval_sha256=None, now=1001)
        with self.assertRaises(EvidenceError):
            issuer.issue(operation="create-pr", challenge=item, qa=qa_evidence(item), attestation=attestation(item), policy=self.policy, human_approval_sha256=None, now=1400)

    def test_high_risk_challenge_cannot_issue_without_human_approval(self) -> None:
        item = challenge(classification="control-plane/high-risk", human=True)
        with self.assertRaisesRegex(EvidenceError, "required human approval is missing"):
            MachineApprovalIssuer(self.schemas, self.store).issue(
                operation="create-pr", challenge=item, qa=qa_evidence(item), attestation=attestation(item),
                policy=self.policy, human_approval_sha256=None, now=1001,
            )

    def test_single_use_state_machine_blocks_replay(self) -> None:
        item = challenge()
        approval = MachineApprovalIssuer(self.schemas, self.store).issue(
            operation="create-pr", challenge=item, qa=qa_evidence(item), attestation=attestation(item),
            policy=self.policy, human_approval_sha256=None, now=1001,
        )
        self.store.transition_approval(approval["approval_id"], "approved", "consuming", now=1002)
        self.store.transition_approval(approval["approval_id"], "consuming", "consumed", now=1003)
        with self.assertRaises(EvidenceError):
            self.store.transition_approval(approval["approval_id"], "approved", "consuming", now=1004)

    def test_only_one_machine_approval_can_be_issued_per_run_and_operation(self) -> None:
        item = challenge()
        issuer = MachineApprovalIssuer(self.schemas, self.store)
        issuer.issue(operation="create-pr", challenge=item, qa=qa_evidence(item), attestation=attestation(item),
                     policy=self.policy, human_approval_sha256=None, now=1001)
        with self.assertRaises(EvidenceError):
            issuer.issue(operation="create-pr", challenge=item, qa=qa_evidence(item), attestation=attestation(item),
                         policy=self.policy, human_approval_sha256=None, now=1001)

    def test_lock_serializes_competing_consumers(self) -> None:
        item = challenge()
        approval = MachineApprovalIssuer(self.schemas, self.store).issue(
            operation="create-pr", challenge=item, qa=qa_evidence(item), attestation=attestation(item),
            policy=self.policy, human_approval_sha256=None, now=1001,
        )
        outcomes: list[str] = []
        def consume() -> None:
            try:
                self.store.transition_approval(approval["approval_id"], "approved", "consuming", now=1002)
                outcomes.append("won")
            except EvidenceError:
                outcomes.append("lost")
        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertCountEqual(outcomes, ["won", "lost"])


if __name__ == "__main__":
    unittest.main()
