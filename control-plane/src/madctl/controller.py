from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .approvals import HumanApprovalVerifier, MachineApprovalIssuer
from .canonical import (
    add_self_hash,
    atomic_write_bytes,
    canonical_sha256,
    read_json_bytes,
    sha256_bytes,
    verify_self_hash,
)
from .codex import CodexVerifier
from .config import validate_orchestration_config
from .errors import AuthorityError, EvidenceError, IndeterminateExternalResult
from .github import GitHubAdapter, canonical_pr_number
from .gitops import GitRunner, parse_name_status_z, presence_digest
from .orka import OrkaInspector, OrkaRuntime
from .policy import Policy, classify_paths, parse_policy
from .qa import QaRunner
from .repository import RepositoryRegistry
from .schemas import SchemaRegistry
from .state import EvidenceStore


POLICY_PATH = ".mad/policy.yaml"
CONFIG_PATH = ".orchestration/config.yaml"


class MadController:
    """Authoritative orchestration. This object is instantiated only by an installed release."""

    def __init__(
        self,
        *,
        schemas: SchemaRegistry,
        registry: RepositoryRegistry,
        store: EvidenceStore,
        git: GitRunner,
        github: GitHubAdapter,
        qa: QaRunner,
        codex: CodexVerifier,
        human: HumanApprovalVerifier,
        issuer: MachineApprovalIssuer,
        orka: OrkaRuntime,
        orka_inspector: OrkaInspector | None,
        release: dict[str, str],
        release_inventory_digest: str,
        release_root: Path,
        orka_root: Path,
        genesis_policy: bytes,
        genesis_config: bytes,
        cache_root: Path,
    ) -> None:
        self.schemas = schemas
        self.registry = registry
        self.store = store
        self.git = git
        self.github = github
        self.qa_runner = qa
        self.codex_verifier = codex
        self.human_verifier = human
        self.issuer = issuer
        self.orka = orka
        self.orka_inspector = orka_inspector
        self.release = release
        self.release_inventory_digest = release_inventory_digest
        self.release_root = release_root.resolve(strict=True)
        self.orka_root = orka_root.resolve(strict=True)
        self.genesis_policy = genesis_policy
        self.genesis_config = genesis_config
        self.cache_root = cache_root.resolve()
        self.cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def register_repository(self, record: dict[str, Any]) -> Path:
        expected_release = {
            "version": self.release["version"], "digest": self.release["digest"],
            "inventory_digest": self.release_inventory_digest, "root": str(self.release_root)
        }
        if record.get("active_release") != expected_release:
            raise AuthorityError("repository registration must bind the active installed release")
        expected_codex = {
            "path": str(self.codex_verifier.codex.path), "sha256": self.codex_verifier.codex.sha256,
            "home": str(self.codex_verifier.codex_home),
        }
        expected_orka = {
            "root": str(self.orka_root), "version": self.orka.version,
            "digest": self.orka.digest, "inventory_digest": self.orka.inventory_digest,
        }
        if record.get("codex") != expected_codex or record.get("orka") != expected_orka:
            raise AuthorityError("repository registration must bind installed Codex and trusted Orka runtime")
        authority = self.github.repository_identity(record["name_with_owner"])
        return self.registry.register(record, authority)

    def self_test(self) -> dict[str, Any]:
        policy = parse_policy(self.genesis_policy)
        validate_orchestration_config(self.genesis_config)
        if self.orka.version != "1.8.0":
            raise AuthorityError("installed Orka self-test version mismatch")
        return {
            "status": "PASS", "authoritative": True, "release": self.release,
            "policy_sha256": policy.digest, "orka_digest": self.orka.digest,
            "schema_count": len(self.schemas._schemas),
        }

    def prepare_pre_pr(
        self,
        *,
        repository_id: int,
        source_branch: str,
        candidate_checkout: Path | None,
        genesis: bool = False,
        now: int | None = None,
    ) -> dict[str, Any]:
        return self._prepare(
            repository_id=repository_id,
            source_branch=source_branch,
            stage="pre-pr",
            pr=None,
            candidate_checkout=candidate_checkout,
            genesis=genesis,
            now=now,
        )

    def prepare_pre_merge(
        self,
        *,
        repository_id: int,
        pr: int | str,
        now: int | None = None,
    ) -> dict[str, Any]:
        number = canonical_pr_number(pr)
        record = self.registry.load(repository_id)
        self._assert_repository(record)
        metadata = normalize_pr(self.github.pr(record["name_with_owner"], number))
        self._assert_pr_shape(metadata, record, require_open=True)
        if metadata["base_branch"] != record["target_branch"]:
            raise EvidenceError("PR targets an unregistered base branch")
        return self._prepare(
            repository_id=repository_id,
            source_branch=metadata["head_branch"],
            stage="pre-merge",
            pr=number,
            candidate_checkout=None,
            genesis=False,
            expected_source_sha=metadata["head_sha"],
            expected_target_sha=metadata["base_sha"],
            now=now,
        )

    def _prepare(self, **kwargs: Any) -> dict[str, Any]:
        repository_id = kwargs.get("repository_id")
        if not isinstance(repository_id, int) or repository_id <= 0:
            raise EvidenceError("repository ID must be positive")
        with self.store.lock(f"repository-{repository_id}-prepare"):
            return self._prepare_locked(**kwargs)

    def _prepare_locked(
        self,
        *,
        repository_id: int,
        source_branch: str,
        stage: str,
        pr: int | None,
        candidate_checkout: Path | None,
        genesis: bool,
        expected_source_sha: str | None = None,
        expected_target_sha: str | None = None,
        now: int | None,
    ) -> dict[str, Any]:
        now = int(time.time()) if now is None else now
        record = self.registry.load(repository_id)
        self._assert_repository(record)
        target_branch = record["target_branch"]
        source_authority = self.github.branch_sha(record["name_with_owner"], source_branch).lower()
        target_authority = self.github.branch_sha(record["name_with_owner"], target_branch).lower()
        if expected_source_sha and source_authority != expected_source_sha:
            raise EvidenceError("PR head moved before challenge preparation")
        if expected_target_sha and target_authority != expected_target_sha:
            raise EvidenceError("PR base moved before challenge preparation")
        mirror = self._mirror(repository_id)
        fetched_source, fetched_target = self.git.fetch_exact_branches(
            mirror, record["registered_remote"], source_branch, target_branch
        )
        if (fetched_source, fetched_target) != (source_authority, target_authority):
            raise EvidenceError("independent Git fetch disagrees with authoritative GitHub refs")
        if (
            self.github.branch_sha(record["name_with_owner"], source_branch).lower() != source_authority
            or self.github.branch_sha(record["name_with_owner"], target_branch).lower() != target_authority
        ):
            raise EvidenceError("source or target moved during challenge preparation")
        if candidate_checkout is not None:
            self.git.assert_clean_candidate(candidate_checkout, source_authority)
        merge_base = self.git.merge_base(mirror, target_authority, source_authority)
        raw_diff = self.git.raw_diff(mirror, target_authority, source_authority)
        raw_paths = self.git.changed_paths_raw(mirror, target_authority, source_authority)
        paths = parse_name_status_z(raw_paths)
        target_policy = self.git.optional_blob(mirror, target_authority, POLICY_PATH)
        target_config = self.git.optional_blob(mirror, target_authority, CONFIG_PATH)
        candidate_policy = self.git.optional_blob(mirror, source_authority, POLICY_PATH)
        candidate_config = self.git.optional_blob(mirror, source_authority, CONFIG_PATH)
        target_absent = target_policy is None and target_config is None
        target_partial = (target_policy is None) != (target_config is None)
        if target_partial:
            raise EvidenceError("trusted target policy/config presence is inconsistent")
        if candidate_policy is None or candidate_config is None:
            raise EvidenceError("candidate must preserve mandatory MAD policy and orchestration config")
        if genesis:
            if stage != "pre-pr" or not target_absent or candidate_policy is None or candidate_config is None:
                raise EvidenceError("Genesis requires an initial pre-PR run with both target files absent and both candidate files present")
            policy = parse_policy(self.genesis_policy)
            effective_config = self.genesis_config
        else:
            if target_policy is None or target_config is None:
                raise EvidenceError("post-Genesis trusted target policy/config is missing")
            policy = parse_policy(target_policy)
            effective_config = target_config
        validate_orchestration_config(effective_config)
        candidate_policy_value = parse_policy(candidate_policy)
        validate_orchestration_config(candidate_config)
        if candidate_policy_value.target_branch != target_branch:
            raise EvidenceError("candidate policy proposes a different registered target branch")
        if policy.target_branch != target_branch:
            raise EvidenceError("trusted policy target branch disagrees with repository registration")
        classification, reasons = classify_paths(paths, policy, genesis=genesis)
        run_id, nonce = self.store.new_run()
        challenge = add_self_hash(
            {
                "schema_version": 1,
                "kind": "mad-challenge",
                "stage": stage,
                "run_id": run_id,
                "nonce": nonce,
                "prepared_at": now,
                "expires_at": now + policy.challenge_ttl(stage),
                "repository": {
                    "host": record["host"], "database_id": record["database_id"],
                    "name_with_owner": record["name_with_owner"], "registered_remote": record["registered_remote"],
                },
                "source": {"repository_id": repository_id, "branch": source_branch, "sha": source_authority},
                "target": {"repository_id": repository_id, "branch": target_branch, "sha": target_authority},
                "merge_base_sha": merge_base,
                "pr": pr,
                "diff": {"algorithm": "sha256", "sha256": sha256_bytes(raw_diff), "byte_length": len(raw_diff)},
                "changed_paths_sha256": sha256_bytes(raw_paths),
                "classification": classification,
                "risk_reasons": reasons,
                "trusted_policy": presence_digest(target_policy),
                "candidate_policy": presence_digest(candidate_policy),
                "trusted_config": presence_digest(target_config),
                "candidate_config": presence_digest(candidate_config),
                "control_plane": self.release,
                "orka": {"name": "orka", "version": self.orka.version, "digest": self.orka.digest},
                "effective_policy_sha256": policy.digest,
                "qa_plan_sha256": policy.qa_plan_digest(classification),
                "required_human_approval": classification in {"genesis", "control-plane/high-risk"},
            },
            "challenge_sha256",
        )
        self.schemas.validate("challenge", challenge)
        verify_self_hash(challenge, "challenge_sha256")
        self.store.write_run_json(run_id, "challenge.json", challenge)
        atomic_write_bytes(self.store.run_dir(run_id) / "diff.bin", raw_diff, exclusive=True)
        atomic_write_bytes(self.store.run_dir(run_id) / "changed-paths.bin", raw_paths, exclusive=True)
        atomic_write_bytes(self.store.run_dir(run_id) / "effective-policy.bin", policy.raw, exclusive=True)
        atomic_write_bytes(self.store.run_dir(run_id) / "effective-config.bin", effective_config, exclusive=True)
        self.git.materialize_snapshot(mirror, source_authority, self.store.run_dir(run_id) / "source")
        return challenge

    def run_qa(self, run_id: str, *, now: int | None = None) -> dict[str, Any]:
        challenge = self._challenge(run_id)
        policy = parse_policy((self.store.run_dir(run_id) / "effective-policy.bin").read_bytes())
        evidence = self.qa_runner.run(
            challenge=challenge, policy=policy, source=self.store.run_dir(run_id) / "source", now=now
        )
        self.store.write_run_json(run_id, "qa-evidence.json", evidence)
        return evidence

    def run_codex(self, run_id: str, *, now: int | None = None) -> dict[str, Any]:
        challenge = self._challenge(run_id)
        neutral = self.store.root / "neutral" / run_id
        neutral.mkdir(parents=True, exist_ok=False, mode=0o700)
        evidence = self.codex_verifier.verify(
            challenge=challenge,
            source=self.store.run_dir(run_id) / "source",
            neutral_directory=neutral,
            output_directory=self.store.run_dir(run_id) / "codex-output",
            now=now,
        )
        self.store.write_run_json(run_id, "codex-attestation.json", evidence)
        return evidence

    def verify_human_approval(self, run_id: str, approval: dict[str, Any], *, operation: str, raw: bytes | None = None, now: int | None = None) -> str:
        challenge = self._challenge(run_id)
        policy = parse_policy((self.store.run_dir(run_id) / "effective-policy.bin").read_bytes())
        digest = self.human_verifier.verify(
            approval,
            challenge=challenge,
            repository_record=self.registry.load(challenge["repository"]["database_id"]),
            policy=policy,
            operation=operation,
            raw=raw,
            now=now,
        )
        self.store.write_run_json(run_id, "human-approval.json", approval)
        return digest

    def create_machine_approval(self, run_id: str, *, operation: str, now: int | None = None) -> dict[str, Any]:
        challenge = self._challenge(run_id)
        qa_raw, qa = self.store.read_run_json(run_id, "qa-evidence.json")
        attestation_raw, attestation = self.store.read_run_json(run_id, "codex-attestation.json")
        policy = parse_policy((self.store.run_dir(run_id) / "effective-policy.bin").read_bytes())
        human_digest = None
        human_path = self.store.run_dir(run_id) / "human-approval.json"
        if human_path.exists():
            human_raw, human = read_json_bytes(human_path)
            human_digest = self.human_verifier.verify(
                human, challenge=challenge,
                repository_record=self.registry.load(challenge["repository"]["database_id"]),
                policy=policy, operation=operation, raw=human_raw, now=now,
            )
        return self.issuer.issue(
            operation=operation, challenge=challenge, qa=qa, attestation=attestation,
            policy=policy, human_approval_sha256=human_digest,
            qa_raw=qa_raw, attestation_raw=attestation_raw, now=now,
        )

    def create_pr(self, approval_id: str, *, title: str, body: str, draft: bool = False, now: int | None = None) -> dict[str, Any]:
        approval = self.store.load_machine_approval(approval_id)
        with self.store.lock(f"repository-{approval['repository_id']}-create-pr"):
            return self._create_pr_locked(approval_id, title=title, body=body, draft=draft, now=now)

    def _create_pr_locked(self, approval_id: str, *, title: str, body: str, draft: bool = False, now: int | None = None) -> dict[str, Any]:
        now = int(time.time()) if now is None else now
        if not title or len(title) > 256 or len(body) > 65536:
            raise EvidenceError("PR presentation metadata is invalid")
        approval = self.store.load_machine_approval(approval_id)
        if approval["operation"] != "create-pr":
            raise EvidenceError("approval does not authorize PR creation")
        challenge = self._challenge(approval["run_id"])
        record = self.registry.load(approval["repository_id"])
        policy = parse_policy((self.store.run_dir(approval["run_id"]) / "effective-policy.bin").read_bytes())
        if draft and not policy.value["draft_pr_allowed"]:
            raise EvidenceError("trusted policy forbids draft PRs")
        self._assert_current_refs(challenge, record)
        self.store.transition_approval(approval_id, "approved", "consuming", now)
        pre = canonical_sha256(challenge)
        consumption = self._consumption(approval, now, pre, None)
        self.store.put_consumption(consumption, exclusive=True)
        metadata: dict[str, Any] | None = None
        try:
            try:
                created = self.github.create_pr(
                    record["name_with_owner"], base=challenge["target"]["branch"],
                    head=challenge["source"]["branch"], title=title, body=body, draft=draft,
                )
                number = canonical_pr_number(created.get("number"))
                metadata = normalize_pr(self.github.pr(record["name_with_owner"], number))
            except IndeterminateExternalResult:
                reconciled = self.github.reconcile_pr(
                    record["name_with_owner"], base=challenge["target"]["branch"],
                    head=challenge["source"]["branch"], head_sha=challenge["source"]["sha"],
                )
                if reconciled is None:
                    self.store.transition_approval(approval_id, "consuming", "indeterminate", now)
                    self._finish_consumption(consumption, "indeterminate", now, None, None)
                    raise
                metadata = normalize_pr(reconciled)
            self._assert_pr_matches_challenge(metadata, challenge, record, draft=draft)
            self._finish_consumption(consumption, "success", now, metadata["number"], canonical_sha256(metadata))
            self.store.transition_approval(approval_id, "consuming", "consumed", now)
            return metadata
        except Exception:
            if self.store.load_machine_approval(approval_id)["state"] == "consuming":
                self._finish_consumption(consumption, "failure", now, metadata["number"] if metadata else None, canonical_sha256(metadata) if metadata else None)
                self.store.transition_approval(approval_id, "consuming", "indeterminate", now)
            raise

    def merge_pr(self, pr: int | str, approval_id: str, *, now: int | None = None) -> dict[str, Any]:
        number = canonical_pr_number(pr)
        approval = self.store.load_machine_approval(approval_id)
        with self.store.lock(f"repository-{approval['repository_id']}-pr-{number}-merge"):
            return self._merge_pr_locked(number, approval_id, now=now)

    def _merge_pr_locked(self, pr: int | str, approval_id: str, *, now: int | None = None) -> dict[str, Any]:
        now = int(time.time()) if now is None else now
        number = canonical_pr_number(pr)
        approval = self.store.load_machine_approval(approval_id)
        if approval["operation"] != "merge":
            raise EvidenceError("approval does not authorize merge")
        challenge = self._challenge(approval["run_id"])
        if challenge["stage"] != "pre-merge" or challenge["pr"] != number:
            raise EvidenceError("merge approval is bound to a different PR or stage")
        record = self.registry.load(approval["repository_id"])
        before = normalize_pr(self.github.pr(record["name_with_owner"], number))
        self._assert_pr_matches_challenge(before, challenge, record, draft=False)
        self._assert_current_refs(challenge, record)
        if not self.github.required_checks_green(record["name_with_owner"], number, challenge["source"]["sha"]):
            raise EvidenceError("required GitHub checks are not green for the approved head")
        if self.orka_inspector is None:
            raise EvidenceError("installed Orka inspector is unavailable")
        ledger = self.orka_inspector.ledger_status(
            config=self.store.run_dir(challenge["run_id"]) / "effective-config.bin",
            ledger_dir=self.store.root / "orka" / "ledger",
            pr=number,
        )
        self.orka_inspector.assert_premerge(
            ledger=ledger, marker=self.store.root / "orka" / "markers" / f"pr-{number}.green",
            source_branch=challenge["source"]["branch"], source_sha=challenge["source"]["sha"],
            target_branch=challenge["target"]["branch"], target_sha=challenge["target"]["sha"], now=now,
        )
        immediate = normalize_pr(self.github.pr(record["name_with_owner"], number))
        if canonical_sha256(immediate) != canonical_sha256(before):
            raise EvidenceError("PR metadata changed during the immediate pre-merge recheck")
        self._assert_current_refs(challenge, record)
        self.store.transition_approval(approval_id, "approved", "consuming", now)
        consumption = self._consumption(approval, now, canonical_sha256(before), number)
        self.store.put_consumption(consumption, exclusive=True)
        try:
            result = normalize_pr(self.github.merge_pr(
                record["name_with_owner"], pr=number, expected_head=challenge["source"]["sha"],
                strategy="squash",
            ))
            if result["state"] != "MERGED" or not result.get("merge_commit_sha"):
                raise EvidenceError("post-merge authoritative metadata does not prove a merge")
            self._finish_consumption(consumption, "success", now, number, canonical_sha256(result))
            self.store.transition_approval(approval_id, "consuming", "consumed", now)
            return result
        except Exception:
            if self.store.load_machine_approval(approval_id)["state"] == "consuming":
                self._finish_consumption(consumption, "indeterminate", now, number, None)
                self.store.transition_approval(approval_id, "consuming", "indeterminate", now)
            raise

    def _assert_repository(self, record: dict[str, Any]) -> None:
        if record["active_release"]["version"] != self.release["version"] or record["active_release"]["digest"] != self.release["digest"]:
            raise AuthorityError("repository registration is bound to a different control-plane release")
        if record["active_release"]["inventory_digest"] != self.release_inventory_digest:
            raise AuthorityError("repository registration is bound to a different release inventory")
        if record["active_release"]["root"] != str(self.release_root):
            raise AuthorityError("repository registration release root differs from the installed release")
        expected_orka = {
            "root": str(self.orka_root), "version": self.orka.version,
            "digest": self.orka.digest, "inventory_digest": self.orka.inventory_digest,
        }
        if record["orka"] != expected_orka:
            raise AuthorityError("repository registration Orka runtime differs from installed authority")
        expected_codex = {
            "path": str(self.codex_verifier.codex.path), "sha256": self.codex_verifier.codex.sha256,
            "home": str(self.codex_verifier.codex_home),
        }
        if record["codex"] != expected_codex:
            raise AuthorityError("repository registration Codex identity differs from the installed verifier")
        authority = self.github.repository_identity(record["name_with_owner"])
        expected = {key: record[key] for key in ("host", "database_id", "name_with_owner")}
        if authority != expected:
            raise AuthorityError("fresh GitHub repository identity differs from registration")

    def _assert_current_refs(self, challenge: dict[str, Any], record: dict[str, Any]) -> None:
        if self.github.branch_sha(record["name_with_owner"], challenge["source"]["branch"]).lower() != challenge["source"]["sha"]:
            raise EvidenceError("authoritative source branch moved")
        if self.github.branch_sha(record["name_with_owner"], challenge["target"]["branch"]).lower() != challenge["target"]["sha"]:
            raise EvidenceError("authoritative target branch moved")

    def _assert_pr_matches_challenge(self, metadata: dict[str, Any], challenge: dict[str, Any], record: dict[str, Any], *, draft: bool) -> None:
        self._assert_pr_shape(metadata, record, require_open=True)
        expected = {
            "head_repo_id": record["database_id"], "head_branch": challenge["source"]["branch"],
            "head_sha": challenge["source"]["sha"], "base_repo_id": record["database_id"],
            "base_branch": challenge["target"]["branch"], "base_sha": challenge["target"]["sha"],
            "draft": draft,
        }
        for field, value in expected.items():
            if metadata.get(field) != value:
                raise EvidenceError(f"authoritative PR metadata mismatch: {field}")

    @staticmethod
    def _assert_pr_shape(metadata: dict[str, Any], record: dict[str, Any], *, require_open: bool) -> None:
        if metadata["repository"] != record["name_with_owner"]:
            raise EvidenceError("PR belongs to the wrong repository")
        if require_open and metadata["state"] != "OPEN":
            raise EvidenceError("PR is not open")

    def _challenge(self, run_id: str) -> dict[str, Any]:
        _, value = self.store.read_run_json(run_id, "challenge.json")
        self.schemas.validate("challenge", value)
        verify_self_hash(value, "challenge_sha256")
        return value

    def _mirror(self, repository_id: int) -> Path:
        return self.cache_root / "mirrors" / f"{repository_id}.git"

    @staticmethod
    def _consumption(approval: dict[str, Any], now: int, pre: str, pr: int | None) -> dict[str, Any]:
        return {
            "schema_version": 1, "kind": "mad-consumption-record", "approval_id": approval["approval_id"],
            "nonce": approval["nonce"], "operation": approval["operation"], "started_at": now,
            "completed_at": None, "external_request_id": None, "pr": pr, "outcome": "consuming",
            "pre_action_sha256": pre, "post_action_sha256": None, "signature": "0" * 64,
        }

    def _finish_consumption(self, value: dict[str, Any], outcome: str, now: int, pr: int | None, post: str | None) -> None:
        value.update({"completed_at": now, "pr": pr, "outcome": outcome, "post_action_sha256": post})
        self.store.put_consumption(value, exclusive=False)


def normalize_pr(value: dict[str, Any]) -> dict[str, Any]:
    """Normalize either a test adapter record or gh's GraphQL-shaped result."""
    if set(("repository", "number", "state", "draft", "head_repo_id", "head_branch", "head_sha", "base_repo_id", "base_branch", "base_sha")) <= set(value):
        result = dict(value)
        result["head_sha"] = str(result["head_sha"]).lower()
        result["base_sha"] = str(result["base_sha"]).lower()
        return result
    try:
        head_repo = value["headRepository"]
        base_repo = value["baseRepository"]
        result = {
            "repository": base_repo["nameWithOwner"],
            "number": canonical_pr_number(value["number"]),
            "state": value["state"],
            "draft": value["isDraft"],
            "head_repo_id": head_repo["databaseId"],
            "head_branch": value["headRefName"],
            "head_sha": value["headRefOid"].lower(),
            "base_repo_id": base_repo["databaseId"],
            "base_branch": value["baseRefName"],
            "base_sha": value["baseRefOid"].lower(),
            "url": value.get("url"),
            "merge_commit_sha": (value.get("mergeCommit") or {}).get("oid"),
        }
    except (KeyError, TypeError, AttributeError) as exc:
        raise EvidenceError("GitHub returned malformed PR metadata") from exc
    return result
