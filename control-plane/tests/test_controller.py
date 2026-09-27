from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

from madctl.approvals import HumanApprovalVerifier, MachineApprovalIssuer
from madctl.canonical import add_self_hash, sha256_file
from madctl.cli import parser
from madctl.controller import MadController
from madctl.errors import EvidenceError, IndeterminateExternalResult
from madctl.gitops import GitRunner, TrustedTool
from madctl.orka import OrkaRuntime
from madctl.policy import parse_policy
from madctl.qa import CheckResult, QaRunner
from madctl.repository import RepositoryRegistry
from madctl.schemas import SchemaRegistry
from madctl.state import EvidenceStore, HmacSigner

from test_core import POLICY_RAW, SCHEMAS, attestation, challenge, qa_evidence


ROOT = Path(__file__).resolve().parents[2]


class Sandbox:
    profile_digest = "8" * 64
    def run(self, argv, *, cwd, timeout):
        return CheckResult(0, False, b"ok\n", b"")


class UnusedCodex:
    def __init__(self, tool, home):
        self.codex = tool
        self.codex_home = home
    def verify(self, **kwargs):
        raise AssertionError("not invoked")


class FakeOrkaInspector:
    def ledger_status(self, **kwargs):
        return {"next_action": "gates-clear", "missing_gates": [], "required_gates": ["code-review", "security-review"], "generation_head": kwargs.get("source_sha")}
    def assert_premerge(self, **kwargs):
        return "9" * 64


class FakeGitHub:
    def __init__(self, repository_id: int, name: str, source_branch: str, source_sha: str, target_sha: str) -> None:
        self.repository_id = repository_id
        self.name = name
        self.refs = {source_branch: source_sha, "main": target_sha}
        self.prs: dict[int, dict] = {}
        self.post_create_mismatch = False
        self.unknown_create = False
        self.expected_head_used: str | None = None
        self.create_calls: list[dict] = []
        self.checks_green = True

    def repository_identity(self, name):
        return {"host": "github.com", "database_id": self.repository_id, "name_with_owner": self.name}
    def branch_sha(self, name, branch):
        return self.refs[branch]
    def pr(self, name, pr):
        return dict(self.prs[int(pr)])
    def create_pr(self, name, *, base, head, title, body, draft):
        self.create_calls.append({"repository": name, "base": base, "head": head, "title": title, "body": body, "draft": draft})
        value = self._metadata(1, head, base, draft)
        self.prs[1] = value
        if self.post_create_mismatch:
            self.prs[1]["head_sha"] = "d" * 40
        if self.unknown_create:
            raise IndeterminateExternalResult("connection dropped after submit")
        return value
    def reconcile_pr(self, *args, **kwargs):
        return self.prs.get(1)
    def required_checks_green(self, name, pr, head_sha):
        return self.checks_green and self.prs[pr]["head_sha"] == head_sha
    def merge_pr(self, name, *, pr, expected_head, strategy):
        self.expected_head_used = expected_head
        if self.prs[pr]["head_sha"] != expected_head:
            raise EvidenceError("expected head mismatch")
        self.prs[pr]["state"] = "MERGED"
        self.prs[pr]["merge_commit_sha"] = "e" * 40
        return dict(self.prs[pr])
    def _metadata(self, number, head, base, draft=False):
        return {
            "repository": self.name, "number": number, "state": "OPEN", "draft": draft,
            "head_repo_id": self.repository_id, "head_branch": head, "head_sha": self.refs[head],
            "base_repo_id": self.repository_id, "base_branch": base, "base_sha": self.refs[base],
            "url": f"https://github.com/{self.name}/pull/{number}", "merge_commit_sha": None,
        }


class ControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.schemas = SchemaRegistry(SCHEMAS)
        self.store = EvidenceStore(self.root / "state", self.schemas, HmacSigner(b"z" * 32))
        self.registry = RepositoryRegistry.for_tests(self.root / "registry", self.schemas)
        self.release_root = self.root / "release"; self.release_root.mkdir()
        self.plugin_cache = self.root / "plugins"; self.plugin_cache.mkdir()
        self.record = {
            "schema_version": 1, "host": "github.com", "database_id": 7, "name_with_owner": "o/r",
            "registered_remote": str(self.root / "remote.git"), "target_branch": "main",
            "active_release": {"version": "2", "digest": "1" * 64, "inventory_digest": "4" * 64, "root": str(self.release_root)},
            "codex": {"path": "/bin/false", "sha256": "2" * 64, "home": str(self.root)},
            "orka": {"root": str(self.plugin_cache), "version": "1.8.0", "digest": "3" * 64, "inventory_digest": "5" * 64},
            "human_approvers": [],
        }
        git_path = Path(shutil.which("git") or "/usr/bin/git")
        python_path = Path(shutil.which("python3") or "/usr/bin/python3").resolve()
        self.git = GitRunner.for_tests(TrustedTool.for_tests(git_path, sha256_file(git_path)))
        self.python = TrustedTool.for_tests(python_path, sha256_file(python_path))
        self.record["codex"] = {"path": str(self.python.path), "sha256": self.python.sha256, "home": str(self.root)}
        self.github = FakeGitHub(7, "o/r", "feature", "a" * 40, "b" * 40)
        self.registry.register(self.record, self.github.repository_identity("o/r"))
        qa = QaRunner(self.schemas, Sandbox(), {"python3": self.python})
        issuer = MachineApprovalIssuer(self.schemas, self.store)
        self.controller = MadController(
            schemas=self.schemas, registry=self.registry, store=self.store, git=self.git, github=self.github,
            qa=qa, codex=UnusedCodex(self.python, self.root), human=HumanApprovalVerifier(self.schemas), issuer=issuer,
            orka=OrkaRuntime(self.plugin_cache, "1.8.0", "3" * 64, "5" * 64), orka_inspector=FakeOrkaInspector(),
            release={"name": "madctl", "version": "2", "digest": "1" * 64},
            release_inventory_digest="4" * 64,
            release_root=self.release_root, orka_root=self.plugin_cache,
            genesis_policy=POLICY_RAW, genesis_config=(ROOT / ".orchestration/config.yaml").read_bytes(),
            cache_root=self.root / "cache",
        )

    def _create_remote(
        self, candidate_path: str | tuple[str, ...] = "app.py", *, target_has_policy: bool = False,
    ) -> tuple[Path, str, str]:
        work = self.root / "work"
        subprocess.run(["git", "init", "-b", "main", str(work)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(work), "config", "user.name", "MAD Test"], check=True)
        subprocess.run(["git", "-C", str(work), "config", "user.email", "mad@example.invalid"], check=True)
        (work / "README.md").write_text("base\n")
        if target_has_policy:
            (work / ".mad").mkdir()
            (work / ".mad/policy.yaml").write_bytes(POLICY_RAW)
            (work / ".orchestration").mkdir()
            (work / ".orchestration/config.yaml").write_bytes((ROOT / ".orchestration/config.yaml").read_bytes())
        subprocess.run(["git", "-C", str(work), "add", "."], check=True)
        subprocess.run(["git", "-C", str(work), "commit", "-m", "base"], check=True, stdout=subprocess.DEVNULL)
        target = subprocess.check_output(["git", "-C", str(work), "rev-parse", "HEAD"], text=True).strip()
        subprocess.run(["git", "init", "--bare", str(self.root / "remote.git")], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(work), "remote", "add", "origin", str(self.root / "remote.git")], check=True)
        subprocess.run(["git", "-C", str(work), "push", "origin", "main"], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(work), "switch", "-c", "feature"], check=True, stdout=subprocess.DEVNULL)
        (work / ".mad").mkdir(exist_ok=True); (work / ".mad/policy.yaml").write_bytes(POLICY_RAW)
        (work / ".orchestration").mkdir(exist_ok=True); (work / ".orchestration/config.yaml").write_bytes((ROOT / ".orchestration/config.yaml").read_bytes())
        candidate_paths = (candidate_path,) if isinstance(candidate_path, str) else candidate_path
        for relative in candidate_paths:
            candidate = work / relative
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_text("candidate\n")
        subprocess.run(["git", "-C", str(work), "add", "."], check=True)
        subprocess.run(["git", "-C", str(work), "commit", "-m", "candidate"], check=True, stdout=subprocess.DEVNULL)
        source = subprocess.check_output(["git", "-C", str(work), "rev-parse", "HEAD"], text=True).strip()
        subprocess.run(["git", "-C", str(work), "push", "origin", "feature"], check=True, stdout=subprocess.DEVNULL)
        self.github.refs.update({"feature": source, "main": target})
        return work, source, target

    def test_genesis_target_absence_and_detached_authoritative_source(self) -> None:
        work, source, target = self._create_remote()
        value = self.controller.prepare_pre_pr(repository_id=7, source_branch="feature", candidate_checkout=work, genesis=True, now=1000)
        self.assertFalse(value["trusted_policy"]["present"])
        self.assertFalse(value["trusted_config"]["present"])
        self.assertEqual(value["classification"], "genesis")
        self.assertEqual(value["source"]["sha"], source)
        self.assertEqual(value["target"]["sha"], target)
        self.assertEqual(value["control_plane"]["digest"], "1" * 64)
        self.assertTrue((self.store.run_dir(value["run_id"]) / "source/app.py").is_file())
        self.assertEqual(subprocess.check_output(["git", "-C", str(work), "status", "--porcelain"], text=True), "")
        self.assertNotIn(".mad", subprocess.check_output(["git", "-C", str(work), "status", "--porcelain"], text=True))

    def test_compiled_high_risk_path_requires_human_approval(self) -> None:
        work, _, _ = self._create_remote("nested/deeper/requirements.in", target_has_policy=True)
        value = self.controller.prepare_pre_pr(
            repository_id=7, source_branch="feature", candidate_checkout=work, genesis=False, now=1000,
        )
        self.assertEqual(value["classification"], "control-plane/high-risk")
        self.assertTrue(value["required_human_approval"])

    def test_nix_and_ansible_paths_require_human_approval(self) -> None:
        paths = (
            "ansible/site.yml", "nested/ansible/site.yml", "roles/web/tasks/main.yml",
            "default.nix", "nested/shell.nix",
        )
        work, _, _ = self._create_remote(paths, target_has_policy=True)
        value = self.controller.prepare_pre_pr(
            repository_id=7, source_branch="feature", candidate_checkout=work, genesis=False, now=1000,
        )
        self.assertEqual(value["classification"], "control-plane/high-risk")
        self.assertTrue(value["required_human_approval"])
        self.assertEqual(
            value["risk_reasons"], [f"protected path: {path}" for path in sorted(paths)],
        )

    def test_missing_target_policy_fails_outside_genesis_and_dirty_fails(self) -> None:
        work, _, _ = self._create_remote()
        with self.assertRaises(EvidenceError):
            self.controller.prepare_pre_pr(repository_id=7, source_branch="feature", candidate_checkout=work, genesis=False, now=1000)
        (work / "untracked").write_text("x")
        with self.assertRaises(EvidenceError):
            self.controller.prepare_pre_pr(repository_id=7, source_branch="feature", candidate_checkout=work, genesis=True, now=1000)

    def _operation(self, *, operation: str, stage: str = "pre-pr", pr: int | None = None) -> tuple[dict, dict]:
        item = challenge()
        item["stage"] = stage; item["pr"] = pr
        item = add_self_hash(item, "challenge_sha256")
        self.store.run_dir(item["run_id"]).mkdir(parents=True, exist_ok=True)
        self.store.write_run_json(item["run_id"], "challenge.json", item)
        (self.store.run_dir(item["run_id"]) / "effective-policy.bin").write_bytes(POLICY_RAW)
        (self.store.run_dir(item["run_id"]) / "effective-config.bin").write_text("gates: []\n")
        approval = MachineApprovalIssuer(self.schemas, self.store).issue(
            operation=operation, challenge=item, qa=qa_evidence(item), attestation=attestation(item),
            policy=parse_policy(POLICY_RAW), human_approval_sha256=None, now=1001,
        )
        self.github.refs.update({"feature": item["source"]["sha"], "main": item["target"]["sha"]})
        return item, approval

    def test_pr_create_derives_protected_identity_and_rereads_metadata(self) -> None:
        item, approval = self._operation(operation="create-pr")
        value = self.controller.create_pr(approval["approval_id"], title="Safe", body="Body", now=1002)
        self.assertEqual(value["head_sha"], item["source"]["sha"])
        self.assertEqual(self.github.create_calls, [{
            "repository": "o/r", "base": "main", "head": "feature", "title": "Safe", "body": "Body", "draft": False,
        }])
        self.assertEqual(self.store.load_machine_approval(approval["approval_id"])["state"], "consumed")

    def test_post_create_mismatch_fails_closed(self) -> None:
        _, approval = self._operation(operation="create-pr")
        self.github.post_create_mismatch = True
        with self.assertRaises(EvidenceError):
            self.controller.create_pr(approval["approval_id"], title="Safe", body="Body", now=1002)
        self.assertEqual(self.store.load_machine_approval(approval["approval_id"])["state"], "indeterminate")

    def test_unknown_pr_create_outcome_reconciles_without_retry(self) -> None:
        _, approval = self._operation(operation="create-pr")
        self.github.unknown_create = True
        value = self.controller.create_pr(approval["approval_id"], title="Safe", body="Body", now=1002)
        self.assertEqual(value["number"], 1)
        self.assertEqual(self.store.load_machine_approval(approval["approval_id"])["state"], "consumed")

    def test_merge_uses_expected_head_and_detects_target_movement(self) -> None:
        item, approval = self._operation(operation="merge", stage="pre-merge", pr=1)
        self.github.prs[1] = self.github._metadata(1, "feature", "main")
        value = self.controller.merge_pr(1, approval["approval_id"], now=1002)
        self.assertEqual(value["state"], "MERGED")
        self.assertEqual(self.github.expected_head_used, item["source"]["sha"])
        item2, approval2 = self._operation(operation="merge", stage="pre-merge", pr=2)
        self.github.prs[2] = self.github._metadata(2, "feature", "main")
        self.github.refs["main"] = "f" * 40
        with self.assertRaises(EvidenceError):
            self.controller.merge_pr(2, approval2["approval_id"], now=1002)

    def test_merge_requires_current_server_checks(self) -> None:
        _, approval = self._operation(operation="merge", stage="pre-merge", pr=1)
        self.github.prs[1] = self.github._metadata(1, "feature", "main")
        self.github.checks_green = False
        with self.assertRaises(EvidenceError):
            self.controller.merge_pr(1, approval["approval_id"], now=1002)
        self.assertEqual(self.store.load_machine_approval(approval["approval_id"])["state"], "approved")

    def test_cli_rejects_protected_identity_and_merge_verify_path(self) -> None:
        for argv in (
            ["pr", "create", "--approval-id", "x", "--title", "t", "--body", "b", "--base", "evil"],
            ["pr", "create", "--approval-id", "x", "--title", "t", "--body", "b", "--repo", "evil/x"],
            ["pr", "merge", "--pr", "1", "--approval-id", "x", "--verify-path", "/tmp/pwn"],
            ["pr", "merge", "--pr", "1", "--approval-id", "x", "--head", "evil"],
        ):
            with self.assertRaises(SystemExit):
                parser().parse_args(argv)


if __name__ == "__main__":
    unittest.main()
