from __future__ import annotations

import os
import ast
import json
import resource
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .canonical import add_self_hash, canonical_sha256, sha256_bytes
from .errors import AuthorityError, EvidenceError
from .gitops import TrustedTool, sanitized_env
from .policy import Policy
from .policy import parse_policy
from .config import validate_orchestration_config
from .schemas import SchemaRegistry


@dataclass(frozen=True)
class CheckResult:
    exit_code: int | None
    timed_out: bool
    stdout: bytes
    stderr: bytes


class Sandbox(Protocol):
    @property
    def profile_digest(self) -> str: ...

    def run(self, argv: list[str], *, cwd: Path, timeout: int) -> CheckResult: ...


class InstalledSandbox:
    """A pinned bubblewrap runtime with no network, home, credentials, or writable source."""

    def __init__(self, bwrap: TrustedTool, profile: bytes) -> None:
        self.bwrap = bwrap
        self._profile_digest = sha256_bytes(profile)

    @property
    def profile_digest(self) -> str:
        return self._profile_digest

    def run(self, argv: list[str], *, cwd: Path, timeout: int) -> CheckResult:
        limit = 4 * 1024 * 1024

        def limits() -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            executable = self.bwrap.revalidate()
            command = [
                str(executable), "--unshare-all", "--die-with-parent", "--new-session",
                "--ro-bind", "/usr", "/usr", "--ro-bind-try", "/usr/local", "/usr/local",
                "--ro-bind-try", "/bin", "/bin", "--ro-bind-try", "/lib", "/lib",
                "--ro-bind-try", "/lib64", "/lib64", "--dev", "/dev", "--proc", "/proc",
                "--tmpfs", "/tmp", "--ro-bind", str(cwd), "/workspace", "--chdir", "/workspace",
                "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
                "--setenv", "PYTHONPATH", "/workspace/control-plane/src",
                "--setenv", "HOME", "/tmp", "--", *argv,
            ]
            process = subprocess.Popen(
                command,
                cwd=Path("/"),
                env=sanitized_env(path_entries=(executable.parent, Path("/usr/bin"), Path("/bin"))),
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
                preexec_fn=limits,
            )
            timed_out = False
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            stdout.seek(0)
            stderr.seek(0)
            return CheckResult(None if timed_out else process.returncode, timed_out, stdout.read(), stderr.read())


class QaRunner:
    def __init__(
        self,
        schemas: SchemaRegistry,
        sandbox: Sandbox,
        tools: Mapping[str, TrustedTool],
    ) -> None:
        self.schemas = schemas
        self.sandbox = sandbox
        self.tools = dict(tools)

    def run(
        self,
        *,
        challenge: dict[str, Any],
        policy: Policy,
        source: Path,
        now: int | None = None,
    ) -> dict[str, Any]:
        now = int(time.time()) if now is None else now
        _assert_live_challenge(challenge, now=now, skew=policy.clock_skew)
        plan = policy.qa_plan(challenge["classification"])
        if canonical_sha256(plan) != challenge["qa_plan_sha256"]:
            raise EvidenceError("trusted QA plan no longer matches the challenge")
        if challenge["classification"] in {"genesis", "control-plane/high-risk", "code"}:
            if not any(entry["tool"] != "builtin" for entry in plan):
                raise EvidenceError("code and high-risk QA require a real deterministic check")
        checks: list[dict[str, Any]] = []
        for entry in plan:
            started = int(time.time()) if now is None else now
            if entry["tool"] == "builtin":
                argv = ["builtin", *entry["args"]]
                if entry["args"] == ["diff-integrity"]:
                    result = CheckResult(0, False, b"challenge diff digest is bound\n", b"")
                elif entry["args"] == ["mad-v2-source-invariants"]:
                    result = _source_invariants(source)
                else:
                    raise EvidenceError("unknown builtin QA check")
            else:
                tool = self.tools.get(entry["tool"])
                if tool is None:
                    raise AuthorityError(f"trusted QA executable is unavailable: {entry['tool']}")
                if not entry["args"] or any(not arg for arg in entry["args"]):
                    raise EvidenceError("QA command contains an empty argument")
                argv = [str(tool.revalidate()), *entry["args"]]
                result = self.sandbox.run(argv, cwd=source, timeout=entry["timeout_seconds"])
            finished = int(time.time()) if now is None else now
            passed = not result.timed_out and result.exit_code == 0
            checks.append(
                {
                    "id": entry["id"],
                    "argv_sha256": canonical_sha256(argv),
                    "started_at": started,
                    "finished_at": finished,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "stdout": {"sha256": sha256_bytes(result.stdout), "byte_length": len(result.stdout)},
                    "stderr": {"sha256": sha256_bytes(result.stderr), "byte_length": len(result.stderr)},
                    "result": "PASS" if passed else "FAIL",
                }
            )
        if not checks:
            raise EvidenceError("zero QA checks are forbidden")
        evidence = add_self_hash(
            {
                "schema_version": 1,
                "kind": "mad-qa-evidence",
                "run_id": challenge["run_id"],
                "nonce": challenge["nonce"],
                "challenge_sha256": challenge["challenge_sha256"],
                "source_sha": challenge["source"]["sha"],
                "target_sha": challenge["target"]["sha"],
                "merge_base_sha": challenge["merge_base_sha"],
                "qa_plan_sha256": challenge["qa_plan_sha256"],
                "sandbox_profile_sha256": self.sandbox.profile_digest,
                "checks": checks,
                "result": "PASS" if all(item["result"] == "PASS" for item in checks) else "FAIL",
            },
            "qa_evidence_sha256",
        )
        self.schemas.validate("qa-evidence", evidence)
        return evidence


def _assert_live_challenge(challenge: dict[str, Any], *, now: int, skew: int) -> None:
    if challenge["prepared_at"] > now + skew:
        raise EvidenceError("challenge preparation time is too far in the future")
    if challenge["expires_at"] <= now:
        raise EvidenceError("challenge preparation has expired")


def _source_invariants(source: Path) -> CheckResult:
    required = (
        ".mad/policy.yaml", ".orchestration/config.yaml", ".codex/hooks.json",
        "control-plane/src/madctl/controller.py", "control-plane/src/madctl/activation.py",
        "control-plane/src/madctl/inventory.py", "control-plane/launcher/madctl-launcher.py",
        "control-plane/launcher/madctl-launcher.c",
        "control-plane/schemas/challenge.schema.json", "control-plane/schemas/activation-record.schema.json",
        "control-plane/sandbox-profile.json", "control-plane/genesis-policy.json",
        "control-plane/genesis-config.yaml", "control-plane/control-plane.lock.json",
        "control-plane/release-metadata.json", "control-plane/tools/build_release.py",
        "control-plane/tools/build_wheel.py", "control-plane/tools/build_launcher.py",
        "control-plane/tools/stage_python_runtime.py", "control-plane/tools/stage_orka.py",
        "docs/MAD_FINAL_GATES_V2.md",
    )
    forbidden = (
        "scripts/mad-codex-command-guard.py", "scripts/mad-codex-gate.py",
        "scripts/mad-codex-verify.sh", "scripts/mad-create-pr.sh", "scripts/mad-merge-pr.sh",
        "tests/mad-codex-gates.test.sh",
    )
    errors: list[str] = []
    for relative in required:
        path = source / relative
        if not path.is_file() or path.is_symlink():
            errors.append(f"missing regular required file: {relative}")
    for relative in forbidden:
        if (source / relative).exists():
            errors.append(f"legacy authority remains: {relative}")
    try:
        parse_policy((source / ".mad/policy.yaml").read_bytes())
        validate_orchestration_config((source / ".orchestration/config.yaml").read_bytes())
        hooks = json.loads((source / ".codex/hooks.json").read_bytes())
        command = hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        if command != "/usr/local/bin/madctl hook pre-tool-use":
            errors.append("project hook does not call the fixed installed madctl path")
    except Exception as exc:
        errors.append(f"declarative control file invalid: {exc}")
    for path in sorted((source / "control-plane/src").rglob("*.py")) if (source / "control-plane/src").is_dir() else []:
        try:
            ast.parse(path.read_bytes(), filename=str(path))
        except (SyntaxError, UnicodeDecodeError) as exc:
            errors.append(f"Python syntax invalid: {path.relative_to(source)}: {exc}")
    stdout = f"checked {len(required)} required paths and trusted declarative invariants\n".encode()
    stderr = ("\n".join(errors) + ("\n" if errors else "")).encode()
    return CheckResult(1 if errors else 0, False, stdout, stderr)
