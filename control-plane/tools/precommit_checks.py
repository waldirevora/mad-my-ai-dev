#!/usr/bin/env python3
"""Check repository hygiene and Python syntax without changing files."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, TextIO


_PROHIBITED_COMPONENTS = frozenset({
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".temp",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "logs",
    "node_modules",
    "tmp",
    "venv",
})

_PROHIBITED_SUFFIXES = (
    ".7z",
    ".a",
    ".bz2",
    ".class",
    ".dll",
    ".dylib",
    ".egg",
    ".gz",
    ".jar",
    ".key",
    ".log",
    ".o",
    ".pem",
    ".pfx",
    ".pyo",
    ".pyc",
    ".rar",
    ".so",
    ".sock",
    ".socket",
    ".tar",
    ".tgz",
    ".whl",
    ".xz",
    ".zip",
)

_ORKA_RUNTIME_PREFIXES = (
    ".orchestration/.env",
    ".orchestration/.gate-logs/",
    ".orchestration/.gate-status/",
    ".orchestration/.llm-runs/",
    ".orchestration/.llm-usage/",
    ".orchestration/.review-ledger/",
    ".orchestration/.review-results/",
    ".orchestration/.sprint-state/",
    ".orchestration/worktrees/",
)

MAX_FILE_BYTES = 500 * 1024
_READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, order=True)
class Violation:
    path: str
    reason: str


def _git_paths(root: Path) -> bytes:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise RuntimeError("cannot enumerate repository paths")
    return result.stdout


def enumerate_repository_paths(root: Path) -> tuple[str, ...]:
    """Return tracked and candidate untracked paths in stable order."""

    raw_paths = _git_paths(root)
    paths = {
        os.fsdecode(raw_path)
        for raw_path in raw_paths.split(b"\0")
        if raw_path
    }
    return tuple(sorted(paths))


def _path_reason(path: str) -> str | None:
    pure = PurePosixPath(path)
    name = pure.name.lower()
    components = {component.lower() for component in pure.parts}

    if name == ".env" or name.startswith(".env."):
        return "prohibited environment file"
    if name in {".ds_store", "thumbs.db"}:
        return "prohibited operating-system artifact"
    if components & _PROHIBITED_COMPONENTS:
        return "prohibited generated or cache path"
    if any(component.endswith(".egg-info") for component in components):
        return "prohibited package build output"
    if path.lower().startswith(_ORKA_RUNTIME_PREFIXES):
        return "prohibited Orka runtime state"
    if name.endswith(_PROHIBITED_SUFFIXES):
        return "prohibited generated, secret, or binary artifact"
    return None


def _read_regular_file_bounded(candidate: Path) -> tuple[bytes | None, str | None]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)

    descriptor: int | None = None
    data: bytes | None = None
    reason: str | None = None
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            reason = "unsupported non-regular repository object"
        elif opened.st_size > MAX_FILE_BYTES:
            reason = "file exceeds 500 KiB limit"
        else:
            chunks: list[bytes] = []
            remaining = MAX_FILE_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                chunks.append(chunk[:remaining])
                remaining -= min(len(chunk), remaining)
            data = b"".join(chunks)
            if len(data) > MAX_FILE_BYTES:
                data = None
                reason = "file exceeds 500 KiB limit"
    except OSError:
        reason = "cannot read repository file"
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                data = None
                reason = "cannot close repository file"

    return data, reason


def check_repository(
    root: Path,
    paths: Iterable[str],
) -> tuple[Violation, ...]:
    violations: list[Violation] = []

    for relative in sorted(set(paths)):
        reason = _path_reason(relative)
        if reason is not None:
            violations.append(Violation(relative, reason))
            continue

        candidate = root / relative
        try:
            metadata = candidate.lstat()
        except OSError:
            violations.append(Violation(relative, "cannot inspect repository path"))
            continue

        if not stat.S_ISREG(metadata.st_mode):
            violations.append(Violation(relative, "unsupported non-regular repository object"))
            continue

        if metadata.st_size > MAX_FILE_BYTES:
            violations.append(Violation(relative, "file exceeds 500 KiB limit"))
            continue

        data, read_reason = _read_regular_file_bounded(candidate)
        if read_reason is not None:
            violations.append(Violation(relative, read_reason))
            continue
        assert data is not None

        if b"\0" in data:
            violations.append(Violation(relative, "unexpected NUL-containing file"))
            continue

        if candidate.suffix == ".py":
            try:
                compile(data, relative, "exec", dont_inherit=True)
            except (SyntaxError, UnicodeError, ValueError):
                violations.append(Violation(relative, "invalid Python source"))

    return tuple(sorted(violations))


def _print_safe_secret_diagnostics(output: str, stderr: TextIO) -> None:
    try:
        report = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        print("detect-secrets: suspected secret found", file=stderr)
        return

    results = report.get("results") if isinstance(report, dict) else None
    if not isinstance(results, dict):
        print("detect-secrets: suspected secret found", file=stderr)
        return

    reported = False
    for path in sorted(results):
        findings = results[path]
        if not isinstance(path, str) or not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            detector = finding.get("type", "unknown detector")
            line = finding.get("line_number", "unknown line")
            if not isinstance(detector, str):
                detector = "unknown detector"
            if not isinstance(line, int):
                line = "unknown line"
            safe_path = json.dumps(path, ensure_ascii=True)
            safe_detector = json.dumps(detector, ensure_ascii=True)
            print(f"{safe_path}: {safe_detector} at line {line}", file=stderr)
            reported = True
    if not reported:
        print("detect-secrets: suspected secret found", file=stderr)


def check_secrets(
    *,
    root: Path,
    baseline_argument: str,
    filenames: Iterable[str],
    stderr: TextIO = sys.stderr,
    scanner: str | None = None,
) -> int:
    """Run detect-secrets without allowing it to rewrite the real baseline."""

    root = root.resolve()
    baseline = (root / baseline_argument).resolve()
    try:
        baseline.relative_to(root)
        metadata = baseline.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError
        original_baseline = baseline.read_bytes()
    except (OSError, ValueError):
        print(f"{baseline_argument}: baseline cannot be inspected safely", file=stderr)
        return 1

    scanner = scanner or shutil.which("detect-secrets-hook")
    if scanner is None:
        print("detect-secrets: scanner executable is unavailable", file=stderr)
        return 1

    temporary_parent = Path(tempfile.gettempdir()).resolve()
    if temporary_parent == root or root in temporary_parent.parents:
        print("detect-secrets: temporary storage must be outside repository", file=stderr)
        return 1

    result: subprocess.CompletedProcess[str] | None = None
    temporary_changed = False
    try:
        with tempfile.TemporaryDirectory(
            prefix="mad-detect-secrets-",
            dir=temporary_parent,
        ) as temporary_directory:
            temporary_baseline = Path(temporary_directory) / ".secrets.baseline"
            temporary_baseline.write_bytes(original_baseline)
            command = [
                scanner,
                "--json",
                "--baseline",
                str(temporary_baseline),
                *filenames,
            ]
            result = subprocess.run(
                command,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            temporary_changed = temporary_baseline.read_bytes() != original_baseline
    except OSError:
        print("detect-secrets: scanner execution failed", file=stderr)
        return 1

    try:
        repository_changed = baseline.read_bytes() != original_baseline
    except OSError:
        repository_changed = True
    if repository_changed:
        print(f"{baseline_argument}: repository baseline changed during scan", file=stderr)
        return 1
    if temporary_changed or result.returncode == 3:
        print(f"{baseline_argument}: baseline is stale and requires review", file=stderr)
        return 1
    if result.returncode == 1:
        _print_safe_secret_diagnostics(result.stdout, stderr)
        return 1
    if result.returncode != 0:
        print(
            f"detect-secrets: scanner failed with status {result.returncode}",
            file=stderr,
        )
        return 1
    return 0


def run(
    *,
    root: Path,
    paths: Iterable[str] | None = None,
    stderr: TextIO = sys.stderr,
) -> int:
    try:
        selected = enumerate_repository_paths(root) if paths is None else tuple(paths)
        violations = check_repository(root, selected)
    except RuntimeError:
        print("repository path enumeration failed", file=stderr)
        return 1

    for violation in violations:
        safe_path = json.dumps(violation.path, ensure_ascii=True)
        print(f"{safe_path}: {violation.reason}", file=stderr)
    return 1 if violations else 0


def main() -> int:
    repository_root = Path(__file__).resolve().parents[2]
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "detect-secrets-check-only":
        if len(arguments) < 3 or arguments[1] != "--baseline":
            print("detect-secrets: invalid wrapper arguments", file=sys.stderr)
            return 1
        return check_secrets(
            root=repository_root,
            baseline_argument=arguments[2],
            filenames=arguments[3:],
        )
    if arguments:
        print("mad-repository-checks: unexpected arguments", file=sys.stderr)
        return 1
    return run(root=repository_root)


if __name__ == "__main__":
    raise SystemExit(main())
