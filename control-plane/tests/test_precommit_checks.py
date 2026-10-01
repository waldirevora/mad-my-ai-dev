from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parents[2]
_MODULE_PATH = _ROOT / "control-plane" / "tools" / "precommit_checks.py"
_SPEC = importlib.util.spec_from_file_location("precommit_checks", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
checks = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = checks
_SPEC.loader.exec_module(checks)


def write(root: Path, relative: str, content: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_repository_path_enumeration_is_deterministic(tmp_path, monkeypatch):
    monkeypatch.setattr(
        checks,
        "_git_paths",
        lambda root: b"z.py\0a.py\0nested/b.py\0a.py\0",
    )

    assert checks.enumerate_repository_paths(tmp_path) == (
        "a.py",
        "nested/b.py",
        "z.py",
    )


def test_valid_python_and_text_are_accepted_without_bytecode(tmp_path):
    write(tmp_path, "source.py", b"value = 1\n")
    write(tmp_path, "README.md", b"safe text\n")

    assert checks.check_repository(
        tmp_path,
        ("source.py", "README.md"),
    ) == ()
    assert not list(tmp_path.rglob("*.pyc"))
    assert not list(tmp_path.rglob("__pycache__"))


def test_syntax_invalid_python_is_rejected_without_bytecode(tmp_path):
    write(tmp_path, "broken.py", b"if True print('no')\n")

    assert checks.check_repository(tmp_path, ("broken.py",)) == (
        checks.Violation("broken.py", "invalid Python source"),
    )
    assert not list(tmp_path.rglob("*.pyc"))
    assert not list(tmp_path.rglob("__pycache__"))


@pytest.mark.parametrize(
    ("relative", "expected_reason"),
    [
        (".env.production", "prohibited environment file"),
        ("credentials/private.pem", "prohibited generated, secret, or binary artifact"),
        ("cache/__pycache__/module.pyc", "prohibited generated or cache path"),
        ("logs/run.log", "prohibited generated or cache path"),
        ("runtime/service.sock", "prohibited generated, secret, or binary artifact"),
        (".orchestration/.gate-status/state.json", "prohibited Orka runtime state"),
        ("native/module.o", "prohibited generated, secret, or binary artifact"),
        ("release.zip", "prohibited generated, secret, or binary artifact"),
        ("build/output.txt", "prohibited generated or cache path"),
    ],
)
def test_prohibited_path_categories(tmp_path, relative, expected_reason):
    assert checks._path_reason(relative) == expected_reason


def test_nul_containing_file_is_rejected(tmp_path):
    write(tmp_path, "opaque.data", b"prefix\0suffix")

    assert checks.check_repository(tmp_path, ("opaque.data",)) == (
        checks.Violation("opaque.data", "unexpected NUL-containing file"),
    )


def test_failure_diagnostics_are_sorted_path_only_and_do_not_leak_content(tmp_path):
    secret_text = b"password=do-not-print-this-value\0"
    write(tmp_path, "z.data", secret_text)
    write(tmp_path, "a.py", b"def invalid(:\n")
    stderr = io.StringIO()

    status = checks.run(
        root=tmp_path,
        paths=("z.data", "a.py"),
        stderr=stderr,
    )

    assert status == 1
    assert stderr.getvalue().splitlines() == [
        '"a.py": invalid Python source',
        '"z.data": unexpected NUL-containing file',
    ]
    assert "do-not-print-this-value" not in stderr.getvalue()


def test_success_status_is_zero(tmp_path):
    write(tmp_path, "allowed.txt", b"allowed text\n")
    stderr = io.StringIO()

    assert checks.run(
        root=tmp_path,
        paths=("allowed.txt",),
        stderr=stderr,
    ) == 0
    assert stderr.getvalue() == ""


def test_real_git_enumeration_includes_tracked_untracked_and_deleted(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    write(tmp_path, ".gitignore", b"*.ignored\n")
    write(tmp_path, "tracked.txt", b"tracked\n")
    write(tmp_path, "deleted.txt", b"deleted\n")
    environment = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
    }
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", ".gitignore", "tracked.txt", "deleted.txt"],
        check=True,
        env=environment,
    )
    write(tmp_path, "untracked.txt", b"untracked\n")
    write(tmp_path, "ignored.ignored", b"ignored\n")
    (tmp_path / "deleted.txt").unlink()

    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    assert checks.enumerate_repository_paths(tmp_path) == (
        ".gitignore",
        "deleted.txt",
        "tracked.txt",
        "untracked.txt",
    )
    assert checks.check_repository(
        tmp_path,
        checks.enumerate_repository_paths(tmp_path),
    ) == (
        checks.Violation("deleted.txt", "cannot inspect repository path"),
    )


def test_large_file_is_rejected_before_content_read(tmp_path, monkeypatch):
    path = tmp_path / "large.txt"
    path.write_bytes(b"sensitive-marker" + b"x" * checks.MAX_FILE_BYTES)

    def reject_open(*args, **kwargs):
        raise AssertionError("large file was opened")

    monkeypatch.setattr(checks.os, "open", reject_open)
    violations = checks.check_repository(tmp_path, ("large.txt",))

    assert violations == (
        checks.Violation("large.txt", "file exceeds 500 KiB limit"),
    )
    assert "sensitive-marker" not in violations[0].reason


def test_growth_after_lstat_is_bounded_and_descriptor_closes(tmp_path, monkeypatch):
    write(tmp_path, "growing.txt", b"initial")
    original_open = checks.os.open
    original_fstat = checks.os.fstat
    opened_descriptors = []
    requested = []

    def capture_open(path, flags):
        descriptor = original_open(path, flags)
        opened_descriptors.append(descriptor)
        return descriptor

    def growing_read(descriptor, count):
        requested.append(count)
        return b"x" * count

    monkeypatch.setattr(checks.os, "open", capture_open)
    monkeypatch.setattr(checks.os, "read", growing_read)

    assert checks.check_repository(tmp_path, ("growing.txt",)) == (
        checks.Violation("growing.txt", "file exceeds 500 KiB limit"),
    )
    assert sum(requested) == checks.MAX_FILE_BYTES + 1
    assert max(requested) <= checks._READ_CHUNK_BYTES
    with pytest.raises(OSError):
        original_fstat(opened_descriptors[0])


def test_descriptor_closes_after_success(tmp_path, monkeypatch):
    write(tmp_path, "small.txt", b"small text\n")
    original_open = checks.os.open
    original_fstat = checks.os.fstat
    opened_descriptors = []

    def capture_open(path, flags):
        descriptor = original_open(path, flags)
        opened_descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(checks.os, "open", capture_open)
    assert checks.check_repository(tmp_path, ("small.txt",)) == ()
    with pytest.raises(OSError):
        original_fstat(opened_descriptors[0])


def test_file_that_grows_before_open_is_rejected_before_read(tmp_path, monkeypatch):
    path = tmp_path / "candidate.txt"
    path.write_bytes(b"small\n")
    original_open = checks.os.open
    original_fstat = checks.os.fstat
    opened_descriptors = []

    def grow_then_open(candidate, flags):
        path.write_bytes(b"x" * (checks.MAX_FILE_BYTES + 1))
        descriptor = original_open(candidate, flags)
        opened_descriptors.append(descriptor)
        return descriptor

    def reject_read(descriptor, count):
        raise AssertionError("oversized opened file was read")

    monkeypatch.setattr(checks.os, "open", grow_then_open)
    monkeypatch.setattr(checks.os, "read", reject_read)
    assert checks.check_repository(tmp_path, ("candidate.txt",)) == (
        checks.Violation("candidate.txt", "file exceeds 500 KiB limit"),
    )
    with pytest.raises(OSError):
        original_fstat(opened_descriptors[0])


def test_descriptor_closes_after_fstat_failure(tmp_path, monkeypatch):
    write(tmp_path, "candidate.txt", b"candidate\n")
    original_open = checks.os.open
    original_fstat = checks.os.fstat
    opened_descriptors = []

    def capture_open(path, flags):
        descriptor = original_open(path, flags)
        opened_descriptors.append(descriptor)
        return descriptor

    def fail_fstat(descriptor):
        raise OSError("simulated fstat failure")

    monkeypatch.setattr(checks.os, "open", capture_open)
    monkeypatch.setattr(checks.os, "fstat", fail_fstat)
    assert checks.check_repository(tmp_path, ("candidate.txt",)) == (
        checks.Violation("candidate.txt", "cannot read repository file"),
    )
    with pytest.raises(OSError):
        original_fstat(opened_descriptors[0])


def test_descriptor_closes_after_read_failure(tmp_path, monkeypatch):
    write(tmp_path, "candidate.txt", b"candidate\n")
    original_open = checks.os.open
    original_fstat = checks.os.fstat
    opened_descriptors = []

    def capture_open(path, flags):
        descriptor = original_open(path, flags)
        opened_descriptors.append(descriptor)
        return descriptor

    def fail_read(descriptor, count):
        raise OSError("simulated read failure")

    monkeypatch.setattr(checks.os, "open", capture_open)
    monkeypatch.setattr(checks.os, "read", fail_read)
    assert checks.check_repository(tmp_path, ("candidate.txt",)) == (
        checks.Violation("candidate.txt", "cannot read repository file"),
    )
    with pytest.raises(OSError):
        original_fstat(opened_descriptors[0])


def test_symlink_is_rejected_without_following_target(tmp_path, monkeypatch):
    write(tmp_path, "target.txt", b"sensitive-target")
    (tmp_path / "link.txt").symlink_to("target.txt")

    def reject_open(*args, **kwargs):
        raise AssertionError("symlink was opened")

    monkeypatch.setattr(checks.os, "open", reject_open)
    assert checks.check_repository(tmp_path, ("link.txt",)) == (
        checks.Violation("link.txt", "unsupported non-regular repository object"),
    )


def test_fifo_is_rejected_without_opening(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo is unavailable on this platform")
    os.mkfifo(tmp_path / "runtime.fifo")
    assert checks.check_repository(tmp_path, ("runtime.fifo",)) == (
        checks.Violation("runtime.fifo", "unsupported non-regular repository object"),
    )


def test_fifo_replacement_after_lstat_is_nonblocking_and_rejected(
    tmp_path, monkeypatch
):
    if not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"):
        pytest.skip("nonblocking FIFO operations are unavailable on this platform")
    path = tmp_path / "candidate.txt"
    path.write_bytes(b"regular\n")
    original_open = checks.os.open
    original_fstat = checks.os.fstat
    opened_descriptors = []

    def replace_with_fifo(candidate, flags):
        path.unlink()
        os.mkfifo(path)
        assert flags & os.O_NONBLOCK
        descriptor = original_open(candidate, flags)
        opened_descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(checks.os, "open", replace_with_fifo)
    assert checks.check_repository(tmp_path, ("candidate.txt",)) == (
        checks.Violation("candidate.txt", "unsupported non-regular repository object"),
    )
    with pytest.raises(OSError):
        original_fstat(opened_descriptors[0])


def test_symlink_replacement_after_lstat_fails_closed(tmp_path, monkeypatch):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("O_NOFOLLOW is unavailable on this platform")
    path = tmp_path / "candidate.txt"
    target = tmp_path / "target.txt"
    path.write_bytes(b"regular\n")
    target.write_bytes(b"target-must-not-be-read\n")
    original_open = checks.os.open

    def replace_with_symlink(candidate, flags):
        path.unlink()
        path.symlink_to(target.name)
        assert flags & os.O_NOFOLLOW
        return original_open(candidate, flags)

    def reject_read(descriptor, count):
        raise AssertionError("symlink target was read")

    monkeypatch.setattr(checks.os, "open", replace_with_symlink)
    monkeypatch.setattr(checks.os, "read", reject_read)
    assert checks.check_repository(tmp_path, ("candidate.txt",)) == (
        checks.Violation("candidate.txt", "cannot read repository file"),
    )


def _write_baseline(root: Path) -> bytes:
    content = b'{"version":"1.5.0","plugins_used":[],"filters_used":[],"results":{}}\n'
    (root / ".secrets.baseline").write_bytes(content)
    return content


def test_clean_secret_scan_preserves_baseline_and_cleans_temporary_state(
    tmp_path, monkeypatch
):
    original = _write_baseline(tmp_path)
    temporary_paths = []

    def clean_run(command, **kwargs):
        temporary_paths.append(Path(command[3]).parent)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(checks.subprocess, "run", clean_run)
    assert checks.check_secrets(
        root=tmp_path,
        baseline_argument=".secrets.baseline",
        filenames=("safe.txt",),
        scanner="scanner",
    ) == 0
    assert (tmp_path / ".secrets.baseline").read_bytes() == original
    assert temporary_paths and all(not path.exists() for path in temporary_paths)


def test_stale_secret_baseline_fails_without_repository_mutation(
    tmp_path, monkeypatch
):
    original = _write_baseline(tmp_path)
    temporary_paths = []
    stderr = io.StringIO()

    def stale_run(command, **kwargs):
        temporary_baseline = Path(command[3])
        temporary_paths.append(temporary_baseline.parent)
        temporary_baseline.write_text('{"updated":true}\n', encoding="utf-8")
        return subprocess.CompletedProcess(command, 3, "", "unsafe child stderr")

    monkeypatch.setattr(checks.subprocess, "run", stale_run)
    assert checks.check_secrets(
        root=tmp_path,
        baseline_argument=".secrets.baseline",
        filenames=("shifted.py",),
        stderr=stderr,
        scanner="scanner",
    ) == 1
    assert (tmp_path / ".secrets.baseline").read_bytes() == original
    assert stderr.getvalue() == ".secrets.baseline: baseline is stale and requires review\n"
    assert "unsafe child stderr" not in stderr.getvalue()
    assert temporary_paths and all(not path.exists() for path in temporary_paths)


def test_new_secret_reports_safe_metadata_without_secret_content(
    tmp_path, monkeypatch
):
    original = _write_baseline(tmp_path)
    stderr = io.StringIO()
    report = {
        "results": {
            "candidate.py": [
                {
                    "type": "Secret Keyword",
                    "line_number": 7,
                    "opaque_hash": "hash-" + "must-not-print",
                    "opaque_value": "secret-" + "must-not-print",
                }
            ]
        }
    }

    def secret_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, json.dumps(report), "child-secret")

    monkeypatch.setattr(checks.subprocess, "run", secret_run)
    assert checks.check_secrets(
        root=tmp_path,
        baseline_argument=".secrets.baseline",
        filenames=("candidate.py",),
        stderr=stderr,
        scanner="scanner",
    ) == 1
    assert stderr.getvalue() == '"candidate.py": "Secret Keyword" at line 7\n'
    assert "hash-must-not-print" not in stderr.getvalue()
    assert "secret-must-not-print" not in stderr.getvalue()
    assert "child-secret" not in stderr.getvalue()
    assert (tmp_path / ".secrets.baseline").read_bytes() == original


def test_reviewed_repository_baseline_is_valid_json():
    baseline = json.loads((_ROOT / ".secrets.baseline").read_text(encoding="utf-8"))
    assert baseline["version"] == "1.5.0"
    assert sum(len(findings) for findings in baseline["results"].values()) == 9
