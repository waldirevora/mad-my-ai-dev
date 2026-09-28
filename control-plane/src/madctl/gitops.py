from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .canonical import sha256_bytes, sha256_file
from .errors import AuthorityError, EvidenceError
from .policy import validate_repo_path


GIT_OVERRIDE_ENV = {
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_COMMON_DIR",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
}


@dataclass(frozen=True)
class TrustedTool:
    path: Path
    sha256: str
    uid: int
    gid: int
    system_uid: int
    root: Path
    _test_allow_unsafe_ancestors: bool = False

    @classmethod
    def verify(
        cls, path: Path, expected_sha256: str, *, expected_uid: int,
        expected_gid: int, system_uid: int, allowed_root: Path,
        _test_allow_unsafe_ancestors: bool = False,
    ) -> "TrustedTool":
        if not path.is_absolute() or path.is_symlink():
            raise AuthorityError(f"trusted executable path must be absolute, canonical, and non-symlink: {path}")
        resolved = path.resolve(strict=True)
        if resolved != path or not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise AuthorityError(f"trusted executable is not executable: {resolved}")
        uid = expected_uid
        gid = expected_gid
        root_input = allowed_root
        if not root_input.is_absolute() or root_input.is_symlink():
            raise AuthorityError("trusted tool root must be absolute and non-symlink")
        root = root_input.resolve(strict=True)
        if root != root_input or not root.is_dir():
            raise AuthorityError("trusted tool root must be a canonical directory")
        if not _test_allow_unsafe_ancestors:
            ancestor = root.parent
            while True:
                ancestor_info = ancestor.stat()
                if ancestor_info.st_uid not in {system_uid, uid} or ancestor_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    raise AuthorityError(f"trusted tool root has unsafe ancestor directory: {ancestor}")
                if ancestor == ancestor.parent:
                    break
                ancestor = ancestor.parent
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise AuthorityError("trusted executable escapes its allowed root") from exc
        info = resolved.stat()
        if (info.st_uid != uid or info.st_gid != gid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or
                not stat.S_ISREG(info.st_mode)):
            raise AuthorityError(f"trusted executable has unsafe ownership or permissions: {resolved}")
        current = resolved.parent
        while True:
            parent_info = current.stat()
            if (parent_info.st_uid != uid or parent_info.st_gid != gid or
                    parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise AuthorityError(f"trusted executable has unsafe parent directory: {current}")
            if current == root:
                break
            current = current.parent
        actual = sha256_file(resolved)
        if actual != expected_sha256:
            raise AuthorityError(f"trusted executable digest mismatch: {resolved}")
        return cls(resolved, actual, uid, gid, system_uid, root, _test_allow_unsafe_ancestors)

    @classmethod
    def for_tests(cls, path: Path, expected_sha256: str) -> "TrustedTool":
        """Test-only convenience; production activation always supplies identity."""
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        return cls.verify(
            resolved, expected_sha256, expected_uid=info.st_uid, expected_gid=info.st_gid,
            system_uid=Path("/").stat().st_uid, allowed_root=resolved.parent,
            _test_allow_unsafe_ancestors=True,
        )

    def revalidate(self) -> Path:
        verified = type(self).verify(
            self.path, self.sha256, expected_uid=self.uid, expected_gid=self.gid, allowed_root=self.root,
            system_uid=self.system_uid,
            _test_allow_unsafe_ancestors=self._test_allow_unsafe_ancestors,
        )
        return verified.path


def sanitized_env(*, path_entries: Iterable[Path] = (), extra: dict[str, str] | None = None) -> dict[str, str]:
    entries = [str(item.resolve()) for item in path_entries]
    env = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.pathsep.join(entries) if entries else "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }
    if extra:
        env.update(extra)
    return env


class GitRunner:
    def __init__(self, git: TrustedTool, *, _test_allow_file_protocol: bool = False) -> None:
        self.git = git
        self._allow_file_protocol = _test_allow_file_protocol

    @classmethod
    def for_tests(cls, git: TrustedTool) -> "GitRunner":
        return cls(git, _test_allow_file_protocol=True)

    def run(self, args: list[str], *, cwd: Path | None = None, check: bool = True) -> bytes:
        executable = self.git.revalidate()
        command = [
            str(executable),
            "-c", "core.hooksPath=/dev/null",
            "-c", "core.fsmonitor=false",
            "-c", "diff.external=",
            "-c", "interactive.diffFilter=",
            "-c", "protocol.ext.allow=never",
            "-c", f"protocol.file.allow={'always' if self._allow_file_protocol else 'never'}",
            *args,
        ]
        result = subprocess.run(
            command,
            cwd=cwd,
            env=sanitized_env(path_entries=(executable.parent, Path("/usr/bin"), Path("/bin"))),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if check and result.returncode != 0:
            message = result.stderr.decode("utf-8", "replace")[:2000]
            raise EvidenceError(f"trusted git command failed ({result.returncode}): {message}")
        return result.stdout

    def init_bare(self, mirror: Path) -> None:
        if mirror.exists():
            if not (mirror / "HEAD").is_file():
                raise AuthorityError(f"controller mirror is malformed: {mirror}")
            return
        mirror.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.run(["init", "--bare", str(mirror)])

    def validate_branch(self, branch: str) -> None:
        if not branch or branch.startswith("-"):
            raise EvidenceError("invalid branch name")
        self.run(["check-ref-format", "--branch", branch])

    def fetch_exact_branches(self, mirror: Path, remote: str, source: str, target: str) -> tuple[str, str]:
        self.validate_branch(source)
        self.validate_branch(target)
        self.init_bare(mirror)
        self.run(
            [
                "--git-dir", str(mirror), "fetch", "--no-tags", "--force", remote,
                f"+refs/heads/{source}:refs/mad/source",
                f"+refs/heads/{target}:refs/mad/target",
            ]
        )
        source_sha = self.run(["--git-dir", str(mirror), "rev-parse", "refs/mad/source"]).decode("ascii").strip().lower()
        target_sha = self.run(["--git-dir", str(mirror), "rev-parse", "refs/mad/target"]).decode("ascii").strip().lower()
        _require_oid(source_sha)
        _require_oid(target_sha)
        return source_sha, target_sha

    def merge_base(self, mirror: Path, target_sha: str, source_sha: str) -> str:
        value = self.run(["--git-dir", str(mirror), "merge-base", target_sha, source_sha]).decode("ascii").strip().lower()
        _require_oid(value)
        return value

    def raw_diff(self, mirror: Path, target_sha: str, source_sha: str) -> bytes:
        return self.run([
            "--git-dir", str(mirror), "diff", "--binary", "--full-index",
            "--no-renames", "--no-ext-diff", "--no-textconv", f"{target_sha}...{source_sha}",
        ])

    def changed_paths_raw(self, mirror: Path, target_sha: str, source_sha: str) -> bytes:
        return self.run([
            "--git-dir", str(mirror), "diff", "--name-status", "-z", "--no-renames",
            "--no-ext-diff", "--no-textconv", f"{target_sha}...{source_sha}",
        ])

    def blob(self, mirror: Path, commit: str, path: str) -> bytes:
        validate_repo_path(path)
        return self.run(["--git-dir", str(mirror), "cat-file", "blob", f"{commit}:{path}"])

    def optional_blob(self, mirror: Path, commit: str, path: str) -> bytes | None:
        validate_repo_path(path)
        executable = self.git.revalidate()
        result = subprocess.run(
            [
                str(executable), "-c", "core.hooksPath=/dev/null",
                "--git-dir", str(mirror), "cat-file", "blob", f"{commit}:{path}",
            ],
            env=sanitized_env(path_entries=(executable.parent, Path("/usr/bin"), Path("/bin"))),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout
        if result.returncode == 128:
            return None
        raise EvidenceError(f"cannot inspect blob {commit}:{path}")

    def assert_clean_candidate(self, candidate: Path, expected_sha: str) -> None:
        root = candidate.resolve(strict=True)
        head = self.run(["-C", str(root), "rev-parse", "HEAD"]).decode("ascii").strip().lower()
        if head != expected_sha:
            raise EvidenceError("candidate checkout HEAD differs from authoritative remote source SHA")
        dirty = self.run(["-C", str(root), "status", "--porcelain=v1", "-z", "--untracked-files=all"])
        if dirty:
            raise EvidenceError("candidate checkout is dirty")

    def materialize_snapshot(self, mirror: Path, commit: str, destination: Path) -> dict[str, str]:
        if destination.exists():
            raise EvidenceError(f"snapshot destination already exists: {destination}")
        destination.mkdir(parents=True, mode=0o700)
        listing = self.run(["--git-dir", str(mirror), "ls-tree", "-r", "-z", "--full-tree", commit])
        modes: dict[str, str] = {}
        try:
            records = [record for record in listing.split(b"\0") if record]
            for record in records:
                meta, raw_path = record.split(b"\t", 1)
                mode_raw, object_type, oid_raw = meta.split(b" ", 2)
                mode = mode_raw.decode("ascii")
                object_id = oid_raw.decode("ascii")
                path = raw_path.decode("utf-8", "strict")
                validate_repo_path(path)
                target = destination.joinpath(*PureParts(path))
                if not _within(target, destination):
                    raise EvidenceError(f"snapshot path escapes destination: {path}")
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if object_type == b"blob":
                    data = self.run(["--git-dir", str(mirror), "cat-file", "blob", object_id])
                    if mode == "120000":
                        data = b"MAD_UNTRUSTED_SYMLINK_TARGET\n" + data
                    target.write_bytes(data)
                    os.chmod(target, 0o400)
                elif object_type == b"commit":
                    target.write_bytes(b"MAD_UNTRUSTED_SUBMODULE " + oid_raw + b"\n")
                    os.chmod(target, 0o400)
                else:
                    raise EvidenceError(f"unsupported Git tree object type: {object_type!r}")
                modes[path] = mode
        except (ValueError, UnicodeDecodeError) as exc:
            shutil.rmtree(destination, ignore_errors=True)
            raise EvidenceError(f"malformed Git tree listing: {exc}") from exc
        for directory in sorted((item for item in destination.rglob("*") if item.is_dir()), reverse=True):
            os.chmod(directory, 0o500)
        os.chmod(destination, 0o500)
        return modes


def parse_name_status_z(raw: bytes) -> list[str]:
    if raw and not raw.endswith(b"\0"):
        raise EvidenceError("malformed unterminated NUL name-status stream")
    tokens = raw.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    if len(tokens) % 2:
        raise EvidenceError("malformed NUL name-status stream")
    paths: list[str] = []
    for index in range(0, len(tokens), 2):
        try:
            status = tokens[index].decode("ascii")
            path = tokens[index + 1].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise EvidenceError("non-UTF-8 status or path is not policy-classifiable") from exc
        if not re.fullmatch(r"[ADMTUXB]", status):
            raise EvidenceError(f"unsupported or malformed Git status record: {status!r}")
        validate_repo_path(path)
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise EvidenceError("duplicate paths in Git status stream")
    return paths


def presence_digest(raw: bytes | None) -> dict[str, object]:
    if raw is None:
        return {"present": False, "sha256": None, "byte_length": None}
    return {"present": True, "sha256": sha256_bytes(raw), "byte_length": len(raw)}


def _require_oid(value: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", value):
        raise EvidenceError(f"invalid Git object ID: {value!r}")


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def PureParts(value: str) -> tuple[str, ...]:
    from pathlib import PurePosixPath

    return PurePosixPath(value).parts
