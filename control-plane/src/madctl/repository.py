from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .canonical import atomic_write_json, read_json_bytes, verify_canonical_artifact
from .errors import AuthorityError, EvidenceError
from .schemas import SchemaRegistry


SENSITIVE_ENV = {
    "GH_REPO",
    "ORKA_PLUGIN_ROOT",
    "MERGE_GUARD_STATUS_DIR",
    "MERGE_GUARD_PLUGIN_VERSION",
    "MERGE_GUARD_PR_HEAD_SHA",
    "MERGE_GUARD_PR_HEAD_BRANCH",
    "MERGE_GUARD_PR_BASE_SHA",
    "MERGE_GUARD_PR_BASE_BRANCH",
    "MERGE_GUARD_FORCE_FALLBACK",
    "MERGE_TARGET_ROLE",
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
    "GIT_SSH",
    "GIT_SSH_COMMAND",
}


def reject_sensitive_environment(environment: dict[str, str] | None = None) -> None:
    values = os.environ if environment is None else environment
    present = sorted(name for name in SENSITIVE_ENV if values.get(name))
    if present:
        raise AuthorityError(f"security-sensitive environment overrides are forbidden: {', '.join(present)}")


class RepositoryRegistry:
    def __init__(self, root: Path, schemas: SchemaRegistry, *, _test_allow_file_remotes: bool = False) -> None:
        if not root.is_absolute():
            raise AuthorityError("repository registry root must be absolute")
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.schemas = schemas
        self._allow_file_remotes = _test_allow_file_remotes

    @classmethod
    def for_tests(cls, root: Path, schemas: SchemaRegistry) -> "RepositoryRegistry":
        return cls(root, schemas, _test_allow_file_remotes=True)

    def register(self, record: dict[str, Any], authoritative: dict[str, Any]) -> Path:
        self.schemas.validate("repository-record", record)
        expected = {
            "host": record["host"],
            "database_id": record["database_id"],
            "name_with_owner": record["name_with_owner"],
        }
        if authoritative != expected:
            raise AuthorityError("registered repository identity does not match GitHub authority")
        expected_remote = f"https://{record['host']}/{record['name_with_owner']}.git"
        if record["registered_remote"] != expected_remote:
            if not (self._allow_file_remotes and Path(record["registered_remote"]).is_absolute()):
                raise AuthorityError("registered remote must be the exact HTTPS URL derived from GitHub identity")
        release_input = Path(record["active_release"]["root"])
        release_root = release_input.resolve(strict=True)
        if not release_input.is_absolute() or release_input != release_root or not release_root.is_dir() or release_input.is_symlink():
            raise AuthorityError("active release root is not a canonical directory")
        orka_input = Path(record["orka"]["root"])
        orka_root = orka_input.resolve(strict=True)
        if not orka_input.is_absolute() or orka_input != orka_root or not orka_root.is_dir() or orka_input.is_symlink():
            raise AuthorityError("trusted Orka root is not a canonical directory")
        path = self.root / f"{record['database_id']}.json"
        atomic_write_json(path, record, exclusive=True)
        return path

    def load(self, repository_id: int) -> dict[str, Any]:
        if not isinstance(repository_id, int) or repository_id <= 0:
            raise EvidenceError("repository ID must be a positive integer")
        raw, value = read_json_bytes(self.root / f"{repository_id}.json")
        verify_canonical_artifact(raw, value)
        self.schemas.validate("repository-record", value)
        return value
