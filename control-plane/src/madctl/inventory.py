from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .canonical import canonical_sha256, sha256_bytes
from .errors import AuthorityError


def verify_closed_inventory(
    root: Path,
    *,
    inventory_name: str,
    expected_inventory_digest: str,
    expected_tree_digest: str,
    trusted_uid: int,
    required_paths: set[str],
    trusted_gid: int | None = None,
) -> dict[str, dict[str, str]]:
    supplied = root
    if not supplied.is_absolute() or supplied.is_symlink():
        raise AuthorityError("closed runtime root must be absolute and non-symlink")
    root = supplied.resolve(strict=True)
    if root != supplied or not root.is_dir():
        raise AuthorityError("closed runtime root must be canonical")
    inventory_path = root / inventory_name
    if inventory_path.is_symlink() or not inventory_path.is_file():
        raise AuthorityError("closed runtime inventory is missing")
    inventory_info = inventory_path.stat()
    if (inventory_info.st_uid != trusted_uid or
            (trusted_gid is not None and inventory_info.st_gid != trusted_gid) or
            stat.S_IMODE(inventory_info.st_mode) != 0o444):
        raise AuthorityError("closed runtime inventory has unsafe ownership or permissions")
    raw = inventory_path.read_bytes()
    if sha256_bytes(raw) != expected_inventory_digest:
        raise AuthorityError("closed runtime inventory digest mismatch")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AuthorityError(f"closed runtime inventory is malformed: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "files"} or value["schema_version"] != 1:
        raise AuthorityError("closed runtime inventory has invalid fields")
    entries = value["files"]
    if not isinstance(entries, dict) or not entries or not required_paths <= set(entries):
        raise AuthorityError("closed runtime inventory is incomplete")
    actual: set[str] = set()
    actual_directories: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise AuthorityError(f"closed runtime contains a symlink: {path}")
        if path.is_file() and path != inventory_path:
            actual.add(path.relative_to(root).as_posix())
        elif path.is_dir():
            actual_directories.add(path.relative_to(root).as_posix())
    if actual != set(entries):
        raise AuthorityError(
            f"closed runtime contents differ from inventory; missing={sorted(set(entries)-actual)}, extra={sorted(actual-set(entries))}"
        )
    expected_directories = {
        parent.as_posix()
        for relative in entries
        for parent in Path(relative).parents
        if parent.as_posix() != "."
    }
    if actual_directories != expected_directories:
        raise AuthorityError("closed runtime contains missing or unexpected directories")
    for relative in [".", *sorted(actual_directories)]:
        directory = root if relative == "." else root / relative
        info = directory.stat()
        if (info.st_uid != trusted_uid or (trusted_gid is not None and info.st_gid != trusted_gid) or
                stat.S_IMODE(info.st_mode) != 0o555):
            raise AuthorityError(f"closed runtime directory has unsafe ownership or permissions: {relative}")
    normalized: dict[str, dict[str, str]] = {}
    for relative, record in entries.items():
        candidate = Path(relative)
        if (
            not isinstance(relative, str)
            or candidate.is_absolute()
            or ".." in candidate.parts
            or not isinstance(record, dict)
            or set(record) != {"mode", "sha256"}
        ):
            raise AuthorityError(f"unsafe closed runtime inventory entry: {relative!r}")
        path = root / candidate
        if path.resolve(strict=True) != path or path.is_symlink() or not path.is_file():
            raise AuthorityError(f"closed runtime file escapes its root: {relative}")
        info = path.stat()
        mode = f"{stat.S_IMODE(info.st_mode):04o}"
        if (info.st_uid != trusted_uid or (trusted_gid is not None and info.st_gid != trusted_gid) or
                info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise AuthorityError(f"closed runtime file has unsafe ownership or permissions: {relative}")
        if record["mode"] != mode or record["sha256"] != sha256_bytes(path.read_bytes()):
            raise AuthorityError(f"closed runtime file mismatch: {relative}")
        normalized[relative] = {"mode": mode, "sha256": record["sha256"]}
    if canonical_sha256(normalized) != expected_tree_digest:
        raise AuthorityError("closed runtime tree digest mismatch")
    return normalized


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result
