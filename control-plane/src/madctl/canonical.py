from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from .errors import EvidenceError


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise EvidenceError(f"expected regular non-symlink file: {path}")
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    """Canonical UTF-8 JSON used by MAD evidence signatures and self-hashes."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def self_hash(value: dict[str, Any], field: str) -> str:
    unsigned = dict(value)
    unsigned.pop(field, None)
    return canonical_sha256(unsigned)


def add_self_hash(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result[field] = self_hash(result, field)
    return result


def verify_self_hash(value: dict[str, Any], field: str) -> None:
    claimed = value.get(field)
    if not isinstance(claimed, str) or claimed != self_hash(value, field):
        raise EvidenceError(f"invalid {field}")


def read_json_bytes(path: Path) -> tuple[bytes, Any]:
    raw = path.read_bytes()
    try:
        return raw, json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid JSON evidence {path}: {exc}") from exc


def verify_canonical_artifact(raw: bytes, value: Any) -> None:
    if raw != canonical_bytes(value) + b"\n":
        raise EvidenceError("evidence is not in the one accepted canonical byte serialization")


def atomic_write_bytes(path: Path, raw: bytes, *, exclusive: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    if exclusive:
        tmp = path.parent / f".{path.name}.tmp-{os.getpid()}-{os.urandom(8).hex()}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.close(fd)
            fd = -1

            # Publish without replacing an existing consumption record.
            os.link(tmp, path)
            tmp.unlink()

            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            if tmp.exists():
                tmp.unlink()
        return
    tmp = path.parent / f".{path.name}.tmp-{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp.exists():
            tmp.unlink()


def atomic_write_json(path: Path, value: Any, *, exclusive: bool = False) -> None:
    atomic_write_bytes(path, canonical_bytes(value) + b"\n", exclusive=exclusive)
