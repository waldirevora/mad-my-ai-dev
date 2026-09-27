#!/usr/bin/env python3
"""Build the deterministic closed MAD release directory and ZIP artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path
from typing import Any


EPOCH = max(315532800, int(os.environ.get("SOURCE_DATE_EPOCH", "315532800")))
CONTROL_FILES = (
    "sandbox-profile.json",
    "genesis-policy.json",
    "genesis-config.yaml",
    "control-plane.lock.json",
    "release-metadata.json",
)


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _copy(source: Path, destination: Path, mode: int) -> None:
    if source.is_symlink() or not source.is_file():
        raise RuntimeError(f"release source must be a regular non-symlink file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(source.read_bytes())
    os.chmod(destination, mode)
    os.utime(destination, (EPOCH, EPOCH), follow_symlinks=False)


def build_release(source_root: Path, output: Path) -> dict[str, str]:
    source_root = source_root.resolve(strict=True)
    control = source_root / "control-plane"
    if output.exists():
        raise RuntimeError(f"release destination already exists: {output}")
    output.mkdir(parents=True, mode=0o755)
    for source in sorted((control / "src/madctl").rglob("*")):
        if source.is_symlink():
            raise RuntimeError(f"release Python source must not be a symlink: {source}")
        if source.is_file() and "__pycache__" not in source.parts and source.suffix != ".pyc":
            _copy(source, output / "python/madctl" / source.relative_to(control / "src/madctl"), 0o444)
    for source in sorted((control / "schemas").rglob("*")):
        if source.is_symlink():
            raise RuntimeError(f"release schema source must not be a symlink: {source}")
        if source.is_file():
            _copy(source, output / "schemas" / source.relative_to(control / "schemas"), 0o444)
    for relative in CONTROL_FILES:
        _copy(control / relative, output / relative, 0o444)
    _copy(control / "launcher/madctl-launcher.py", output / "launcher/madctl-launcher.py", 0o444)
    _copy(control / "launcher/madctl-launcher.c", output / "launcher/madctl-launcher.c", 0o444)
    entries: dict[str, dict[str, str]] = {}
    for path in sorted(item for item in output.rglob("*") if item.is_file()):
        relative = path.relative_to(output).as_posix()
        entries[relative] = {"mode": f"{stat.S_IMODE(path.stat().st_mode):04o}", "sha256": digest(path.read_bytes())}
    inventory_raw = canonical({"schema_version": 1, "files": entries}) + b"\n"
    inventory = output / "release-files.json"
    inventory.write_bytes(inventory_raw)
    os.chmod(inventory, 0o444)
    os.utime(inventory, (EPOCH, EPOCH), follow_symlinks=False)
    for directory in sorted((item for item in output.rglob("*") if item.is_dir()), reverse=True):
        os.chmod(directory, 0o555)
        os.utime(directory, (EPOCH, EPOCH), follow_symlinks=False)
    os.chmod(output, 0o555)
    os.utime(output, (EPOCH, EPOCH), follow_symlinks=False)
    return {"release_digest": digest(canonical(entries)), "inventory_digest": digest(inventory_raw)}


def build_zip(release_root: Path, archive: Path) -> str:
    archive.parent.mkdir(parents=True, exist_ok=True)
    timestamp = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(item for item in release_root.rglob("*") if item.is_file()):
            relative = path.relative_to(release_root).as_posix()
            info = zipfile.ZipInfo(relative, timestamp)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IMODE(path.stat().st_mode) & 0xFFFF) << 16
            bundle.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return digest(archive.read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    result = build_release(args.source_root, args.output)
    result["artifact_sha256"] = build_zip(args.output, args.archive)
    print(canonical(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
