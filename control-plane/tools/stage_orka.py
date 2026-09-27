#!/usr/bin/env python3
"""Copy an installed Orka tree into a deterministic closed staging runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


IGNORED_PARTS = {".git", "__pycache__"}
INVENTORY = "orka-files.json"


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def stage(source: Path, destination: Path) -> dict[str, str]:
    source = source.resolve(strict=True)
    if destination.exists():
        raise RuntimeError(f"destination already exists: {destination}")
    destination.mkdir(parents=True, mode=0o755)
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        if any(part in IGNORED_PARTS for part in relative.parts) or item.name == INVENTORY:
            continue
        if item.is_symlink():
            raise RuntimeError(f"Orka source contains a symlink: {relative}")
        target = destination / relative
        if item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.read_bytes())
            executable = bool(stat.S_IMODE(item.stat().st_mode) & 0o111)
            os.chmod(target, 0o555 if executable else 0o444)
    entries: dict[str, dict[str, str]] = {}
    for path in sorted(item for item in destination.rglob("*") if item.is_file()):
        relative = path.relative_to(destination).as_posix()
        entries[relative] = {"mode": f"{stat.S_IMODE(path.stat().st_mode):04o}", "sha256": sha(path.read_bytes())}
    raw = canonical({"schema_version": 1, "files": entries}) + b"\n"
    inventory = destination / INVENTORY
    inventory.write_bytes(raw)
    os.chmod(inventory, 0o444)
    for directory in sorted((item for item in destination.rglob("*") if item.is_dir()), reverse=True):
        os.chmod(directory, 0o555)
    os.chmod(destination, 0o555)
    return {"digest": sha(canonical(entries)), "inventory_digest": sha(raw)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(canonical(stage(args.source, args.destination)).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
