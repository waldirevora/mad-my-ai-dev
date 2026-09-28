#!/usr/bin/env python3
"""Build MAD's dependency-free static native trust anchor."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


def build(source: Path, output: Path, *, active_record: str = "/etc/mad/active-release.json", activation_uid: int = 0,
          system_uid: int = 0) -> Path:
    if not active_record.startswith("/"):
        raise RuntimeError("activation record path must be absolute")
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "gcc", "-std=c11", "-static", "-Os", "-Wall", "-Wextra", "-Werror", "-fPIE", "-pie",
        "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-Wformat", "-Wformat-security", "-Werror=format-security",
        f'-DMAD_ACTIVE_RECORD="{active_record}"', f"-DMAD_ACTIVATION_UID={activation_uid}",
        f"-DMAD_SYSTEM_UID={system_uid}",
        "-Wl,-z,relro,-z,now", "-Wl,--build-id=none", "-o", str(output), str(source),
    ]
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "SOURCE_DATE_EPOCH": "315532800"}
    subprocess.run(command, env=env, stdin=subprocess.DEVNULL, check=True)
    os.chmod(output, 0o555)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--active-record", default="/etc/mad/active-release.json")
    parser.add_argument("--activation-uid", type=int, default=0)
    parser.add_argument("--system-uid", type=int, default=0)
    args = parser.parse_args()
    print(build(args.source.resolve(strict=True), args.output.resolve(), active_record=args.active_record,
                activation_uid=args.activation_uid, system_uid=args.system_uid))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
