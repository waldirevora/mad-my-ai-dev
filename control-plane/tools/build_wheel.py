#!/usr/bin/env python3
"""Build a deterministic transport wheel for the MAD release sources."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def build(source: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update({"SOURCE_DATE_EPOCH": "315532800", "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1"})
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(output), str(source)],
        env=env, stdin=subprocess.DEVNULL, check=True,
    )
    wheels = list(output.glob("mad_final_gates-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("deterministic wheel build did not produce exactly one artifact")
    return wheels[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(build(args.source.resolve(strict=True), args.output.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
