#!/usr/bin/env bash
set -euo pipefail
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
export PYTHONPATH="$repo_root/control-plane/src"
export PYTHONDONTWRITEBYTECODE=1
exec python3 -B -m unittest discover -s "$repo_root/control-plane/tests" -p 'test_*.py' -v
