from __future__ import annotations

from typing import Any

import yaml

from .errors import EvidenceError


def validate_orchestration_config(raw: bytes) -> dict[str, Any]:
    try:
        value = yaml.safe_load(raw)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise EvidenceError(f"orchestration config is malformed YAML: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError("orchestration config must be a mapping")
    if value.get("schema_version") != 1:
        raise EvidenceError("orchestration config schema_version must be 1")
    if value.get("minimum_orka_version") != "1.8.0":
        raise EvidenceError("orchestration config must pin minimum_orka_version to 1.8.0")
    return value
