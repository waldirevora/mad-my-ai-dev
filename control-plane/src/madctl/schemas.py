from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

from .canonical import sha256_file
from .errors import SchemaError


SCHEMAS = {
    "activation-record": "activation-record.schema.json",
    "challenge": "challenge.schema.json",
    "codex-attestation": "codex-attestation.schema.json",
    "orka-review-attestation": "orka-review-attestation.schema.json",
    "qa-evidence": "qa-evidence.schema.json",
    "human-approval": "human-approval.schema.json",
    "machine-approval": "machine-approval.schema.json",
    "consumption-record": "consumption-record.schema.json",
    "repository-record": "repository-record.schema.json",
    "codex-model-output": "codex-model-output.schema.json",
}


class SchemaRegistry:
    def __init__(self, schema_root: Path) -> None:
        self.root = schema_root.resolve(strict=True)
        self._schemas: dict[str, dict[str, Any]] = {}
        self._digests: dict[str, str] = {}
        for name, filename in SCHEMAS.items():
            path = self.root / filename
            if path.parent != self.root or not path.is_file() or path.is_symlink():
                raise SchemaError(f"missing trusted schema: {filename}")
            try:
                value = json.loads(path.read_bytes())
                jsonschema.Draft202012Validator.check_schema(value)
            except Exception as exc:
                raise SchemaError(f"invalid trusted schema {filename}: {exc}") from exc
            self._schemas[name] = value
            self._digests[name] = sha256_file(path)

    def validate(self, name: str, value: Any) -> None:
        if name not in self._schemas:
            raise SchemaError(f"unknown installed schema: {name}")
        validator = jsonschema.Draft202012Validator(self._schemas[name])
        errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
        if errors:
            detail = "; ".join(
                f"{'/'.join(map(str, error.path)) or '<root>'}: {error.message}"
                for error in errors[:8]
            )
            raise SchemaError(f"{name} schema rejected evidence: {detail}")

    def digest(self, name: str) -> str:
        try:
            return self._digests[name]
        except KeyError as exc:
            raise SchemaError(f"unknown installed schema: {name}") from exc


def schema_bundle_digest(registry: SchemaRegistry) -> str:
    from .canonical import canonical_sha256

    return canonical_sha256({name: registry.digest(name) for name in sorted(SCHEMAS)})
