from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import secrets
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .canonical import atomic_write_json, canonical_bytes, read_json_bytes, verify_canonical_artifact
from .errors import AuthorityError, EvidenceError
from .schemas import SchemaRegistry


class HmacSigner:
    """Controller signer. Production keys live outside repository and release roots."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise AuthorityError("controller signing key must contain at least 256 bits")
        self._key = key

    def sign(self, value: dict[str, Any], field: str = "signature") -> str:
        unsigned = dict(value)
        unsigned.pop(field, None)
        return hmac.new(self._key, canonical_bytes(unsigned), hashlib.sha256).hexdigest()

    def verify(self, value: dict[str, Any], field: str = "signature") -> None:
        claimed = value.get(field)
        if not isinstance(claimed, str) or not hmac.compare_digest(claimed, self.sign(value, field)):
            raise EvidenceError("controller signature is invalid")


class EvidenceStore:
    def __init__(self, root: Path, schemas: SchemaRegistry, signer: HmacSigner) -> None:
        if not root.is_absolute():
            raise AuthorityError("controller state root must be absolute")
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.schemas = schemas
        self.signer = signer

    def new_run(self) -> tuple[str, str]:
        run_id = str(uuid.uuid4())
        nonce = secrets.token_hex(32)
        (self.root / "runs" / run_id).mkdir(parents=True, mode=0o700)
        return run_id, nonce

    def run_dir(self, run_id: str) -> Path:
        if not _is_uuid(run_id):
            raise EvidenceError("invalid run ID")
        return self.root / "runs" / run_id

    def approval_path(self, approval_id: str) -> Path:
        if not _is_uuid(approval_id):
            raise EvidenceError("invalid approval ID")
        return self.root / "approvals" / f"{approval_id}.json"

    def write_run_json(self, run_id: str, name: str, value: Any, *, exclusive: bool = True) -> Path:
        if not name.replace("-", "").replace(".", "").isalnum():
            raise EvidenceError("unsafe evidence name")
        path = self.run_dir(run_id) / name
        atomic_write_json(path, value, exclusive=exclusive)
        return path

    def read_run_json(self, run_id: str, name: str) -> tuple[bytes, Any]:
        raw, value = read_json_bytes(self.run_dir(run_id) / name)
        verify_canonical_artifact(raw, value)
        return raw, value

    @contextmanager
    def lock(self, name: str) -> Iterator[None]:
        safe = "".join(ch for ch in name if ch.isalnum() or ch in "._-")
        if safe != name or not safe:
            raise EvidenceError("invalid lock name")
        lock_dir = self.root / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = lock_dir / f"{safe}.lock"
        with path.open("a+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def put_machine_approval(self, value: dict[str, Any]) -> None:
        value["signature"] = self.signer.sign(value)
        self.schemas.validate("machine-approval", value)
        atomic_write_json(self.approval_path(value["approval_id"]), value, exclusive=True)

    def load_machine_approval(self, approval_id: str) -> dict[str, Any]:
        raw, value = read_json_bytes(self.approval_path(approval_id))
        verify_canonical_artifact(raw, value)
        self.schemas.validate("machine-approval", value)
        self.signer.verify(value)
        return value

    def transition_approval(self, approval_id: str, expected: str, target: str, now: int | None = None) -> dict[str, Any]:
        now = int(time.time()) if now is None else now
        with self.lock(f"approval-{approval_id}"):
            value = self.load_machine_approval(approval_id)
            if value["state"] != expected:
                raise EvidenceError(f"approval is {value['state']}, expected {expected}")
            if value["expires_at"] <= now:
                raise EvidenceError("approval is expired")
            value["state"] = target
            value["signature"] = self.signer.sign(value)
            self.schemas.validate("machine-approval", value)
            atomic_write_json(self.approval_path(approval_id), value)
            return value

    def put_consumption(self, value: dict[str, Any], *, exclusive: bool) -> Path:
        value["signature"] = self.signer.sign(value)
        self.schemas.validate("consumption-record", value)
        path = self.root / "consumptions" / f"{value['approval_id']}.json"
        atomic_write_json(path, value, exclusive=exclusive)
        return path


def _is_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False
