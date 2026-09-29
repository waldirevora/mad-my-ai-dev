"""D7 experimental SQLite operation state.

Transactions are durable on a normally functioning local filesystem.
This is NOT an authenticated store, tamper-resistant ledger, or
production signing service. The database directory must be trusted.
Raw requests, responses, credentials, and signing keys are not stored.
"""
from __future__ import annotations

import json
import re
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, sha256_bytes
from .errors import EvidenceError


_HEX64 = re.compile(r"[0-9a-f]{64}")
_OPERATION_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")

_MAX_EVIDENCE_BYTES = 32_768

# Only these experimental metadata/signature fields may be persisted.
# Never persist the raw provider request or response here.
_EVIDENCE_SHAPES = {
    "capture": frozenset({
        "kind", "provider", "endpoint", "model",
        "execution_identity", "response_id", "review_run_id",
        "gate", "review_generation", "result_sha256",
        "response_sha256", "terminal_state",
    }),
    "link": frozenset({
        "kind", "key_id", "attestation_sha256",
        "capture_sha256", "bindings_sha256", "signature",
    }),
    "receipt": frozenset({
        "kind", "operation_id", "key_id", "request_sha256",
        "capture_sha256", "link_sha256", "signature",
    }),
}


def _serialize_evidence(value: Any) -> bytes:
    if type(value) is not dict or set(value) != set(_EVIDENCE_SHAPES):
        raise EvidenceError("invalid durable evidence shape")

    for name, fields in _EVIDENCE_SHAPES.items():
        artifact = value[name]
        if type(artifact) is not dict or set(artifact) != fields:
            raise EvidenceError(
                f"invalid durable evidence artifact: {name}"
            )

    try:
        raw = canonical_bytes(value)
    except (TypeError, ValueError) as exc:
        raise EvidenceError(
            "invalid durable evidence serialization"
        ) from exc

    if not 0 < len(raw) <= _MAX_EVIDENCE_BYTES:
        raise EvidenceError("invalid durable evidence size")

    return raw


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError("duplicate durable evidence property")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise EvidenceError(f"invalid durable JSON constant: {value}")


def _digest(value: str, field: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise EvidenceError(f"invalid durable {field}")
    return value


def _operation_id(value: str) -> str:
    if type(value) is not str or _OPERATION_ID.fullmatch(value) is None:
        raise EvidenceError("invalid durable operation ID")
    return value


class DurableCaptureStore:
    """Atomic, fail-closed state transitions for a mock operation."""

    def __init__(self, path: Path) -> None:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or path.is_symlink()
            or not path.parent.is_dir()
            or (path.exists() and not path.is_file())
        ):
            raise EvidenceError("invalid durable database path")

        # This prototype assumes a trusted, privately provisioned
        # directory. Path checks are not protection against a
        # malicious concurrent filesystem administrator.
        self.path = path

        with self._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    binding_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    claim_sha256 TEXT,
                    evidence_sha256 TEXT,
                    CHECK (
                        (status = 'ready'
                         AND claim_sha256 IS NULL
                         AND evidence_sha256 IS NULL)
                        OR
                        (status = 'needs_reconcile'
                         AND claim_sha256 IS NOT NULL
                         AND evidence_sha256 IS NULL)
                        OR
                        (status = 'completed'
                         AND claim_sha256 IS NOT NULL
                         AND evidence_sha256 IS NOT NULL)
                    )
                )
            """)

        # Separate table preserves compatibility with existing D7
        # databases, including historical digest-only completions.
        with self._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS evidence_artifacts (
                    operation_id TEXT PRIMARY KEY,
                    artifact BLOB NOT NULL,
                    FOREIGN KEY (operation_id)
                        REFERENCES operations(operation_id)
                )
            """)

    @contextmanager
    def _transaction(self):
        connection = sqlite3.connect(
            self.path,
            timeout=5.0,
            isolation_level=None,
        )
        try:
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def register(
        self,
        operation_id: str,
        binding_sha256: str,
    ) -> None:
        operation_id = _operation_id(operation_id)
        binding_sha256 = _digest(
            binding_sha256, "operation binding"
        )

        with self._transaction() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO operations (
                        operation_id, binding_sha256, status
                    ) VALUES (?, ?, 'ready')
                    """,
                    (operation_id, binding_sha256),
                )
            except sqlite3.IntegrityError as exc:
                raise EvidenceError(
                    "duplicate durable operation"
                ) from exc

    def claim(
        self,
        operation_id: str,
        binding_sha256: str,
    ) -> bytes:
        """Reserve the operation before any transport submission."""
        operation_id = _operation_id(operation_id)
        binding_sha256 = _digest(
            binding_sha256, "operation binding"
        )

        claim_token = secrets.token_bytes(32)
        claim_digest = sha256_bytes(claim_token)

        with self._transaction() as connection:
            updated = connection.execute(
                """
                UPDATE operations
                SET status = 'needs_reconcile',
                    claim_sha256 = ?
                WHERE operation_id = ?
                  AND binding_sha256 = ?
                  AND status = 'ready'
                  AND claim_sha256 IS NULL
                """,
                (
                    claim_digest,
                    operation_id,
                    binding_sha256,
                ),
            )

            if updated.rowcount != 1:
                raise EvidenceError(
                    "durable operation unavailable or binding mismatch"
                )

        return claim_token

    def complete(
        self,
        operation_id: str,
        binding_sha256: str,
        claim_token: bytes,
        evidence_sha256: str,
    ) -> None:
        """Atomically record completion after evidence verification."""
        operation_id = _operation_id(operation_id)
        binding_sha256 = _digest(
            binding_sha256, "operation binding"
        )
        evidence_sha256 = _digest(
            evidence_sha256, "evidence digest"
        )

        if type(claim_token) is not bytes or len(claim_token) != 32:
            raise EvidenceError("invalid durable claim token")

        with self._transaction() as connection:
            updated = connection.execute(
                """
                UPDATE operations
                SET status = 'completed',
                    evidence_sha256 = ?
                WHERE operation_id = ?
                  AND binding_sha256 = ?
                  AND status = 'needs_reconcile'
                  AND claim_sha256 = ?
                  AND evidence_sha256 IS NULL
                """,
                (
                    evidence_sha256,
                    operation_id,
                    binding_sha256,
                    sha256_bytes(claim_token),
                ),
            )

            if updated.rowcount != 1:
                raise EvidenceError(
                    "durable completion unavailable or claim mismatch"
                )

    def complete_with_evidence(
        self,
        operation_id: str,
        binding_sha256: str,
        claim_token: bytes,
        evidence: dict[str, Any],
    ) -> None:
        """Commit signed artifacts and completion in one transaction.

        The caller must verify cryptographic evidence before invoking
        this method. The store independently limits artifact shapes
        and computes the digest from the serialized bytes.
        """
        operation_id = _operation_id(operation_id)
        binding_sha256 = _digest(
            binding_sha256, "operation binding"
        )

        if type(claim_token) is not bytes or len(claim_token) != 32:
            raise EvidenceError("invalid durable claim token")

        raw = _serialize_evidence(evidence)
        digest = sha256_bytes(raw)

        with self._transaction() as connection:
            updated = connection.execute(
                """
                UPDATE operations
                SET status = 'completed',
                    evidence_sha256 = ?
                WHERE operation_id = ?
                  AND binding_sha256 = ?
                  AND status = 'needs_reconcile'
                  AND claim_sha256 = ?
                  AND evidence_sha256 IS NULL
                """,
                (
                    digest,
                    operation_id,
                    binding_sha256,
                    sha256_bytes(claim_token),
                ),
            )

            if updated.rowcount != 1:
                raise EvidenceError(
                    "durable completion unavailable or claim mismatch"
                )

            # An insertion failure rolls back the status update too.
            connection.execute(
                """
                INSERT INTO evidence_artifacts (
                    operation_id, artifact
                ) VALUES (?, ?)
                """,
                (operation_id, raw),
            )

    def load_completed_evidence(
        self,
        operation_id: str,
    ) -> dict[str, Any]:
        """Load locally consistent artifacts, not yet trusted evidence.

        Callers must independently verify D1, companion signatures,
        request bindings, signer identity, and authorization.
        """
        operation_id = _operation_id(operation_id)

        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT
                    o.status,
                    o.evidence_sha256,
                    e.artifact
                FROM operations AS o
                LEFT JOIN evidence_artifacts AS e
                  ON e.operation_id = o.operation_id
                WHERE o.operation_id = ?
                """,
                (operation_id,),
            ).fetchone()

        if row is None:
            raise EvidenceError("unknown durable operation")

        status, recorded_digest, raw = row

        if status != "completed":
            raise EvidenceError(
                "durable evidence unavailable: operation not completed"
            )

        # A D7 digest-only completion cannot be reconstructed.
        if (
            type(raw) is not bytes
            or not 0 < len(raw) <= _MAX_EVIDENCE_BYTES
            or type(recorded_digest) is not str
            or _HEX64.fullmatch(recorded_digest) is None
        ):
            raise EvidenceError("missing or invalid durable evidence")

        if sha256_bytes(raw) != recorded_digest:
            raise EvidenceError("durable evidence digest mismatch")

        try:
            evidence = json.loads(
                raw,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (ValueError, UnicodeDecodeError, TypeError) as exc:
            raise EvidenceError("invalid durable evidence JSON") from exc

        if _serialize_evidence(evidence) != raw:
            raise EvidenceError(
                "noncanonical durable evidence serialization"
            )

        return evidence

    def state(self, operation_id: str) -> str:
        operation_id = _operation_id(operation_id)

        with self._transaction() as connection:
            row = connection.execute(
                "SELECT status FROM operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()

        if row is None:
            raise EvidenceError("unknown durable operation")

        return row[0]

    def evidence_sha256(self, operation_id: str) -> str | None:
        operation_id = _operation_id(operation_id)

        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT evidence_sha256
                FROM operations
                WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()

        if row is None:
            raise EvidenceError("unknown durable operation")

        return row[0]
