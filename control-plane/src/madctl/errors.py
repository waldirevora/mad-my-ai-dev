class MadError(RuntimeError):
    """Fail-closed MAD policy or verification failure."""


class SchemaError(MadError):
    """Evidence did not match its installed canonical schema."""


class AuthorityError(MadError):
    """Repository, executable, release, or remote authority was not established."""


class EvidenceError(MadError):
    """Evidence was missing, stale, mismatched, tampered, or replayed."""


class IndeterminateExternalResult(MadError):
    """An external mutation may have completed and must be reconciled."""
