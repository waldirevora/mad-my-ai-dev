# D7: Durable Mock Capture State

Status: experimental, not production-approved.

## Purpose

Add optional SQLite-backed operation transitions to the D6 mock
capture boundary. Existing in-memory tests remain supported, but
in-memory operation state does not survive process restarts.

## State transitions

- `ready`: registration committed before mock submission.
- `needs_reconcile`: an atomic claim committed before transport.
- `completed`: evidence verified and its digest committed atomically.

There is no automatic retry after a claim. An interruption after
claim but before completion leaves `needs_reconcile`, including
when the external operation might not have been submitted.

A duplicate operation ID, changed operation binding, invalid claim
token, repeat claim, or repeat completion is rejected.

The database stores commitments and states, not raw prompts,
responses, credentials, or private signing keys.

## Crash windows and recovery

A crash after registration but before the in-memory operation is
attached can leave a registered operation that requires manual
recovery. A crash after claim leaves an indeterminate operation.
A crash after completion can leave verified evidence unavailable
to the caller; only its digest is retained by this prototype.

Reconciliation, evidence retrieval, retention policy, and secure
operator recovery are not implemented. Do not reset ambiguous
operations to `ready` or automatically resubmit them.

## Trust limitations

SQLite transactions provide local atomic state transitions. They
do not establish provider authenticity, independently authenticated
operation registration, secure process isolation, or protection
against a privileged actor modifying or replacing the database.

The database directory and local filesystem are trusted inputs for
this test. Production deployment requires independently governed
storage access, tamper/rollback controls, and recovery design.

The existing D6 mock signer remains in-process. No production
merge authority or MAD activation is provided.
