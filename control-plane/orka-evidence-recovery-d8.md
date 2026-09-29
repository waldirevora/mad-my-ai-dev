# D8: Recoverable Mock Evidence

Status: experimental, not production-approved.

## Objective

Recover signed experimental evidence after the capture process
finishes and the SQLite database is reopened.

D7 stored completed status and an evidence digest, but did not
retain the corresponding artifact. D8 stores the canonical
capture/link/receipt bundle in a separate table.

## Atomicity

The store commits three things in one SQLite transaction:

- The transition to `completed`.
- The digest of the serialized evidence.
- The serialized evidence itself.

If artifact insertion fails, the completion transition rolls back.
A claimed operation remains `needs_reconcile`.

This assumes a normally functioning, trusted local filesystem.
It is not a defense against a privileged database administrator,
storage rollback, or compromised SQLite files.

## Recovery

The recovery path:

1. Reads only an operation recorded as `completed`.
2. Checks the stored evidence against its stored digest.
3. Requires canonical JSON and exact experimental field shapes.
4. Checks the signed receipt's operation identifier.
5. Verifies the D1 attestation against independently supplied
   expected values and verification time.
6. Verifies the signed companion link and request receipt against
   independently provisioned signing keys and request bytes.

Loading an artifact from SQLite alone never grants authority.
The caller must request cryptographic re-verification before
treating the recovered artifacts as valid.

Recovery does not contact the simulated provider or repeat the
original request.

## Compatibility

Existing D7 databases are supported by adding a separate evidence
table. Historical digest-only `completed` records remain completed,
but their unavailable artifacts cannot be reconstructed. Recovery
rejects these records instead of inventing a receipt.

The D7 `complete()` method remains for compatibility and does not
become a recoverable completion. D8's mock boundary uses
`complete_with_evidence()`.

## Privacy and failure policy

Only the bounded, structured experimental metadata and signatures
are stored. Raw transport requests, raw provider responses,
credentials, and private signing keys are not intentionally stored.

Metadata can still be sensitive. Encryption at rest, retention,
access restrictions, secure deletion, and backup handling require
separate deployment decisions.

An operation left in `needs_reconcile` cannot be recovered as a
completed review and must not be automatically resubmitted.

Expired D1 evidence or an invalid signature must fail verification
at recovery time. A stored hash does not override that result.

## Remaining trust limitations

This is a local mock workflow. The database is not tamper-resistant.
The signer and transport remain in the same process. Operation
registration is not independently authenticated.

The prototype does not establish actual provider identity, real
network response provenance, protected signing keys, storage
rollback resistance, or production merge authority.

No installed Orka modification, main-branch change, or MAD
activation is authorized.
