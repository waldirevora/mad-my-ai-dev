# MAD × Orka — D2: Review Provenance Contract

Status: proposed specification; not implemented.
Base: D1, commit 45df7f8d32660ac2facce4ff6c21a086e65d0fb7.

## 1. Objective and Scope

Define verifiable evidence that a review result was captured
by a trusted component during an identified execution.

D2 does not authorize merges, replace human approval, modify
the installed activation, or treat the Orka ledger as an
independent authority for provider identity.

## 2. Findings from the Inspected Orka 1.8.0 Copy

- The API runner obtains a response through its configured
  transport, records response_id, provider, and model, and
  persists local state.
- The review receipt binds the permit, role, HEAD, generation,
  and result digest, but does not include response_id.
- The desktop path can complete a permit using an existing
  structured result.
- The all-green marker and ledger represent Orka workflow
  states; by themselves, they do not authenticate review origin.
- A response_id provides traceability; it is not a
  cryptographic signature from the provider.

These findings concern the inspected local copy. The identity
and integrity of the installation actually used must be
revalidated separately.

## 3. Trust Boundaries

A. MAD controller: supplies expected bindings from protected
   state and authoritative sources independent of the
   attestation.

B. Protected capture component: observes requests and responses
   at the transport boundary. Its code, identity, configuration,
   and signing-key access must not be controlled by the reviewing
   agent or the candidate repository content.

C. Provider: communicates over an authenticated transport
   connection. The assurance obtained depends on the actual
   provider, endpoint, TLS configuration, credentials, and
   intermediaries.

D. Orka: supplies complementary workflow data, permits,
   results, and receipts. These records do not, by themselves,
   turn identity claims into proof of origin.

## 4. Minimum Capture Contract

A candidate capture must verifiably bind:

- the capture component's identity and trusted version;
- the provider and endpoint actually used, including an
  allowed-destination policy and transport validation;
- the requested model and observed execution identity;
- a returned request or response identifier, when available;
- the canonical digest of the structured result actually received;
- the execution identifier, role, gate, and review generation;
- repository, PR, and source and target branches and SHAs;
- challenge, policy, and nonce supplied by MAD;
- timestamp and terminal state, distinguishing success,
  failure, and indeterminate outcomes.

Agent-declared fields must not populate or override identities
observed by the protected capture component.

The capture must retain sufficient evidence to link the result
used by Orka to the observed response. For multi-call reviews,
it must identify which terminal response produced the result,
rather than inferring that relationship solely from record order.

## 5. Authentication and Limits of the Claim

The capture component must use protected configuration and
authorized endpoints. URL overrides, proxies, and redirects
require explicit policy; they are not presumed trustworthy.

An authenticated connection and response_id allow the capture
component to attest to what it observed. This is not equivalent
to a provider's cryptographic signature over the content and
does not, by itself, prove details of internal model execution.

If provider identity, response binding, or terminal state
cannot be established, issuance must fail closed. Indeterminate
operations require reconciliation; they must not automatically
be converted into PASS.

## 6. Relationship to the D1 Attestation

A future issuer may sign only after verifying the protected
capture, MAD's expected bindings, and the exact correspondence
with the applicable Orka result and receipt.

The D1 verifier remains responsible for the Ed25519 signature,
schema, validity period, and independently supplied bindings.
It must not infer provenance from self-declared fields.

The closed D1 v1 schema includes reviewer.execution_identity,
result_sha256, and Orka evidence digests, but has no field for a
provider response identifier, observed endpoint, or protected
capture-evidence digest. These existing fields do not by
themselves establish authenticated provider provenance.

The implementation must select and document one verifiable
cross-artifact binding before an issuer or merge integration
is introduced. Candidate approaches include:

- Retain D1 v1 and use independently authenticated companion
  evidence. A protected verifier must bind that evidence to
  the exact attestation digest, terminal provider response,
  canonical result digest, and applicable MAD and Orka context.
  Matching agent-writable identifiers alone is insufficient.
- Introduce a separately versioned attestation schema that
  signs an explicit capture-evidence commitment. This requires
  coordinated schema, verifier, issuer, and compatibility tests.

Neither approach is selected by this specification. The final
design must prevent substitution, omission, or replay of
capture evidence and must fail closed when the binding cannot
be independently verified.

Public-key trust and private-key protection require separate
provisioning. Any activation-manifest change must update the
schema, C launcher, Python launcher, inventories, and security
tests consistently.

## 7. Desktop Path

The desktop path does not automatically inherit the assurances
of the API transport. Until an independent authenticated capture
mechanism binds its execution, it must not originate trusted
attestations for merge authorization.

## 8. Single-Use Consumption and Indeterminate Operations

Attestation consumption must be persistent, uniquely identified
by attestation_id and/or canonical digest, and bound to the
approval, operation, run, PR, and exact source and target SHAs.
Distinct approval_ids must not permit reuse of one attestation.

The MAD approval transition and attestation consumption
reservation are separate persistent writes unless an atomic
transaction is explicitly implemented and verified. No external
merge request may be issued before the required reservation
and approval state have been durably established and rechecked.

Recovery must explicitly distinguish:

- failure before reservation publication;
- publication that may have succeeded despite an error,
  including failure during directory synchronization;
- failure between reservation and approval-state writes;
- an approval in consuming state with a missing or present
  consumption record;
- an external merge request with an unknown outcome.

A pre-existing reservation blocks automatic reuse, including
under another approval_id. A missing record alone does not
establish that an external operation was never attempted.
Indeterminate states must fail closed until independently
reconciled against durable local evidence and authoritative
remote state.

Recovery must not blindly repeat an external operation or
reset an approval to approved. The protocol must specify
locking, unique reservation identity, permitted state
transitions, operator intervention, and auditable outcomes.

Existing consumption by approval_id does not replace
attestation-specific consumption. Exclusive file publication
does not, by itself, make separate approval and consumption
writes transactional.

## 9. Criteria for an Implementable Increment

Before controller integration, tests must cover:

- authorized capture and exact result correspondence;
- missing, substituted, or replayed capture evidence;
- disallowed origin, endpoint, or identity;
- modified response, digest, role, or generation;
- mismatched PR, HEAD, challenge, policy, or nonce;
- missing terminal response and transport failure;
- repeated responses and attempted reuse;
- concurrent attempts to consume one attestation under
  different approval_ids;
- failure before and after consumption publication,
  including directory synchronization failure;
- failure between reservation and approval-state writes;
- reconciliation of missing, existing, and indeterminate
  consumption records without repeating an external merge;
- desktop execution without independent proof;
- inability to issue PASS from a ledger, marker, or
  response_id alone.

Tests using simulated adapters do not replace validation of
the real installation, isolation, transport, and native chain.

## 10. Out of Scope

This specification provides no production issuer, new key
material, manifest changes, schema migration, operational
consumption, merge enablement, or MAD activation.

Implementation depends on technical review of the trust
boundary and an independent test plan.
