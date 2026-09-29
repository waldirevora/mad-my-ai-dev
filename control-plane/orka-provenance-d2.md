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

Attestation consumption must be persistent, identified by
attestation_id and/or canonical digest, and bound to the
operation.

The MAD approval transition and consumption reservation require
an explicit recovery protocol. A failure after publication does
not authorize reuse or blind repetition of the external operation.

Existing consumption by approval_id does not replace
attestation-specific consumption.

## 9. Criteria for an Implementable Increment

Before controller integration, tests must cover:

- authorized capture and exact result correspondence;
- disallowed origin, endpoint, or identity;
- modified response, digest, role, or generation;
- mismatched PR, HEAD, challenge, policy, or nonce;
- missing terminal response and transport failure;
- repeated responses and attempted reuse;
- failure before and after consumption publication;
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
