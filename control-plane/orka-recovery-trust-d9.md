# D9: Recovery Trust-Input Boundary

Status: experimental in-process contract; not production-approved.

## Problem

D8 verifies signed recovered artifacts, but the recovery function
accepts its verifier, expected D1 bindings, original request bytes,
verification time, and public keys as direct parameters.

A caller able to choose those inputs can construct a self-consistent
verification environment. A valid signature under a caller-selected
key does not establish an independently trusted issuer.

## Experimental change

D9 introduces a mock-controller registry provisioned before
recovery. An operation ID selects a snapshot containing:

- The D1 attestation and independently authorized expectations.
- The original request bytes needed to verify its signed receipt.
- A controller-selected receipt signing-key identifier.

The registry separately pins issuer and capture public-key allowlists
and obtains verification time from its configured controller clock.

Its recovery interface accepts only an operation ID and durable
store, rather than allowing each recovery caller to replace
expectations, signing keys, or verification time.

Provisioned mappings are defensively copied. Subsequent mutation
of the caller's original objects does not silently rewrite the
registry's snapshots.

## Required production trust sources

The MAD controller must independently establish review expectations,
request authorization, operation identity, and the current time.

Issuer and capture trust roots must come from protected configuration
or an independently governed key authority. An agent must not be
able to register itself as trusted or replace those roots.

Only an authenticated, authorized controller may provision recovery
records. The reviewer must not be able to call the provisioning
operation or alter already provisioned records.

The trusted record must remain linked to the originally authorized
operation across persistence, restart, and recovery.

## Explicit limitations

This registry is an ordinary Python object. It does not authenticate
its constructor's caller or protect its private attributes from code
running with the same interpreter privileges.

A hostile actor that controls provisioning or the mock transport can
still construct apparently valid experimental evidence. The D9
tests preserve this counterexample.

The original request bytes are held in process memory to reuse D8's
receipt verifier. Their confidentiality, reconstruction, lifetime,
and secure deletion need separate production design.

SQLite remains a trusted local input without rollback resistance.
There is no real provider authentication, protected signer, secure
interprocess channel, or production merge authorization.

D9 adds a testable integration seam, not an independent proof of
trustworthiness. These limitations must be resolved and independently
reviewed before production use.

No installed Orka changes, main-branch changes, merges, or MAD
activation are authorized.
