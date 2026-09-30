# D6: Trusted Capture Boundary

Status: design contract; not implemented or production-approved.

## Objective

Establish independently attributable evidence for a provider response.
D1–D5 establish simulated artifact consistency. They do not establish
authentic provider origin, signing-key isolation, durable consumption,
or merge authority.

## Trust separation

The review agent is untrusted for provenance. It must not supply
authoritative capture metadata, choose the trusted signing key,
declare that a network response was observed, or create an
authoritative capture record.

A separately controlled capture component must own the provider
request, observe the response at its transport boundary, and
construct capture metadata from its own execution context.

MAD must supply trusted review expectations independently of the
reviewer's output. The capture component must not infer them from
the review result.

## Provider communication

Provider adapters must explicitly define their supported API
operations, approved endpoints, TLS verification, redirect policy,
response parsing, and provider-specific response identifiers.

An HTTPS-looking string or a response ID supplied by an agent is
not provider authentication. Endpoint identity must be established
by the actual authenticated transport. SDK-based provider paths
require separate validation; HTTP assumptions must not be copied
onto Bedrock or other SDK transports.

The capture component must bind one authorized request to one
observed response. A request identifier or idempotency key alone
does not establish that a response was received.

## Minimum evidence

For a successful observation, the next capture format must bind:

- Independently authorized review context and execution identity.
- Actual provider adapter and authenticated destination.
- A safe canonical commitment to the authorized request, excluding
  credentials and other secrets.
- Exact observed response-byte digest.
- Provider response identifier, when the adapter exposes one.
- Independently validated terminal state.
- Digest of the extracted structured review result.
- The relevant D1 attestation and signed companion commitment.

The current simulated v1 format must not silently acquire
production authority. Any incompatible evidence changes require
an explicit, versioned format and corresponding adversarial tests.

## Protected signing

Only the trusted capture component may request capture signatures.
The reviewer must not have access to capture-signing private keys.

A signing service must verify the authorization and recorded
observation before signing. Merely accepting a digest from a caller
would reproduce the D5 demonstrated forgery limitation.

Key identity, rotation, revocation, and the authority to configure
the signer must be independently governed. Operating on the same
host does not, by itself, provide process isolation.

## Failure and reconciliation

Record a pending operation before external submission.

Timeouts, connection loss after submission, missing provider
identifiers, or uncertain provider completion must produce an
indeterminate state. They must never be interpreted as success.

Recovery must use provider-supported reconciliation or an
independent authoritative record. Do not resubmit uncertain work
merely to produce a clean-looking receipt.

Persist evidence and consumption transitions atomically. Repeated
verification is not one-time consumption. A future merge gate must
reject replayed, expired, superseded, or already-consumed evidence.

## Privacy and retention

Do not log credentials or unrestricted prompts and responses.
Retain minimal commitments and necessary operational metadata by
default. If raw evidence is required for reconciliation, define
encryption, access controls, retention, and deletion first.

## D6 acceptance tests

The implementation must reject:

- Agent-invented provider identity or response metadata.
- Unapproved or redirected destinations.
- Changed request, response, review result, or D1 bindings.
- A fabricated response digest offered directly to the signer.
- Unauthorized signing and reused signing authority.
- Uncertain submission treated as successful completion.
- Replay or double consumption once persistence is implemented.

Successful mocked integration tests are necessary but insufficient
to claim real-provider provenance. Provider-specific integration,
runtime isolation, and independent security review are separate
release gates.

## Deployment restriction

No change to installed Orka, active MAD, production merge
authorization, or the main branch is authorized by this document.
