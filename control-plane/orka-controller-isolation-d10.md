# D10: Controller and Capture Isolation

Status: proposed architecture; not implemented or approved for
production use.

## Objective

Separate review-agent execution from MAD authorization, provider
transport, evidence capture, and capture-signing authority.

D1–D9 provide experimental verification, simulated capture,
persistence, recovery, and pinned trust inputs. They do not provide
authenticated process isolation or real-provider provenance.

## Security principals

Three independently controlled roles are required:

1. Review agent: untrusted for provenance. May submit review
   proposals and receive permitted results. Must not provision
   trust roots, sign capture evidence, or authorize a merge.

2. MAD controller: establishes repository, PR, revision,
   challenge, policy, reviewer, and request authorization from
   independently verified state. Owns operation authorization,
   trust policy, and verification decisions.

3. Capture component: executes an authorized provider request
   through a controlled adapter, observes the actual response,
   constructs capture evidence, and requests a signature only
   after required checks.

Logical Python classes do not constitute security isolation.
Production separation requires independently enforced operating
system identities or another reviewed security boundary.

## Process and credential boundaries

The reviewer must not run with the controller or capture-service
identity.

The reviewer must not read provider credentials, capture-signing
private keys, controller trust-root configuration, or protected
operation records.

Only the controller may provision authorized operations. The
capture component must independently authenticate the controller
and verify the operation authorization.

A local Unix-domain socket with restricted directory permissions
and operating-system peer credential verification is one candidate
transport. It is not approved until deployment identities,
permissions, lifecycle, and threat model are validated.

A socket shared by mutually untrusted processes running under the
same unrestricted operating-system account is insufficient.

No caller-facing operation may sign an arbitrary digest or accept
a caller-declared provider observation as authoritative.

## Corrected evidence sequence

The D6 mock verifies a fixture D1 attestation before executing its
simulated transport. This order must not be interpreted as a
production provenance protocol.

The production sequence must distinguish:

1. Independently authorize the review operation and request.
2. Durably record authorization and a unique operation identity.
3. Atomically claim the operation before external submission.
4. Execute the request through the capture-owned provider adapter.
5. Observe and validate the response at the authenticated
   transport boundary.
6. Construct evidence from the observed request/response and
   trusted operation context, not agent-supplied metadata.
7. Validate review-result correspondence.
8. Produce an attestation and signed evidence in an order that
   cryptographically binds them without circular trust.
9. Atomically persist verified evidence and completion.
10. Reverify against independently provisioned expectations
    before any subsequent authorization decision.

The exact attestation-versus-companion signing protocol requires
a separate design review. Existing simulated v1 artifacts must
not silently become production evidence.

## Provider transport

Each provider adapter must define approved destinations,
authenticated TLS or SDK transport, redirect behavior, operation
identifiers, response schemas, terminal states, and reconciliation.

The capture component must not trust an agent-supplied provider
name, endpoint, response ID, response digest, or success flag.

Credentials must be injected exclusively into the trusted
transport. They must not enter signed evidence or application logs.

## Failure and recovery

A claim must be durable before sending an external request.

Timeout or uncertain completion remains needs_reconcile.
No automatic repeat submission is allowed for an ambiguous
operation.

Recovered evidence requires independently pinned trust roots,
authorized request context, current verification time, and
fresh cryptographic verification.

A digest-only historical record cannot be reconstructed.
A completed record without valid evidence must fail closed.

Storage tampering, rollback, lost evidence, key rotation,
revocation, and disaster recovery require independent controls.

## Required adversarial validation

Before claiming actual process isolation, tests must demonstrate:

- The reviewer cannot reach the provisioning or signing interface.
- The reviewer cannot read protected keys or provider credentials.
- An unauthorized peer cannot register or execute an operation.
- The capture component rejects caller-selected trust roots,
  endpoints, response metadata, and arbitrary signing requests.
- Changed request, response, revision, or policy bindings fail.
- A crash after claim cannot silently resubmit a request.
- Recovered evidence fails with expired or revoked authorization.
- Replay and repeated completion cannot grant new authority.
- A malicious mock transport remains an explicit counterexample
  until real-provider authentication is independently tested.

These checks must exercise real operating-system permissions,
not merely Python method signatures or object attributes.

## Architecture review gate

Before implementing the process boundary, inspect the repository's
existing launcher, isolation tests, controller startup model, and
packaging constraints.

Select the runtime identity model, authenticated IPC protocol,
authorization-record ownership, signing-key custody, provider
adapter boundary, and operational recovery procedure.

Document deployment assumptions separately for development,
CI, and any intended production environment.

## Non-goals and restrictions

This design does not activate MAD, change installed Orka, contact
a real provider, provision credentials, authorize a merge, or
modify the main branch.

D10 remains a specification until the architecture review and
adversarial implementation tests are complete.

## Repository inspection decision

The current native launcher validates the activated release and
Python runtime before launching the Python stage. Its inspected
fork/exec path does not establish a separate operating-system
identity for the experimental Orka capture component.

The existing QA executor uses a sandbox abstraction backed by
bubblewrap. This does not establish that the experimental Orka
transport or signing key is isolated by that sandbox.

No Unix-domain peer-credential authentication was found in the
inspected MAD Python source or launcher code. This observation
does not constitute a repository-wide proof of absence.

The release builder collects Python modules into a closed,
inventory-bound release. Inclusion in an inventory establishes
file integrity, not authorization to act as a trusted service.

### Proposed deployment boundary

The reviewer, MAD controller, and capture/signing service must
execute under separately enforced security identities.

The reviewer must not inherit the controller identity or obtain
access to capture credentials, signing keys, controller trust
roots, or protected operation records.

The controller remains responsible for independently obtaining
repository and review authorization data. It may request only
operations permitted by its own policy.

The capture/signing service must authenticate its controller
peer, validate the authorization for the exact operation, and
execute provider transport with credentials unavailable to the
reviewer.

A Unix-domain socket with operating-system peer-credential
checks is the initial Linux IPC design candidate. Socket
permissions alone are insufficient when mutually untrusted
components share the same unrestricted user identity.

The capture service must not expose a general-purpose signing
endpoint. Signing is conditional on a recorded authorized
operation and evidence constructed from observed transport.

### Compatibility and implementation gates

Do not modify the existing native launcher merely to host the
capture service. Design and test the capture service's own
launch identity, authorization channel, credential ownership,
and shutdown/restart behavior first.

A deployment design must state which component owns the
durable operation database, which identity may read or mutate
it, and how recovery verifies independently provisioned
authorization after a restart.

New runtime entry points, configuration, schemas, and service
files require deliberate packaging and activation review.
Being included in the release inventory is not itself a grant
of authority.

Before accepting an implementation, test operating-system
identity separation, unauthorized peer rejection, inaccessible
secret material, request substitution, ambiguous completion,
restart recovery, and the absence of an arbitrary-signing API.

Development under WSL and CI may validate protocol behavior,
but any production isolation claim also requires validation
under the intended deployment permissions and service manager.

This is an architecture decision for subsequent experiments,
not a declaration that process isolation is implemented.
