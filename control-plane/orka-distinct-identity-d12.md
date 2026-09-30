# D12: Real Distinct-Identity Validation

Status: experimental identity validation; not production isolation.

## Objective

D11 proved that Linux `SO_PEERCRED` returns kernel peer credentials.
Its successful distinct-identity path still used a simulated service UID.
D12 validates the same authentication path with a real mapped process.

## Validated mechanism

The development test uses:

- Linux `SO_PEERCRED`;
- `unshare --user --map-auto`;
- `newuidmap` and `newgidmap`;
- subordinate UID/GID ranges;
- `--setuid 0 --setgid 0`;
- an ephemeral Unix-domain socket.

The validated mapping was:

```text
inside UID 0 -> outside UID 100000
inside GID 0 -> outside GID 100000
```

The service remained UID/GID 1000 and observed the peer as UID/GID
100000 through kernel-provided `SO_PEERCRED`.

## Automated evidence

`tests/test_orka_distinct_identity.py` exercises the existing D11
authentication path with a real distinct kernel identity.

The test skips when Linux, `SO_PEERCRED`, subordinate IDs, or the
required user-namespace helpers are unavailable.

A skipped generic CI runner is not proof that the mechanism failed.

## Security boundary demonstrated

D12 demonstrates only that a process with a subordinate Linux UID/GID
can be distinguished from the service using kernel peer credentials.

D12 does not prove provider provenance, executable trust, key custody,
signing authority, filesystem or network isolation, replay protection,
service supervision, or production deployment security.

The WSL2 result is development evidence and requires independent
validation on the eventual production Linux environment.

## Endpoint limitation

The test socket is intentionally accessible to the subordinate test
identity. This is not the production endpoint permission model.

Protected parent directory, ownership, permissions, safe lifecycle,
and fail-closed endpoint handling remain separate work.

## Integration restrictions

D12 does not authorize integration with the MAD launcher, installed
Orka, provider transport, provisioning, signing, or production services.

Successful peer authentication is not review approval, provenance
evidence, signing authority, or production authorization.
