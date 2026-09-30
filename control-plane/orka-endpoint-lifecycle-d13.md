# D13 — Secure Unix Endpoint Lifecycle / Fail-Closed

## Status

Experimental prototype only.

D13 does not activate a production Orka service and does not establish a
production deployment, service account, privileged runtime directory, or
cross-identity group model.

## Relationship to D11 and D12

D11 authenticates an already-connected Linux Unix-stream peer by kernel
credentials (`SO_PEERCRED`).

D12 demonstrates that a controller process can present a real host UID/GID
different from the service process in the configured local WSL environment.

Neither milestone established the filesystem lifecycle of the Unix-socket
endpoint itself.

D13 addresses that separate boundary.

## Responsibility

`madctl.orka_endpoint` owns only the experimental Unix endpoint lifecycle:

1. validate a pre-provisioned parent directory;
2. refuse unexpected existing endpoint state;
3. bind a Unix stream socket;
4. verify the resulting socket inode;
5. apply and verify explicit endpoint permissions;
6. enter listening state only after those checks;
7. remove the pathname only if it is still the exact socket created by this
   instance.

Peer authentication and diagnostic protocol parsing remain in
`madctl.orka_peer_ipc`.

## Parent directory trust

The parent directory must already exist.

D13 does not create a trusted runtime root automatically.

The parent must be:

- absolute;
- canonical;
- a real directory rather than a symlink;
- owned by the expected UID/GID;
- not group-writable;
- inaccessible to `other`;
- writable and searchable by its owner.

This is a local prototype trust model, not a final production deployment
policy.

## Ancestor directory trust

The direct parent is not sufficient to establish pathname trust by itself.

D13 also walks from the direct parent's parent directory to the filesystem
root and requires each ancestor to be a real, non-symlink directory.

An ancestor that is writable by group or `other` is rejected unless the
directory has the sticky bit set.

This permits conventional shared sticky directories such as `/tmp` while
rejecting an intermediate `0777` or `0770` directory without sticky
semantics.

`UnixEndpointPolicy` carries an explicit `trusted_system_uid`.

D13 verifies that this UID is the current owner of the filesystem root (`/`).
It is therefore a checked trust anchor rather than an implicitly accepted
environment value.

Every ancestor must be owned by either:

- the endpoint service `expected_uid`; or
- the verified `trusted_system_uid`.

System-owned ancestors such as `/`, `/var`, `/run`, and `/tmp` may therefore
be part of a legitimate path when they are owned by that verified system UID.

Sticky semantics do not make an ancestor with an otherwise untrusted owner
acceptable. The directory owner retains authority over its own entries.

The direct endpoint parent remains subject to the stricter ownership and
permission rules above.

Ancestor validation is repeated during setup and cleanup so that a trust-path
change observed before pathname removal causes cleanup to fail closed.

This is a prototype pathname policy, not a claim that sticky-directory
semantics alone constitute a complete production filesystem security model.

## Existing endpoint state

D13 never removes an endpoint path merely because it looks stale.

Any pre-existing object causes binding to fail closed, including:

- regular files;
- directories;
- symlinks;
- dangling symlinks;
- Unix sockets;
- other filesystem object types.

Automatic stale-socket recovery requires an independent authority/lifecycle
design and remains outside D13.

## Bind and post-bind verification

After `bind()` D13 records the socket inode identity as:

- `st_dev`;
- `st_ino`.

It verifies that the path is a Unix socket owned by the expected UID/GID,
applies an explicit endpoint mode, re-reads the inode, and verifies that:

- device/inode did not change;
- the object remains a socket;
- ownership remains expected;
- the final permission mode is exact.

Only then does it call `listen()`.

D13 supports explicit prototype modes:

- `0600`;
- `0660`.

The normal local test path uses `0600`.

D13 does not use the process umask as the final security policy.

## Cleanup

Cleanup first closes the listener.

The pathname is removed only when the current filesystem object still matches
the original `(st_dev, st_ino)`, socket type, expected ownership, and endpoint
mode.

If the path:

- disappears unexpectedly;
- becomes a symlink;
- becomes a regular file;
- becomes another socket;
- changes inode;
- changes ownership;
- or the parent trust conditions become unsafe;

cleanup fails closed and does not delete the ambiguous replacement.

A second `close()` after a verified successful cleanup is idempotent.

## Setup failure

If setup fails after a socket inode has been created, rollback removes it only
when that same inode can still be authenticated as the object created by this
instance.

If safe rollback cannot be established, setup reports a cleanup failure rather
than deleting ambiguous state.

## Security boundary

D13 reduces risks from:

- accidental overwrite/removal of pre-existing paths;
- symlink substitution;
- unsafe parent permissions;
- unsafe writable ancestor directories;
- untrusted ancestor ownership;
- permissive endpoint modes;
- cleanup of a substituted inode;
- automatic deletion of an unproven stale endpoint.

D13 does **not** establish protection against malicious code already running
with the same operating-system UID as the endpoint service.

The protected-parent assumption is therefore part of this prototype boundary.

## Cross-identity permissions

D12 proves a distinct controller identity mechanism, but D13 does not invent a
production group model to connect those identities.

D13 does not:

- create users;
- create groups;
- invoke `sudo`;
- perform privileged `chown`;
- configure systemd;
- provision `/run`;
- install a daemon;
- activate Orka.

A future deployment milestone must provision the service/runtime directory and
trusted group ownership when cross-identity access is required.

## Release boundary

The module is named `orka_endpoint.py`.

The existing experimental release gate discovers `orka_*.py` modules
dynamically and excludes experimental Orka modules from closed release
artifacts.

No release-gate modification is required by D13 unless testing demonstrates a
real regression.

## Limitations

D13 is not a race-free or TOCTOU-free filesystem capability design.

It uses pathname-based checks and pre/post validation under a trusted
parent/ancestor model. Those controls reduce replacement risk within the
prototype boundary, but they do not establish general resistance to malicious
same-UID or privileged actors that can mutate the filesystem between checks.

This prototype does not prove:

- production service isolation;
- system-service supervision;
- safe stale-socket recovery;
- privileged runtime-directory provisioning;
- provider provenance;
- signing-key isolation;
- authorization of production controller requests;
- resistance to malicious same-UID processes;
- deployment correctness outside the tested local environment.

No production-security claim should be inferred from D13 test names or passing
results.
