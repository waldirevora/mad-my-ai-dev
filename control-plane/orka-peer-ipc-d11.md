# D11: Linux Peer-Credential IPC Prototype

Status: local experimental diagnostic; not production isolation.

## Mechanism

Linux SO_PEERCRED provides the kernel's PID, UID, and GID for
a connected Unix-domain stream socket.

The prototype rejects non-Unix sockets, disconnected sockets,
unexpected controller UID/GID, and a controller using the
service's own effective UID.

The expected controller UID/GID must be configured by a trusted
service, independently of the peer's request.

A one-frame diagnostic probe is accepted only after the
identity check. The envelope has an exact canonical JSON
shape, a bounded length, and a nonce. Its response only echoes
the nonce in a diagnostic acknowledgement.

There are no operation-registration, provider-transport,
key-management, arbitrary-signing, or merge interfaces.

## Test evidence and limitations

A real subprocess establishes that SO_PEERCRED reports kernel
peer credentials. Because the test controller and service
share a UID, the authentication check correctly denies it.

A separate unit test mocks the service UID to exercise the
successful diagnostic message path. That simulation is not
proof of real operating-system identity separation.

The handler is not a daemon. No actual privileged service
or different-UID process is launched or configured.

A process holding the expected UID/GID is not necessarily an
authorized MAD controller. The deployment must protect the
controller identity and its executable, ensure restricted
socket access, and define an authenticated authorization
protocol for each operation.

SO_PEERCRED does not attest provider provenance or prove that
a process binary is trustworthy. A PID alone is not a durable
identity, and this prototype does not protect secrets.

Unix-socket files require a protected parent directory,
careful binding and lifecycle management, and explicit
rejection of unexpected filesystem states. These controls
are outside the diagnostic handler.

The production service needs its own identity, supervised
startup, protected credentials, admission configuration,
and authenticated controller authorization. WSL unit tests
cannot substitute for deployment-specific privilege tests.

## Integration restrictions

Do not wire this module into the current MAD launcher,
activated release, reviewer sandbox, or installed Orka.

Do not regard a successful diagnostic acknowledgement as
review approval, provenance evidence, or signing authority.

No main-branch merge, production activation, or real-provider
execution is authorized by D11.
