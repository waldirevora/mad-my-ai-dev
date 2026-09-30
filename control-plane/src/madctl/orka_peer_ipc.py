"""D11: Linux Unix-socket peer credential probe.

Experimental only. No privileged service, authorization records,
provider requests, secrets, signing, or production isolation.
"""
from __future__ import annotations

import json
import os
import re
import socket
import struct
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes
from .errors import EvidenceError


_PROBE_KIND = "mad.orka.mock-peer-probe.v0"
_ACK_KIND = "mad.orka.mock-peer-probe-ack.v0"
_MAX_FRAME = 1024
_NONCE = re.compile(r"[A-Za-z0-9_-]{16,64}\Z")


@dataclass(frozen=True)
class KernelPeerIdentity:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True)
class ControllerPeerPolicy:
    """Expected Linux controller identity, configured by the service."""

    controller_uid: int
    controller_gid: int

    def __post_init__(self) -> None:
        for value in (self.controller_uid, self.controller_gid):
            if type(value) is not int or value < 0:
                raise EvidenceError("invalid controller peer policy")


def read_kernel_peer_identity(
    connection: socket.socket,
) -> KernelPeerIdentity:
    """Read real Linux credentials; never use caller-declared IDs."""
    if (
        type(connection) is not socket.socket
        or connection.family != socket.AF_UNIX
        or connection.type != socket.SOCK_STREAM
    ):
        raise EvidenceError("peer must use a Unix stream socket")

    if not hasattr(socket, "SO_PEERCRED"):
        raise EvidenceError("Linux peer credentials unavailable")

    try:
        connection.getpeername()
        packed = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12
        )
    except (OSError, ValueError) as exc:
        raise EvidenceError("cannot verify connected peer") from exc

    if len(packed) != 12:
        raise EvidenceError("invalid kernel peer credentials")

    pid, uid, gid = struct.unpack("3i", packed)

    if pid <= 0 or uid < 0 or gid < 0:
        raise EvidenceError("invalid kernel peer identity")

    return KernelPeerIdentity(pid=pid, uid=uid, gid=gid)


def authenticate_controller_peer(
    connection: socket.socket,
    *,
    policy: ControllerPeerPolicy,
) -> KernelPeerIdentity:
    """Require exact controller UID/GID and a different service UID.

    The service must obtain policy from protected configuration.
    This function cannot authenticate the caller that constructs
    the policy or prove that a separate service has been deployed.
    """
    if type(policy) is not ControllerPeerPolicy:
        raise EvidenceError("invalid controller peer policy")

    peer = read_kernel_peer_identity(connection)

    if (
        peer.uid != policy.controller_uid
        or peer.gid != policy.controller_gid
    ):
        raise EvidenceError("unauthorized controller peer identity")

    if peer.uid == os.geteuid():
        raise EvidenceError(
            "controller and service share an operating-system UID"
        )

    return peer


def _unique_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate peer probe JSON field")
        result[key] = value

    return result


def _reject_constant(value: str) -> None:
    raise EvidenceError("invalid peer probe numeric constant")


def _read_frame(connection: socket.socket) -> bytes:
    """Read one bounded newline-delimited frame, then stop."""
    original_timeout = connection.gettimeout()
    frame = bytearray()

    try:
        connection.settimeout(2.0)

        while True:
            try:
                chunk = connection.recv(_MAX_FRAME + 1)
            except (OSError, TimeoutError) as exc:
                raise EvidenceError(
                    "peer probe frame read failed"
                ) from exc

            if not chunk:
                raise EvidenceError("incomplete peer probe frame")

            frame.extend(chunk)

            if len(frame) > _MAX_FRAME:
                raise EvidenceError("peer probe frame too large")

            if b"\n" in frame:
                if (
                    not frame.endswith(b"\n")
                    or frame.count(b"\n") != 1
                ):
                    raise EvidenceError(
                        "invalid peer probe frame boundary"
                    )

                return bytes(frame[:-1])
    finally:
        connection.settimeout(original_timeout)


def _parse_probe(raw: bytes) -> str:
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError) as exc:
        raise EvidenceError("invalid peer probe JSON") from exc

    if (
        type(payload) is not dict
        or set(payload) != {"kind", "nonce"}
        or payload["kind"] != _PROBE_KIND
        or type(payload["nonce"]) is not str
        or _NONCE.fullmatch(payload["nonce"]) is None
    ):
        raise EvidenceError("invalid peer probe envelope")

    if canonical_bytes(payload) != raw:
        raise EvidenceError("noncanonical peer probe JSON")

    return payload["nonce"]


def handle_one_mock_probe(
    connection: socket.socket,
    *,
    policy: ControllerPeerPolicy,
) -> KernelPeerIdentity:
    """Authenticate before reading one diagnostic-only request.

    The caller must close the connection after this one exchange.
    This function never handles provisioning, transport, or signing.
    """
    peer = authenticate_controller_peer(
        connection, policy=policy
    )
    nonce = _parse_probe(_read_frame(connection))

    connection.sendall(
        canonical_bytes({
            "kind": _ACK_KIND,
            "nonce": nonce,
        }) + b"\n"
    )

    return peer
