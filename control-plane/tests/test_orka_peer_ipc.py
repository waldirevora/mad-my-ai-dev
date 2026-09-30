"""D11 kernel peer-probe tests; not a production isolation test."""
from __future__ import annotations

from contextlib import contextmanager

import json
import os
import socket
import subprocess
import sys

import pytest

from madctl.canonical import canonical_bytes
from madctl.errors import EvidenceError
from madctl import orka_peer_ipc as ipc


pytestmark = pytest.mark.skipif(
    sys.platform != "linux"
    or not hasattr(socket, "SO_PEERCRED"),
    reason="Linux SO_PEERCRED required",
)

_NONCE = "example-probe-nonce-0001"


@contextmanager
def connected_pair():
    client, server = socket.socketpair()
    with client, server:
        yield client, server


def frame(value):
    return canonical_bytes(value) + b"\n"


def valid_frame():
    return frame({
        "kind": "mad.orka.mock-peer-probe.v0",
        "nonce": _NONCE,
    })


def policy_for_current_process():
    return ipc.ControllerPeerPolicy(
        controller_uid=os.getuid(),
        controller_gid=os.getgid(),
    )


@pytest.fixture
def simulated_distinct_service_uid(monkeypatch):
    # Unit simulation only: no actual OS privilege separation.
    real_uid = os.geteuid()
    monkeypatch.setattr(ipc.os, "geteuid", lambda: real_uid + 1)


def test_kernel_reports_real_subprocess_identity(tmp_path):
    path = tmp_path / "peer.sock"

    script = """
import socket
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(sys.argv[1])
    client.recv(1)
"""

    with socket.socket(
        socket.AF_UNIX, socket.SOCK_STREAM
    ) as listener:
        listener.bind(str(path))
        listener.listen(1)
        listener.settimeout(5.0)

        child = subprocess.Popen(
            [sys.executable, "-P", "-B", "-c", script, str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        try:
            connection, _ = listener.accept()

            with connection:
                peer = ipc.read_kernel_peer_identity(connection)

                assert peer.pid == child.pid
                assert peer.uid == os.getuid()
                assert peer.gid == os.getgid()

                with pytest.raises(
                    EvidenceError,
                    match="share an operating-system UID",
                ):
                    ipc.authenticate_controller_peer(
                        connection,
                        policy=policy_for_current_process(),
                    )

            _, stderr = child.communicate(timeout=5)
            assert child.returncode == 0, stderr
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)


def test_same_uid_fails_even_when_allowlisted():
    with connected_pair() as (client, server):
        with pytest.raises(
            EvidenceError,
            match="share an operating-system UID",
        ):
            ipc.authenticate_controller_peer(
                server,
                policy=policy_for_current_process(),
            )


def test_wrong_controller_uid_is_rejected():
    with connected_pair() as (client, server):
        with pytest.raises(
            EvidenceError,
            match="unauthorized controller peer identity",
        ):
            ipc.authenticate_controller_peer(
                server,
                policy=ipc.ControllerPeerPolicy(
                    controller_uid=os.getuid() + 1,
                    controller_gid=os.getgid(),
                ),
            )


def test_wrong_controller_gid_is_rejected():
    with connected_pair() as (client, server):
        with pytest.raises(
            EvidenceError,
            match="unauthorized controller peer identity",
        ):
            ipc.authenticate_controller_peer(
                server,
                policy=ipc.ControllerPeerPolicy(
                    controller_uid=os.getuid(),
                    controller_gid=os.getgid() + 1,
                ),
            )


@pytest.mark.parametrize(
    "uid,gid",
    [
        (True, 1000),
        (1000, False),
        (-1, 1000),
        (1000, -1),
        ("1000", 1000),
    ],
)
def test_invalid_policy_rejected(uid, gid):
    with pytest.raises(
        EvidenceError, match="invalid controller peer policy"
    ):
        ipc.ControllerPeerPolicy(uid, gid)


def test_unconnected_socket_rejected():
    with socket.socket(
        socket.AF_UNIX, socket.SOCK_STREAM
    ) as unconnected:
        with pytest.raises(
            EvidenceError,
            match="cannot verify connected peer",
        ):
            ipc.read_kernel_peer_identity(unconnected)


def test_tcp_socket_rejected_before_credential_lookup():
    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM
    ) as tcp:
        with pytest.raises(
            EvidenceError,
            match="Unix stream socket",
        ):
            ipc.read_kernel_peer_identity(tcp)


def test_valid_probe_with_mocked_separate_service_uid(
    simulated_distinct_service_uid,
):
    # This establishes handler behavior, NOT actual UID isolation.
    with connected_pair() as (client, server):
        client.sendall(valid_frame())

        peer = ipc.handle_one_mock_probe(
            server,
            policy=policy_for_current_process(),
        )

        response = client.recv(1024)

    assert peer.uid == os.getuid()
    assert json.loads(response) == {
        "kind": "mad.orka.mock-peer-probe-ack.v0",
        "nonce": _NONCE,
    }


@pytest.mark.parametrize(
    "bad",
    [
        b'{"kind":"mad.orka.mock-peer-probe.v0",'
        b'"nonce":"example-probe-nonce-0001",'
        b'"nonce":"example-probe-nonce-0001"}\n',
        b'{"kind": "mad.orka.mock-peer-probe.v0",'
        b' "nonce": "example-probe-nonce-0001"}\n',
        frame({
            "kind": "mad.orka.mock-peer-probe.v0",
            "nonce": _NONCE,
            "uid": 0,
        }),
        frame({
            "kind": "mad.orka.mock-peer-probe.v0",
            "nonce": _NONCE,
            "sign": "arbitrary-digest",
        }),
        frame({
            "kind": "mad.orka.mock-peer-probe.v0",
            "nonce": "short",
        }),
        b'{"kind":"mad.orka.mock-peer-probe.v0",'
        b'"nonce":NaN}\n',
        b"x" * 1025 + b"\n",
        b"not-json\n",
        valid_frame() + b"second-frame\n",
    ],
)
def test_invalid_or_unauthorized_probe_rejected(
    simulated_distinct_service_uid,
    bad,
):
    with connected_pair() as (client, server):
        client.sendall(bad)

        with pytest.raises(EvidenceError):
            ipc.handle_one_mock_probe(
                server,
                policy=policy_for_current_process(),
            )


def test_incomplete_frame_rejected(
    simulated_distinct_service_uid,
):
    with connected_pair() as (client, server):
        client.sendall(valid_frame()[:-1])
        client.shutdown(socket.SHUT_WR)

        with pytest.raises(
            EvidenceError, match="incomplete peer probe frame"
        ):
            ipc.handle_one_mock_probe(
                server,
                policy=policy_for_current_process(),
            )


def test_unauthorized_peer_rejected_before_frame_parsing():
    with connected_pair() as (client, server):
        client.sendall(b"deliberately-invalid-data\n")

        with pytest.raises(
            EvidenceError,
            match="share an operating-system UID",
        ):
            ipc.handle_one_mock_probe(
                server,
                policy=policy_for_current_process(),
            )

        server.close()
        try:
            response = client.recv(1)
        except ConnectionResetError:
            response = b""
        assert response == b""
