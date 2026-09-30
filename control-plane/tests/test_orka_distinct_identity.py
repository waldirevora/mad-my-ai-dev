"""D12 real distinct-identity validation for Linux SO_PEERCRED.

Experimental only. This test validates a kernel-observed subordinate
UID/GID boundary. It does not establish production service identity,
provider provenance, key isolation, or deployment authorization.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import uuid

import pytest

from madctl import orka_peer_ipc as ipc


pytestmark = pytest.mark.skipif(
    sys.platform != "linux"
    or not hasattr(socket, "SO_PEERCRED"),
    reason="Linux SO_PEERCRED required",
)


_PROBE = (
    b'{"kind":"mad.orka.mock-peer-probe.v0",'
    b'"nonce":"example-probe-nonce-0001"}\n'
)

_ACK = (
    b'{"kind":"mad.orka.mock-peer-probe-ack.v0",'
    b'"nonce":"example-probe-nonce-0001"}\n'
)


def _outside_id_for_inside_zero(section: str) -> int:
    for line in section.splitlines():
        fields = line.split()

        if len(fields) != 3:
            continue

        inside_start, outside_start, count = map(int, fields)

        if inside_start <= 0 < inside_start + count:
            return outside_start - inside_start

    raise ValueError("inside UID/GID 0 is not mapped")


def _mapped_host_ids() -> tuple[int, int]:
    """Return host UID/GID corresponding to namespace UID/GID zero."""
    required = ("unshare", "newuidmap", "newgidmap")
    missing = [name for name in required if shutil.which(name) is None]

    if missing:
        pytest.skip(
            "D12 subordinate-ID helpers unavailable: "
            + ", ".join(missing)
        )

    probe = subprocess.run(
        [
            "unshare",
            "--user",
            "--map-auto",
            "--setgid",
            "0",
            "--setuid",
            "0",
            "--",
            "/bin/sh",
            "-c",
            (
                'echo "UIDMAP"; '
                "cat /proc/self/uid_map; "
                'echo "GIDMAP"; '
                "cat /proc/self/gid_map"
            ),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )

    if probe.returncode != 0:
        detail = probe.stderr.strip() or "user namespace unavailable"
        pytest.skip(f"D12 subordinate mapping unavailable: {detail}")

    try:
        _, remainder = probe.stdout.split("UIDMAP\n", 1)
        uid_text, gid_text = remainder.split("GIDMAP\n", 1)

        expected_uid = _outside_id_for_inside_zero(uid_text)
        expected_gid = _outside_id_for_inside_zero(gid_text)
    except (ValueError, TypeError) as exc:
        pytest.fail(
            f"cannot parse D12 subordinate mapping: {probe.stdout!r}; "
            f"error={exc}"
        )

    if (
        expected_uid == os.geteuid()
        or expected_gid == os.getegid()
    ):
        pytest.skip(
            "D12 host mapping does not provide a distinct UID/GID"
        )

    return expected_uid, expected_gid


def test_real_distinct_controller_identity_is_kernel_authenticated():
    """Authenticate a real peer mapped to a distinct host UID/GID."""
    expected_uid, expected_gid = _mapped_host_ids()

    system_python = Path("/usr/bin/python3")

    if not system_python.is_file():
        pytest.skip("D12 requires /usr/bin/python3")

    socket_path = Path(
        f"/tmp/mad-orka-d12-{os.getpid()}-{uuid.uuid4().hex}.sock"
    )

    child_script = r'''
import socket
import sys

path = sys.argv[1]

probe = (
    b'{"kind":"mad.orka.mock-peer-probe.v0",'
    b'"nonce":"example-probe-nonce-0001"}\n'
)

expected_ack = (
    b'{"kind":"mad.orka.mock-peer-probe-ack.v0",'
    b'"nonce":"example-probe-nonce-0001"}\n'
)

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(5.0)
    client.connect(path)
    client.sendall(probe)

    response = bytearray()

    while not response.endswith(b"\n"):
        chunk = client.recv(1024)

        if not chunk:
            raise SystemExit("incomplete diagnostic acknowledgement")

        response.extend(chunk)

if bytes(response) != expected_ack:
    raise SystemExit("unexpected diagnostic acknowledgement")
'''

    child = None

    try:
        with socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        ) as listener:
            listener.bind(str(socket_path))

            # Test-only accessibility for the subordinate host UID/GID.
            # This is not the production endpoint permission model.
            os.chmod(socket_path, 0o666)

            listener.listen(1)
            listener.settimeout(5.0)

            child = subprocess.Popen(
                [
                    "unshare",
                    "--user",
                    "--map-auto",
                    "--setgid",
                    "0",
                    "--setuid",
                    "0",
                    "--",
                    str(system_python),
                    "-P",
                    "-B",
                    "-c",
                    child_script,
                    str(socket_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            try:
                connection, _ = listener.accept()
            except socket.timeout:
                stdout, stderr = child.communicate(timeout=5)

                pytest.fail(
                    "mapped controller did not connect; "
                    f"stdout={stdout!r} stderr={stderr!r}"
                )

            with connection:
                peer = ipc.handle_one_mock_probe(
                    connection,
                    policy=ipc.ControllerPeerPolicy(
                        controller_uid=expected_uid,
                        controller_gid=expected_gid,
                    ),
                )

                assert peer.pid == child.pid
                assert peer.uid == expected_uid
                assert peer.gid == expected_gid
                assert peer.uid != os.geteuid()
                assert peer.gid != os.getegid()

            stdout, stderr = child.communicate(timeout=5)

            assert child.returncode == 0, (
                f"stdout={stdout!r} stderr={stderr!r}"
            )

    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate(timeout=5)

        socket_path.unlink(missing_ok=True)
