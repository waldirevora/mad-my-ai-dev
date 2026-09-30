"""D13 tests for the experimental fail-closed Unix endpoint lifecycle."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import stat

import pytest

from madctl import orka_endpoint as endpoint
from madctl.errors import EvidenceError


pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="Unix sockets required",
)


def make_parent(tmp_path: Path, *, mode: int = 0o700) -> Path:
    parent = tmp_path / "runtime"
    parent.mkdir(mode=0o700)
    os.chmod(parent, mode)
    return parent


def make_nested_parent(
    tmp_path: Path,
    *,
    ancestor_mode: int = 0o700,
) -> tuple[Path, Path]:
    ancestor = tmp_path / "ancestor"
    ancestor.mkdir(mode=0o700)
    os.chmod(ancestor, ancestor_mode)

    parent = ancestor / "runtime"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o700)

    return ancestor, parent


def make_policy(
    parent: Path,
    *,
    socket_name: str = "orka.sock",
    uid: int | None = None,
    gid: int | None = None,
    system_uid: int | None = None,
    socket_mode: int = 0o600,
) -> endpoint.UnixEndpointPolicy:
    return endpoint.UnixEndpointPolicy(
        parent=parent,
        socket_name=socket_name,
        expected_uid=os.geteuid() if uid is None else uid,
        expected_gid=os.getegid() if gid is None else gid,
        trusted_system_uid=(
            os.lstat("/").st_uid
            if system_uid is None
            else system_uid
        ),
        socket_mode=socket_mode,
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"parent": Path("relative")},
        {"socket_name": ""},
        {"socket_name": "."},
        {"socket_name": ".."},
        {"socket_name": "../orka.sock"},
        {"socket_name": "nested/orka.sock"},
        {"socket_name": "bad\x00name"},
        {"uid": -1},
        {"gid": -1},
        {"uid": True},
        {"gid": False},
        {"system_uid": -1},
        {"system_uid": True},
        {"socket_mode": 0o644},
    ],
)
def test_invalid_policy_rejected(tmp_path, kwargs):
    values = {
        "parent": (tmp_path / "runtime").absolute(),
        "socket_name": "orka.sock",
        "expected_uid": os.geteuid(),
        "expected_gid": os.getegid(),
        "trusted_system_uid": os.lstat("/").st_uid,
        "socket_mode": 0o600,
    }

    if "uid" in kwargs:
        values["expected_uid"] = kwargs.pop("uid")

    if "gid" in kwargs:
        values["expected_gid"] = kwargs.pop("gid")

    if "system_uid" in kwargs:
        values["trusted_system_uid"] = kwargs.pop("system_uid")

    values.update(kwargs)

    with pytest.raises(EvidenceError):
        endpoint.UnixEndpointPolicy(**values)


def test_invalid_policy_object_rejected():
    with pytest.raises(EvidenceError, match="invalid Unix endpoint policy"):
        endpoint.bind_unix_endpoint(object())


@pytest.mark.parametrize("backlog", [True, 0, -1, 129, "1"])
def test_invalid_backlog_rejected(tmp_path, backlog):
    parent = make_parent(tmp_path)

    with pytest.raises(EvidenceError, match="backlog"):
        endpoint.bind_unix_endpoint(
            make_policy(parent),
            backlog=backlog,
        )


def test_missing_parent_rejected(tmp_path):
    parent = tmp_path / "missing"

    with pytest.raises(EvidenceError, match="does not exist"):
        endpoint.bind_unix_endpoint(make_policy(parent))


def test_symlink_parent_rejected(tmp_path):
    real_parent = make_parent(tmp_path)
    link = tmp_path / "runtime-link"
    link.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(EvidenceError):
        endpoint.bind_unix_endpoint(make_policy(link))


def test_noncanonical_parent_rejected(tmp_path):
    real_parent = make_parent(tmp_path)
    noncanonical = real_parent / ".." / real_parent.name

    with pytest.raises(EvidenceError, match="canonical"):
        endpoint.bind_unix_endpoint(make_policy(noncanonical))


@pytest.mark.parametrize("mode", [0o777, 0o770])
def test_nonsticky_writable_ancestor_rejected(tmp_path, mode):
    _, parent = make_nested_parent(
        tmp_path,
        ancestor_mode=mode,
    )

    with pytest.raises(
        EvidenceError,
        match="ancestor has unsafe writable permissions",
    ):
        endpoint.bind_unix_endpoint(make_policy(parent))


def test_sticky_writable_ancestor_is_allowed(tmp_path):
    ancestor, parent = make_nested_parent(
        tmp_path,
        ancestor_mode=0o1777,
    )

    info = os.lstat(ancestor)

    assert stat.S_IMODE(info.st_mode) == 0o1777
    assert info.st_mode & stat.S_ISVTX

    bound = endpoint.bind_unix_endpoint(make_policy(parent))

    try:
        assert os.path.lexists(bound.path)
    finally:
        bound.close()

    assert bound.cleanup_complete
    assert not os.path.lexists(bound.path)


def test_symlink_ancestor_rejected(tmp_path):
    real_ancestor = tmp_path / "real-ancestor"
    real_ancestor.mkdir(mode=0o700)

    real_parent = real_ancestor / "runtime"
    real_parent.mkdir(mode=0o700)

    linked_ancestor = tmp_path / "linked-ancestor"
    linked_ancestor.symlink_to(
        real_ancestor,
        target_is_directory=True,
    )

    linked_parent = linked_ancestor / "runtime"

    with pytest.raises(
        EvidenceError,
        match="canonical|ancestor",
    ):
        endpoint.bind_unix_endpoint(
            make_policy(linked_parent)
        )


def test_ancestor_becoming_unsafe_blocks_cleanup(tmp_path):
    ancestor, parent = make_nested_parent(tmp_path)
    bound = endpoint.bind_unix_endpoint(make_policy(parent))

    os.chmod(ancestor, 0o777)

    with pytest.raises(
        EvidenceError,
        match="ancestor has unsafe writable permissions",
    ):
        bound.close()

    assert os.path.lexists(bound.path)
    assert not bound.cleanup_complete

    os.chmod(ancestor, 0o700)
    bound.close()

    assert bound.cleanup_complete
    assert not os.path.lexists(bound.path)


def test_trusted_system_uid_mismatch_rejected(tmp_path):
    parent = make_parent(tmp_path)
    actual = os.lstat("/").st_uid

    with pytest.raises(
        EvidenceError,
        match="trusted system UID does not match filesystem root owner",
    ):
        endpoint.bind_unix_endpoint(
            make_policy(
                parent,
                system_uid=actual + 1,
            )
        )


@pytest.mark.parametrize("ancestor_mode", [0o755, 0o1777])
def test_untrusted_ancestor_owner_rejected(
    tmp_path,
    monkeypatch,
    ancestor_mode,
):
    ancestor, parent = make_nested_parent(tmp_path)
    real_reader = endpoint._read_ancestor_stat

    untrusted_uid = max(
        os.geteuid(),
        os.lstat("/").st_uid,
    ) + 100000

    def fake_reader(path):
        info = real_reader(path)

        if Path(path) != ancestor:
            return info

        values = list(info)
        values[0] = stat.S_IFDIR | ancestor_mode
        values[4] = untrusted_uid

        return os.stat_result(values)

    monkeypatch.setattr(
        endpoint,
        "_read_ancestor_stat",
        fake_reader,
    )

    with pytest.raises(
        EvidenceError,
        match="ancestor has untrusted ownership",
    ):
        endpoint.bind_unix_endpoint(make_policy(parent))


def test_ancestor_owner_change_blocks_cleanup(
    tmp_path,
    monkeypatch,
):
    ancestor, parent = make_nested_parent(tmp_path)
    bound = endpoint.bind_unix_endpoint(make_policy(parent))

    real_reader = endpoint._read_ancestor_stat

    untrusted_uid = max(
        os.geteuid(),
        os.lstat("/").st_uid,
    ) + 100000

    def fake_reader(path):
        info = real_reader(path)

        if Path(path) != ancestor:
            return info

        values = list(info)
        values[4] = untrusted_uid

        return os.stat_result(values)

    monkeypatch.setattr(
        endpoint,
        "_read_ancestor_stat",
        fake_reader,
    )

    with pytest.raises(
        EvidenceError,
        match="ancestor has untrusted ownership",
    ):
        bound.close()

    assert os.path.lexists(bound.path)
    assert not bound.cleanup_complete

    monkeypatch.setattr(
        endpoint,
        "_read_ancestor_stat",
        real_reader,
    )

    bound.close()

    assert bound.cleanup_complete
    assert not os.path.lexists(bound.path)


def test_parent_uid_mismatch_rejected(tmp_path):
    parent = make_parent(tmp_path)

    with pytest.raises(EvidenceError, match="ownership"):
        endpoint.bind_unix_endpoint(
            make_policy(parent, uid=os.geteuid() + 1)
        )


def test_parent_gid_mismatch_rejected(tmp_path):
    parent = make_parent(tmp_path)

    with pytest.raises(EvidenceError, match="ownership"):
        endpoint.bind_unix_endpoint(
            make_policy(parent, gid=os.getegid() + 1)
        )


def test_group_writable_parent_rejected(tmp_path):
    parent = make_parent(tmp_path, mode=0o770)

    with pytest.raises(EvidenceError, match="group-writable"):
        endpoint.bind_unix_endpoint(make_policy(parent))


@pytest.mark.parametrize("mode", [0o701, 0o704, 0o705])
def test_parent_permissions_for_other_rejected(tmp_path, mode):
    parent = make_parent(tmp_path, mode=mode)

    with pytest.raises(EvidenceError, match="other"):
        endpoint.bind_unix_endpoint(make_policy(parent))


@pytest.mark.parametrize("mode", [0o400, 0o500, 0o600])
def test_parent_without_owner_write_and_search_rejected(tmp_path, mode):
    parent = make_parent(tmp_path, mode=mode)

    with pytest.raises(EvidenceError, match="owner-writable"):
        endpoint.bind_unix_endpoint(make_policy(parent))


def test_existing_regular_file_is_preserved(tmp_path):
    parent = make_parent(tmp_path)
    path = parent / "orka.sock"
    path.write_text("do-not-remove", encoding="utf-8")

    with pytest.raises(EvidenceError, match="already exists"):
        endpoint.bind_unix_endpoint(make_policy(parent))

    assert path.is_file()
    assert path.read_text(encoding="utf-8") == "do-not-remove"


def test_existing_directory_is_preserved(tmp_path):
    parent = make_parent(tmp_path)
    path = parent / "orka.sock"
    path.mkdir()

    with pytest.raises(EvidenceError, match="already exists"):
        endpoint.bind_unix_endpoint(make_policy(parent))

    assert path.is_dir()


def test_existing_symlink_is_preserved(tmp_path):
    parent = make_parent(tmp_path)
    target = parent / "target"
    target.write_text("target", encoding="utf-8")
    path = parent / "orka.sock"
    path.symlink_to(target)

    with pytest.raises(EvidenceError, match="already exists"):
        endpoint.bind_unix_endpoint(make_policy(parent))

    assert path.is_symlink()
    assert target.read_text(encoding="utf-8") == "target"


def test_existing_dangling_symlink_is_preserved(tmp_path):
    parent = make_parent(tmp_path)
    path = parent / "orka.sock"
    path.symlink_to(parent / "missing-target")

    with pytest.raises(EvidenceError, match="already exists"):
        endpoint.bind_unix_endpoint(make_policy(parent))

    assert path.is_symlink()
    assert os.lstat(path)


def test_existing_unix_socket_is_preserved(tmp_path):
    parent = make_parent(tmp_path)
    path = parent / "orka.sock"

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as existing:
        existing.bind(str(path))

        original = os.lstat(path)

        with pytest.raises(EvidenceError, match="already exists"):
            endpoint.bind_unix_endpoint(make_policy(parent))

        after = os.lstat(path)

        assert stat.S_ISSOCK(after.st_mode)
        assert (after.st_dev, after.st_ino) == (
            original.st_dev,
            original.st_ino,
        )

    path.unlink()


@pytest.mark.parametrize("socket_mode", [0o600, 0o660])
def test_bind_creates_verified_socket_with_exact_mode(
    tmp_path,
    socket_mode,
):
    parent = make_parent(tmp_path)
    bound = endpoint.bind_unix_endpoint(
        make_policy(parent, socket_mode=socket_mode)
    )

    try:
        info = os.lstat(bound.path)

        assert stat.S_ISSOCK(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == socket_mode
        assert info.st_uid == os.geteuid()
        assert info.st_gid == os.getegid()
        assert bound.identity == (info.st_dev, info.st_ino)
        assert not bound.cleanup_complete
    finally:
        bound.close()

    assert not bound.path.exists()
    assert bound.cleanup_complete


def test_listener_accepts_unix_connection(tmp_path):
    parent = make_parent(tmp_path)
    bound = endpoint.bind_unix_endpoint(make_policy(parent))

    bound.listener.settimeout(2.0)

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(str(bound.path))

            connection, _ = bound.listener.accept()

            with connection:
                connection.sendall(b"x")
                assert client.recv(1) == b"x"
    finally:
        bound.close()


def test_successful_cleanup_is_idempotent(tmp_path):
    parent = make_parent(tmp_path)
    bound = endpoint.bind_unix_endpoint(make_policy(parent))

    bound.close()
    bound.close()

    assert bound.cleanup_complete
    assert not bound.path.exists()


def test_missing_path_before_cleanup_fails_closed(tmp_path):
    parent = make_parent(tmp_path)
    bound = endpoint.bind_unix_endpoint(make_policy(parent))

    bound.path.unlink()

    with pytest.raises(EvidenceError, match="disappeared"):
        bound.close()

    assert not bound.path.exists()
    assert not bound.cleanup_complete


def test_replaced_regular_file_is_not_removed(tmp_path):
    parent = make_parent(tmp_path)
    bound = endpoint.bind_unix_endpoint(make_policy(parent))

    bound.path.unlink()
    bound.path.write_text("replacement", encoding="utf-8")

    with pytest.raises(EvidenceError, match="expected socket|replaced"):
        bound.close()

    assert bound.path.is_file()
    assert bound.path.read_text(encoding="utf-8") == "replacement"


def test_replaced_symlink_is_not_followed_or_removed(tmp_path):
    parent = make_parent(tmp_path)
    bound = endpoint.bind_unix_endpoint(make_policy(parent))

    target = parent / "replacement-target"
    target.write_text("preserve", encoding="utf-8")

    bound.path.unlink()
    bound.path.symlink_to(target)

    with pytest.raises(EvidenceError, match="expected socket|replaced"):
        bound.close()

    assert bound.path.is_symlink()
    assert target.read_text(encoding="utf-8") == "preserve"


def test_replaced_socket_inode_is_not_removed(tmp_path):
    parent = make_parent(tmp_path)
    bound = endpoint.bind_unix_endpoint(make_policy(parent))

    bound.path.unlink()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as replacement:
        replacement.bind(str(bound.path))
        replacement_info = os.lstat(bound.path)

        assert (
            replacement_info.st_dev,
            replacement_info.st_ino,
        ) != bound.identity

        with pytest.raises(EvidenceError, match="replaced"):
            bound.close()

        after = os.lstat(bound.path)

        assert stat.S_ISSOCK(after.st_mode)
        assert (after.st_dev, after.st_ino) == (
            replacement_info.st_dev,
            replacement_info.st_ino,
        )

    bound.path.unlink()


def test_unsafe_parent_change_blocks_cleanup(tmp_path):
    parent = make_parent(tmp_path)
    bound = endpoint.bind_unix_endpoint(make_policy(parent))

    os.chmod(parent, 0o770)

    with pytest.raises(EvidenceError, match="group-writable"):
        bound.close()

    assert os.path.lexists(bound.path)
    assert not bound.cleanup_complete

    os.chmod(parent, 0o700)
    bound.close()

    assert bound.cleanup_complete


def test_setup_failure_removes_only_original_socket(
    tmp_path,
    monkeypatch,
):
    parent = make_parent(tmp_path)
    path = parent / "orka.sock"
    real_chmod = endpoint.os.chmod

    def fail_socket_chmod(candidate, mode):
        if Path(candidate) == path:
            raise OSError("simulated endpoint chmod failure")

        return real_chmod(candidate, mode)

    monkeypatch.setattr(endpoint.os, "chmod", fail_socket_chmod)

    with pytest.raises(
        EvidenceError,
        match="cannot configure Unix endpoint permissions",
    ):
        endpoint.bind_unix_endpoint(make_policy(parent))

    assert not os.path.lexists(path)
