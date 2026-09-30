"""D13: fail-closed lifecycle for an experimental Unix socket endpoint.

This module manages only the filesystem lifecycle of a local AF_UNIX
listener. Peer authentication remains the responsibility of
orka_peer_ipc. This is not a production service or deployment model.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
from dataclasses import dataclass

from .errors import EvidenceError


_ALLOWED_SOCKET_MODES = frozenset({0o600, 0o660})


@dataclass(frozen=True)
class UnixEndpointPolicy:
    """Expected filesystem identity for one experimental Unix endpoint."""

    parent: Path
    socket_name: str
    expected_uid: int
    expected_gid: int
    trusted_system_uid: int
    socket_mode: int = 0o600

    def __post_init__(self) -> None:
        if not isinstance(self.parent, Path) or not self.parent.is_absolute():
            raise EvidenceError(
                "Unix endpoint parent must be an absolute Path"
            )

        if (
            type(self.socket_name) is not str
            or not self.socket_name
            or self.socket_name in {".", ".."}
            or "/" in self.socket_name
            or "\x00" in self.socket_name
            or Path(self.socket_name).name != self.socket_name
        ):
            raise EvidenceError("invalid Unix endpoint socket name")

        for value in (
            self.expected_uid,
            self.expected_gid,
            self.trusted_system_uid,
        ):
            if type(value) is not int or value < 0:
                raise EvidenceError("invalid Unix endpoint ownership policy")

        if (
            type(self.socket_mode) is not int
            or self.socket_mode not in _ALLOWED_SOCKET_MODES
        ):
            raise EvidenceError("invalid Unix endpoint socket mode")


def _lstat_optional(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise EvidenceError(
            f"cannot inspect Unix endpoint path: {path}"
        ) from exc


def _read_ancestor_stat(path: Path) -> os.stat_result:
    try:
        return os.lstat(path)
    except FileNotFoundError as exc:
        raise EvidenceError(
            "Unix endpoint ancestor directory does not exist"
        ) from exc
    except OSError as exc:
        raise EvidenceError(
            "cannot inspect Unix endpoint ancestor directory"
        ) from exc


def _validate_system_trust(policy: UnixEndpointPolicy) -> None:
    root_info = _read_ancestor_stat(Path("/"))

    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
    ):
        raise EvidenceError(
            "filesystem root is not a trusted real directory"
        )

    if root_info.st_uid != policy.trusted_system_uid:
        raise EvidenceError(
            "trusted system UID does not match filesystem root owner"
        )


def _validate_ancestor_chain(policy: UnixEndpointPolicy) -> None:
    """Validate ownership and writable semantics for every ancestor."""

    _validate_system_trust(policy)

    trusted_uids = {
        policy.expected_uid,
        policy.trusted_system_uid,
    }

    current = policy.parent.parent

    while True:
        info = _read_ancestor_stat(current)

        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise EvidenceError(
                "Unix endpoint ancestor must be a real directory"
            )

        if info.st_uid not in trusted_uids:
            raise EvidenceError(
                "Unix endpoint ancestor has untrusted ownership"
            )

        mode = stat.S_IMODE(info.st_mode)

        writable_by_group_or_other = bool(
            mode & (stat.S_IWGRP | stat.S_IWOTH)
        )
        sticky = bool(info.st_mode & stat.S_ISVTX)

        if writable_by_group_or_other and not sticky:
            raise EvidenceError(
                "Unix endpoint ancestor has unsafe writable permissions"
            )

        if current == current.parent:
            break

        current = current.parent


def _validate_parent(policy: UnixEndpointPolicy) -> os.stat_result:
    parent = policy.parent

    try:
        info = os.lstat(parent)
    except FileNotFoundError as exc:
        raise EvidenceError(
            "Unix endpoint parent directory does not exist"
        ) from exc
    except OSError as exc:
        raise EvidenceError(
            "cannot inspect Unix endpoint parent directory"
        ) from exc

    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise EvidenceError(
            "Unix endpoint parent must be a real directory"
        )

    try:
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise EvidenceError(
            "cannot resolve Unix endpoint parent directory"
        ) from exc

    if resolved != parent:
        raise EvidenceError(
            "Unix endpoint parent must be canonical and non-symlinked"
        )

    _validate_ancestor_chain(policy)

    if (
        info.st_uid != policy.expected_uid
        or info.st_gid != policy.expected_gid
    ):
        raise EvidenceError(
            "Unix endpoint parent has unexpected ownership"
        )

    mode = stat.S_IMODE(info.st_mode)

    if mode & stat.S_IWGRP:
        raise EvidenceError(
            "Unix endpoint parent must not be group-writable"
        )

    if mode & (
        stat.S_IROTH
        | stat.S_IWOTH
        | stat.S_IXOTH
    ):
        raise EvidenceError(
            "Unix endpoint parent must not grant permissions to other"
        )

    required_owner_bits = stat.S_IWUSR | stat.S_IXUSR

    if mode & required_owner_bits != required_owner_bits:
        raise EvidenceError(
            "Unix endpoint parent must be owner-writable and searchable"
        )

    return info


def _validate_socket_identity(
    *,
    path: Path,
    info: os.stat_result,
    policy: UnixEndpointPolicy,
    identity: tuple[int, int] | None = None,
    require_mode: bool,
) -> None:
    if not stat.S_ISSOCK(info.st_mode):
        raise EvidenceError(
            "Unix endpoint path is not the expected socket"
        )

    if identity is not None and (
        info.st_dev,
        info.st_ino,
    ) != identity:
        raise EvidenceError(
            "Unix endpoint path was replaced"
        )

    if (
        info.st_uid != policy.expected_uid
        or info.st_gid != policy.expected_gid
    ):
        raise EvidenceError(
            "Unix endpoint socket has unexpected ownership"
        )

    if (
        require_mode
        and stat.S_IMODE(info.st_mode) != policy.socket_mode
    ):
        raise EvidenceError(
            "Unix endpoint socket has unexpected permissions"
        )


def _verified_unlink(
    *,
    path: Path,
    policy: UnixEndpointPolicy,
    identity: tuple[int, int],
    require_mode: bool,
) -> None:
    info = _lstat_optional(path)

    if info is None:
        raise EvidenceError(
            "Unix endpoint disappeared before authenticated cleanup"
        )

    _validate_socket_identity(
        path=path,
        info=info,
        policy=policy,
        identity=identity,
        require_mode=require_mode,
    )

    try:
        os.unlink(path)
    except OSError as exc:
        raise EvidenceError(
            "cannot remove authenticated Unix endpoint"
        ) from exc

    if _lstat_optional(path) is not None:
        raise EvidenceError(
            "Unix endpoint path reappeared after cleanup"
        )


class BoundUnixEndpoint:
    """One bound listener whose pathname is removed only if still authentic."""

    def __init__(
        self,
        *,
        listener: socket.socket,
        path: Path,
        policy: UnixEndpointPolicy,
        identity: tuple[int, int],
    ) -> None:
        self.listener = listener
        self.path = path
        self.policy = policy
        self._identity = identity
        self._listener_closed = False
        self._cleanup_complete = False

    @property
    def identity(self) -> tuple[int, int]:
        return self._identity

    @property
    def cleanup_complete(self) -> bool:
        return self._cleanup_complete

    def close(self) -> None:
        if self._cleanup_complete:
            return

        if not self._listener_closed:
            self.listener.close()
            self._listener_closed = True

        _validate_parent(self.policy)

        _verified_unlink(
            path=self.path,
            policy=self.policy,
            identity=self._identity,
            require_mode=True,
        )

        self._cleanup_complete = True


def bind_unix_endpoint(
    policy: UnixEndpointPolicy,
    *,
    backlog: int = 1,
) -> BoundUnixEndpoint:
    """Bind, verify, chmod, and listen without replacing existing state."""

    if type(policy) is not UnixEndpointPolicy:
        raise EvidenceError("invalid Unix endpoint policy")

    if type(backlog) is not int or backlog <= 0 or backlog > 128:
        raise EvidenceError("invalid Unix endpoint backlog")

    _validate_parent(policy)

    path = policy.parent / policy.socket_name

    if path.parent != policy.parent:
        raise EvidenceError(
            "Unix endpoint path must be a direct child of its parent"
        )

    if _lstat_optional(path) is not None:
        raise EvidenceError(
            "Unix endpoint path already exists"
        )

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    identity: tuple[int, int] | None = None

    try:
        try:
            listener.bind(str(path))
        except OSError as exc:
            raise EvidenceError(
                "cannot bind Unix endpoint"
            ) from exc

        info = _lstat_optional(path)

        if info is None:
            raise EvidenceError(
                "Unix endpoint missing immediately after bind"
            )

        identity = (info.st_dev, info.st_ino)

        _validate_socket_identity(
            path=path,
            info=info,
            policy=policy,
            identity=identity,
            require_mode=False,
        )

        try:
            os.chmod(path, policy.socket_mode)
        except OSError as exc:
            raise EvidenceError(
                "cannot configure Unix endpoint permissions"
            ) from exc

        _validate_parent(policy)

        verified = _lstat_optional(path)

        if verified is None:
            raise EvidenceError(
                "Unix endpoint disappeared during setup"
            )

        _validate_socket_identity(
            path=path,
            info=verified,
            policy=policy,
            identity=identity,
            require_mode=True,
        )

        try:
            listener.listen(backlog)
        except OSError as exc:
            raise EvidenceError(
                "cannot listen on Unix endpoint"
            ) from exc

        return BoundUnixEndpoint(
            listener=listener,
            path=path,
            policy=policy,
            identity=identity,
        )

    except EvidenceError as exc:
        listener.close()

        if identity is not None:
            try:
                _verified_unlink(
                    path=path,
                    policy=policy,
                    identity=identity,
                    require_mode=False,
                )
            except EvidenceError as cleanup_exc:
                raise EvidenceError(
                    "Unix endpoint setup failed and cleanup was unsafe"
                ) from cleanup_exc

        raise exc
