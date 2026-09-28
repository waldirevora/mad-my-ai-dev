from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .errors import AuthorityError


@dataclass(frozen=True)
class VerifiedActivation:
    manifest: Mapping[str, Any]
    inventory: Mapping[str, Mapping[str, str]]
    launcher_path: Path
    python_launcher_path: Path


_activation: VerifiedActivation | None = None


def _install_verified_activation(
    manifest: dict[str, Any], inventory: dict[str, dict[str, str]], launcher_path: str
) -> None:
    global _activation
    expected = Path(manifest["native_launcher_path"])
    actual = Path(launcher_path)
    if _activation is not None:
        raise AuthorityError("MAD activation context is already installed")
    release_launcher = Path(manifest["release_root"]) / "launcher/madctl-launcher.py"
    parent = Path(f"/proc/{__import__('os').getppid()}/exe").resolve(strict=True)
    if (not sys.flags.safe_path or not sys.flags.no_site or not expected.is_absolute() or parent != expected or
            actual != release_launcher or Path(sys.argv[0]).resolve() != release_launcher):
        raise AuthorityError("MAD authority requires the verified isolated external launcher")
    _activation = VerifiedActivation(
        manifest=MappingProxyType(dict(manifest)),
        inventory=MappingProxyType({key: MappingProxyType(dict(value)) for key, value in inventory.items()}),
        launcher_path=expected,
        python_launcher_path=actual,
    )


def require_verified_activation() -> VerifiedActivation:
    if _activation is None:
        raise AuthorityError(
            "authoritative MAD commands require the root-installed verified launcher; python -m madctl is non-authoritative"
        )
    return _activation
