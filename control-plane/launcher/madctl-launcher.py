#!/usr/bin/python3 -P
"""Second-stage MAD launcher inside the closed release.

The statically linked native launcher is the first trust boundary.  It validates
the activation record, release, and Python runtime before starting this file.
This stage independently repeats those checks before importing ``madctl``.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


INVENTORY_NAME = "release-files.json"
PYTHON_INVENTORY_NAME = "python-runtime-files.json"
REQUIRED_RELEASE_PATHS = {
    "control-plane.lock.json",
    "genesis-config.yaml",
    "genesis-policy.json",
    "launcher/madctl-launcher.py",
    "launcher/madctl-launcher.c",
    "release-metadata.json",
    "sandbox-profile.json",
    "schemas/activation-record.schema.json",
    "schemas/challenge.schema.json",
    "schemas/codex-attestation.schema.json",
    "schemas/codex-model-output.schema.json",
    "schemas/consumption-record.schema.json",
    "schemas/human-approval.schema.json",
    "schemas/machine-approval.schema.json",
    "schemas/qa-evidence.schema.json",
    "schemas/repository-record.schema.json",
    "python/madctl/__init__.py",
    "python/madctl/__main__.py",
    "python/madctl/activation.py",
    "python/madctl/approvals.py",
    "python/madctl/canonical.py",
    "python/madctl/cli.py",
    "python/madctl/codex.py",
    "python/madctl/config.py",
    "python/madctl/controller.py",
    "python/madctl/errors.py",
    "python/madctl/github.py",
    "python/madctl/gitops.py",
    "python/madctl/hook.py",
    "python/madctl/inventory.py",
    "python/madctl/orka.py",
    "python/madctl/policy.py",
    "python/madctl/qa.py",
    "python/madctl/repository.py",
    "python/madctl/runtime.py",
    "python/madctl/schemas.py",
    "python/madctl/state.py",
}
class LaunchError(RuntimeError):
    pass


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise LaunchError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _read_object(path: Path) -> tuple[bytes, dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise LaunchError(f"required regular metadata file is missing: {path}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LaunchError(f"invalid JSON metadata: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise LaunchError(f"metadata must be an object: {path}")
    return raw, value


def _absolute_regular(path_text: Any, *, uid: int, gid: int, executable: bool = False, root: Path | None = None) -> Path:
    if not isinstance(path_text, str):
        raise LaunchError("trusted file path must be a string")
    supplied = Path(path_text)
    if not supplied.is_absolute() or supplied.is_symlink():
        raise LaunchError(f"trusted file path must be absolute and non-symlink: {supplied}")
    path = supplied.resolve(strict=True)
    if path != supplied or not path.is_file():
        raise LaunchError(f"trusted file path is not canonical and regular: {supplied}")
    info = path.stat()
    if info.st_uid != uid or info.st_gid != gid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise LaunchError(f"trusted file has unsafe ownership or permissions: {path}")
    if executable and not info.st_mode & stat.S_IXUSR:
        raise LaunchError(f"trusted executable is not executable: {path}")
    if root is not None and not _inside(path, root):
        raise LaunchError(f"trusted executable escapes its allowed root: {path}")
    if root is not None:
        current = path.parent
        while True:
            parent_info = current.stat()
            if (parent_info.st_uid != uid or parent_info.st_gid != gid or
                    parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise LaunchError(f"trusted executable has an unsafe parent directory: {current}")
            if current == root:
                break
            if not _inside(current, root):
                raise LaunchError(f"trusted executable parent escapes its allowed root: {current}")
            current = current.parent
    return path


def _absolute_directory(path_text: Any, *, uid: int, gid: int, writable: bool, system_uid: int = 0) -> Path:
    if not isinstance(path_text, str):
        raise LaunchError("trusted directory path must be a string")
    supplied = Path(path_text)
    if not supplied.is_absolute() or supplied.is_symlink():
        raise LaunchError(f"trusted directory must be absolute and non-symlink: {supplied}")
    path = supplied.resolve(strict=True)
    if path != supplied or not path.is_dir():
        raise LaunchError(f"trusted directory is not canonical: {supplied}")
    info = path.stat()
    if info.st_uid != uid or info.st_gid != gid or info.st_mode & stat.S_IWOTH or (not writable and info.st_mode & stat.S_IWGRP):
        raise LaunchError(f"trusted directory has unsafe ownership or permissions: {path}")
    current = path.parent
    while True:
        parent_info = current.stat()
        if parent_info.st_uid not in {system_uid, uid} or parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise LaunchError(f"trusted directory has an unsafe ancestor: {current}")
        if current == current.parent:
            break
        current = current.parent
    return path


def verify_closed_tree(
    root: Path,
    *,
    inventory_name: str,
    expected_inventory_digest: str,
    expected_tree_digest: str,
    trusted_uid: int,
    trusted_gid: int,
    required_paths: set[str],
) -> dict[str, dict[str, str]]:
    inventory_path = root / inventory_name
    raw, inventory = _read_object(inventory_path)
    inventory_info = inventory_path.stat()
    if (inventory_info.st_uid != trusted_uid or inventory_info.st_gid != trusted_gid or
            stat.S_IMODE(inventory_info.st_mode) != 0o444):
        raise LaunchError("closed inventory has unsafe ownership or permissions")
    if _sha256(raw) != expected_inventory_digest:
        raise LaunchError("closed inventory digest mismatch")
    if set(inventory) != {"schema_version", "files"} or inventory["schema_version"] != 1:
        raise LaunchError("closed inventory metadata is malformed")
    entries = inventory["files"]
    if not isinstance(entries, dict) or not entries:
        raise LaunchError("closed inventory has no files")
    if not required_paths <= set(entries):
        raise LaunchError(f"closed inventory is missing required files: {sorted(required_paths - set(entries))}")
    actual_paths: set[str] = set()
    actual_directories: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise LaunchError(f"symlink in closed runtime: {path}")
        if path.is_file() and path != inventory_path:
            actual_paths.add(path.relative_to(root).as_posix())
        elif path.is_dir():
            actual_directories.add(path.relative_to(root).as_posix())
    if actual_paths != set(entries):
        missing = sorted(set(entries) - actual_paths)
        extra = sorted(actual_paths - set(entries))
        raise LaunchError(f"closed runtime tree mismatch; missing={missing}, extra={extra}")
    expected_directories = {
        parent.as_posix()
        for relative in entries
        for parent in Path(relative).parents
        if parent.as_posix() != "."
    }
    if actual_directories != expected_directories:
        raise LaunchError("closed runtime contains missing or unexpected directories")
    for relative in [".", *sorted(actual_directories)]:
        directory = root if relative == "." else root / relative
        info = directory.stat()
        if info.st_uid != trusted_uid or info.st_gid != trusted_gid or stat.S_IMODE(info.st_mode) != 0o555:
            raise LaunchError(f"closed runtime directory has unsafe ownership or permissions: {relative}")
    normalized: dict[str, dict[str, str]] = {}
    for relative, record in entries.items():
        candidate = Path(relative)
        if (
            not isinstance(relative, str)
            or candidate.is_absolute()
            or ".." in candidate.parts
            or not isinstance(record, dict)
            or set(record) != {"mode", "sha256"}
        ):
            raise LaunchError(f"unsafe closed inventory entry: {relative!r}")
        path = root / candidate
        if path.resolve(strict=True) != path or not path.is_file() or path.is_symlink():
            raise LaunchError(f"closed runtime file escapes or is not regular: {relative}")
        info = path.stat()
        mode = f"{stat.S_IMODE(info.st_mode):04o}"
        if info.st_uid != trusted_uid or info.st_gid != trusted_gid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise LaunchError(f"unsafe closed runtime ownership or permissions: {relative}")
        if record["mode"] != mode or record["sha256"] != _sha256(path.read_bytes()):
            raise LaunchError(f"closed runtime file mismatch: {relative}")
        normalized[relative] = {"mode": mode, "sha256": record["sha256"]}
    if _sha256(_canonical(normalized)) != expected_tree_digest:
        raise LaunchError("closed runtime tree digest mismatch")
    return normalized


def verify_activation(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, str]], dict[str, dict[str, str]], list[str]]:
    if not sys.flags.safe_path or sys.flags.no_user_site != 1 or not sys.flags.no_site:
        raise LaunchError("MAD launcher requires safe-path mode with user site and site initialization disabled")
    allowed_environment = {
        "LANG": "C", "LC_ALL": "C", "PATH": "/nonexistent", "HOME": "/nonexistent",
        "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1",
    }
    present = sorted(name for name, value in os.environ.items()
                     if name not in {"LD_LIBRARY_PATH", "PYTHONHOME"} and allowed_environment.get(name) != value)
    if present:
        raise LaunchError(f"inherited or unexpected environment is forbidden: {', '.join(present)}")
    raw, manifest = _read_object(path)
    if path.resolve(strict=True) != path:
        raise LaunchError("activation record path must be canonical")
    if raw != _canonical(manifest) + b"\n":
        raise LaunchError("activation record is not canonical JSON")
    required = {
        "schema_version", "trusted_uid", "trusted_gid", "trusted_system_uid", "expected_mad_version", "release_root",
        "release_digest", "inventory_digest", "native_launcher_path", "native_launcher_sha256",
        "python_runtime_root", "python_executable", "python_runtime_digest", "python_runtime_inventory_digest",
        "state_root", "registry_root", "human_approval_registry_root", "cache_root",
        "controller_key_path", "codex_home", "tools", "orka",
    }
    if set(manifest) != required or manifest["schema_version"] != 1 or manifest["expected_mad_version"] != "2.0.0":
        raise LaunchError("activation record has missing or unknown fields")
    uid = manifest["trusted_uid"]
    if not isinstance(uid, int) or uid < 0:
        raise LaunchError("activation trusted_uid is invalid")
    if path.stat().st_uid != uid or path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise LaunchError("activation record is not owned and protected by the trusted activation identity")
    gid = manifest["trusted_gid"]
    if not isinstance(gid, int) or gid < 0:
        raise LaunchError("activation trusted_gid is invalid")
    system_uid = manifest["trusted_system_uid"]
    if not isinstance(system_uid, int) or system_uid != 0:
        raise LaunchError("production trusted_system_uid must be root")
    native = _absolute_regular(manifest["native_launcher_path"], uid=uid, gid=gid, executable=True)
    parent_exe = Path(f"/proc/{os.getppid()}/exe").resolve(strict=True)
    if parent_exe != native or _sha256(native.read_bytes()) != manifest["native_launcher_sha256"]:
        raise LaunchError("Python stage was not started by the activated native launcher")
    release_root = _absolute_directory(manifest["release_root"], uid=uid, gid=gid, writable=False, system_uid=system_uid)
    if any((parent / ".git").exists() for parent in (release_root, *release_root.parents)):
        raise LaunchError("activated release must not be inside a Git tree")
    entries = verify_closed_tree(
        release_root,
        inventory_name=INVENTORY_NAME,
        expected_inventory_digest=manifest["inventory_digest"],
        expected_tree_digest=manifest["release_digest"],
        trusted_uid=uid,
        trusted_gid=gid,
        required_paths=REQUIRED_RELEASE_PATHS,
    )
    internal = release_root / "launcher/madctl-launcher.py"
    if Path(__file__).resolve(strict=True) != internal or _sha256(internal.read_bytes()) != entries["launcher/madctl-launcher.py"]["sha256"]:
        raise LaunchError("running Python launcher is outside the activated release")
    metadata_raw, metadata = _read_object(release_root / "release-metadata.json")
    if metadata != {"schema_version": 1, "name": "madctl", "version": manifest["expected_mad_version"]}:
        raise LaunchError("release metadata does not match activation record")
    if metadata_raw != _canonical(metadata) + b"\n":
        raise LaunchError("release metadata is not canonical")
    for field in ("state_root", "registry_root", "human_approval_registry_root", "cache_root", "codex_home"):
        _absolute_directory(manifest[field], uid=uid, gid=gid, writable=True, system_uid=system_uid)
    if manifest["human_approval_registry_root"] != manifest["registry_root"]:
        raise LaunchError("human approval registry must be the activated repository registry")
    _absolute_regular(manifest["controller_key_path"], uid=uid, gid=gid)
    python_root = _absolute_directory(manifest["python_runtime_root"], uid=uid, gid=gid, writable=False, system_uid=system_uid)
    if os.environ.get("LD_LIBRARY_PATH") != str(python_root / "lib"):
        raise LaunchError("trusted Python library path was not constructed by the native launcher")
    if os.environ.get("PYTHONHOME") != str(python_root):
        raise LaunchError("trusted Python home was not constructed by the native launcher")
    runtime_entries = verify_closed_tree(
        python_root, inventory_name=PYTHON_INVENTORY_NAME,
        expected_inventory_digest=manifest["python_runtime_inventory_digest"],
        expected_tree_digest=manifest["python_runtime_digest"], trusted_uid=uid, trusted_gid=gid,
        required_paths={"python-runtime.json", "python-runtime-input-lock.json"},
    )
    python = _absolute_regular(manifest["python_executable"], uid=uid, gid=gid, executable=True, root=python_root)
    if Path(sys.executable).resolve(strict=True) != python:
        raise LaunchError("running interpreter is not the activated Python executable")
    relative_python = python.relative_to(python_root).as_posix()
    if relative_python not in runtime_entries:
        raise LaunchError("Python executable is absent from the runtime inventory")
    metadata_raw, metadata = _read_object(python_root / "python-runtime.json")
    if metadata_raw != _canonical(metadata) + b"\n" or set(metadata) != {
        "schema_version", "python_executable", "import_paths", "required_distributions", "distribution_metadata", "closure",
        "elf_closure", "input_lock", "input_lock_sha256",
    } or metadata["schema_version"] != 1 or metadata["python_executable"] != relative_python:
        raise LaunchError("Python runtime metadata is malformed")
    required_distributions = {
        "cryptography": "41.0.7", "jsonschema": "4.10.3", "PyYAML": "6.0.1",
        "attrs": "23.2.0", "pyrsistent": "0.20.0", "cffi": "1.16.0", "pycparser": "2.21",
    }
    if metadata["required_distributions"] != required_distributions or metadata["closure"] != "interpreter-stdlib-site-packages-native-extensions-and-runtime-shared-objects":
        raise LaunchError("Python runtime dependency contract is incomplete")
    if metadata["input_lock"] != "python-runtime-input-lock.json":
        raise LaunchError("Python runtime input lock path is invalid")
    input_lock_raw, input_lock = _read_object(python_root / metadata["input_lock"])
    if (_sha256(input_lock_raw) != metadata["input_lock_sha256"]
            or runtime_entries[metadata["input_lock"]]["sha256"] != metadata["input_lock_sha256"]
            or set(input_lock) != {"schema_version", "python_executable", "import_paths", "site_packages", "runtime_files", "wheels"}
            or input_lock.get("schema_version") != 1
            or input_lock.get("python_executable") != relative_python
            or input_lock.get("import_paths") != metadata["import_paths"]
            or not isinstance(input_lock.get("runtime_files"), dict)
            or not isinstance(input_lock.get("wheels"), dict)
            or set(input_lock["wheels"]) != set(required_distributions)):
        raise LaunchError("Python runtime input lock is malformed or unbound")
    distribution_metadata = metadata["distribution_metadata"]
    if not isinstance(distribution_metadata, dict) or set(distribution_metadata) != set(required_distributions):
        raise LaunchError("Python runtime distribution metadata is incomplete")
    for name, record in distribution_metadata.items():
        if not isinstance(record, dict) or set(record) != {
            "version", "metadata", "metadata_sha256", "record", "record_sha256", "wheel_filename", "wheel_sha256",
        }:
            raise LaunchError("Python distribution metadata record is malformed")
        relative = record["metadata"]
        candidate = Path(relative) if isinstance(relative, str) else Path("/")
        if (record["version"] != required_distributions[name] or candidate.is_absolute() or ".." in candidate.parts
                or candidate.as_posix() not in runtime_entries
                or runtime_entries[candidate.as_posix()]["sha256"] != record["metadata_sha256"]):
            raise LaunchError("Python distribution metadata escaped the runtime inventory")
        record_path = Path(record["record"]) if isinstance(record["record"], str) else Path("/")
        wheel_lock = input_lock["wheels"].get(name)
        if (record_path.is_absolute() or ".." in record_path.parts
                or record_path.as_posix() not in runtime_entries
                or runtime_entries[record_path.as_posix()]["sha256"] != record["record_sha256"]
                or not isinstance(wheel_lock, dict)
                or wheel_lock != {"version": record["version"], "filename": record["wheel_filename"], "sha256": record["wheel_sha256"]}):
            raise LaunchError("Python wheel provenance escaped the trusted input lock")
    elf_closure = metadata["elf_closure"]
    if not isinstance(elf_closure, dict) or relative_python not in elf_closure:
        raise LaunchError("Python ELF closure is incomplete")
    for relative, record in elf_closure.items():
        if (relative not in runtime_entries or not isinstance(record, dict)
                or set(record) != {"sha256", "interpreter", "needed"}
                or record["sha256"] != runtime_entries[relative]["sha256"]
                or not isinstance(record["needed"], dict)):
            raise LaunchError("Python ELF closure record is malformed")
        referenced = [record["interpreter"], *record["needed"].values()]
        if any(value is not None and value not in runtime_entries for value in referenced):
            raise LaunchError("Python ELF closure references an unbound runtime file")
    import_paths: list[str] = []
    if not isinstance(metadata["import_paths"], list) or not metadata["import_paths"]:
        raise LaunchError("Python runtime import paths are missing")
    for relative in metadata["import_paths"]:
        candidate = Path(relative) if isinstance(relative, str) else Path("/")
        path_value = (python_root / candidate).resolve(strict=True)
        if candidate.is_absolute() or ".." in candidate.parts or not path_value.is_dir() or not _inside(path_value, python_root):
            raise LaunchError("Python runtime import path escapes its closed root")
        import_paths.append(str(path_value))
    tools = manifest["tools"]
    if not isinstance(tools, dict) or set(tools) != {"git", "gh", "python3", "codex", "bwrap"}:
        raise LaunchError("trusted tool inventory is malformed")
    for name, record in tools.items():
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "uid", "gid", "root"}:
            raise LaunchError(f"trusted tool record is malformed: {name}")
        if record["uid"] != uid or record["gid"] != gid:
            raise LaunchError(f"trusted tool identity differs from activation authority: {name}")
        tool_root = _absolute_directory(record["root"], uid=uid, gid=gid, writable=False, system_uid=system_uid)
        tool = _absolute_regular(record["path"], uid=uid, gid=gid, executable=True, root=tool_root)
        if _sha256(tool.read_bytes()) != record["sha256"]:
            raise LaunchError(f"trusted tool digest mismatch: {name}")
        if name == "python3" and tool != python:
            raise LaunchError("trusted python3 tool must be the activated Python runtime executable")
    return manifest, entries, runtime_entries, import_paths


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _verify_loaded_modules(root: Path, entries: dict[str, dict[str, str]]) -> None:
    package_root = root / "python" / "madctl"
    for name, module in tuple(sys.modules.items()):
        if name != "madctl" and not name.startswith("madctl."):
            continue
        origin = getattr(module, "__file__", None)
        if not origin:
            raise LaunchError(f"loaded MAD module has no regular origin: {name}")
        path = Path(origin).resolve(strict=True)
        if not _inside(path, package_root) or path.is_symlink():
            raise LaunchError(f"loaded MAD module escaped activated release: {name}: {path}")
        relative = path.relative_to(root).as_posix()
        record = entries.get(relative)
        if record is None or _sha256(path.read_bytes()) != record["sha256"]:
            raise LaunchError(f"loaded MAD module is not inventory-bound: {name}")


def _verify_loaded_runtime_modules(release_root: Path, runtime_root: Path, runtime_entries: dict[str, dict[str, str]]) -> None:
    for name, module in tuple(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        if not origin:
            continue
        path = Path(origin).resolve(strict=True)
        if _inside(path, release_root):
            continue
        if not _inside(path, runtime_root) or path.is_symlink():
            raise LaunchError(f"loaded Python module escaped activated roots: {name}: {path}")
        relative = path.relative_to(runtime_root).as_posix()
        record = runtime_entries.get(relative)
        if record is None or _sha256(path.read_bytes()) != record["sha256"]:
            raise LaunchError(f"loaded Python module is not runtime-inventory-bound: {name}")


def _verify_native_mappings(release_root: Path, runtime_root: Path, runtime_entries: dict[str, dict[str, str]]) -> None:
    """Reject an interpreter or extension that mapped code outside the closed roots."""
    for line in Path("/proc/self/maps").read_text(encoding="utf-8").splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or not fields[5].startswith("/"):
            continue
        path = Path(fields[5].removesuffix(" (deleted)")).resolve(strict=True)
        if _inside(path, release_root):
            continue
        if not _inside(path, runtime_root):
            raise LaunchError(f"native Python mapping escaped activated runtime: {path}")
        relative = path.relative_to(runtime_root).as_posix()
        record = runtime_entries.get(relative)
        if record is None or _sha256(path.read_bytes()) != record["sha256"]:
            raise LaunchError(f"native Python mapping is not runtime-inventory-bound: {relative}")


def main() -> int:
    try:
        if len(sys.argv) < 3 or sys.argv[1] != "--mad-active-record":
            raise LaunchError("Python launcher may only be entered by the native launcher")
        activation_path = Path(sys.argv[2])
        if not activation_path.is_absolute():
            raise LaunchError("activation record path is not absolute")
        del sys.argv[1:3]
        if any(name == "madctl" or name.startswith("madctl.") for name in sys.modules):
            raise LaunchError("MAD package was imported before release verification")
        manifest, entries, runtime_entries, import_paths = verify_activation(activation_path)
        release_root = Path(manifest["release_root"])
        runtime_root = Path(manifest["python_runtime_root"])
        release_python = release_root / "python"
        sys.path[:] = [str(release_python), *import_paths]
        importlib.invalidate_caches()
        _verify_native_mappings(release_root, runtime_root, runtime_entries)
        activation = importlib.import_module("madctl.activation")
        _verify_loaded_modules(release_root, entries)
        _verify_loaded_runtime_modules(release_root, runtime_root, runtime_entries)
        _verify_native_mappings(release_root, runtime_root, runtime_entries)
        activation._install_verified_activation(manifest, entries, str(Path(__file__).resolve()))
        cli = importlib.import_module("madctl.cli")
        _verify_loaded_modules(release_root, entries)
        _verify_loaded_runtime_modules(release_root, runtime_root, runtime_entries)
        result = int(cli.main())
        _verify_loaded_modules(release_root, entries)
        _verify_loaded_runtime_modules(release_root, runtime_root, runtime_entries)
        return result
    except (LaunchError, OSError, ValueError, KeyError) as exc:
        print(f"madctl-launcher: {exc}", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
