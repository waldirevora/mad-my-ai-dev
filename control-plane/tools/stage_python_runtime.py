#!/usr/bin/env python3
"""Stage and inventory a preassembled, hermetic MAD Python runtime.

The input is an installation-shaped tree.  It must already contain the Python
interpreter, standard library, third-party dependencies, native extensions and
their runtime libraries.  This tool never resolves packages from the network or
from the invoking Python installation.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import re
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


EPOCH = max(315532800, int(os.environ.get("SOURCE_DATE_EPOCH", "315532800")))
INVENTORY = "python-runtime-files.json"
METADATA = "python-runtime.json"
INPUT_LOCK = "python-runtime-input-lock.json"
REQUIRED_DISTRIBUTIONS = {
    "cryptography": "41.0.7",
    "jsonschema": "4.10.3",
    "PyYAML": "6.0.1",
    "attrs": "23.2.0",
    "pyrsistent": "0.20.0",
    "cffi": "1.16.0",
    "pycparser": "2.21",
}
REQUIRED_DEPENDENCIES = {
    "cryptography": {"cffi"},
    "jsonschema": {"attrs", "pyrsistent"},
    "PyYAML": set(),
    "attrs": set(),
    "pyrsistent": set(),
    "cffi": {"pycparser"},
    "pycparser": set(),
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _relative(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise RuntimeError(f"runtime path must be a normalized relative path: {value!r}")
    return path.as_posix()


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "_", value).lower()


def _safe_archive_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or "\\" in value or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise RuntimeError(f"wheel path must be normalized and contained: {value!r}")
    return path.as_posix()


def _record_rows(raw: bytes, *, label: str) -> dict[str, tuple[str, str]]:
    try:
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8", "strict"), newline="")))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise RuntimeError(f"malformed wheel RECORD: {label}") from exc
    result: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3:
            raise RuntimeError(f"malformed wheel RECORD row: {label}")
        relative = _safe_archive_path(row[0])
        if relative in result:
            raise RuntimeError(f"duplicate wheel RECORD ownership: {relative}")
        result[relative] = (row[1], row[2])
    return result


def _verify_record_entry(relative: str, raw: bytes, record: tuple[str, str], *, record_path: str) -> None:
    hash_field, size_field = record
    if relative == record_path:
        if hash_field or size_field:
            raise RuntimeError("wheel RECORD must not self-hash")
        return
    if not hash_field.startswith("sha256=") or not size_field.isdecimal() or int(size_field) != len(raw):
        raise RuntimeError(f"wheel RECORD size or algorithm mismatch: {relative}")
    encoded = hash_field.split("=", 1)[1]
    try:
        expected = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except ValueError as exc:
        raise RuntimeError(f"wheel RECORD hash is malformed: {relative}") from exc
    if expected != hashlib.sha256(raw).digest():
        raise RuntimeError(f"wheel RECORD hash mismatch: {relative}")


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _read_regular_snapshot(path: Path, *, label: str) -> tuple[bytes, tuple[int, ...]]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"cannot open trusted input as a regular file: {label}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"trusted input is not a regular file: {label}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(after):
            raise RuntimeError(f"trusted input changed while being read: {label}")
    finally:
        os.close(descriptor)
    try:
        pathname = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"trusted input disappeared after reading: {label}") from exc
    if stat.S_ISLNK(pathname.st_mode) or _file_identity(pathname) != _file_identity(after):
        raise RuntimeError(f"trusted input pathname changed while being read: {label}")
    return b"".join(chunks), _file_identity(after)


def _parse_wheel_bytes(raw: bytes, *, filename: str) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                relative = _safe_archive_path(info.filename)
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK or relative in members:
                    raise RuntimeError(f"unsafe or duplicate wheel member: {relative}")
                members[relative] = archive.read(info)
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"trusted wheel is not a valid archive: {filename}") from exc
    return members


def _verify_snapshot_unchanged(path: Path, identity: tuple[int, ...], expected_sha256: str, *, label: str) -> None:
    raw, final_identity = _read_regular_snapshot(path, label=label)
    if final_identity != identity or digest(raw) != expected_sha256:
        raise RuntimeError(f"trusted input changed after approval verification: {label}")


def _verify_input_lock(
    source: Path, *, executable: str, import_paths: list[str], input_lock: Path, wheelhouse: Path,
) -> tuple[bytes, dict[str, dict[str, str]], dict[str, Any]]:
    lock_path = input_lock.resolve(strict=True)
    if input_lock.is_symlink() or not lock_path.is_file():
        raise RuntimeError("trusted Python input lock must be a regular non-symlink file")
    raw, _ = _read_regular_snapshot(lock_path, label="Python input lock")
    try:
        lock = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("trusted Python input lock is malformed") from exc
    if raw != canonical(lock) + b"\n" or not isinstance(lock, dict) or set(lock) != {
        "schema_version", "python_executable", "import_paths", "site_packages", "runtime_files", "wheels",
    } or lock["schema_version"] != 1 or lock["python_executable"] != executable or lock["import_paths"] != import_paths:
        raise RuntimeError("trusted Python input lock contract is invalid")
    site_relative = _relative(lock["site_packages"])
    if site_relative not in import_paths:
        raise RuntimeError("trusted Python input lock site-packages is not an import path")
    runtime_files = lock["runtime_files"]
    if not isinstance(runtime_files, dict):
        raise RuntimeError("trusted runtime input file lock is malformed")
    actual_runtime: dict[str, str] = {}
    site_root = source / site_relative
    for path in sorted(item for item in source.rglob("*") if item.is_file()):
        try:
            path.relative_to(site_root)
        except ValueError:
            actual_runtime[path.relative_to(source).as_posix()] = digest(path.read_bytes())
    if runtime_files != actual_runtime:
        raise RuntimeError("interpreter or standard runtime inputs differ from trusted input lock")
    wheels = lock["wheels"]
    if not isinstance(wheels, dict) or set(wheels) != set(REQUIRED_DISTRIBUTIONS):
        raise RuntimeError("trusted wheel lock does not contain the exact dependency closure")
    wheel_root = wheelhouse.resolve(strict=True)
    if wheelhouse.is_symlink() or not wheel_root.is_dir():
        raise RuntimeError("trusted wheelhouse must be a canonical non-symlink directory")
    owned: dict[str, str] = {}
    provenance: dict[str, dict[str, str]] = {}
    packages: dict[str, dict[str, Any]] = {}
    wheel_snapshots: list[tuple[Path, tuple[int, ...], str, str]] = []
    expected_site_files: set[str] = set()
    for name, expected_version in REQUIRED_DISTRIBUTIONS.items():
        item = wheels[name]
        if not isinstance(item, dict) or set(item) != {"version", "filename", "sha256"} or item["version"] != expected_version:
            raise RuntimeError(f"trusted wheel lock entry is malformed: {name}")
        filename = item["filename"]
        if not isinstance(filename, str) or PurePosixPath(filename).name != filename:
            raise RuntimeError(f"trusted wheel filename is unsafe: {name}")
        wheel = wheel_root / filename
        wheel_raw, wheel_identity = _read_regular_snapshot(wheel, label=f"wheel {name}")
        if digest(wheel_raw) != item["sha256"]:
            raise RuntimeError(f"trusted wheel artifact hash mismatch: {name}")
        members = _parse_wheel_bytes(wheel_raw, filename=filename)
        metadata_paths = [path for path in members if path.endswith(".dist-info/METADATA")]
        record_paths = [path for path in members if path.endswith(".dist-info/RECORD")]
        if len(metadata_paths) != 1 or len(record_paths) != 1 or metadata_paths[0].rsplit("/", 1)[0] != record_paths[0].rsplit("/", 1)[0]:
            raise RuntimeError(f"wheel lacks a unique METADATA/RECORD pair: {name}")
        metadata_text = members[metadata_paths[0]].decode("utf-8", "strict")
        metadata_name = metadata_version = None
        for line in metadata_text.splitlines():
            if line.startswith("Name: ") and metadata_name is None: metadata_name = line[6:]
            if line.startswith("Version: ") and metadata_version is None: metadata_version = line[9:]
            if not line: break
        if _normalized_name(metadata_name or "") != _normalized_name(name) or metadata_version != expected_version:
            raise RuntimeError(f"wheel identity differs from trusted lock: {name}")
        records = _record_rows(members[record_paths[0]], label=filename)
        if set(records) != set(members):
            raise RuntimeError(f"wheel RECORD is incomplete or contains unknown paths: {name}")
        for relative, member_raw in members.items():
            _verify_record_entry(relative, member_raw, records[relative], record_path=record_paths[0])
            if relative in owned:
                raise RuntimeError(f"wheel file has multiple owners: {relative}")
            installed = site_root / relative
            if installed.is_symlink() or not installed.is_file() or installed.read_bytes() != member_raw:
                raise RuntimeError(f"installed package file differs from trusted wheel: {relative}")
            owned[relative] = name
            expected_site_files.add(relative)
        installed_record = site_root / record_paths[0]
        installed_rows = _record_rows(installed_record.read_bytes(), label=str(installed_record))
        if set(installed_rows) != set(members):
            raise RuntimeError(f"installed RECORD is incomplete: {name}")
        for relative, record in installed_rows.items():
            _verify_record_entry(relative, (site_root / relative).read_bytes(), record, record_path=record_paths[0])
        provenance[name] = {
            "record": f"{site_relative}/{record_paths[0]}",
            "record_sha256": digest(members[record_paths[0]]),
            "wheel_filename": filename,
            "wheel_sha256": item["sha256"],
        }
        packages[name] = {"members": members, "records": records, "record_path": record_paths[0]}
        wheel_snapshots.append((wheel, wheel_identity, item["sha256"], name))
    actual_site_files = {
        path.relative_to(site_root).as_posix() for path in site_root.rglob("*") if path.is_file()
    }
    if actual_site_files != expected_site_files:
        raise RuntimeError("site-packages contains unowned or missing files")
    return raw, provenance, {
        "lock": lock,
        "site_relative": site_relative,
        "packages": packages,
        "wheel_snapshots": wheel_snapshots,
    }


def _copy_source_tree(source: Path, target: Path) -> None:
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        destination = target / relative
        item_info = item.lstat()
        if stat.S_ISLNK(item_info.st_mode):
            raise RuntimeError(f"runtime source contains a symlink: {relative}")
        if stat.S_ISDIR(item_info.st_mode):
            destination.mkdir(mode=0o755)
        elif stat.S_ISREG(item_info.st_mode):
            raw, identity = _read_regular_snapshot(item, label=f"runtime source {relative.as_posix()}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            mode = 0o555 if stat.S_IMODE(identity[2]) & 0o111 else 0o444
            os.chmod(destination, mode)
            os.utime(destination, (EPOCH, EPOCH), follow_symlinks=False)
        else:
            raise RuntimeError(f"runtime source contains a non-regular object: {relative}")


def _verify_wheel_snapshots(approved: dict[str, Any]) -> None:
    for path, identity, expected_sha256, name in approved["wheel_snapshots"]:
        _verify_snapshot_unchanged(path, identity, expected_sha256, label=f"wheel {name}")


def _verify_staged_inputs(root: Path, approved: dict[str, Any], input_lock_raw: bytes) -> None:
    """Revalidate the private output against held wheel bytes and the approved lock."""
    expected_uid, expected_gid = os.geteuid(), os.getegid()
    site_root = root / approved["site_relative"]
    if site_root.is_symlink() or not site_root.is_dir():
        raise RuntimeError("final staged site-packages directory is missing")

    actual_site: dict[str, bytes] = {}
    actual_runtime: dict[str, str] = {}
    lock_seen = False
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"private staged runtime contains a symlink: {relative}")
        if info.st_uid != expected_uid or info.st_gid != expected_gid:
            raise RuntimeError(f"private staged runtime has unexpected ownership: {relative}")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise RuntimeError(f"private staged runtime is group/world writable: {relative}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"private staged runtime contains a non-regular object: {relative}")
        raw = path.read_bytes()
        try:
            package_relative = path.relative_to(site_root).as_posix()
        except ValueError:
            if relative == INPUT_LOCK:
                if raw != input_lock_raw:
                    raise RuntimeError("final staged input lock differs from approved bytes")
                lock_seen = True
            elif relative == METADATA:
                pass
            elif relative == INVENTORY:
                raise RuntimeError("runtime inventory exists before final verification")
            else:
                actual_runtime[relative] = digest(raw)
        else:
            actual_site[package_relative] = raw

    if not lock_seen:
        raise RuntimeError("final staged input lock is missing")
    if actual_runtime != approved["lock"]["runtime_files"]:
        raise RuntimeError("final staged interpreter or standard runtime differs from trusted input lock")

    expected_site: dict[str, tuple[str, bytes, tuple[str, str], str]] = {}
    for name, package in approved["packages"].items():
        members = package["members"]
        records = package["records"]
        record_path = package["record_path"]
        for relative, raw in members.items():
            if relative in expected_site:
                raise RuntimeError(f"final staged wheel file has multiple owners: {relative}")
            expected_site[relative] = (name, raw, records[relative], record_path)
    if set(actual_site) != set(expected_site):
        raise RuntimeError("final staged site-packages contains unowned or missing files")
    for relative, actual_raw in actual_site.items():
        _, expected_raw, record, record_path = expected_site[relative]
        if actual_raw != expected_raw:
            raise RuntimeError(f"final staged package file differs from approved wheel: {relative}")
        _verify_record_entry(relative, actual_raw, record, record_path=record_path)
    _verify_wheel_snapshots(approved)


def _discard_private_tree(path: Path) -> None:
    if not path.exists():
        return
    for item in [path, *path.rglob("*")]:
        if not item.is_symlink():
            try:
                os.chmod(item, 0o700 if item.is_dir() else 0o600)
            except FileNotFoundError:
                pass
    shutil.rmtree(path, ignore_errors=True)


def _distribution_metadata(source: Path, import_paths: list[str], provenance: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    expected = {_normalized_name(name): (name, version) for name, version in REQUIRED_DISTRIBUTIONS.items()}
    for import_path in import_paths:
        base = source / import_path
        if not base.is_dir() or base.is_symlink():
            raise RuntimeError(f"runtime import directory is missing: {import_path}")
        metadata_files = [*base.glob("*.dist-info/METADATA"), *base.glob("*.egg-info/PKG-INFO")]
        for metadata in sorted(metadata_files):
            if metadata.is_symlink() or not metadata.is_file():
                raise RuntimeError(f"distribution metadata is not a regular file: {metadata}")
            raw = metadata.read_bytes()
            headers: dict[str, str] = {}
            requirements: list[str] = []
            for line in raw.decode("utf-8").splitlines():
                if not line: break
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers.setdefault(key, value)
                    if key == "Requires-Dist":
                        requirements.append(value)
            normalized = _normalized_name(headers.get("Name", ""))
            if normalized not in expected:
                raise RuntimeError(f"unexpected distribution in closed runtime: {headers.get('Name', metadata.parent.name)}")
            canonical_name, version = expected[normalized]
            if headers.get("Version") != version or canonical_name in found:
                raise RuntimeError(f"wrong or duplicate required distribution: {canonical_name}")
            active_dependencies: set[str] = set()
            for requirement in requirements:
                requirement_text, _, marker = requirement.partition(";")
                if "extra" in marker or re.search(r"python_version\s*<\s*['\"]3\.(?:8|9)['\"]", marker):
                    continue
                match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement_text)
                if not match:
                    raise RuntimeError(f"cannot parse dependency metadata for {canonical_name}: {requirement}")
                dependency_normalized = _normalized_name(match.group(1))
                dependency = expected.get(dependency_normalized)
                if dependency is None:
                    raise RuntimeError(f"untrusted transitive dependency for {canonical_name}: {match.group(1)}")
                active_dependencies.add(dependency[0])
            if active_dependencies != REQUIRED_DEPENDENCIES[canonical_name]:
                raise RuntimeError(
                    f"dependency closure mismatch for {canonical_name}: "
                    f"expected={sorted(REQUIRED_DEPENDENCIES[canonical_name])}, actual={sorted(active_dependencies)}"
                )
            found[canonical_name] = {
                "version": version,
                "metadata": metadata.relative_to(source).as_posix(),
                "metadata_sha256": digest(raw),
                **provenance[canonical_name],
            }
    missing = set(REQUIRED_DISTRIBUTIONS) - set(found)
    if missing:
        raise RuntimeError(f"runtime lacks required distribution metadata: {sorted(missing)}")
    return found


def _audit_elf_closure(root: Path, *, activated_root: Path | None = None) -> dict[str, dict[str, Any]]:
    """Inspect, but never execute, ELF inputs and require an in-tree loader/library closure."""
    activation_root = root if activated_root is None else activated_root

    def staged_path_for_activated(path: Path) -> Path:
        if not path.is_absolute():
            raise RuntimeError("ELF loader path is not absolute")
        try:
            relative = path.relative_to(activation_root)
        except ValueError as exc:
            raise RuntimeError("ELF loader path escapes the activated runtime") from exc
        if ".." in relative.parts:
            raise RuntimeError("ELF loader path escapes the activated runtime")
        staged = root / relative
        try:
            staged.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise RuntimeError("ELF loader path is absent from the staged runtime") from exc
        return staged

    library_root = root / "lib"
    if not library_root.is_dir():
        raise RuntimeError("runtime must provide its trusted shared objects under lib/")
    libraries: dict[str, Path] = {}
    for path in sorted(item for item in library_root.rglob("*") if item.is_file()):
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                continue
        if path.name in libraries:
            raise RuntimeError(f"duplicate runtime library basename: {path.name}")
        libraries[path.name] = path
    closure: dict[str, dict[str, Any]] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic != b"\x7fELF":
            continue
        program = subprocess.run(
            ["/usr/bin/readelf", "-lW", str(path)], env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        dynamic = subprocess.run(
            ["/usr/bin/readelf", "-dW", str(path)], env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        if program.returncode or dynamic.returncode:
            raise RuntimeError(f"cannot inspect runtime ELF file: {path.relative_to(root)}")
        interpreter_relative: str | None = None
        for line in program.stdout.splitlines():
            marker = "Requesting program interpreter: "
            if marker in line:
                interpreter = Path(line.split(marker, 1)[1].rstrip("]"))
                try:
                    interpreter_relative = staged_path_for_activated(interpreter).relative_to(root).as_posix()
                except RuntimeError as exc:
                    raise RuntimeError(f"ELF interpreter escapes trusted runtime: {path.relative_to(root)}") from exc
        needed_files: dict[str, str] = {}
        for line in dynamic.stdout.splitlines():
            if any(tag in line for tag in ("(AUDIT)", "(DEPAUDIT)", "(FILTER)", "(AUXILIARY)")):
                raise RuntimeError(f"unsafe dynamic loader directive: {path.relative_to(root)}")
            if "(NEEDED)" in line and "[" in line:
                needed = line.split("[", 1)[1].split("]", 1)[0]
                if PurePosixPath(needed).name != needed or needed not in libraries:
                    raise RuntimeError(f"ELF dependency is absent from runtime lib/: {needed} ({path.relative_to(root)})")
                needed_files[needed] = libraries[needed].relative_to(root).as_posix()
            if any(tag in line for tag in ("(RPATH)", "(RUNPATH)")) and "[" in line:
                for value in line.split("[", 1)[1].split("]", 1)[0].split(":"):
                    expanded = value.replace("${ORIGIN}", str(path.parent)).replace("$ORIGIN", str(path.parent))
                    if not value or "$" in expanded:
                        raise RuntimeError(f"unsafe ELF search path: {path.relative_to(root)}")
                    search = Path(expanded)
                    if not search.is_absolute():
                        raise RuntimeError(f"relative ELF search path is forbidden: {path.relative_to(root)}")
                    try:
                        search.resolve(strict=True).relative_to(root)
                    except (OSError, ValueError):
                        try:
                            staged_path_for_activated(search)
                        except RuntimeError as exc:
                            raise RuntimeError(f"ELF search path escapes trusted runtime: {path.relative_to(root)}") from exc
        closure[path.relative_to(root).as_posix()] = {
            "sha256": digest(path.read_bytes()),
            "interpreter": interpreter_relative,
            "needed": needed_files,
        }
    return closure


def stage(
    source: Path, target: Path, *, executable: str, import_paths: list[str], input_lock: Path, wheelhouse: Path,
) -> dict[str, str]:
    source = source.resolve(strict=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    target = target.parent.resolve(strict=True) / target.name
    if os.path.lexists(target):
        raise RuntimeError(f"runtime destination already exists: {target}")
    executable = _relative(executable)
    imports = [_relative(value) for value in import_paths]
    if len(imports) != len(set(imports)) or not imports:
        raise RuntimeError("runtime import paths must be a nonempty unique list")
    if any(os.path.lexists(source / name) for name in (INVENTORY, METADATA, INPUT_LOCK)):
        raise RuntimeError("runtime source must not contain generated metadata")
    source_python = source / executable
    if source_python.is_symlink() or not source_python.is_file() or not stat.S_IMODE(source_python.stat().st_mode) & 0o111:
        raise RuntimeError("source Python executable is missing, symlinked, or not executable")
    input_lock_raw, provenance, approved = _verify_input_lock(
        source, executable=executable, import_paths=imports, input_lock=input_lock, wheelhouse=wheelhouse,
    )
    private = Path(tempfile.mkdtemp(prefix=f".{target.name}.stage-", dir=target.parent))
    os.chmod(private, 0o700)
    published = False
    try:
        _copy_source_tree(source, private)
        lock_target = private / INPUT_LOCK
        lock_target.write_bytes(input_lock_raw)
        os.chmod(lock_target, 0o444)
        os.utime(lock_target, (EPOCH, EPOCH), follow_symlinks=False)
        _verify_staged_inputs(private, approved, input_lock_raw)

        python = private / executable
        if not python.is_file() or not stat.S_IMODE(python.stat().st_mode) & 0o111:
            raise RuntimeError("staged Python executable is missing or not executable")
        for relative in imports:
            path = private / relative
            if not path.is_dir() or path.is_symlink():
                raise RuntimeError(f"runtime import directory is missing: {relative}")
        distribution_metadata = _distribution_metadata(private, imports, provenance)
        metadata = {
            "schema_version": 1,
            "python_executable": executable,
            "import_paths": imports,
            "required_distributions": REQUIRED_DISTRIBUTIONS,
            "distribution_metadata": distribution_metadata,
            "input_lock": INPUT_LOCK,
            "input_lock_sha256": digest(input_lock_raw),
            "closure": "interpreter-stdlib-site-packages-native-extensions-and-runtime-shared-objects",
            "elf_closure": _audit_elf_closure(private, activated_root=target),
        }
        metadata_raw = canonical(metadata) + b"\n"
        (private / METADATA).write_bytes(metadata_raw)
        os.chmod(private / METADATA, 0o444)
        os.utime(private / METADATA, (EPOCH, EPOCH), follow_symlinks=False)

        _verify_staged_inputs(private, approved, input_lock_raw)
        entries: dict[str, dict[str, str]] = {}
        for path in sorted(item for item in private.rglob("*") if item.is_file()):
            relative = path.relative_to(private).as_posix()
            entries[relative] = {
                "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
                "sha256": digest(path.read_bytes()),
            }
        inventory_raw = canonical({"schema_version": 1, "files": entries}) + b"\n"
        (private / INVENTORY).write_bytes(inventory_raw)
        os.chmod(private / INVENTORY, 0o444)
        os.utime(private / INVENTORY, (EPOCH, EPOCH), follow_symlinks=False)
        for directory in sorted((item for item in private.rglob("*") if item.is_dir()), reverse=True):
            os.chmod(directory, 0o555)
            os.utime(directory, (EPOCH, EPOCH), follow_symlinks=False)
        os.chmod(private, 0o555)
        os.utime(private, (EPOCH, EPOCH), follow_symlinks=False)
        if os.path.lexists(target):
            raise RuntimeError(f"runtime destination appeared before publication: {target}")
        os.rename(private, target)
        published = True
        return {"digest": digest(canonical(entries)), "inventory_digest": digest(inventory_raw)}
    finally:
        if not published:
            _discard_private_tree(private)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--python-executable", required=True)
    parser.add_argument("--import-path", action="append", required=True)
    parser.add_argument("--input-lock", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    args = parser.parse_args()
    result = stage(
        args.source, args.target, executable=args.python_executable, import_paths=args.import_path,
        input_lock=args.input_lock, wheelhouse=args.wheelhouse,
    )
    print(canonical(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
