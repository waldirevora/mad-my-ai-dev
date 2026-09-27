from __future__ import annotations

import base64
import csv
import hashlib
import io
import importlib.util
import importlib.machinery
import json
import os
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from madctl.errors import AuthorityError
from madctl.gitops import TrustedTool
from madctl.inventory import verify_closed_inventory
from madctl.orka import ORKA_INVENTORY, REQUIRED_RUNTIME_FILES, OrkaRuntime


ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "control-plane"


def load_tool(name: str):
    path = CONTROL / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"mad_test_{name}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILD = load_tool("build_release")
STAGE_ORKA = load_tool("stage_orka")
BUILD_WHEEL = load_tool("build_wheel")
BUILD_LAUNCHER = load_tool("build_launcher")
STAGE_PYTHON = load_tool("stage_python_runtime")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


WHEEL_PACKAGES = {
    "cryptography": {"cryptography"}, "jsonschema": {"jsonschema"}, "PyYAML": {"yaml"},
    "attrs": {"attrs"}, "pyrsistent": {"pyrsistent"}, "cffi": {"cffi"}, "pycparser": {"pycparser"},
}

APPROVED_CP311_X86_64_WHEELS = {
    "cryptography": {"version": "41.0.7", "filename": "cryptography-41.0.7-cp37-abi3-manylinux_2_28_x86_64.whl", "sha256": "43f2552a2378b44869fe8827aa19e69512e3245a219104438692385b0ee119d1"},
    "jsonschema": {"version": "4.10.3", "filename": "jsonschema-4.10.3-py3-none-any.whl", "sha256": "443442f9ac2fdfde7bc99079f0ba08e5d167fc67749e9fc706a393bc8857ca48"},
    "PyYAML": {"version": "6.0.1", "filename": "PyYAML-6.0.1-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "sha256": "d2b04aac4d386b172d5b9692e2d2da8de7bfb6c387fa4f801fbf6fb2e6ba4673"},
    "attrs": {"version": "23.2.0", "filename": "attrs-23.2.0-py3-none-any.whl", "sha256": "99b87a485a5820b23b879f04c2305b44b951b502fd64be915879d77a7e8fc6f1"},
    "pyrsistent": {"version": "0.20.0", "filename": "pyrsistent-0.20.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "sha256": "cae40a9e3ce178415040a0383f00e8d68b569e97f31928a3a8ad37e3fde6df6a"},
    "cffi": {"version": "1.16.0", "filename": "cffi-1.16.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "sha256": "7b78010e7b97fef4bee1e896df8a4bbb6712b7f05b7ef630f9d1da00f6444d2e"},
    "pycparser": {"version": "2.21", "filename": "pycparser-2.21-py2.py3-none-any.whl", "sha256": "8ee45429555515e1f6b185e78100aea234072576aa43ab53aefcae078162fca9"},
}


def _record_line(relative: str, raw: bytes) -> list[str]:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode("ascii")
    return [relative, f"sha256={encoded}", str(len(raw))]


def make_python_input_lock(
    source: Path, *, executable: str, import_paths: list[str], site_relative: str = "lib/python/site-packages",
) -> tuple[Path, Path]:
    """Create test-fixture trust inputs before mutation; production never derives its own approval lock."""
    site = source / site_relative
    wheelhouse = source.parent / f"{source.name}-wheelhouse"
    wheelhouse.mkdir()
    wheels: dict[str, dict[str, str]] = {}
    claimed: set[str] = set()
    for name, version in STAGE_PYTHON.REQUIRED_DISTRIBUTIONS.items():
        metadata_matches = []
        for metadata in site.glob("*.dist-info/METADATA"):
            text = metadata.read_text(encoding="utf-8")
            if f"Name: {name}\n" in text:
                metadata_matches.append(metadata)
        if len(metadata_matches) != 1:
            raise AssertionError(f"fixture lacks unique metadata for {name}")
        metadata_dir = metadata_matches[0].parent
        members = {
            path.relative_to(site).as_posix(): path.read_bytes()
            for path in site.rglob("*")
            if path.is_file() and (path.parent == metadata_dir or path.relative_to(site).parts[0] in WHEEL_PACKAGES[name])
        }
        record_relative = f"{metadata_dir.name}/RECORD"
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        for relative, raw in sorted(members.items()):
            writer.writerow(_record_line(relative, raw))
        writer.writerow([record_relative, "", ""])
        record_raw = output.getvalue().encode("utf-8")
        (site / record_relative).write_bytes(record_raw)
        members[record_relative] = record_raw
        filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        wheel = wheelhouse / filename
        with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_STORED) as archive:
            for relative, raw in sorted(members.items()):
                info = zipfile.ZipInfo(relative, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100444 << 16
                archive.writestr(info, raw, compress_type=zipfile.ZIP_STORED)
        wheels[name] = {"version": version, "filename": filename, "sha256": sha(wheel)}
        overlap = claimed & set(members)
        if overlap:
            raise AssertionError(f"fixture wheel ownership overlaps: {sorted(overlap)}")
        claimed.update(members)
    actual_site = {path.relative_to(site).as_posix() for path in site.rglob("*") if path.is_file()}
    if actual_site != claimed:
        raise AssertionError(f"fixture contains unowned site files: {sorted(actual_site - claimed)}")
    runtime_files = {}
    for path in sorted(item for item in source.rglob("*") if item.is_file()):
        try:
            path.relative_to(site)
        except ValueError:
            runtime_files[path.relative_to(source).as_posix()] = sha(path)
    lock = {
        "schema_version": 1, "python_executable": executable, "import_paths": import_paths,
        "site_packages": site_relative, "runtime_files": runtime_files, "wheels": wheels,
    }
    lock_path = source.parent / f"{source.name}-input-lock.json"
    lock_path.write_bytes(STAGE_PYTHON.canonical(lock) + b"\n")
    return lock_path, wheelhouse


def stage_python_fixture(
    source: Path, target: Path, *, executable: str, import_paths: list[str],
) -> dict[str, str]:
    input_lock, wheelhouse = make_python_input_lock(source, executable=executable, import_paths=import_paths)
    return STAGE_PYTHON.stage(
        source, target, executable=executable, import_paths=import_paths,
        input_lock=input_lock, wheelhouse=wheelhouse,
    )


def make_writable(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    for item in [path, *path.rglob("*")]:
        if not item.is_symlink():
            try:
                os.chmod(item, 0o700 if item.is_dir() else 0o600)
            except FileNotFoundError:
                pass


class ClosedReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="mad-release-test-"))
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        make_writable(self.root)
        shutil.rmtree(self.root, ignore_errors=True)

    def _build(self, name: str) -> tuple[Path, dict[str, str]]:
        release = self.root / name
        result = BUILD.build_release(ROOT, release)
        return release, result

    def _verify(self, release: Path, result: dict[str, str]) -> None:
        verify_closed_inventory(
            release,
            inventory_name="release-files.json",
            expected_inventory_digest=result["inventory_digest"],
            expected_tree_digest=result["release_digest"],
            trusted_uid=os.getuid(),
            required_paths={
                "python/madctl/__init__.py", "python/madctl/cli.py", "schemas/challenge.schema.json",
                "sandbox-profile.json", "genesis-policy.json", "genesis-config.yaml",
                "control-plane.lock.json", "release-metadata.json", "launcher/madctl-launcher.py",
                "launcher/madctl-launcher.c",
            },
        )

    def test_release_and_archive_are_reproducible_and_complete(self) -> None:
        source_a = self.root / "source-a"
        source_b = self.root / "source-b"
        shutil.copytree(ROOT, source_a, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "build", "dist", "*.egg-info"))
        shutil.copytree(ROOT, source_b, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "build", "dist", "*.egg-info"))
        release_a = self.root / "release-a"
        release_b = self.root / "release-b"
        result_a = BUILD.build_release(source_a, release_a)
        result_b = BUILD.build_release(source_b, release_b)
        archive_a = self.root / "a.zip"
        archive_b = self.root / "b.zip"
        artifact_a = BUILD.build_zip(release_a, archive_a)
        artifact_b = BUILD.build_zip(release_b, archive_b)
        self.assertEqual(result_a, result_b)
        self.assertEqual(artifact_a, artifact_b)
        self.assertEqual(archive_a.read_bytes(), archive_b.read_bytes())
        self._verify(release_a, result_a)
        with zipfile.ZipFile(archive_a) as bundle:
            names = set(bundle.namelist())
        for required in (
            "schemas/challenge.schema.json", "sandbox-profile.json", "genesis-policy.json",
            "genesis-config.yaml", "control-plane.lock.json", "release-metadata.json",
            "launcher/madctl-launcher.py", "release-files.json", "python/madctl/runtime.py",
            "launcher/madctl-launcher.c",
        ):
            self.assertIn(required, names)
        wheel_a = BUILD_WHEEL.build(source_a / "control-plane", self.root / "wheel-a")
        wheel_b = BUILD_WHEEL.build(source_b / "control-plane", self.root / "wheel-b")
        self.assertEqual(wheel_a.read_bytes(), wheel_b.read_bytes())
        with zipfile.ZipFile(wheel_a) as bundle:
            wheel_names = set(bundle.namelist())
        for suffix in (
            "mad-release/schemas/activation-record.schema.json", "mad-release/sandbox-profile.json",
            "mad-release/genesis-policy.json", "mad-release/genesis-config.yaml",
            "mad-release/control-plane.lock.json", "mad-release/release-metadata.json",
            "mad-release/launcher/madctl-launcher.py", "madctl/activation.py", "madctl/inventory.py",
            "mad-release/launcher/madctl-launcher.c",
        ):
            self.assertTrue(any(name.endswith(suffix) for name in wheel_names), suffix)
        native_a = BUILD_LAUNCHER.build(CONTROL / "launcher/madctl-launcher.c", self.root / "native-a")
        native_b = BUILD_LAUNCHER.build(CONTROL / "launcher/madctl-launcher.c", self.root / "native-b")
        self.assertEqual(native_a.read_bytes(), native_b.read_bytes())

    def test_closed_release_rejects_omission_alteration_extras_symlinks_and_writable_files(self) -> None:
        targets = (
            "python/madctl/controller.py", "schemas/challenge.schema.json", "sandbox-profile.json",
            "genesis-policy.json", "genesis-config.yaml", "release-metadata.json",
            "control-plane.lock.json", "launcher/madctl-launcher.py",
            "launcher/madctl-launcher.c",
        )
        for index, relative in enumerate(targets):
            release, result = self._build(f"omit-{index}")
            path = release / relative
            os.chmod(path.parent, 0o755)
            path.unlink()
            with self.assertRaises(AuthorityError, msg=f"omission: {relative}"):
                self._verify(release, result)
        for index, relative in enumerate(targets):
            release, result = self._build(f"alter-{index}")
            path = release / relative
            os.chmod(path, 0o644)
            path.write_bytes(path.read_bytes() + b"tampered\n")
            with self.assertRaises(AuthorityError, msg=f"alteration: {relative}"):
                self._verify(release, result)
        for index, relative in enumerate(("python/madctl/evil.py", "schemas/evil.schema.json", "extra-policy.json")):
            release, result = self._build(f"extra-{index}")
            path = release / relative
            os.chmod(path.parent, 0o755)
            path.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(AuthorityError, msg=f"extra: {relative}"):
                self._verify(release, result)
        release, result = self._build("symlink")
        target = release / "python/madctl/controller.py"
        os.chmod(target.parent, 0o755)
        target.unlink()
        target.symlink_to("__init__.py")
        with self.assertRaises(AuthorityError):
            self._verify(release, result)
        release, result = self._build("writable")
        os.chmod(release / "schemas/challenge.schema.json", 0o666)
        with self.assertRaises(AuthorityError):
            self._verify(release, result)
        release, result = self._build("writable-directory")
        os.chmod(release / "python/madctl", 0o755)
        with self.assertRaises(AuthorityError):
            self._verify(release, result)
        release, result = self._build("writable-inventory")
        os.chmod(release / "release-files.json", 0o644)
        with self.assertRaises(AuthorityError):
            self._verify(release, result)


class TrustedOrkaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="mad-orka-test-"))
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        make_writable(self.root)
        shutil.rmtree(self.root, ignore_errors=True)

    def _source(self) -> Path:
        source = self.root / f"source-{len(list(self.root.glob('source-*')))}"
        for relative in REQUIRED_RUNTIME_FILES:
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative.endswith("plugin.json"):
                path.write_text(json.dumps({"name": "orka", "version": "1.8.0"}), encoding="utf-8")
            else:
                path.write_text(f"# trusted {relative}\n", encoding="utf-8")
        return source

    def _stage(self, name: str) -> tuple[Path, dict[str, str]]:
        target = self.root / name
        result = STAGE_ORKA.stage(self._source(), target)
        return target, result

    def _load(self, root: Path, result: dict[str, str], version: str = "1.8.0") -> OrkaRuntime:
        return OrkaRuntime.load_trusted(
            root=root, expected_version=version, expected_digest=result["digest"],
            expected_inventory_digest=result["inventory_digest"], trusted_uid=os.getuid(),
        )

    def test_complete_orka_tree_and_transitive_import_are_pinned(self) -> None:
        root, result = self._stage("trusted")
        runtime = self._load(root, result)
        self.assertEqual(runtime.digest, result["digest"])
        self.assertIn("scripts/context_pipeline.py", json.loads((root / ORKA_INVENTORY).read_bytes())["files"])
        path = root / "scripts/context_pipeline.py"
        os.chmod(path, 0o644)
        path.write_text("# altered transitive import\n", encoding="utf-8")
        with self.assertRaises(AuthorityError):
            self._load(root, result)
        with self.assertRaises(AuthorityError):
            runtime.verify()

    def test_orka_rejects_wrong_digest_missing_extra_symlink_writable_version_and_escape(self) -> None:
        root, result = self._stage("wrong-digest")
        with self.assertRaises(AuthorityError):
            OrkaRuntime.load_trusted(root=root, expected_version="1.8.0", expected_digest="0" * 64,
                                     expected_inventory_digest=result["inventory_digest"], trusted_uid=os.getuid())
        root, result = self._stage("missing")
        path = root / "scripts/runtime_state.py"; os.chmod(path.parent, 0o755); path.unlink()
        with self.assertRaises(AuthorityError): self._load(root, result)
        root, result = self._stage("extra")
        path = root / "scripts/evil.py"; os.chmod(path.parent, 0o755); path.write_text("pass\n")
        with self.assertRaises(AuthorityError): self._load(root, result)
        root, result = self._stage("symlink")
        path = root / "scripts/runtime_state.py"; os.chmod(path.parent, 0o755); path.unlink(); path.symlink_to("version_policy.py")
        with self.assertRaises(AuthorityError): self._load(root, result)
        root, result = self._stage("writable")
        os.chmod(root / "scripts/runtime_state.py", 0o666)
        with self.assertRaises(AuthorityError): self._load(root, result)
        root, result = self._stage("writable-directory")
        os.chmod(root / "scripts", 0o755)
        with self.assertRaises(AuthorityError): self._load(root, result)
        root, result = self._stage("writable-inventory")
        os.chmod(root / ORKA_INVENTORY, 0o644)
        with self.assertRaises(AuthorityError): self._load(root, result)
        root, result = self._stage("version")
        with self.assertRaises(AuthorityError): self._load(root, result, version="1.8.1")
        relative = Path("relative-orka")
        with self.assertRaises(AuthorityError):
            OrkaRuntime.load_trusted(root=relative, expected_version="1.8.0", expected_digest="0" * 64,
                                     expected_inventory_digest="0" * 64, trusted_uid=os.getuid())


class TrustedPythonRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="mad-python-runtime-test-"))
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        make_writable(self.root)
        shutil.rmtree(self.root, ignore_errors=True)

    def _source(self, name: str) -> Path:
        source = self.root / f"source-{name}"
        for relative, raw, mode in (
            ("lib/python/os.py", b"# standard library\n", 0o644),
            ("lib/python/site-packages/cryptography/__init__.py", b"__version__='41.0.7'\n", 0o644),
            ("lib/python/site-packages/jsonschema/__init__.py", b"__version__='4.10.3'\n", 0o644),
            ("lib/python/site-packages/yaml/__init__.py", b"__version__='6.0.1'\n", 0o644),
            ("lib/python/site-packages/attrs/__init__.py", b"__version__='23.2.0'\n", 0o644),
            ("lib/python/site-packages/pyrsistent/__init__.py", b"__version__='0.20.0'\n", 0o644),
            ("lib/python/site-packages/cffi/__init__.py", b"__version__='1.16.0'\n", 0o644),
            ("lib/python/site-packages/pycparser/__init__.py", b"__version__='2.21'\n", 0o644),
            ("lib/python/site-packages/cryptography-41.0.7.dist-info/METADATA", b"Name: cryptography\nVersion: 41.0.7\nRequires-Dist: cffi>=1.12; platform_python_implementation != 'PyPy'\n\n", 0o644),
            ("lib/python/site-packages/jsonschema-4.10.3.dist-info/METADATA", b"Name: jsonschema\nVersion: 4.10.3\nRequires-Dist: attrs>=17.4.0\nRequires-Dist: pyrsistent>=0.14.0\n\n", 0o644),
            ("lib/python/site-packages/PyYAML-6.0.1.dist-info/METADATA", b"Name: PyYAML\nVersion: 6.0.1\n\n", 0o644),
            ("lib/python/site-packages/attrs-23.2.0.dist-info/METADATA", b"Name: attrs\nVersion: 23.2.0\n\n", 0o644),
            ("lib/python/site-packages/pyrsistent-0.20.0.dist-info/METADATA", b"Name: pyrsistent\nVersion: 0.20.0\n\n", 0o644),
            ("lib/python/site-packages/cffi-1.16.0.dist-info/METADATA", b"Name: cffi\nVersion: 1.16.0\nRequires-Dist: pycparser\n\n", 0o644),
            ("lib/python/site-packages/pycparser-2.21.dist-info/METADATA", b"Name: pycparser\nVersion: 2.21\n\n", 0o644),
        ):
            path = source / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw); os.chmod(path, mode)
        build = self.root / f"elf-{name}"
        build.mkdir()
        python_source = build / "python.c"
        python_source.write_text("int main(void){return 0;}\n")
        (source / "bin").mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["gcc", "-static", "-Wl,--build-id=none", "-o", str(source / "bin/python3"), str(python_source)],
            check=True,
        )
        library_source = build / "crypto.c"
        library_source.write_text("int trusted_crypto(void){return 7;}\n")
        subprocess.run(
            ["gcc", "-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none", "-Wl,-soname,libcrypto.so.3",
             "-o", str(source / "lib/libcrypto.so.3"), str(library_source)], check=True,
        )
        extension = source / "lib/python/site-packages/cryptography/hazmat/bindings/_rust.abi3.so"
        extension.parent.mkdir(parents=True, exist_ok=True)
        extension_source = build / "extension.c"
        extension_source.write_text("extern int trusted_crypto(void); int use_crypto(void){return trusted_crypto();}\n")
        subprocess.run(
            ["gcc", "-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none", "-Wl,--no-as-needed",
             "-L", str(source / "lib"), "-o", str(extension), str(extension_source), "-l:libcrypto.so.3"], check=True,
        )
        return source

    def _stage(self, name: str) -> tuple[Path, dict[str, str]]:
        target = self.root / f"runtime-{name}"
        result = stage_python_fixture(
            self._source(name), target, executable="bin/python3",
            import_paths=["lib/python", "lib/python/site-packages"],
        )
        return target, result

    def _verify(self, root: Path, result: dict[str, str]) -> None:
        verify_closed_inventory(
            root, inventory_name="python-runtime-files.json",
            expected_inventory_digest=result["inventory_digest"], expected_tree_digest=result["digest"],
            trusted_uid=os.getuid(), trusted_gid=os.getgid(),
            required_paths={
                "python-runtime.json", "bin/python3", "lib/python/os.py",
                "lib/python/site-packages/cryptography/__init__.py",
                "lib/python/site-packages/cryptography/hazmat/bindings/_rust.abi3.so",
                "lib/python/site-packages/jsonschema/__init__.py", "lib/python/site-packages/yaml/__init__.py",
                "lib/python/site-packages/attrs/__init__.py", "lib/python/site-packages/pyrsistent/__init__.py",
                "lib/python/site-packages/cffi/__init__.py", "lib/python/site-packages/pycparser/__init__.py",
                "lib/python/site-packages/cryptography-41.0.7.dist-info/METADATA",
                "lib/python/site-packages/jsonschema-4.10.3.dist-info/METADATA",
                "lib/python/site-packages/PyYAML-6.0.1.dist-info/METADATA",
                "lib/python/site-packages/attrs-23.2.0.dist-info/METADATA",
                "lib/python/site-packages/pyrsistent-0.20.0.dist-info/METADATA",
                "lib/python/site-packages/cffi-1.16.0.dist-info/METADATA",
                "lib/python/site-packages/pycparser-2.21.dist-info/METADATA",
                "lib/libcrypto.so.3",
            },
        )

    def test_runtime_inventory_is_deterministic_and_covers_dependencies(self) -> None:
        first, result_a = self._stage("a")
        second, result_b = self._stage("b")
        self.assertEqual(result_a, result_b)
        self.assertEqual((first / "python-runtime-files.json").read_bytes(),
                         (second / "python-runtime-files.json").read_bytes())
        self._verify(first, result_a)

    def test_wheel_substitution_between_hash_and_parse_is_rejected_without_publication(self) -> None:
        source = self._source("wheel-hash-parse-race")
        imports = ["lib/python", "lib/python/site-packages"]
        input_lock, wheelhouse = make_python_input_lock(
            source, executable="bin/python3", import_paths=imports,
        )
        lock = json.loads(input_lock.read_bytes())
        wheel = wheelhouse / lock["wheels"]["cryptography"]["filename"]
        original_parse = STAGE_PYTHON._parse_wheel_bytes
        changed = False

        def substitute_after_hash(raw: bytes, *, filename: str) -> dict[str, bytes]:
            nonlocal changed
            if not changed:
                wheel.write_bytes(wheel.read_bytes() + b"substituted-after-hash")
                changed = True
            return original_parse(raw, filename=filename)

        target = self.root / "runtime-wheel-hash-parse-race"
        with mock.patch.object(STAGE_PYTHON, "_parse_wheel_bytes", side_effect=substitute_after_hash):
            with self.assertRaisesRegex(RuntimeError, "changed after approval verification"):
                STAGE_PYTHON.stage(
                    source, target, executable="bin/python3", import_paths=imports,
                    input_lock=input_lock, wheelhouse=wheelhouse,
                )
        self.assertTrue(changed)
        self.assertFalse(target.exists())

    def test_source_mutation_between_verification_and_copy_is_rejected_without_publication(self) -> None:
        source = self._source("source-copy-race")
        imports = ["lib/python", "lib/python/site-packages"]
        input_lock, wheelhouse = make_python_input_lock(
            source, executable="bin/python3", import_paths=imports,
        )
        original_copy = STAGE_PYTHON._copy_source_tree

        def mutate_then_copy(copy_source: Path, copy_target: Path) -> None:
            (copy_source / "lib/python/os.py").write_bytes(b"# changed after lock verification\n")
            original_copy(copy_source, copy_target)

        target = self.root / "runtime-source-copy-race"
        with mock.patch.object(STAGE_PYTHON, "_copy_source_tree", side_effect=mutate_then_copy):
            with self.assertRaisesRegex(RuntimeError, "final staged interpreter or standard runtime differs"):
                STAGE_PYTHON.stage(
                    source, target, executable="bin/python3", import_paths=imports,
                    input_lock=input_lock, wheelhouse=wheelhouse,
                )
        self.assertFalse(target.exists())

    def test_staged_mutation_before_final_inventory_is_rejected_without_publication(self) -> None:
        source = self._source("staged-inventory-race")
        imports = ["lib/python", "lib/python/site-packages"]
        input_lock, wheelhouse = make_python_input_lock(
            source, executable="bin/python3", import_paths=imports,
        )
        original_verify = STAGE_PYTHON._verify_staged_inputs
        verification_count = 0

        def mutate_before_second_verification(root: Path, approved: dict, lock_raw: bytes) -> None:
            nonlocal verification_count
            verification_count += 1
            if verification_count == 2:
                package = root / "lib/python/site-packages/jsonschema/__init__.py"
                os.chmod(package, 0o600)
                package.write_bytes(b"# changed before final inventory\n")
            original_verify(root, approved, lock_raw)

        target = self.root / "runtime-staged-inventory-race"
        with mock.patch.object(STAGE_PYTHON, "_verify_staged_inputs", side_effect=mutate_before_second_verification):
            with self.assertRaisesRegex(RuntimeError, "final staged package file differs"):
                STAGE_PYTHON.stage(
                    source, target, executable="bin/python3", import_paths=imports,
                    input_lock=input_lock, wheelhouse=wheelhouse,
                )
        self.assertEqual(verification_count, 2)
        self.assertFalse(target.exists())

    def test_unchanged_approved_inputs_are_published_from_private_staging(self) -> None:
        source = self._source("unchanged-private-stage")
        imports = ["lib/python", "lib/python/site-packages"]
        input_lock, wheelhouse = make_python_input_lock(
            source, executable="bin/python3", import_paths=imports,
        )
        target = self.root / "runtime-unchanged-private-stage"
        result = STAGE_PYTHON.stage(
            source, target, executable="bin/python3", import_paths=imports,
            input_lock=input_lock, wheelhouse=wheelhouse,
        )
        self._verify(target, result)
        self.assertEqual(list(self.root.glob(f".{target.name}.stage-*")), [])

    def test_runtime_rejects_dependency_native_extra_missing_symlink_writable_and_digest(self) -> None:
        cases = (
            ("alter", "lib/python/site-packages/jsonschema/__init__.py", "alter"),
            ("native", "lib/python/site-packages/cryptography/hazmat/bindings/_rust.abi3.so", "alter"),
            ("missing", "lib/python/site-packages/yaml/__init__.py", "remove"),
            ("extra", "lib/python/site-packages/evil.py", "extra"),
            ("writable", "lib/python/os.py", "writable"),
        )
        for name, relative, action in cases:
            runtime, result = self._stage(name)
            path = runtime / relative
            if action == "alter": os.chmod(path, 0o644); path.write_bytes(b"tampered\n")
            elif action == "remove": os.chmod(path.parent, 0o755); path.unlink()
            elif action == "extra": os.chmod(path.parent, 0o755); path.write_bytes(b"evil\n")
            else: os.chmod(path, 0o666)
            with self.assertRaises(AuthorityError, msg=name): self._verify(runtime, result)
        runtime, result = self._stage("symlink")
        path = runtime / "lib/python/os.py"; os.chmod(path.parent, 0o755); path.unlink(); path.symlink_to("../libcrypto.so.3")
        with self.assertRaises(AuthorityError): self._verify(runtime, result)
        runtime, result = self._stage("digest")
        bad = dict(result); bad["digest"] = "0" * 64
        with self.assertRaises(AuthorityError): self._verify(runtime, bad)

    def test_runtime_stage_rejects_path_escape_wrong_interpreter_and_source_symlink(self) -> None:
        with self.assertRaises(RuntimeError):
            STAGE_PYTHON.stage(self._source("escape"), self.root / "runtime-escape", executable="../python3",
                               import_paths=["lib/python"], input_lock=self.root, wheelhouse=self.root)
        with self.assertRaises(RuntimeError):
            STAGE_PYTHON.stage(self._source("wrong"), self.root / "runtime-wrong", executable="bin/missing",
                               import_paths=["lib/python"], input_lock=self.root, wheelhouse=self.root)
        source = self._source("link")
        input_lock, wheelhouse = make_python_input_lock(
            source, executable="bin/python3", import_paths=["lib/python", "lib/python/site-packages"],
        )
        (source / "escape").symlink_to("/usr")
        with self.assertRaises(RuntimeError):
            STAGE_PYTHON.stage(source, self.root / "runtime-link", executable="bin/python3",
                               import_paths=["lib/python", "lib/python/site-packages"],
                               input_lock=input_lock, wheelhouse=wheelhouse)

    def test_runtime_requires_complete_exact_distribution_closure(self) -> None:
        missing = self._source("missing-transitive")
        missing_lock, missing_wheels = make_python_input_lock(
            missing, executable="bin/python3", import_paths=["lib/python", "lib/python/site-packages"],
        )
        shutil.rmtree(missing / "lib/python/site-packages/attrs-23.2.0.dist-info")
        with self.assertRaises(RuntimeError):
            STAGE_PYTHON.stage(
                missing, self.root / "runtime-missing-transitive", executable="bin/python3",
                import_paths=["lib/python", "lib/python/site-packages"], input_lock=missing_lock, wheelhouse=missing_wheels,
            )
        unexpected = self._source("unexpected-distribution")
        unexpected_lock, unexpected_wheels = make_python_input_lock(
            unexpected, executable="bin/python3", import_paths=["lib/python", "lib/python/site-packages"],
        )
        metadata = unexpected / "lib/python/site-packages/untrusted-1.0.dist-info/METADATA"
        metadata.parent.mkdir(parents=True)
        metadata.write_text("Name: untrusted\nVersion: 1.0\n\n")
        with self.assertRaises(RuntimeError):
            STAGE_PYTHON.stage(
                unexpected, self.root / "runtime-unexpected-distribution", executable="bin/python3",
                import_paths=["lib/python", "lib/python/site-packages"], input_lock=unexpected_lock, wheelhouse=unexpected_wheels,
            )
        wrong_edge = self._source("wrong-dependency-edge")
        wrong_lock, wrong_wheels = make_python_input_lock(
            wrong_edge, executable="bin/python3", import_paths=["lib/python", "lib/python/site-packages"],
        )
        metadata = wrong_edge / "lib/python/site-packages/jsonschema-4.10.3.dist-info/METADATA"
        metadata.write_text("Name: jsonschema\nVersion: 4.10.3\nRequires-Dist: attrs>=17.4.0\n\n")
        with self.assertRaises(RuntimeError):
            STAGE_PYTHON.stage(
                wrong_edge, self.root / "runtime-wrong-dependency-edge", executable="bin/python3",
                import_paths=["lib/python", "lib/python/site-packages"], input_lock=wrong_lock, wheelhouse=wrong_wheels,
            )

    def test_runtime_requires_trusted_wheels_and_complete_record_provenance(self) -> None:
        imports = ["lib/python", "lib/python/site-packages"]

        missing = self._source("record-missing")
        missing_lock, missing_wheels = make_python_input_lock(missing, executable="bin/python3", import_paths=imports)
        record = missing / "lib/python/site-packages/jsonschema-4.10.3.dist-info/RECORD"
        record.unlink()
        with self.assertRaises(RuntimeError):
            STAGE_PYTHON.stage(
                missing, self.root / "runtime-record-missing", executable="bin/python3", import_paths=imports,
                input_lock=missing_lock, wheelhouse=missing_wheels,
            )

        def corrupt_record(name: str, field: int, replacement: str) -> None:
            source = self._source(name)
            lock_path, wheelhouse = make_python_input_lock(source, executable="bin/python3", import_paths=imports)
            lock = json.loads(lock_path.read_bytes())
            wheel = wheelhouse / lock["wheels"]["jsonschema"]["filename"]
            with zipfile.ZipFile(wheel) as archive:
                members = {info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()}
            record_name = next(path for path in members if path.endswith("jsonschema-4.10.3.dist-info/RECORD"))
            rows = list(csv.reader(io.StringIO(members[record_name].decode("utf-8"))))
            target = next(row for row in rows if row[0].endswith("jsonschema/__init__.py"))
            target[field] = replacement
            output = io.StringIO(newline="")
            csv.writer(output, lineterminator="\n").writerows(rows)
            members[record_name] = output.getvalue().encode("utf-8")
            (source / "lib/python/site-packages" / record_name).write_bytes(members[record_name])
            with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_STORED) as archive:
                for relative, raw in sorted(members.items()): archive.writestr(relative, raw)
            lock["wheels"]["jsonschema"]["sha256"] = sha(wheel)
            lock_path.write_bytes(STAGE_PYTHON.canonical(lock) + b"\n")
            with self.assertRaises(RuntimeError):
                STAGE_PYTHON.stage(
                    source, self.root / f"runtime-{name}", executable="bin/python3", import_paths=imports,
                    input_lock=lock_path, wheelhouse=wheelhouse,
                )

        corrupt_record("record-hash", 1, "sha256=" + "A" * 43)
        corrupt_record("record-size", 2, "999999")

        unexpected = self._source("unowned-file")
        unexpected_lock, unexpected_wheels = make_python_input_lock(unexpected, executable="bin/python3", import_paths=imports)
        (unexpected / "lib/python/site-packages/unowned.py").write_text("untrusted = True\n")
        with self.assertRaisesRegex(RuntimeError, "unowned or missing"):
            STAGE_PYTHON.stage(
                unexpected, self.root / "runtime-unowned-file", executable="bin/python3", import_paths=imports,
                input_lock=unexpected_lock, wheelhouse=unexpected_wheels,
            )

        native_extra = self._source("unowned-native-extension")
        native_lock, native_wheels = make_python_input_lock(
            native_extra, executable="bin/python3", import_paths=imports,
        )
        (native_extra / "lib/python/site-packages/cryptography/unexpected.abi3.so").write_bytes(b"\x7fELFunowned")
        with self.assertRaisesRegex(RuntimeError, "unowned or missing"):
            STAGE_PYTHON.stage(
                native_extra, self.root / "runtime-unowned-native-extension", executable="bin/python3",
                import_paths=imports, input_lock=native_lock, wheelhouse=native_wheels,
            )

        substituted = self._source("same-version-substitution")
        substituted_lock, substituted_wheels = make_python_input_lock(substituted, executable="bin/python3", import_paths=imports)
        (substituted / "lib/python/site-packages/cryptography/__init__.py").write_text("__version__='41.0.7'\nsubstituted=True\n")
        with self.assertRaisesRegex(RuntimeError, "differs from trusted wheel"):
            STAGE_PYTHON.stage(
                substituted, self.root / "runtime-same-version-substitution", executable="bin/python3", import_paths=imports,
                input_lock=substituted_lock, wheelhouse=substituted_wheels,
            )

        wheel_swap = self._source("wheel-substitution")
        wheel_lock, wheelhouse = make_python_input_lock(wheel_swap, executable="bin/python3", import_paths=imports)
        lock = json.loads(wheel_lock.read_bytes())
        wheel = wheelhouse / lock["wheels"]["attrs"]["filename"]
        wheel.write_bytes(wheel.read_bytes() + b"substituted")
        with self.assertRaisesRegex(RuntimeError, "artifact hash mismatch"):
            STAGE_PYTHON.stage(
                wheel_swap, self.root / "runtime-wheel-substitution", executable="bin/python3", import_paths=imports,
                input_lock=wheel_lock, wheelhouse=wheelhouse,
            )

    def test_runtime_audits_genuine_elf_interpreter_dependencies_and_loader_directives(self) -> None:
        runtime, _ = self._stage("genuine-elf")
        metadata = json.loads((runtime / "python-runtime.json").read_bytes())
        extension = "lib/python/site-packages/cryptography/hazmat/bindings/_rust.abi3.so"
        self.assertEqual(metadata["elf_closure"][extension]["needed"], {"libcrypto.so.3": "lib/libcrypto.so.3"})
        self.assertIsNone(metadata["elf_closure"]["bin/python3"]["interpreter"])

        external_interpreter = self._source("external-interpreter")
        shutil.copy2(Path(sys.executable).resolve(), external_interpreter / "bin/python3")
        external_lock, external_wheels = make_python_input_lock(
            external_interpreter, executable="bin/python3", import_paths=["lib/python", "lib/python/site-packages"],
        )
        with self.assertRaisesRegex(RuntimeError, "interpreter escapes trusted runtime"):
            STAGE_PYTHON.stage(
                external_interpreter, self.root / "runtime-external-interpreter", executable="bin/python3",
                import_paths=["lib/python", "lib/python/site-packages"], input_lock=external_lock, wheelhouse=external_wheels,
            )

        unsafe = self._source("unsafe-loader-directive")
        source = self.root / "unsafe-audit.c"
        source.write_text("int audited(void){return 0;}\n")
        extension_path = unsafe / "lib/python/site-packages/cryptography/hazmat/bindings/_rust.abi3.so"
        subprocess.run(
            ["gcc", "-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none", "-Wl,-audit,/outside/libaudit.so",
             "-o", str(extension_path), str(source)], check=True,
        )
        unsafe_lock, unsafe_wheels = make_python_input_lock(
            unsafe, executable="bin/python3", import_paths=["lib/python", "lib/python/site-packages"],
        )
        with self.assertRaisesRegex(RuntimeError, "unsafe dynamic loader directive"):
            STAGE_PYTHON.stage(
                unsafe, self.root / "runtime-unsafe-loader-directive", executable="bin/python3",
                import_paths=["lib/python", "lib/python/site-packages"], input_lock=unsafe_lock, wheelhouse=unsafe_wheels,
            )


class TrustedExecutableIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="mad-tool-identity-test-", dir=ROOT))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.bin = self.root / "bin"; self.bin.mkdir(mode=0o700)
        self.tool = self.bin / "tool"; self.tool.write_text("#!/bin/sh\nexit 0\n"); os.chmod(self.tool, 0o500)

    def _verify(self, path: Path | None = None, digest: str | None = None, *, uid: int | None = None,
                gid: int | None = None, root: Path | None = None) -> TrustedTool:
        return TrustedTool.verify(
            self.tool if path is None else path, sha(self.tool) if digest is None else digest,
            expected_uid=os.getuid() if uid is None else uid, expected_gid=os.getgid() if gid is None else gid,
            system_uid=Path("/").stat().st_uid, allowed_root=self.root if root is None else root,
        )

    def test_candidate_owner_wrong_identity_modes_parent_symlink_digest_and_relative_fail(self) -> None:
        with self.assertRaises(AuthorityError): self._verify(uid=os.getuid() + 1)
        with self.assertRaises(AuthorityError): self._verify(gid=os.getgid() + 1)
        with self.assertRaises(AuthorityError): self._verify(digest="0" * 64)
        for mode in (0o520, 0o502):
            os.chmod(self.tool, mode)
            with self.assertRaises(AuthorityError): self._verify()
        os.chmod(self.tool, 0o500); os.chmod(self.bin, 0o770)
        with self.assertRaises(AuthorityError): self._verify()
        os.chmod(self.bin, 0o700)
        link = self.bin / "link"; link.symlink_to("tool")
        with self.assertRaises(AuthorityError): self._verify(path=link)
        with self.assertRaises(AuthorityError): self._verify(path=Path("bin/tool"))
        unsafe_root = Path(tempfile.mkdtemp(prefix="mad-unsafe-tool-root-"))
        self.addCleanup(lambda: shutil.rmtree(unsafe_root, ignore_errors=True))
        unsafe_tool = unsafe_root / "tool"; unsafe_tool.write_text("#!/bin/sh\nexit 0\n"); os.chmod(unsafe_tool, 0o500)
        with self.assertRaises(AuthorityError):
            TrustedTool.verify(
                unsafe_tool, sha(unsafe_tool), expected_uid=os.getuid(), expected_gid=os.getgid(),
                system_uid=Path("/").stat().st_uid, allowed_root=unsafe_root,
            )

    def test_replacement_is_detected_immediately_and_path_shadowing_is_irrelevant(self) -> None:
        trusted = self._verify()
        os.chmod(self.tool, 0o700); self.tool.write_text("#!/bin/sh\nexit 9\n"); os.chmod(self.tool, 0o500)
        with self.assertRaises(AuthorityError): trusted.revalidate()
        shadow = self.root / "shadow"; shadow.mkdir(); (shadow / "tool").write_text("evil")
        old_path = os.environ.get("PATH")
        try:
            os.environ["PATH"] = str(shadow)
            with self.assertRaises(AuthorityError): trusted.revalidate()
        finally:
            if old_path is None: os.environ.pop("PATH", None)
            else: os.environ["PATH"] = old_path


class RealPythonTransitionTests(unittest.TestCase):
    """Production-shaped integration; unlike LauncherIsolationTests this never substitutes a C stub for Python."""

    def setUp(self) -> None:
        parent = Path(os.environ.get("MAD_REAL_PYTHON_TEST_PARENT", ROOT))
        self.root = Path(tempfile.mkdtemp(prefix="mad-real-python-test-", dir=parent))
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        make_writable(self.root)
        shutil.rmtree(self.root, ignore_errors=True)

    @staticmethod
    def _elf_metadata(path: Path) -> tuple[str | None, list[str]]:
        program = subprocess.run(
            ["/usr/bin/readelf", "-lW", str(path)], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        ).stdout
        dynamic = subprocess.run(
            ["/usr/bin/readelf", "-dW", str(path)], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        ).stdout
        interpreter = None
        for line in program.splitlines():
            if "Requesting program interpreter: " in line:
                interpreter = line.split("Requesting program interpreter: ", 1)[1].rstrip("]")
        needed = [line.split("[", 1)[1].split("]", 1)[0] for line in dynamic.splitlines()
                  if "(NEEDED)" in line and "[" in line]
        return interpreter, needed

    @staticmethod
    def _system_libraries() -> dict[str, Path]:
        result = subprocess.run(
            ["/usr/sbin/ldconfig", "-p"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True, env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
        )
        libraries: dict[str, Path] = {}
        for line in result.stdout.splitlines():
            if " => /" not in line:
                continue
            name, path = line.strip().split(" => ", 1)
            libraries.setdefault(name.split()[0], Path(path))
        return libraries

    def _copy_real_runtime_source(self, target: Path) -> tuple[str, list[str], Path, Path]:
        patchelf = shutil.which("patchelf")
        limitations: list[str] = []
        if patchelf is None:
            limitations.append("patchelf is absent, so PT_INTERP cannot be bound into the temporary runtime")
        if not Path("/usr/sbin/ldconfig").is_file():
            limitations.append("/usr/sbin/ldconfig is absent")
        wheelhouse_text = os.environ.get("MAD_PYTHON_WHEELHOUSE")
        wheelhouse = Path(wheelhouse_text) if wheelhouse_text else Path("/")
        if not wheelhouse_text or not wheelhouse.is_dir():
            limitations.append("MAD_PYTHON_WHEELHOUSE does not name the approved genuine-wheel directory")
        if sys.version_info[:2] != (3, 11) or sysconfig.get_platform() != "linux-x86_64":
            limitations.append("approved genuine-wheel fixture requires CPython 3.11 on linux-x86_64")
        if wheelhouse_text and wheelhouse.is_dir():
            for name, record in APPROVED_CP311_X86_64_WHEELS.items():
                wheel = wheelhouse / record["filename"]
                if not wheel.is_file() or sha(wheel) != record["sha256"]:
                    limitations.append(f"approved wheel artifact is missing or mismatched: {name}")
        if limitations:
            self.skipTest("real native-to-Python integration unavailable: " + "; ".join(limitations))
        assert patchelf is not None
        executable = Path(sys.executable).resolve()
        stdlib = Path(sysconfig.get_path("stdlib")).resolve()
        version_dir = f"python{sys.version_info.major}.{sys.version_info.minor}"
        runtime_python = target / "bin/python3"
        runtime_python.parent.mkdir(parents=True)
        shutil.copy2(executable, runtime_python)
        shutil.copytree(
            stdlib, target / f"lib/{version_dir}",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "site-packages", "dist-packages", "EXTERNALLY-MANAGED"),
        )
        site_relative = "lib/python/site-packages"
        site = target / site_relative
        site.mkdir(parents=True)
        extracted: set[str] = set()
        for record in APPROVED_CP311_X86_64_WHEELS.values():
            with zipfile.ZipFile(wheelhouse / record["filename"]) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    relative = STAGE_PYTHON._safe_archive_path(info.filename)
                    if relative in extracted:
                        raise AssertionError(f"approved wheels overlap at {relative}")
                    destination = site / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive.read(info))
                    extracted.add(relative)
        interpreter, _ = self._elf_metadata(runtime_python)
        if interpreter is None:
            self.skipTest("host Python is not dynamically linked; this integration specifically validates PT_INTERP closure")
        loader_name = Path(interpreter).name
        shutil.copy2(Path(interpreter).resolve(), target / "lib" / loader_name)
        libraries = self._system_libraries()
        pending = [runtime_python, *(path for path in target.rglob("*.so") if path.is_file())]
        inspected: set[Path] = set()
        while pending:
            elf = pending.pop()
            if elf in inspected:
                continue
            inspected.add(elf)
            _, needed = self._elf_metadata(elf)
            for library in needed:
                destination = target / "lib" / library
                if destination.exists():
                    continue
                source = libraries.get(library)
                if source is None:
                    self.skipTest(f"cannot resolve genuine ELF dependency {library}")
                shutil.copy2(source.resolve(), destination)
                pending.append(destination)
        activated_loader = (self.root / "python-runtime/lib" / loader_name).resolve()
        for elf in sorted(inspected):
            elf_interpreter, _ = self._elf_metadata(elf)
            if elf_interpreter is not None:
                subprocess.run([patchelf, "--set-interpreter", str(activated_loader), str(elf)], check=True)
        executable_relative = "bin/python3"
        import_paths = [f"lib/{version_dir}", f"lib/{version_dir}/lib-dynload", site_relative]
        runtime_files = {}
        for path in sorted(item for item in target.rglob("*") if item.is_file()):
            try:
                path.relative_to(site)
            except ValueError:
                runtime_files[path.relative_to(target).as_posix()] = sha(path)
        lock = {
            "schema_version": 1, "python_executable": executable_relative, "import_paths": import_paths,
            "site_packages": site_relative, "runtime_files": runtime_files,
            "wheels": APPROVED_CP311_X86_64_WHEELS,
        }
        input_lock = self.root / "approved-python-input-lock.json"
        input_lock.write_bytes(STAGE_PYTHON.canonical(lock) + b"\n")
        return executable_relative, import_paths, input_lock, wheelhouse

    def test_real_python_valid_activation_startup_imports_and_native_mappings_are_closed(self) -> None:
        source = self.root / "runtime-source"
        source.mkdir()
        executable, import_paths, input_lock, wheelhouse = self._copy_real_runtime_source(source)
        runtime = self.root / "python-runtime"
        runtime_result = STAGE_PYTHON.stage(
            source, runtime, executable=executable, import_paths=import_paths,
            input_lock=input_lock, wheelhouse=wheelhouse,
        )

        trusted_import_paths = [str(runtime / relative) for relative in import_paths]
        diagnostic = (
            f"import sys;sys.path[:]={trusted_import_paths!r};"
            "import attr,cffi,cryptography,json,jsonschema,pathlib,pycparser,pyrsistent,yaml;"
            "r=pathlib.Path(sys.prefix).resolve();"
            "mods=sorted(str(pathlib.Path(m.__file__).resolve()) for m in sys.modules.values() if getattr(m,'__file__',None));"
            "maps=sorted(set(x.split(maxsplit=5)[5].removesuffix(' (deleted)') for x in pathlib.Path('/proc/self/maps').read_text().splitlines() if len(x.split(maxsplit=5))==6 and x.split(maxsplit=5)[5].startswith('/')));"
            "print(json.dumps({'prefix':str(r),'modules':mods,'maps':maps},sort_keys=True))"
        )
        env = {
            "LANG": "C", "LC_ALL": "C", "PATH": "/nonexistent", "HOME": "/nonexistent",
            "PYTHONHOME": str(runtime), "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1",
            "LD_LIBRARY_PATH": str(runtime / "lib"),
        }
        traced = subprocess.run(
            [str(runtime / executable), "-P", "-s", "-S", "-B", "-c", diagnostic], env=env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(traced.returncode, 0, traced.stderr)
        evidence = json.loads(traced.stdout)
        self.assertEqual(Path(evidence["prefix"]), runtime)
        for path_text in [*evidence["modules"], *evidence["maps"]]:
            self.assertTrue(Path(path_text).resolve().is_relative_to(runtime), path_text)

        release = self.root / "release"
        release_result = BUILD.build_release(ROOT, release)
        orka_source = self.root / "orka-source"
        for relative in REQUIRED_RUNTIME_FILES:
            path = orka_source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"name": "orka", "version": "1.8.0"}) if relative.endswith("plugin.json") else "trusted\n")
        orka = self.root / "orka"
        orka_result = STAGE_ORKA.stage(orka_source, orka)
        launcher = self.root / "madctl"
        activation = self.root / "active-release.json"
        BUILD_LAUNCHER.build(
            CONTROL / "launcher/madctl-launcher.c", launcher,
            active_record=str(activation), activation_uid=os.getuid(), system_uid=Path("/").stat().st_uid,
        )
        for name in ("state", "registry", "cache", "codex-home"):
            (self.root / name).mkdir(mode=0o700)
        key = self.root / "controller.key"
        key.write_bytes(b"k" * 32)
        os.chmod(key, 0o400)
        python = runtime / executable
        tools = {
            name: {"path": str(python), "sha256": sha(python), "uid": os.getuid(), "gid": os.getgid(), "root": str(runtime)}
            for name in ("git", "gh", "python3", "codex", "bwrap")
        }
        manifest = {
            "schema_version": 1, "trusted_uid": os.getuid(), "trusted_gid": os.getgid(),
            "trusted_system_uid": Path("/").stat().st_uid, "expected_mad_version": "2.0.0",
            "release_root": str(release), "release_digest": release_result["release_digest"],
            "inventory_digest": release_result["inventory_digest"], "native_launcher_path": str(launcher),
            "native_launcher_sha256": sha(launcher), "python_runtime_root": str(runtime),
            "python_executable": str(python), "python_runtime_digest": runtime_result["digest"],
            "python_runtime_inventory_digest": runtime_result["inventory_digest"],
            "state_root": str(self.root / "state"), "registry_root": str(self.root / "registry"),
            "human_approval_registry_root": str(self.root / "registry"), "cache_root": str(self.root / "cache"),
            "controller_key_path": str(key), "codex_home": str(self.root / "codex-home"), "tools": tools,
            "orka": {"root": str(orka), "version": "1.8.0", "digest": orka_result["digest"],
                     "inventory_digest": orka_result["inventory_digest"], "uid": os.getuid(), "gid": os.getgid()},
        }
        activation.write_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        os.chmod(activation, 0o400)
        result = subprocess.run(
            [str(launcher), "self-test"], cwd=self.root,
            env={"PATH": "/tmp/untrusted", "PYTHONPATH": "/tmp/untrusted", "PYTHONHOME": "/tmp/untrusted",
                 "LD_PRELOAD": "/does/not/exist", "LD_AUDIT": "/does/not/exist"},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "PASS")

    def test_genuine_wheels_reject_record_and_provenance_substitution(self) -> None:
        source = self.root / "negative-runtime-source"
        source.mkdir()
        executable, import_paths, input_lock, wheelhouse = self._copy_real_runtime_source(source)
        site = source / "lib/python/site-packages"

        def verify(lock_path: Path = input_lock, wheel_root: Path = wheelhouse) -> None:
            STAGE_PYTHON._verify_input_lock(
                source, executable=executable, import_paths=import_paths,
                input_lock=lock_path, wheelhouse=wheel_root,
            )

        record = site / "jsonschema-4.10.3.dist-info/RECORD"
        original_record = record.read_bytes()
        record.unlink()
        with self.assertRaises(RuntimeError):
            verify()
        record.write_bytes(original_record)

        original_lock = json.loads(input_lock.read_bytes())
        original_wheelhouse = self.root / "negative-wheelhouse"
        shutil.copytree(wheelhouse, original_wheelhouse)
        wheel = original_wheelhouse / original_lock["wheels"]["jsonschema"]["filename"]
        with zipfile.ZipFile(wheel) as archive:
            members = {info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()}
        record_name = next(name for name in members if name.endswith("jsonschema-4.10.3.dist-info/RECORD"))

        cases = (
            ("hash", 1, "sha256=" + "A" * 43, "RECORD hash mismatch"),
            ("size", 2, "999999", "RECORD size or algorithm mismatch"),
        )
        for label, field, replacement, error in cases:
            rows = list(csv.reader(io.StringIO(members[record_name].decode("utf-8"))))
            target = next(row for row in rows if row[0].endswith("jsonschema/__init__.py"))
            target[field] = replacement
            output = io.StringIO(newline="")
            csv.writer(output, lineterminator="\n").writerows(rows)
            changed = dict(members)
            changed[record_name] = output.getvalue().encode("utf-8")
            with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_STORED) as archive:
                for relative, raw in sorted(changed.items()):
                    archive.writestr(relative, raw)
            record.write_bytes(changed[record_name])
            lock = json.loads(input_lock.read_bytes())
            lock["wheels"]["jsonschema"]["sha256"] = sha(wheel)
            malformed_lock = self.root / f"malformed-record-{label}.json"
            malformed_lock.write_bytes(STAGE_PYTHON.canonical(lock) + b"\n")
            with self.assertRaisesRegex(RuntimeError, error):
                verify(malformed_lock, original_wheelhouse)
            record.write_bytes(original_record)

        unowned = site / "cryptography/unexpected.abi3.so"
        unowned.write_bytes(b"\x7fELFunowned")
        with self.assertRaisesRegex(RuntimeError, "unowned or missing"):
            verify()
        unowned.unlink()

        package = site / "jsonschema/__init__.py"
        original_package = package.read_bytes()
        package.write_bytes(original_package + b"\n# same-version substitution\n")
        with self.assertRaisesRegex(RuntimeError, "differs from trusted wheel"):
            verify()
        package.write_bytes(original_package)

        substituted_wheelhouse = self.root / "substituted-wheelhouse"
        shutil.copytree(wheelhouse, substituted_wheelhouse)
        substituted = substituted_wheelhouse / original_lock["wheels"]["attrs"]["filename"]
        substituted.write_bytes(substituted.read_bytes() + b"substituted")
        with self.assertRaisesRegex(RuntimeError, "artifact hash mismatch"):
            verify(input_lock, substituted_wheelhouse)


class LauncherIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="mad-launcher-test-", dir=ROOT))
        self.addCleanup(self._cleanup)
        self.release = self.root / "release"
        self.release_result = BUILD.build_release(ROOT, self.release)
        self.orka, self.orka_result = self._orka()
        self.launcher = self.root / "madctl"
        self.activation = self.root / "active-release.json"
        self.runtime = self.root / "python-runtime"
        runtime_source = self.root / "runtime-source"
        (runtime_source / "bin").mkdir(parents=True)
        (runtime_source / "lib/python/site-packages").mkdir(parents=True)
        for distribution, version in STAGE_PYTHON.REQUIRED_DISTRIBUTIONS.items():
            metadata = runtime_source / f"lib/python/site-packages/{distribution}-{version}.dist-info/METADATA"
            metadata.parent.mkdir(parents=True)
            dependencies = ""
            if distribution == "jsonschema":
                dependencies = "Requires-Dist: attrs>=17.4.0\nRequires-Dist: pyrsistent>=0.14.0\n"
            elif distribution == "cryptography":
                dependencies = "Requires-Dist: cffi>=1.12; platform_python_implementation != 'PyPy'\n"
            elif distribution == "cffi":
                dependencies = "Requires-Dist: pycparser\n"
            metadata.write_text(f"Name: {distribution}\nVersion: {version}\n{dependencies}\n")
        stub_source = self.root / "python-stub.c"
        stub_source.write_text(
            "#include <stdlib.h>\n#include <string.h>\nint main(void){const char*n[]={\"LD_PRELOAD\",\"LD_AUDIT\","
            "\"PYTHONPATH\",\"PYTHONSTARTUP\",\"PYTHONUSERBASE\",\"PYTHONINSPECT\","
            f'\"PYTHONWARNINGS\",0}};for(int i=0;n[i];i++)if(getenv(n[i]))return 77;'
            f'const char*l=getenv("LD_LIBRARY_PATH");const char*h=getenv("PYTHONHOME");'
            f'return (!l||strcmp(l,"{self.runtime}/lib")||!h||strcmp(h,"{self.runtime}"))?78:0;}}\n'
        )
        subprocess.run(["gcc", "-static", "-Os", "-Wl,--build-id=none", "-o", str(runtime_source / "bin/python3"),
                        str(stub_source)], check=True)
        self.runtime_result = stage_python_fixture(
            runtime_source, self.runtime, executable="bin/python3", import_paths=["lib/python", "lib/python/site-packages"]
        )
        BUILD_LAUNCHER.build(
            CONTROL / "launcher/madctl-launcher.c", self.launcher,
            active_record=str(self.activation), activation_uid=os.getuid(), system_uid=Path("/").stat().st_uid,
        )
        for name in ("state", "registry", "cache", "codex-home"):
            (self.root / name).mkdir(mode=0o700)
        key = self.root / "controller.key"; key.write_bytes(b"k" * 32); os.chmod(key, 0o400)
        tools = {}
        for name in ("git", "gh", "python3", "codex", "bwrap"):
            path = self.runtime / "bin/python3"
            tools[name] = {"path": str(path), "sha256": sha(path), "uid": os.getuid(), "gid": os.getgid(),
                           "root": str(self.runtime)}
        self.manifest = {
            "schema_version": 1, "trusted_uid": os.getuid(), "trusted_gid": os.getgid(),
            "trusted_system_uid": Path("/").stat().st_uid,
            "expected_mad_version": "2.0.0",
            "release_root": str(self.release), "release_digest": self.release_result["release_digest"],
            "inventory_digest": self.release_result["inventory_digest"],
            "native_launcher_path": str(self.launcher), "native_launcher_sha256": sha(self.launcher),
            "python_runtime_root": str(self.runtime), "python_executable": str(self.runtime / "bin/python3"),
            "python_runtime_digest": self.runtime_result["digest"],
            "python_runtime_inventory_digest": self.runtime_result["inventory_digest"],
            "state_root": str(self.root / "state"),
            "registry_root": str(self.root / "registry"),
            "human_approval_registry_root": str(self.root / "registry"), "cache_root": str(self.root / "cache"),
            "controller_key_path": str(key), "codex_home": str(self.root / "codex-home"), "tools": tools,
            "orka": {"root": str(self.orka), "version": "1.8.0", "digest": self.orka_result["digest"],
                     "inventory_digest": self.orka_result["inventory_digest"], "uid": os.getuid(), "gid": os.getgid()},
        }
        self._write_activation()

    def _write_activation(self) -> None:
        if self.activation.exists(): os.chmod(self.activation, 0o600)
        self.activation.write_bytes(json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        os.chmod(self.activation, 0o400)

    def _cleanup(self) -> None:
        make_writable(self.root)
        shutil.rmtree(self.root, ignore_errors=True)

    def _orka(self) -> tuple[Path, dict[str, str]]:
        source = self.root / "orka-source"
        for relative in REQUIRED_RUNTIME_FILES:
            path = source / relative; path.parent.mkdir(parents=True, exist_ok=True)
            if relative.endswith("plugin.json"):
                path.write_text(json.dumps({"name": "orka", "version": "1.8.0"}))
            else:
                path.write_text(f"# {relative}\n")
        target = self.root / "orka"
        return target, STAGE_ORKA.stage(source, target)

    def _run(self, *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        clean = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        if env: clean.update(env)
        return subprocess.run([str(self.launcher), "self-test"], cwd=cwd or self.root, env=clean,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def test_launcher_ignores_candidate_cwd_and_refuses_python_environment_shadowing(self) -> None:
        candidate = self.root / "candidate"; candidate.mkdir()
        sentinel = self.root / "executed"
        (candidate / "madctl.py").write_text(f"open({str(sentinel)!r}, 'w').write('bad')\n")
        (candidate / "sitecustomize.py").write_text(f"open({str(sentinel)!r}, 'w').write('bad')\n")
        (candidate / "usercustomize.py").write_text(f"open({str(sentinel)!r}, 'w').write('bad')\n")
        result = self._run(cwd=candidate, env={"PYTHONPATH": str(candidate), "PYTHONHOME": str(candidate),
                                               "PYTHONSTARTUP": str(candidate / "madctl.py"), "PYTHONINSPECT": "1",
                                               "PYTHONWARNINGS": "error", "LD_LIBRARY_PATH": str(candidate)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())
        fake = self.root / "fake"; (fake / "madctl").mkdir(parents=True)
        (fake / "madctl/__init__.py").write_text(f"open({str(sentinel)!r}, 'w').write('bad')\n")
        (fake / "sitecustomize.py").write_text(f"open({str(sentinel)!r}, 'w').write('bad')\n")
        (fake / "usercustomize.py").write_text(f"open({str(sentinel)!r}, 'w').write('bad')\n")
        result = self._run(env={"PYTHONPATH": str(fake), "PYTHONHOME": str(fake), "PYTHONUSERBASE": str(fake)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())

    def test_static_launcher_loader_attacks_cannot_run_before_trust(self) -> None:
        library = self.root / "marker.c"
        marker = self.root / "loader-marker"
        library.write_text(
            f'#include <stdio.h>\n__attribute__((constructor)) static void x(void){{FILE*f=fopen("{marker}","w");if(f){{fputs("bad",f);fclose(f);}}}}\n'
        )
        shared = self.root / "marker.so"
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(shared), str(library)], check=True)
        self.manifest["release_digest"] = "0" * 64
        self._write_activation()
        for variable in ("LD_PRELOAD", "LD_AUDIT"):
            marker.unlink(missing_ok=True)
            result = self._run(env={variable: str(shared)})
            self.assertEqual(result.returncode, 126)
            self.assertFalse(marker.exists(), variable)
        info = subprocess.run(["file", str(self.launcher)], text=True, stdout=subprocess.PIPE, check=True).stdout
        self.assertIn("statically linked", info)
        linked = subprocess.run(["ldd", str(self.launcher)], text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, check=False).stdout
        self.assertIn("not a dynamic executable", linked)

    def test_native_launcher_rejects_inventory_bound_external_elf_dependency_before_execution(self) -> None:
        if sysconfig.get_platform() != "linux-x86_64":
            self.skipTest("negative pre-exec constructor fixture is specific to the supported linux-x86_64 contract")
        host_python = Path(sys.executable).resolve()
        interpreter, _ = RealPythonTransitionTests._elf_metadata(host_python)
        if interpreter is None:
            self.skipTest("host has no dynamic ELF loader for the pre-exec negative fixture")
        runtime_lib = self.runtime / "lib"
        os.chmod(runtime_lib, 0o755)
        loader = runtime_lib / Path(interpreter).name
        shutil.copy2(Path(interpreter).resolve(), loader)
        os.chmod(loader, 0o555)
        os.chmod(runtime_lib, 0o555)

        outside = self.root / "outside-loader-path"
        outside.mkdir(mode=0o700)
        marker = self.root / "external-constructor-ran"
        library_source = self.root / "outside.c"
        library_source.write_text(
            "static long s(long n,long a,long b,long c,long d){long r;register long r10 __asm__(\"r10\")=d;"
            "__asm__ volatile(\"syscall\":\"=a\"(r):\"a\"(n),\"D\"(a),\"S\"(b),\"d\"(c),\"r\"(r10):\"rcx\",\"r11\",\"memory\");return r;}"
            f"__attribute__((constructor))static void init(void){{const char*p=\"{marker}\";long f=s(257,-100,(long)p,577,384);"
            "if(f>=0){const char*x=\"ran\\n\";s(1,f,(long)x,4,0);s(3,f,0,0,0);}}int outside(void){return 0;}\n"
        )
        external_library = outside / "liboutside.so"
        subprocess.run(
            ["gcc", "-shared", "-fPIC", "-nostdlib", "-fno-stack-protector", "-Wl,--build-id=none",
             "-Wl,-soname,liboutside.so", "-o", str(external_library), str(library_source)], check=True,
        )
        program_source = self.root / "external-program.c"
        program_source.write_text(
            "extern int outside(void);void _start(void){outside();__asm__ volatile(\"mov $60,%rax;xor %rdi,%rdi;syscall\");}\n"
        )
        replacement = self.root / "external-python"
        subprocess.run(
            ["gcc", "-nostdlib", "-fPIE", "-pie", "-fno-stack-protector", "-Wl,--build-id=none", "-Wl,-e,_start",
             f"-Wl,--dynamic-linker,{loader}", f"-Wl,-rpath,{outside}", "-Wl,--no-as-needed", "-L", str(outside),
             "-o", str(replacement), str(program_source), "-l:liboutside.so"], check=True,
        )
        python = self.runtime / "bin/python3"
        os.chmod(python.parent, 0o755)
        os.chmod(python, 0o755)
        python.write_bytes(replacement.read_bytes())
        os.chmod(python, 0o555)
        os.chmod(python.parent, 0o555)
        inventory = self.runtime / "python-runtime-files.json"
        entries = {
            path.relative_to(self.runtime).as_posix(): {
                "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}", "sha256": sha(path),
            }
            for path in sorted(item for item in self.runtime.rglob("*") if item.is_file() and item != inventory)
        }
        raw = STAGE_PYTHON.canonical({"schema_version": 1, "files": entries}) + b"\n"
        os.chmod(inventory, 0o644)
        inventory.write_bytes(raw)
        os.chmod(inventory, 0o444)
        self.manifest["python_runtime_digest"] = STAGE_PYTHON.digest(STAGE_PYTHON.canonical(entries))
        self.manifest["python_runtime_inventory_digest"] = STAGE_PYTHON.digest(raw)
        for tool in self.manifest["tools"].values():
            tool["sha256"] = sha(python)
        self._write_activation()
        result = self._run()
        self.assertEqual(result.returncode, 126, result.stderr)
        self.assertIn("ELF", result.stderr)
        self.assertFalse(marker.exists(), "external dependency constructor ran before native rejection")

    def test_python_module_entry_is_non_authoritative_and_loaded_path_escape_is_rejected(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "madctl", "self-test"],
            env={"PYTHONPATH": str(self.release / "python"), "PATH": "/usr/bin:/bin"},
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(result.returncode, 126)
        self.assertIn("non-authoritative", result.stderr)
        loader = importlib.machinery.SourceFileLoader("launcher_under_test", str(CONTROL / "launcher/madctl-launcher.py"))
        spec = importlib.util.spec_from_loader("launcher_under_test", loader)
        assert spec and spec.loader
        launcher_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(launcher_module)
        saved = {name: module for name, module in sys.modules.items() if name == "madctl" or name.startswith("madctl.")}
        try:
            for name in saved: sys.modules.pop(name, None)
            evil = types.ModuleType("madctl.evil"); evil.__file__ = str(self.root / "evil.py")
            (self.root / "evil.py").write_text("pass\n")
            sys.modules["madctl.evil"] = evil
            with self.assertRaises(launcher_module.LaunchError):
                launcher_module._verify_loaded_modules(self.release, json.loads((self.release / "release-files.json").read_bytes())["files"])
        finally:
            sys.modules.pop("madctl.evil", None); sys.modules.update(saved)

    def test_relative_activation_authority_path_fails_closed(self) -> None:
        self.manifest["release_root"] = "relative-release"
        self._write_activation()
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
