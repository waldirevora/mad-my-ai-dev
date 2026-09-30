"""Verify that experimental Orka code is absent from closed releases."""
from __future__ import annotations

import ast
import importlib.util
import json
import os
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "control-plane"

spec = importlib.util.spec_from_file_location(
    "experimental_release_gate_builder",
    CONTROL / "tools/build_release.py",
)
assert spec is not None and spec.loader is not None

BUILD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILD)


EXPERIMENTAL_MODULES = {
    "orka_attestation.py",
    "orka_capture.py",
    "orka_companion.py",
    "orka_durable_state.py",
    "orka_mock_boundary.py",
    "orka_peer_ipc.py",
    "orka_recovery_trust.py",
}


def required_release_paths() -> set[str]:
    """Read the launcher's literal required-file contract."""
    source = (
        CONTROL / "launcher/madctl-launcher.py"
    ).read_text(encoding="utf-8")

    tree = ast.parse(source)

    assignments = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == "REQUIRED_RELEASE_PATHS"
            for target in node.targets
        )
    ]

    assert len(assignments) == 1
    required = ast.literal_eval(assignments[0].value)

    assert type(required) is set
    assert all(type(item) is str for item in required)

    return required


def test_experimental_orka_modules_are_not_packaged(tmp_path):
    source_modules = {
        path.name
        for path in (
            CONTROL / "src/madctl"
        ).glob("orka_*.py")
    }

    # Detect newly introduced experimental modules instead of
    # silently considering the original seven an exhaustive set.
    assert EXPERIMENTAL_MODULES <= source_modules

    release = tmp_path / "release"
    archive = tmp_path / "release.zip"

    try:
        BUILD.build_release(ROOT, release)
        BUILD.build_zip(release, archive)

        inventory = json.loads(
            (release / "release-files.json").read_bytes()
        )

        assert inventory["schema_version"] == 1

        inventoried = set(inventory["files"])
        actual = {
            path.relative_to(release).as_posix()
            for path in release.rglob("*")
            if path.is_file()
        }

        assert actual == inventoried | {
            "release-files.json"
        }

        with ZipFile(archive) as zipped:
            archived = set(zipped.namelist())

        assert archived == actual

        for relative in actual:
            if relative.startswith("python/madctl/"):
                module_path = Path(relative).relative_to(
                    "python/madctl"
                )

                assert not BUILD._excluded_orka_experiment(
                    module_path
                ), relative

        for module in source_modules:
            assert (
                f"python/madctl/{module}"
                not in actual
            )

        # The existing operational Orka integration remains
        # in the release.
        assert "python/madctl/orka.py" in actual

        # Check the complete existing launcher contract,
        # not just a manually selected subset.
        assert required_release_paths() <= inventoried

    finally:
        # build_release deliberately closes directory modes.
        # Restore temporary-directory cleanup permissions.
        if release.exists():
            directories = [
                item
                for item in release.rglob("*")
                if item.is_dir()
            ]
            for directory in sorted(
                directories,
                key=lambda item: len(item.parts),
                reverse=True,
            ):
                os.chmod(directory, 0o755)
            os.chmod(release, 0o755)


def test_future_experimental_names_are_excluded():
    for relative in (
        "orka_future.py",
        "orka_future/__init__.py",
        "extensions/orka_future.py",
        "extensions/orka_future/helper.py",
    ):
        assert BUILD._excluded_orka_experiment(
            Path(relative)
        )

    for relative in (
        "orka.py",
        "controller.py",
        "extensions/approved.py",
    ):
        assert not BUILD._excluded_orka_experiment(
            Path(relative)
        )


def test_direct_wheel_excludes_experimental_modules(tmp_path):
    """Exercise setuptools itself, without installing the wheel."""
    import os
    import shutil
    import subprocess
    import sys
    from pathlib import PurePosixPath
    from zipfile import ZipFile

    source = tmp_path / "wheel-source"
    wheels = tmp_path / "wheels"
    source.mkdir()
    wheels.mkdir()

    for directory in ("src", "schemas", "launcher"):
        shutil.copytree(
            CONTROL / directory,
            source / directory,
            ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", "*.pyo", "*.egg-info"
            ),
        )

    for relative in (
        "pyproject.toml",
        "setup.py",
        "sandbox-profile.json",
        "genesis-policy.json",
        "genesis-config.yaml",
        "control-plane.lock.json",
        "release-metadata.json",
    ):
        shutil.copy2(
            CONTROL / relative,
            source / relative,
        )

    package = source / "src/madctl"

    # Future experimental modules and packages must also
    # be excluded, not merely today's seven files.
    (package / "orka_future_module.py").write_text(
        "VALUE = 1\n", encoding="utf-8"
    )

    experimental_package = (
        package / "orka_future_package"
    )
    experimental_package.mkdir()
    (experimental_package / "__init__.py").write_text(
        "VALUE = 2\n", encoding="utf-8"
    )

    nested = package / "wheel_gate_fixture"
    nested.mkdir()
    (nested / "__init__.py").write_text(
        "", encoding="utf-8"
    )
    (nested / "approved.py").write_text(
        "VALUE = 3\n", encoding="utf-8"
    )
    (nested / "orka_nested.py").write_text(
        "VALUE = 4\n", encoding="utf-8"
    )

    nested_experimental_package = (
        nested / "orka_nested_package"
    )
    nested_experimental_package.mkdir()
    (
        nested_experimental_package / "__init__.py"
    ).write_text(
        "VALUE = 5\n", encoding="utf-8"
    )

    env = dict(os.environ)
    env.update(
        PIP_NO_INDEX="1",
        PIP_NO_INPUT="1",
        PIP_DISABLE_PIP_VERSION_CHECK="1",
        PIP_NO_CACHE_DIR="1",
        PYTHONDONTWRITEBYTECODE="1",
        SOURCE_DATE_EPOCH="315532800",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--no-cache-dir",
            "--wheel-dir",
            str(wheels),
            str(source),
        ],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, (
        result.stdout[-3000:]
        + "\n"
        + result.stderr[-3000:]
    )

    artifacts = list(wheels.glob("*.whl"))
    assert len(artifacts) == 1

    with ZipFile(artifacts[0]) as archive:
        members = set(archive.namelist())

    assert "madctl/orka.py" in members
    assert (
        "madctl/wheel_gate_fixture/approved.py"
        in members
    )

    experimental = {
        member
        for member in members
        if member.startswith("madctl/")
        and any(
            part.startswith("orka_")
            for part in PurePosixPath(member).parts[1:]
        )
    }

    assert not experimental

    # The source copy still contains all original
    # experimental modules; the package configuration,
    # rather than deleting source, excludes them.
    for module in EXPERIMENTAL_MODULES:
        assert (package / module).is_file()


def test_wheel_builder_rejects_experimental_artifact(
    tmp_path, monkeypatch
):
    """A broken packaging configuration cannot pass the wrapper."""
    import importlib.util
    from zipfile import ZipFile

    import pytest

    path = CONTROL / "tools/build_wheel.py"
    spec = importlib.util.spec_from_file_location(
        "experimental_wheel_gate_builder", path
    )
    assert spec is not None and spec.loader is not None

    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    output = tmp_path / "wheels"
    output.mkdir()

    artifact = (
        output / "mad_final_gates-2.0.0-py3-none-any.whl"
    )

    with ZipFile(artifact, "w") as archive:
        archive.writestr(
            "madctl/orka.py", b"# operational\n"
        )
        archive.writestr(
            "madctl/orka_future.py", b"# experimental\n"
        )

    monkeypatch.setattr(
        builder.subprocess,
        "run",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        RuntimeError,
        match="experimental Orka source",
    ):
        builder.build(tmp_path, output)
