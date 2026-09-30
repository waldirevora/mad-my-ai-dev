"""Exclude experimental Orka modules from Python distributions."""
from __future__ import annotations

from setuptools import setup
from setuptools.command.build_py import build_py


class FilteredBuildPy(build_py):
    """Exclude experimental modules from every madctl package."""

    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(
            package, package_dir
        )
        if package != "madctl" and not package.startswith(
            "madctl."
        ):
            return modules

        return [
            entry
            for entry in modules
            if not entry[1].startswith("orka_")
        ]


setup(cmdclass={"build_py": FilteredBuildPy})
