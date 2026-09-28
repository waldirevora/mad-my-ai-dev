from __future__ import annotations

import json
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from typing import Any

from .canonical import canonical_sha256, sha256_bytes
from .errors import EvidenceError


COMPILED_PROTECTED_PREFIXES = ("AGENTS.md",)

COMPILED_PROTECTED_SEGMENTS = frozenset({
    ".codex", ".github", ".mad", ".orchestration", "control-plane", "policies", "schemas",
    "scripts", "tests", ".circleci", ".gitlab", ".azure-pipelines", "security", "release",
    "releases", "packaging", "installer", "installers", "deploy", "deployment", "terraform",
    "helm", "kustomize", "signing", "provenance", "sbom", "gradle", ".buildkite", "requirements",
    ".ci", "ci", "workflows", "k8s", "kubernetes", "manifests", "sigstore",
    "ansible",
})

COMPILED_HIGH_RISK_BASENAMES = frozenset({
    "agents.md", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "pipfile.lock",
    "poetry.lock", "uv.lock", "pdm.lock", "tox.ini", "noxfile.py", "makefile",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "cargo.toml", "cargo.lock", "go.mod", "go.sum", "gemfile",
    "gemfile.lock", "pom.xml", "gradle.properties", "codeowners", ".pre-commit-config.yaml",
    "cmakelists.txt", "cmakepresets.json", "cmakeuserpresets.json", "requirements.in",
    "constraints.txt", "composer.json", "composer.lock", "deno.json", "deno.jsonc", "deno.lock",
    "flake.nix", "flake.lock", "podfile", "podfile.lock", "mix.exs", "mix.lock", "pubspec.yaml",
    "pubspec.lock", "workspace", "workspace.bazel", "module.bazel", "renovate.json", "renovate.json5",
    ".gitlab-ci.yml", ".gitlab-ci.yaml", "azure-pipelines.yml", "azure-pipelines.yaml",
    "bitbucket-pipelines.yml", "bitbucket-pipelines.yaml", ".travis.yml", ".travis.yaml",
    "jenkinsfile", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "gradlew", "gradlew.bat", "directory.build.props", "directory.build.targets",
    "directory.packages.props", "global.json", "nuget.config", "chart.yaml", "values.yaml",
    "kustomization.yaml", "kustomization.yml", "install.sh", "install.ps1", "cosign.pub",
    "manifest.in", ".drone.yml", ".drone.yaml", "appveyor.yml", "appveyor.yaml",
})

COMPILED_HIGH_RISK_GLOBS = (
    "requirements*.txt", "requirements*.in", "constraints*.txt", "constraints*.in",
    "dockerfile*", "containerfile*", "docker-compose*", "compose*.yml", "compose*.yaml",
    "bun.lock*", "*.csproj", "*.fsproj", "*.vbproj", "*.sln", "*.tf", "*.tfvars",
    "release-manifest.*", "release-metadata.*", "release*.json", "release*.toml", "release*.yml",
    "release*.yaml", "manifest*.json", "manifest*.toml", "manifest*.yml", "manifest*.yaml",
    "installer*", "install*.sh", "install*.ps1", "deploy*.json", "deploy*.yml", "deploy*.yaml",
    "deployment*.json", "deployment*.yml", "deployment*.yaml", "security*", "merge-policy*",
    "merge_policy*", "signing*", "cosign.*", "provenance*", "sbom*", "buildspec*",
    "cloudbuild*", "jenkinsfile*", "buildkite*", ".buildkite*", "slsa*", "sigstore*",
    "*.bzl", "build.bazel", "*.bazelrc", "*.nix", "ansible*.yml", "ansible*.yaml",
    "playbook*.yml", "playbook*.yaml",
)


@dataclass(frozen=True)
class Policy:
    raw: bytes
    value: dict[str, Any]

    @property
    def digest(self) -> str:
        return sha256_bytes(self.raw)

    @property
    def target_branch(self) -> str:
        return str(self.value["target_branch"])

    def challenge_ttl(self, stage: str) -> int:
        return int(self.value["challenge_ttl_seconds"][stage])

    def approval_ttl(self, operation: str) -> int:
        return int(self.value["machine_approval_ttl_seconds"][operation])

    @property
    def clock_skew(self) -> int:
        return int(self.value["maximum_clock_skew_seconds"])

    def qa_plan(self, classification: str) -> list[dict[str, Any]]:
        plan = self.value["qa_plans"].get(classification)
        if not isinstance(plan, list):
            raise EvidenceError(f"trusted policy has no QA plan for {classification}")
        return plan

    def qa_plan_digest(self, classification: str) -> str:
        return canonical_sha256(self.qa_plan(classification))


def parse_policy(raw: bytes) -> Policy:
    """Policy YAML is deliberately restricted to the JSON subset of YAML 1.2."""
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"policy must be canonical JSON-compatible YAML: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "target_branch",
        "merge_strategy",
        "draft_pr_allowed",
        "challenge_ttl_seconds",
        "machine_approval_ttl_seconds",
        "maximum_clock_skew_seconds",
        "documentation_paths",
        "protected_paths",
        "build_configuration_names",
        "qa_plans",
    }:
        raise EvidenceError("trusted policy has missing or unknown top-level fields")
    if value["schema_version"] != 1 or value["merge_strategy"] not in {"squash"}:
        raise EvidenceError("unsupported policy schema or merge strategy")
    if not isinstance(value["target_branch"], str) or not value["target_branch"]:
        raise EvidenceError("trusted policy target branch is invalid")
    for stage in ("pre-pr", "pre-merge"):
        ttl = value["challenge_ttl_seconds"].get(stage)
        if not isinstance(ttl, int) or ttl <= 0 or ttl > 3600:
            raise EvidenceError(f"invalid challenge TTL for {stage}")
    for operation in ("create-pr", "merge"):
        ttl = value["machine_approval_ttl_seconds"].get(operation)
        if not isinstance(ttl, int) or ttl <= 0 or ttl > 1800:
            raise EvidenceError(f"invalid approval TTL for {operation}")
    if not isinstance(value["maximum_clock_skew_seconds"], int) or not 0 <= value["maximum_clock_skew_seconds"] <= 300:
        raise EvidenceError("invalid maximum clock skew")
    for key in ("documentation_paths", "protected_paths", "build_configuration_names"):
        if not isinstance(value[key], list) or any(not isinstance(item, str) or not item for item in value[key]):
            raise EvidenceError(f"invalid {key}")
    plans = value["qa_plans"]
    required = {"genesis", "control-plane/high-risk", "code", "documentation-only"}
    if not isinstance(plans, dict) or set(plans) != required:
        raise EvidenceError("trusted policy QA plans are incomplete")
    for classification, entries in plans.items():
        if not isinstance(entries, list) or not entries:
            raise EvidenceError(f"zero QA checks for {classification}")
        identifiers: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"id", "tool", "args", "timeout_seconds"}:
                raise EvidenceError(f"malformed QA entry for {classification}")
            if not isinstance(entry["id"], str) or not entry["id"]:
                raise EvidenceError("QA check ID is empty")
            if entry["id"] in identifiers:
                raise EvidenceError(f"duplicate QA check ID for {classification}")
            identifiers.add(entry["id"])
            if not isinstance(entry["tool"], str) or not entry["tool"]:
                raise EvidenceError("QA tool is empty")
            if not isinstance(entry["args"], list) or any(not isinstance(arg, str) for arg in entry["args"]):
                raise EvidenceError("QA args must be strings")
            if not isinstance(entry["timeout_seconds"], int) or not 1 <= entry["timeout_seconds"] <= 900:
                raise EvidenceError("QA timeout is invalid")
            if entry["tool"] != "builtin" and not entry["args"]:
                raise EvidenceError("real QA command must not be empty")
    return Policy(raw=raw, value=value)


def validate_repo_path(path: str) -> None:
    candidate = PurePosixPath(path)
    if not path or candidate.is_absolute() or ".." in candidate.parts or "\x00" in path:
        raise EvidenceError(f"unsafe repository path: {path!r}")


def classify_paths(paths: list[str], policy: Policy, *, genesis: bool = False) -> tuple[str, list[str]]:
    if not paths:
        raise EvidenceError("no-change operations are refused")
    for path in paths:
        validate_repo_path(path)
    if genesis:
        return "genesis", ["explicit Genesis run"]
    protected = tuple(dict.fromkeys(COMPILED_PROTECTED_PREFIXES + tuple(policy.value["protected_paths"])))
    high_risk = sorted(
        path for path in paths
        if any(_matches_rule(path, prefix) for prefix in protected)
        or PurePosixPath(path).name in policy.value["build_configuration_names"]
        or _compiled_high_risk(path)
    )
    if high_risk:
        return "control-plane/high-risk", [f"protected path: {path}" for path in high_risk]
    docs = policy.value["documentation_paths"]
    if all(any(_matches_rule(path, item) for item in docs) for path in paths):
        return "documentation-only", []
    return "code", []


def _matches_rule(path: str, rule: str) -> bool:
    return path.startswith(rule) if rule.endswith("/") else path == rule


def _compiled_high_risk(path: str) -> bool:
    candidate = PurePosixPath(path)
    name = candidate.name.lower()
    all_parts = tuple(part.lower() for part in candidate.parts)
    parts = set(all_parts[:-1])
    authority_like = re.compile(
        r"(?:^|[-_.])(build|ci|deploy(?:ment)?|install(?:er)?|merge-policy|packag(?:e|ing)|"
        r"provenance|release|sbom|security|signing|workflow)(?:$|[-_.])"
    )
    return (
        bool(set(all_parts) & COMPILED_PROTECTED_SEGMENTS)
        or bool(parts & {"group_vars", "host_vars"})
        or ("roles" in parts and bool(parts & {"defaults", "files", "handlers", "meta", "tasks", "templates", "vars"}))
        or ("gradle" in parts and "wrapper" in parts)
        or name in COMPILED_HIGH_RISK_BASENAMES
        or any(fnmatchcase(name, pattern) for pattern in COMPILED_HIGH_RISK_GLOBS)
        or bool(authority_like.search(name))
    )
