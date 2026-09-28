from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_sha256, sha256_file
from .errors import AuthorityError, EvidenceError
from .gitops import TrustedTool, sanitized_env
from .inventory import verify_closed_inventory


REQUIRED_SCRIPTS = (
    "scripts/version_policy.py",
    "scripts/orchestration-engine.py",
    "scripts/review-ledger.py",
    "scripts/run-gates.sh",
    "scripts/run-verification.sh",
    "scripts/merge-guard.sh",
)

ORKA_INVENTORY = "orka-files.json"
REQUIRED_RUNTIME_FILES = set(REQUIRED_SCRIPTS) | {
    ".codex-plugin/plugin.json",
    ".claude-plugin/plugin.json",
    "scripts/context_pipeline.py",
    "scripts/review_permit.py",
    "scripts/operator_authority.py",
    "scripts/runtime_state.py",
}


@dataclass(frozen=True)
class OrkaRuntime:
    root: Path
    version: str
    digest: str
    inventory_digest: str = ""
    trusted_uid: int = -1
    trusted_gid: int | None = None

    @classmethod
    def load_trusted(
        cls,
        *,
        root: Path,
        expected_version: str,
        expected_digest: str,
        expected_inventory_digest: str,
        trusted_uid: int,
        trusted_gid: int | None = None,
    ) -> "OrkaRuntime":
        if expected_version != "1.8.0":
            raise AuthorityError("trusted Orka version must be exactly 1.8.0")
        verify_closed_inventory(
            root,
            inventory_name=ORKA_INVENTORY,
            expected_inventory_digest=expected_inventory_digest,
            expected_tree_digest=expected_digest,
            trusted_uid=trusted_uid,
            trusted_gid=trusted_gid,
            required_paths=REQUIRED_RUNTIME_FILES,
        )
        manifests = []
        for relative in (".codex-plugin/plugin.json", ".claude-plugin/plugin.json"):
            try:
                manifests.append(json.loads((root / relative).read_bytes()))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AuthorityError(f"trusted Orka manifest is malformed: {relative}") from exc
        if any(item.get("name") != "orka" or item.get("version") != expected_version for item in manifests):
            raise AuthorityError("trusted Orka manifests do not match the activated version")
        return cls(root, expected_version, expected_digest, expected_inventory_digest, trusted_uid, trusted_gid)

    def verify(self) -> None:
        if self.trusted_uid < 0 or not self.inventory_digest:
            raise AuthorityError("Orka runtime is not an externally pinned closed runtime")
        verify_closed_inventory(
            self.root, inventory_name=ORKA_INVENTORY,
            expected_inventory_digest=self.inventory_digest, expected_tree_digest=self.digest,
            trusted_uid=self.trusted_uid, required_paths=REQUIRED_RUNTIME_FILES,
            trusted_gid=self.trusted_gid,
        )


class OrkaDiscovery:
    def __init__(self, codex: TrustedTool, codex_home: Path, plugin_cache_root: Path) -> None:
        self.codex = codex
        self.codex_home = codex_home.resolve(strict=True)
        self.plugin_cache_root = plugin_cache_root.resolve(strict=True)
        if plugin_cache_root.is_symlink() or plugin_cache_root != self.plugin_cache_root:
            raise AuthorityError("plugin cache root must be an explicit canonical path")

    def discover(self) -> OrkaRuntime:
        executable = self.codex.revalidate()
        result = subprocess.run(
            [str(executable), "plugin", "list", "--marketplace", "personal", "--json"],
            env=sanitized_env(
                path_entries=(executable.parent, Path("/usr/bin"), Path("/bin")),
                extra={"CODEX_HOME": str(self.codex_home)},
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        if result.returncode:
            raise AuthorityError("cannot read authoritative Codex plugin metadata")
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorityError(f"malformed Codex plugin metadata: {exc}") from exc
        installed = value.get("installed") if isinstance(value, dict) else None
        if not isinstance(installed, list):
            raise AuthorityError("Codex plugin metadata has no installed list")
        matches = [item for item in installed if isinstance(item, dict) and item.get("pluginId") == "orka@personal"]
        if len(matches) != 1:
            raise AuthorityError("expected exactly one installed orka@personal plugin")
        item = matches[0]
        if item.get("installed") is not True or item.get("enabled") is not True:
            raise AuthorityError("orka@personal is not installed and enabled")
        if item.get("version") != "1.8.0":
            raise AuthorityError("orka@personal version must be exactly 1.8.0")
        root = self.plugin_cache_root / "personal" / "orka" / "1.8.0"
        for component in (self.plugin_cache_root / "personal", self.plugin_cache_root / "personal/orka", root):
            if component.is_symlink():
                raise AuthorityError("Orka cache path must not contain symlinks")
        resolved = root.resolve(strict=True)
        try:
            resolved.relative_to(self.plugin_cache_root)
        except ValueError as exc:
            raise AuthorityError("Orka cache root escapes the trusted plugin cache") from exc
        manifests: list[dict[str, Any]] = []
        digest_map: dict[str, str] = {}
        for relative in (".codex-plugin/plugin.json", ".claude-plugin/plugin.json"):
            path = resolved / relative
            if not path.is_file() or path.is_symlink() or path.resolve() != path:
                raise AuthorityError(f"missing regular Orka manifest: {relative}")
            try:
                manifest = json.loads(path.read_bytes())
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AuthorityError(f"malformed Orka manifest: {relative}") from exc
            manifests.append(manifest)
            digest_map[relative] = sha256_file(path)
        if any(item.get("name") != "orka" or item.get("version") != "1.8.0" for item in manifests):
            raise AuthorityError("Orka manifests do not agree on name/version 1.8.0")
        for relative in REQUIRED_SCRIPTS:
            path = resolved / relative
            if not path.is_file() or path.is_symlink() or path.resolve() != path:
                raise AuthorityError(f"missing regular Orka script: {relative}")
            digest_map[relative] = sha256_file(path)
        return OrkaRuntime(resolved, "1.8.0", canonical_sha256(digest_map), "")


class OrkaInspector:
    """Reads controller-owned Orka ledger and marker using the validated runtime."""

    def __init__(self, runtime: OrkaRuntime, python: TrustedTool) -> None:
        self.runtime = runtime
        self.python = python

    def ledger_status(self, *, config: Path, ledger_dir: Path, pr: int) -> dict[str, Any]:
        self.runtime.verify()
        executable = self.python.revalidate()
        result = subprocess.run(
            [str(executable), str(self.runtime.root / "scripts/review-ledger.py"), "--config", str(config), "--ledger-dir", str(ledger_dir), "status", str(pr)],
            env=sanitized_env(path_entries=(executable.parent, Path("/usr/bin"), Path("/bin"))),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        if result.returncode:
            raise EvidenceError("Orka review ledger status failed")
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceError("Orka review ledger returned malformed JSON") from exc
        return value

    def assert_premerge(
        self,
        *,
        ledger: dict[str, Any],
        marker: Path,
        source_branch: str,
        source_sha: str,
        target_branch: str,
        target_sha: str,
        now: int | None = None,
        max_age: int = 3600,
    ) -> str:
        required = set(ledger.get("required_gates") or [])
        if ledger.get("next_action") != "gates-clear" or ledger.get("missing_gates") or {"code-review", "security-review"} - required:
            raise EvidenceError("Orka ledger is not gates-clear with both required reviews")
        if str(ledger.get("generation_head", "")).lower() != source_sha:
            raise EvidenceError("Orka review generation head does not match PR head")
        if not marker.is_file() or marker.is_symlink():
            raise EvidenceError("controller-owned Orka green marker is missing")
        raw = marker.read_bytes()
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise EvidenceError("Orka marker is not UTF-8") from exc
        if not text.startswith("all-green "):
            raise EvidenceError("Orka marker is not all-green")
        pairs = dict(re.findall(r"(?:^|\s)([a-z_]+)=([^\s]+)", text))
        expected = {
            "plugin_version": self.runtime.version,
            "head_branch": source_branch,
            "head_sha": source_sha,
            "base_branch": target_branch,
            "base_sha": target_sha,
        }
        if any(pairs.get(key) != value for key, value in expected.items()):
            raise EvidenceError("Orka marker identity is stale or mismatched")
        recorded = pairs.get("recorded_at", "")
        try:
            from datetime import datetime, timezone

            epoch = int(datetime.strptime(recorded, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
        except ValueError as exc:
            raise EvidenceError("Orka marker timestamp is invalid") from exc
        now = int(time.time()) if now is None else now
        age = now - epoch
        if age < -60 or age > max_age:
            raise EvidenceError("Orka marker is stale or from the future")
        return sha256_file(marker)
