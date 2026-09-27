from __future__ import annotations

from pathlib import Path
from typing import Any

from .activation import require_verified_activation
from .approvals import HumanApprovalVerifier, MachineApprovalIssuer
from .canonical import sha256_file
from .codex import CodexVerifier
from .controller import MadController
from .errors import AuthorityError
from .github import SubprocessGitHubAdapter
from .gitops import GitRunner, TrustedTool
from .orka import OrkaInspector, OrkaRuntime
from .policy import parse_policy
from .qa import InstalledSandbox, QaRunner
from .repository import RepositoryRegistry, reject_sensitive_environment
from .schemas import SchemaRegistry
from .state import EvidenceStore, HmacSigner


def load_installed_controller() -> MadController:
    """Build authority only from the external launcher's verified activation."""
    reject_sensitive_environment()
    activation = require_verified_activation()
    manifest = dict(activation.manifest)
    release_root = Path(manifest["release_root"])
    schemas = SchemaRegistry(release_root / "schemas")
    tools = manifest["tools"]
    if not isinstance(tools, dict) or set(tools) != {"git", "gh", "python3", "codex", "bwrap"}:
        raise AuthorityError("installed trusted tool inventory is malformed")
    trusted = {name: _trusted_tool(value, manifest["trusted_system_uid"]) for name, value in tools.items()}
    codex_home = Path(manifest["codex_home"])
    orka_record = manifest["orka"]
    if not isinstance(orka_record, dict) or set(orka_record) != {"root", "version", "digest", "inventory_digest", "uid", "gid"}:
        raise AuthorityError("activated Orka record is malformed")
    if orka_record["uid"] != manifest["trusted_uid"] or orka_record["gid"] != manifest["trusted_gid"]:
        raise AuthorityError("activated Orka ownership differs from the trusted activation identity")
    orka = OrkaRuntime.load_trusted(
        root=Path(orka_record["root"]), expected_version=orka_record["version"],
        expected_digest=orka_record["digest"], expected_inventory_digest=orka_record["inventory_digest"],
        trusted_uid=manifest["trusted_uid"],
        trusted_gid=manifest["trusted_gid"],
    )
    key_input = Path(manifest["controller_key_path"])
    if not key_input.is_absolute() or key_input.is_symlink():
        raise AuthorityError("controller signing key path must be absolute and non-symlink")
    key_path = key_input.resolve(strict=True)
    if key_path != key_input or not key_path.is_file():
        raise AuthorityError("controller signing key is not a canonical regular external file")
    key = key_path.read_bytes()
    registry = RepositoryRegistry(Path(manifest["registry_root"]), schemas)
    store = EvidenceStore(Path(manifest["state_root"]), schemas, HmacSigner(key))
    sandbox_profile = (release_root / "sandbox-profile.json").read_bytes()
    qa = QaRunner(schemas, InstalledSandbox(trusted["bwrap"], sandbox_profile), {"python3": trusted["python3"]})
    human = HumanApprovalVerifier(schemas)
    return MadController(
        schemas=schemas, registry=registry, store=store, git=GitRunner(trusted["git"]),
        github=SubprocessGitHubAdapter(trusted["gh"]), qa=qa,
        codex=CodexVerifier(trusted["codex"], codex_home, schemas), human=human,
        issuer=MachineApprovalIssuer(schemas, store), orka=orka,
        orka_inspector=OrkaInspector(orka, trusted["python3"]),
        release={"name": "madctl", "version": "2.0.0", "digest": manifest["release_digest"]},
        release_inventory_digest=manifest["inventory_digest"],
        release_root=release_root, orka_root=orka.root,
        genesis_policy=(release_root / "genesis-policy.json").read_bytes(),
        genesis_config=(release_root / "genesis-config.yaml").read_bytes(),
        cache_root=Path(manifest["cache_root"]),
    )


def source_self_test(source_root: Path) -> dict[str, Any]:
    """Non-authoritative source integrity check; it cannot construct a controller."""
    schemas = SchemaRegistry(source_root / "schemas")
    policy = parse_policy((source_root.parent / ".mad" / "policy.yaml").read_bytes())
    return {"schemas": len(schemas._schemas), "policy_sha256": policy.digest, "authoritative": False}


def _trusted_tool(value: Any, system_uid: int) -> TrustedTool:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "uid", "gid", "root"}:
        raise AuthorityError("trusted tool record is malformed")
    return TrustedTool.verify(
        Path(value["path"]), value["sha256"], expected_uid=value["uid"], expected_gid=value["gid"],
        system_uid=system_uid, allowed_root=Path(value["root"]),
    )


def _reject_git_tree(root: Path) -> None:
    if any((parent / ".git").exists() for parent in (root, *root.parents)):
        raise AuthorityError("authoritative MAD release must not run from a Git worktree")
