from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .errors import MadError
from .github import canonical_pr_number
from .hook import evaluate_event
from .repository import reject_sensitive_environment
from .runtime import load_installed_controller, source_self_test


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="madctl")
    commands = root.add_subparsers(dest="command", required=True)
    repo = commands.add_parser("repository")
    repo_sub = repo.add_subparsers(dest="repository_command", required=True)
    register = repo_sub.add_parser("register")
    register.add_argument("--record", type=Path, required=True)
    validate = repo_sub.add_parser("validate")
    validate.add_argument("--repository-id", type=int, required=True)
    prepare = commands.add_parser("prepare")
    prep_sub = prepare.add_subparsers(dest="prepare_command", required=True)
    pre_pr = prep_sub.add_parser("pre-pr")
    pre_pr.add_argument("--repository-id", type=int, required=True)
    pre_pr.add_argument("--source-branch", required=True)
    pre_pr.add_argument("--candidate-checkout", type=Path, required=True)
    pre_pr.add_argument("--genesis", action="store_true")
    pre_merge = prep_sub.add_parser("pre-merge")
    pre_merge.add_argument("--repository-id", type=int, required=True)
    pre_merge.add_argument("--pr", required=True)
    qa = commands.add_parser("qa")
    qa.add_argument("--run-id", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--run-id", required=True)
    human = commands.add_parser("human-approval")
    human.add_argument("--run-id", required=True)
    human.add_argument("--operation", choices=("create-pr", "merge"), required=True)
    human.add_argument("--approval", type=Path, required=True)
    approval = commands.add_parser("approval")
    approval.add_argument("--run-id", required=True)
    approval.add_argument("--operation", choices=("create-pr", "merge"), required=True)
    pr = commands.add_parser("pr")
    pr_sub = pr.add_subparsers(dest="pr_command", required=True)
    create = pr_sub.add_parser("create")
    create.add_argument("--approval-id", required=True)
    create.add_argument("--title", required=True)
    create.add_argument("--body", required=True)
    create.add_argument("--draft", action="store_true")
    merge = pr_sub.add_parser("merge")
    merge.add_argument("--pr", required=True)
    merge.add_argument("--approval-id", required=True)
    self_test = commands.add_parser("self-test")
    self_test.add_argument("--source-root", type=Path)
    hook = commands.add_parser("hook")
    hook.add_argument("event", choices=("pre-tool-use",))
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "hook":
            print(json.dumps(evaluate_event(sys.stdin.buffer.read()), separators=(",", ":")))
            return 0
        if args.command == "self-test" and args.source_root:
            print(json.dumps(source_self_test(args.source_root.resolve(strict=True)), sort_keys=True))
            return 0
        reject_sensitive_environment()
        controller = load_installed_controller()
        result: Any
        if args.command == "repository":
            if args.repository_command == "register":
                if os.geteuid() != 0:
                    raise MadError("repository registration is a root-controlled Genesis/activation operation")
                record = _json_file(args.record)
                result = {"path": str(controller.register_repository(record))}
            else:
                record = controller.registry.load(args.repository_id)
                controller._assert_repository(record)
                result = record
        elif args.command == "prepare" and args.prepare_command == "pre-pr":
            result = controller.prepare_pre_pr(
                repository_id=args.repository_id, source_branch=args.source_branch,
                candidate_checkout=args.candidate_checkout, genesis=args.genesis,
            )
        elif args.command == "prepare":
            result = controller.prepare_pre_merge(repository_id=args.repository_id, pr=canonical_pr_number(args.pr))
        elif args.command == "qa":
            result = controller.run_qa(args.run_id)
        elif args.command == "verify":
            result = controller.run_codex(args.run_id)
        elif args.command == "human-approval":
            raw = args.approval.read_bytes()
            result = {"sha256": controller.verify_human_approval(args.run_id, _json_bytes(raw), operation=args.operation, raw=raw)}
        elif args.command == "approval":
            result = controller.create_machine_approval(args.run_id, operation=args.operation)
        elif args.command == "pr" and args.pr_command == "create":
            result = controller.create_pr(args.approval_id, title=args.title, body=args.body, draft=args.draft)
        elif args.command == "pr":
            result = controller.merge_pr(canonical_pr_number(args.pr), args.approval_id)
        else:
            result = controller.self_test()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (MadError, OSError, ValueError, KeyError) as exc:
        print(f"madctl: {exc}", file=sys.stderr)
        return 2


def _json_file(path: Path) -> dict[str, Any]:
    return _json_bytes(path.read_bytes())


def _json_bytes(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("JSON input must be an object")
    return value
