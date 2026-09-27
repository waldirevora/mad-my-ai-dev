from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

from .errors import AuthorityError, IndeterminateExternalResult
from .gitops import TrustedTool, sanitized_env


class GitHubAdapter(Protocol):
    def repository_identity(self, name_with_owner: str) -> dict[str, Any]: ...
    def branch_sha(self, name_with_owner: str, branch: str) -> str: ...
    def pr(self, name_with_owner: str, pr: int | str) -> dict[str, Any]: ...
    def create_pr(self, name_with_owner: str, *, base: str, head: str, title: str, body: str, draft: bool) -> dict[str, Any]: ...
    def reconcile_pr(self, name_with_owner: str, *, base: str, head: str, head_sha: str) -> dict[str, Any] | None: ...
    def required_checks_green(self, name_with_owner: str, pr: int, head_sha: str) -> bool: ...
    def merge_pr(self, name_with_owner: str, *, pr: int, expected_head: str, strategy: str) -> dict[str, Any]: ...


class SubprocessGitHubAdapter:
    def __init__(self, gh: TrustedTool) -> None:
        self.gh = gh

    def _run(self, args: list[str], *, timeout: int = 60, indeterminate_on_failure: bool = False) -> bytes:
        executable = self.gh.revalidate()
        try:
            result = subprocess.run(
                [str(executable), *args],
                env=sanitized_env(path_entries=(executable.parent, Path("/usr/bin"), Path("/bin"))),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise IndeterminateExternalResult("GitHub command timed out") from exc
        if result.returncode:
            message = result.stderr.decode("utf-8", "replace")[:2000] or "GitHub command failed"
            if indeterminate_on_failure:
                raise IndeterminateExternalResult(message)
            raise AuthorityError(message)
        return result.stdout

    def _json(self, args: list[str]) -> Any:
        try:
            return json.loads(self._run(args))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AuthorityError(f"GitHub returned malformed JSON: {exc}") from exc

    def repository_identity(self, name_with_owner: str) -> dict[str, Any]:
        value = self._json(["repo", "view", name_with_owner, "--json", "databaseId,nameWithOwner,url"])
        host = str(value.get("url", "")).split("/")[2] if "://" in str(value.get("url", "")) else ""
        return {"host": host, "database_id": value.get("databaseId"), "name_with_owner": value.get("nameWithOwner")}

    def branch_sha(self, name_with_owner: str, branch: str) -> str:
        value = self._json(["api", f"repos/{name_with_owner}/git/ref/heads/{quote(branch, safe='')}"])
        return str((value.get("object") or {}).get("sha") or "").lower()

    def pr(self, name_with_owner: str, pr: int | str) -> dict[str, Any]:
        text = str(pr).strip()
        if text.isdecimal():
            number = int(text)
        else:
            match = re.fullmatch(r"https://github\.com/[^/]+/[^/]+/pull/([1-9][0-9]*)", text)
            if not match:
                raise AuthorityError("GitHub returned a noncanonical PR identifier")
            number = int(match.group(1))
        value = self._json(["api", f"repos/{name_with_owner}/pulls/{number}"])
        try:
            head = value["head"]
            base = value["base"]
            head_repo = head["repo"]
            base_repo = base["repo"]
            state = "MERGED" if value.get("merged") is True else str(value["state"]).upper()
            return {
                "repository": base_repo["full_name"], "number": int(value["number"]),
                "state": state, "draft": bool(value["draft"]),
                "head_repo_id": int(head_repo["id"]), "head_branch": head["ref"], "head_sha": str(head["sha"]).lower(),
                "base_repo_id": int(base_repo["id"]), "base_branch": base["ref"], "base_sha": str(base["sha"]).lower(),
                "url": value.get("html_url"), "merge_commit_sha": value.get("merge_commit_sha"),
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorityError("GitHub returned malformed REST PR metadata") from exc

    def create_pr(self, name_with_owner: str, *, base: str, head: str, title: str, body: str, draft: bool) -> dict[str, Any]:
        args = ["pr", "create", "--repo", name_with_owner, "--base", base, "--head", head, "--title", title, "--body", body]
        if draft:
            args.append("--draft")
        url = self._run(args, indeterminate_on_failure=True).decode("utf-8", "strict").strip()
        try:
            return self.pr(name_with_owner, url)
        except AuthorityError as exc:
            raise IndeterminateExternalResult("PR was submitted but authoritative metadata could not be re-read") from exc

    def reconcile_pr(self, name_with_owner: str, *, base: str, head: str, head_sha: str) -> dict[str, Any] | None:
        values = self._json([
            "pr", "list", "--repo", name_with_owner, "--state", "all", "--base", base,
            "--head", head, "--json", "number,headRefOid,baseRefName,headRefName",
        ])
        matches = [item for item in values if item.get("headRefOid", "").lower() == head_sha and item.get("baseRefName") == base and item.get("headRefName") == head]
        if len(matches) > 1:
            raise AuthorityError("ambiguous PR reconciliation result")
        return self.pr(name_with_owner, matches[0]["number"]) if matches else None

    def required_checks_green(self, name_with_owner: str, pr: int, head_sha: str) -> bool:
        value = self._json(["pr", "checks", str(pr), "--repo", name_with_owner, "--required", "--json", "state,link,name"])
        return bool(value) and all(item.get("state") == "SUCCESS" for item in value)

    def merge_pr(self, name_with_owner: str, *, pr: int, expected_head: str, strategy: str) -> dict[str, Any]:
        if strategy != "squash":
            raise AuthorityError("installed policy permits only squash merge")
        self._run(["pr", "merge", str(pr), "--repo", name_with_owner, "--squash", "--match-head-commit", expected_head], indeterminate_on_failure=True)
        return self.pr(name_with_owner, pr)


def canonical_pr_number(value: int | str) -> int:
    text = str(value)
    if not text.isascii() or not text.isdecimal() or text.startswith("0"):
        raise AuthorityError("PR must be a canonical positive decimal number")
    number = int(text)
    if number <= 0:
        raise AuthorityError("PR must be positive")
    return number
