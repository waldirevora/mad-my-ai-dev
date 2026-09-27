from __future__ import annotations

import json
import re
import shlex
from typing import Any


INSTALLED_MADCTL = "/usr/local/bin/madctl"
PROTECTED = re.compile(
    r"(?:\bgh\s+(?:pr\s+(?:create|merge)|api\b[^\n]*(?:/pulls\b|/merges\b))|"
    r"merge-on-green\.sh|mad-(?:create|merge)-pr\.sh|/pulls/[^\s]+/merge)",
    re.IGNORECASE,
)


def evaluate_event(raw: bytes) -> dict[str, str]:
    try:
        value: Any = json.loads(raw)
        if not isinstance(value, dict) or set(value) - {"tool_name", "tool_input", "cwd", "session_id", "transcript_path", "permission_mode", "hook_event_name"}:
            raise ValueError("unknown event fields")
        tool_input = value["tool_input"]
        if not isinstance(tool_input, dict) or set(tool_input) != {"command"}:
            raise ValueError("malformed tool_input")
        command = tool_input["command"]
        if not isinstance(command, str) or not command or "\x00" in command:
            raise ValueError("malformed command")
    except (KeyError, ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return {"decision": "block", "reason": "MAD defense-in-depth hook refused a malformed Bash event."}
    if not PROTECTED.search(command):
        return {"decision": "allow", "reason": "No obvious protected GitHub mutation was detected."}
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return {"decision": "block", "reason": "MAD refused an unparseable protected command."}
    allowed = (
        len(tokens) >= 3
        and tokens[0] == INSTALLED_MADCTL
        and tokens[1:3] in (["pr", "create"], ["pr", "merge"])
        and not any(token in command for token in (";", "&&", "||", "|", "\n", "`", "$("))
    )
    if allowed:
        return {"decision": "allow", "reason": "Command enters the installed MAD controller."}
    return {
        "decision": "block",
        "reason": "Use the installed madctl command. Repository scripts and direct GitHub mutation are not authoritative.",
    }
