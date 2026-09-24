# MAD Architecture

## Current state

The current project has:

1. A public project repository.
2. Branch based development.
3. Isolated Git worktrees.
4. Engineering rules stored in `AGENTS.md`.
5. A mandatory Codex check before Pull Request creation.
6. Project documentation for the current and planned architecture.

Orka, DeepSeek workers, CI, deterministic tests and Pixel Agents integration are not implemented yet.

## Target architecture

### Codex

Codex will act as the Master Orchestrator and Engineering Manager.

Its responsibilities will include workflow coordination, supervision and two mandatory final checks.

The first check happens before a Pull Request is created.

The second check happens before a merge is allowed.

### Orka

Orka will provide the software development workflow.

It will manage isolated work, review stages, security review, QA and merge controls.

### DeepSeek V4.1 Flash

DeepSeek V4.1 Flash will be the worker model.

Planned worker roles are:

1. Requirements Analyst
2. Solution Architect
3. Implementer
4. Code Reviewer
5. Security and Privacy Reviewer
6. QA Engineer
7. Visual QA when required

### Pixel Agents

Pixel Agents will provide visual monitoring for the MAD workflow.

It will represent agent activity, task status, reviews, failures and approvals.

If direct integration is not sufficient, MAD will include a bridge between the engineering workflow and Pixel Agents.

## Planned development flow

1. A task enters the workflow.
2. Codex interprets and coordinates the request.
3. Requirements are checked.
4. An implementation plan is prepared.
5. Work starts in an isolated branch and worktree.
6. A worker implements the change.
7. Another worker performs code review.
8. Security and privacy review runs independently.
9. QA and deterministic tests run.
10. Codex performs the mandatory check before PR creation.
11. The Pull Request is created.
12. Required checks run against the PR.
13. Codex performs the mandatory check before merge.
14. Merge controls validate the result.
15. The approved change reaches `main`.
16. Pixel Agents displays the workflow state.
