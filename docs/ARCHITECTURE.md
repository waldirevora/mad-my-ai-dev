# MAD Architecture

## Current state

The current project has:

1. A public project repository.
2. Branch based development.
3. Isolated Git worktrees.
4. Engineering rules stored in `AGENTS.md`.
5. A Genesis candidate for the external MAD Final Gates v2 control plane.
6. Orka 1.8.0 declarative configuration and local conformance coverage.
7. Project documentation for the current and planned architecture.

MAD v2 is not installed or activated yet. Until the Genesis ceremony finishes,
its repository hook is defense in depth only and PR/merge operations remain
manual. GitHub server-side protection, CI, production signing credentials,
worker orchestration, and Pixel Agents integration remain external work.

The normative gate architecture and its limitations are documented in
[`MAD_FINAL_GATES_V2.md`](MAD_FINAL_GATES_V2.md).

## Target architecture

### Codex

Codex acts as the critical independent verifier for MAD final gates.

Its responsibilities will include workflow coordination, supervision and two mandatory final checks.

The first check happens before a Pull Request is created through the installed
control plane.

The second check happens against a fresh PR head before a merge is allowed.

### Orka

Orka 1.8.0 provides the software development review workflow where it is safe
to reuse it.

It will manage isolated work, review stages, security review, QA and merge controls.

### Model strategy

Normal implementation uses GPT-5.6 Terra Medium. Security architecture, final
review, pre-PR, and pre-merge critical review use GPT-5.6 Sol High. The installed
verifier pins its critical model, effort, executable, and ChatGPT authentication.

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
