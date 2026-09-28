# MAD | My AI Dev

MAD is a personal project for studying and building a software engineering workflow operated with AI agents.

The project is in its early development stage. The current repository contains
the proposed MAD Final Gates v2 Genesis source, engineering rules, documentation,
and Git workflow. It is not an activated production control plane.

## Current state

The following parts are already in place:

1. Public project repository.
2. Development with isolated branches and worktrees.
3. Engineering rules defined in `AGENTS.md`.
4. Candidate source and tests for a future externally installed, statically
   launched and digest-pinned MAD controller, closed Python runtime, and
   independent Codex review gate.
5. Documentation that separates candidate capabilities from externally activated
   production guarantees.

## Planned architecture

The planned deployment and later versions will add:

1. Root-owned closed-inventory MAD, Python, and Orka 1.8.0 runtimes activated by
   a static native trust anchor.
2. DeepSeek V4.1 Flash as the worker model.
3. Independent implementation, code review, security review and QA roles.
4. CI and deterministic tests.
5. A second mandatory Codex check before merge.
6. Pixel Agents as the visual layer for agent activity and workflow status.
7. A MAD Pixel Bridge if direct integration is not sufficient.

## Development approach

MAD is being built in small, validated steps.

Each component is added only after the previous stage is reviewed and understood.

The goal is to build the workflow while learning how each part works in practice.

## Status

Early development.

This repository is also part of my practical study and technical portfolio.
