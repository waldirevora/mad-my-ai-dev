# MAD Agent Rules

## Engineering rules

1. Never work directly on `main`.
2. Use an isolated branch and worktree for development.
3. The implementer must not review its own code.
4. Security review must be independent.
5. QA must produce objective evidence.
6. Failing tests block progression.
7. Critical security findings block progression.
8. Codex must perform a final check before any Pull Request is created.
9. Codex must perform another final check before any merge.
10. Secrets must never be committed.
11. Agents must not expand their own permissions.
12. Unknown business rules must be returned to the orchestrator.
13. Production must not be changed directly by workers.
14. High risk changes require human approval.
15. Pixel Agents is a permanent part of the MAD architecture.
