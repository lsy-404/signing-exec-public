# Stapling recovery

- [x] Fetch default branch and prepare an isolated worktree.
- [x] Mirror the reviewed shared app/DMG stapling implementation.
- [x] Verify existing shared runner tests and syntax checks.
- [x] Publish a pinned recipe after checking branch rules.

Missing-ticket and service failures retry with 5/15/45-second backoff. Other failures retain a safe numeric diagnostic. Existing signature, ticket and Gatekeeper checks remain required.

All 26 existing shared native/runner tests and syntax checks passed. Branch protection and rulesets were empty. Published runner-token-2026-10-14-1 and verified its commit, environment tag restriction, and signing-center approval.
