---
name: dev-eng-ticket
description: Orchestrate full development workflow for an RFC's engineering tickets. Processes tickets in dependency order, implements each, creates PRs, runs AI reviews, iterates until merged, then continues to next ticket.
---

## Procedure

### 1. Parse Arguments

- `$1`: Ticket ID (e.g., `TCK-00049`) - the ticket to implement

### 2. Initialize Development Environment

First, create the worktree and read the context:
```bash
cargo xtask start-ticket $1
```

Read the output carefully - it provides ticket details, RFC context, and file paths.

Then change to the worktree directory:
```bash
cd "$(cargo xtask start-ticket $1 --print-path)"
```

### 3. Process Ticket

#### 3.1 Read Ticket Definition

- Read `documents/work/tickets/$TICKET_ID.yaml` (complete ticket: metadata, scope, plan, criteria)
- Read all referenced requirements in `binds.requirements[]`
- Note: Implement ONLY `scope.in_scope`. Do NOT implement `scope.out_of_scope`.

#### 3.2 Quality Bar: Standard-Library Quality

Your code must be suitable for **deterministic simulated testing**:

- **Determinism by default**: No hidden time, randomness, or IO in core logic
  - Inject `Clock`, `IdGenerator`, `FileSystem` traits instead of calling directly
  - Core logic must be Markov-clean (same input → same output, always)

- **Evidence over narrative**: Prove correctness through:
  - Types and ownership (compile-time guarantees)
  - Tests (negative cases, boundaries, regression tests that fail without fix)
  - Tooling (clippy, miri for unsafe, property tests for state machines)

- **Local reasoning**: Correctness must not depend on hidden state or call ordering

#### 3.3 Write Tests First

- Tests must defend invariants, not just "doesn't panic"
- Include negative cases and boundary conditions
- State machines need property tests with reference model
- Happy-path-only = insufficient evidence

#### 3.4 Implement

Read `documents/skills/rust-textbook/SKILL.md` for comprehensive Rust reference. Follow reference documents as appropriate for the engineering task you're working on.

#### 3.5 Verify and Commit

Satisfy all criteria in `definition_of_done.criteria[]`, then:

```bash
cargo xtask commit "<description>"
```

Expect errors during automated checks. We maintain an extremely high bar for code.

### 4. Push, Create PR, and Run AI Reviews

```bash
cargo xtask push
```

This pushes your branch, creates/updates the PR, requests security + code quality reviews, and enables auto-merge. The PR will merge automatically once CI and reviews pass. Use `--force-review` to re-run reviews on the same commit.

### 5. CI → Review → Merge Loop

Use the status check command to monitor progress and get actionable guidance:

```bash
timeout 30s cargo xtask check
```

**Important**: Always run with `timeout 30s` - the command can hang indefinitely on certain states.

The command reports current state and suggests the next action:

| State | Suggested Action |
|-------|------------------|
| Uncommitted changes | `cargo xtask commit '<message>'` |
| No PR exists | `cargo xtask push` |
| CI running | Wait (use `--watch` to poll) |
| CI failed | See `documents/skills/coding/references/CI_EXPECTATIONS.md` |
| Reviews pending | Wait for reviews (auto-merge enabled) |
| Reviews failed | Address feedback, commit, re-push with `--force-review` |
| All passed | Wait for auto-merge, then cleanup worktree |
| Already merged | Cleanup worktree and continue to next ticket |

For continuous monitoring: `timeout 180s cargo xtask check --watch` (will exit on timeout)

#### After Merge

1. Cleanup and continue:
   ```bash
   cargo xtask finish
   ```
2. Return to step 2 (initialize next ticket)

Note: Ticket status is derived from git state - branches indicate IN_PROGRESS, merged PRs indicate COMPLETED.

### 6. Complete

When all tickets are done (no more processable tickets in step 2), output "Done" and nothing else. You're all done!

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `cargo xtask start-ticket` | Setup dev environment for next unblocked ticket (global) |
| `cargo xtask start-ticket RFC-XXXX` | Setup dev environment for next unblocked ticket in RFC |
| `cargo xtask start-ticket TCK-XXXXX` | Setup dev environment for specific ticket |
| `cargo xtask start-ticket [target] -p` | Output only worktree path (for `cd "$(...)"`) |
| `cargo xtask commit "<msg>"` | Verify, sync with main, and commit |
| `cargo xtask push` | Push, create/update PR, run AI reviews, enable auto-merge |
| `cargo xtask push --force-review` | Force re-run reviews even if already completed |
| `timeout 30s cargo xtask check` | Check CI/review status and get next action |
| `timeout 180s cargo xtask check --watch` | Continuously poll status every 10s (with timeout) |
| `cargo xtask finish` | Cleanup worktree and branch after PR merges |
| `cargo xtask security-review-exec approve [TCK-XXXXX]` | Approve PR after security review |
| `cargo xtask security-review-exec deny [TCK-XXXXX] --reason <reason>` | Deny PR with reason |
