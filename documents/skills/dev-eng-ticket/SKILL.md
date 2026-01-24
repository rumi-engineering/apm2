---
name: dev-eng-ticket
description: Orchestrate full development workflow for an RFC's engineering tickets. Processes tickets in dependency order, implements each, creates PRs, runs AI reviews, iterates until merged, then continues to next ticket.
user-invocable: true
---

## Procedure

### 1. Parse Arguments

- `$1`: Ticket ID (e.g., `TCK-00049`) - the ticket to implement

### 2. Initialize Development Environment

```bash
cd "$(cargo xtask start-ticket $1 --print-path)"
```

Read the output carefully. It provides all context needed to implement the ticket.

### 3. Process Ticket

a. **Implement** following coding standards in `documents/coding/SKILL.md`:
   - Use the prompt from `references/IMPLEMENT_TICKET_PROMPT.md`
   - Substitute `$TICKET_ID` and `$RFC_ID` with actual values
   - Follow the implementation guidelines in that prompt

b. **Run automated checks, sync your branch, and commit** using the commit command. Expect errors to occur during automated checks. We maintain an extremely high bar for code, and it is up to you to maintain that bar.:
   ```bash
   cargo xtask commit "<description>"
   ```

### 4. Push, Create PR, and Run AI Reviews

```bash
cargo xtask push
```

This pushes your branch, creates/updates the PR, requests security + code quality reviews, and enables auto-merge. The PR will merge automatically once CI and reviews pass. Use `--force-review` to re-run reviews on the same commit.

### 5. CI → Review → Merge Loop

Use the status check command to monitor progress and get actionable guidance:

```bash
cargo xtask check
```

The command reports current state and suggests the next action:

| State | Suggested Action |
|-------|------------------|
| Uncommitted changes | `cargo xtask commit '<message>'` |
| No PR exists | `cargo xtask push` |
| CI running | Wait (use `--watch` to poll) |
| CI failed | See `documents/coding/references/CI_EXPECTATIONS.md` |
| Reviews pending | Wait for reviews (auto-merge enabled) |
| Reviews failed | Address feedback, commit, re-push with `--force-review` |
| All passed | Wait for auto-merge, then cleanup worktree |
| Already merged | Cleanup worktree and continue to next ticket |

For continuous monitoring: `cargo xtask check --watch`

#### After Merge

1. Cleanup and continue:
   ```bash
   cargo xtask finish
   ```
2. Return to step 2 (initialize next ticket)

Note: Ticket status is derived from git state - branches indicate IN_PROGRESS, merged PRs indicate COMPLETED.

### 6. Complete

When all tickets are done (no more processable tickets in step 2), report completion.

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
| `cargo xtask check` | Check CI/review status and get next action |
| `cargo xtask check --watch` | Continuously poll status every 10s |
| `cargo xtask finish` | Cleanup worktree and branch after PR merges |
| `cargo xtask security-review-exec approve [TCK-XXXXX]` | Approve PR after security review |
| `cargo xtask security-review-exec deny [TCK-XXXXX] --reason <reason>` | Deny PR with reason |

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Worktree isolation | Prevents conflicts between parallel agents, enables independent CI |
| Branch naming: `ticket/[RFC-XXXX/]TCK-XXXXX` | Traceable to RFC (if present) and ticket |
| Worktree naming: `apm2-{TICKET_ID}` | Clear association with ticket |
| Derive status from git state | Single source of truth, no manual updates needed |
| Idempotent commands | Safe to re-run, handles existing state gracefully |
| AI reviews via local CLIs | No self-hosted runners needed, uses local auth |
| Status checks for merge gating | Reviews block merge until passed |
| Strict dependency ordering | Prevents invalid implementation sequences |
| Rebase before push | Keeps history linear, catches conflicts early |
| Poll CI every 10s for first failure | Errors surface in seconds; don't wait for full run |
| Use `--log-failed` flag | Returns only failed step logs, not entire run output |
| Verify fmt+clippy+test BEFORE commit | Catches 90% of CI failures locally |
| CI must pass before review matters | Never waste time on broken code |
| Cleanup after merge | Remove worktree and branch to avoid clutter |
