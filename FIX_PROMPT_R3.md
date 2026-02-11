# Fix Task: PR #593 (TCK-00468) — Review Round 3

## Context
Branch: `ticket/RFC-0028/TCK-00468`
Worktree: `/home/ubuntu/Projects/apm2-TCK-00468`
Current HEAD: `29c5dbd9`

Quality: PASS. Security: FAIL — 1 BLOCKER.

## BLOCKER: GH CLI bypass via command chaining operators

**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs` — `command_invokes_gh_cli_inner`

**Problem:** The detection function only parses the primary command from whitespace tokens. Commands using shell control operators (`;`, `&&`, `||`, `|`, newlines) can hide `gh` invocations in secondary command segments, bypassing detection.

Examples that bypass the current check:
- `true && gh api /repos/...`
- `echo ok; gh pr view ...`
- `bash -c "echo ok; gh api /repos"`
- `echo;gh api /repos` (no space around `;`)

**Required Fix:**
1. **Split on shell control operators** BEFORE analyzing command segments
2. Split the command string on `;`, `&&`, `||`, `|`, and newlines to get individual command segments
3. Run the existing `command_invokes_gh_cli_inner` detection on EACH segment
4. If ANY segment invokes `gh` or targets `api.github.com`, deny the entire command
5. Handle edge cases:
   - Operators inside quotes should NOT be treated as separators
   - Nested bash -c strings: recursively check the argument to `-c`
   - No-space variants: `echo;gh` (split on `;` regardless of spaces)
6. Add adversarial regression tests:
   - `true && gh api /repos/owner/repo` → DENY
   - `echo ok; gh pr view 123` → DENY
   - `echo;gh api /repos` → DENY
   - `bash -c "true && gh api /repos"` → DENY
   - `echo "gh api /repos"` → ALLOW (gh is inside echo's argument, not a command)

## MANDATORY Pre-Commit Steps (in this exact order)

You MUST run ALL of these and fix any issues BEFORE committing:
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks.

## Push Workflow

```bash
git add -A
git commit -m "fix(TCK-00468): detect gh CLI in all command chain segments"
apm2 fac push --ticket documents/work/tickets/TCK-00468.yaml
```
