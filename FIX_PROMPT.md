# Fix Task: PR #593 (TCK-00468) — Review Round 1

## Context
You are fixing review findings for PR #593 (TCK-00468: RFC-0028 REQ-0008 projection isolation and direct-GitHub authority elimination).

Branch: `ticket/RFC-0028/TCK-00468`
Worktree: `/home/ubuntu/Projects/apm2-TCK-00468`
Current HEAD: `9caa0539`

## Review Results
- **Security Review: PASS** (no findings)
- **Code Quality Review: FAIL** — 1 BLOCKER

## BLOCKER Finding (MUST FIX)

### Direct GitHub actuation deny can be bypassed through wrapped `execute` commands

**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs:2255`

**Problem:** `detect_direct_github_runtime_attempt` only denies `execute` when the primary executable is `gh` or the raw command string contains `api.github.com`. Wrapped forms like `bash -lc gh api ...` (or other interpreter indirection) bypass this guard while still directly actuating GitHub, violating REQ-0008 acceptance criteria for denying any direct gh/GitHub API attempt from production `agent_runtime`.

**Required Fix:**
1. Expand detection/enforcement to cover wrapped command vectors (e.g., `sh|bash -c`, `env ... gh`, interpreter wrappers)
2. Add regression tests proving these attempts are denied with structured defects
3. The detection should handle at minimum:
   - `bash -c "gh api ..."`
   - `sh -c "gh pr ..."`
   - `env gh api ...`
   - `bash -lc "gh ..."` (with shell options)
   - Nested `api.github.com` in shell argument strings

## MANDATORY Pre-Commit Steps (in this exact order)

You MUST run ALL of these and fix any issues BEFORE committing:
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks. Do not push code that fails any of these.

## Push Workflow

After all pre-commit steps pass:
```bash
git add -A
git commit -m "fix(TCK-00468): harden GitHub actuation detection for wrapped command vectors"
apm2 fac push --ticket documents/work/tickets/TCK-00468.yaml
```
