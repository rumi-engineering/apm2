# Complete R2 Fixes: PR #599 (TCK-00469)

Branch: `ticket/RFC-0028/TCK-00469`, worktree: `/home/ubuntu/Projects/apm2-TCK-00469`

## Context

There are UNCOMMITTED partial R2 fixes already in the worktree (+665 insertions, -75 deletions across 4 files). A previous agent ran out of context before completing the work.

The R2 fixes address these review findings:
1. **BLOCKER**: Bind replay receipt trust to authority key set (in `projection_compromise.rs`)
2. **BLOCKER**: Require signed temporal authority envelope verification (in `divergence_watchdog.rs`)
3. **MAJOR**: Bind sink identity to concrete endpoint/key evidence (in `divergence_watchdog.rs`)
4. **MINOR**: Anchor replay sequence to required start boundary (in `projection_compromise.rs`)

## Your Task

1. First, read the existing uncommitted changes: `git diff HEAD`
2. Run `cargo fmt --all`
3. Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix ALL warnings
4. Run `cargo doc --workspace --no-deps` — fix any doc warnings
5. Run `cargo test -p apm2-core` — fix any failures
6. Run `cargo test -p apm2-daemon` (timeout 260s) — fix any failures
7. If ALL checks pass, commit and push

Fix any compilation errors, clippy warnings, or test failures found in the uncommitted changes. The partial changes were made by a competent agent but not tested before the session ended.

## REQUIRED READING (read ALL before editing any code)

- `documents/security/AGENTS.cac.json`
- `documents/security/THREAT_MODEL.cac.json`
- `documents/skills/rust-standards/references/34_security_adjacent_rust.md`
- `documents/skills/rust-standards/references/39_hazard_catalog_checklists.md`
- `documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md`

## Pre-commit checklist (CRITICAL — run IN ORDER)

1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix ALL warnings
3. `cargo doc --workspace --no-deps` — fix any doc warnings
4. `cargo test -p apm2-core` — ALL tests must pass
5. `cargo test -p apm2-daemon` — ALL daemon tests must pass (timeout 260s)
6. `git add -A && git commit -m "fix(TCK-00469): authority-bound replay receipts, signed temporal envelopes, endpoint-bound sink identity" && git push`

You MUST pass ALL CI checks.
