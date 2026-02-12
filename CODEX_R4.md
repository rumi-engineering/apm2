# Codex Fix Agent: PR #599 (TCK-00469) — Round 4

You are working in worktree `/home/ubuntu/Projects/apm2-TCK-00469` on branch `ticket/RFC-0028/TCK-00469`.

No merge needed — branch is current with main.

## Step 1: Read the fix prompt

Read `/home/ubuntu/Projects/apm2-TCK-00469/FIX_PROMPT_R4.md` and implement the legitimate findings.

## Step 2: Fix BLOCKER — Unbounded resource consumption in `sorted_replay_receipts`

In `crates/apm2-core/src/fac/projection_compromise.rs`:

1. Add constant near the top of the file (after existing MAX_* constants):
```rust
const MAX_REPLAY_RECEIPTS: usize = 4096;
```

2. Add error variant to `ProjectionCompromiseError` (after `EmptyReceipts`):
```rust
/// Too many replay receipts provided.
#[error("too many replay receipts: {actual} exceeds maximum {max}")]
TooManyReceipts {
    /// Actual count provided.
    actual: usize,
    /// Maximum allowed.
    max: usize,
},
```

3. In `sorted_replay_receipts()`, add a size check BEFORE the `to_vec()` clone:
```rust
if receipts.len() > MAX_REPLAY_RECEIPTS {
    return Err(ProjectionCompromiseError::TooManyReceipts {
        actual: receipts.len(),
        max: MAX_REPLAY_RECEIPTS,
    });
}
```

4. Add a negative test `reconstruct_projection_state_rejects_excessive_receipts`:
   - Create a single valid receipt
   - Replicate it MAX_REPLAY_RECEIPTS + 1 times
   - Call `reconstruct_projection_state` with the excessive list
   - Assert it returns `TooManyReceipts` error

## Step 3: Fix MINOR — Add `crates/apm2-core/src/fac/AGENTS.md`

Create a module documentation file. Look at `crates/apm2-core/src/cac/AGENTS.md` as a template. Include:
- Module name: `fac` (Forge Admission Cycle)
- Purpose: Evidence gates, projection compromise detection, and admission policy enforcement
- Key types in the `projection_compromise` submodule
- Reference to RFC-0028 REQ-0009

## Step 4 (Optional Cleanup): Remove stale TODO in divergence_watchdog.rs

In `crates/apm2-daemon/src/projection/divergence_watchdog.rs`, lines 4-30 contain a stale TODO from TCK-00307 saying the watchdog is "not yet wired." This is false — it IS wired via main.rs. Remove or update this stale TODO.

## CRITICAL PATTERNS

- Fail-closed semantics: never default to pass
- Binding test evidence: no zero-count assertions
- Wire production paths: no dead code

## Step 5: Pre-Commit Steps (MANDATORY — do ALL in order)

```bash
cd /home/ubuntu/Projects/apm2-TCK-00469
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core
cargo test -p apm2-daemon
```

You MUST pass ALL CI checks. Fix every warning and error before committing.

## Step 6: Commit and Push

```bash
cd /home/ubuntu/Projects/apm2-TCK-00469
git add -A
git commit -m "fix(TCK-00469): bound replay receipts and add fac AGENTS.md (R4 quality)"
git push
```
