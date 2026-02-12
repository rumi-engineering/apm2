# Fix Prompt: Round 4 Code Quality Review (SHA fea83f88)

## Findings Summary

| # | Severity | Verdict | Description |
|---|----------|---------|-------------|
| 1 | BLOCKER | LEGITIMATE | Unbounded resource consumption in `reconstruct_projection_state` |
| 2 | MAJOR | FALSE POSITIVE | "Dead code, not wired into daemon" |
| 3 | MAJOR | DUPLICATE OF #1 | Unbounded allocation in `sorted_replay_receipts` |
| 4 | MINOR | LEGITIMATE | Missing `crates/apm2-core/src/fac/AGENTS.md` |

---

## Finding 1 (BLOCKER) + Finding 3 (MAJOR): Unbounded Receipts -- LEGITIMATE

### Root Cause

`reconstruct_projection_state()` at line 814 accepts `receipts: &[ProjectionReplayReceiptV1]`
with no upper bound. The helper `sorted_replay_receipts()` at line 997 calls `receipts.to_vec()`
which clones the entire slice without checking its size. Each `ProjectionReplayReceiptV1` is a
large struct (~400+ bytes with strings and 32/64-byte arrays), so providing millions of receipts
would exhaust memory before any signature verification even begins.

Finding 3 (MAJOR) about `sorted_replay_receipts` is the same issue -- the clone in
`sorted_replay_receipts` is the first allocation, and the signature verification loop in
`reconstruct_projection_state` is the CPU amplification. Fixing both in one change.

### Fix Instructions

**File**: `crates/apm2-core/src/fac/projection_compromise.rs`

1. Add a constant at line ~24 (after the existing `MAX_*` constants):
   ```rust
   const MAX_REPLAY_RECEIPTS: usize = 4096;
   ```
   Rationale: 4096 is generous for any real replay sequence. The existing sequence bounds
   already constrain the *expected* count, but we need a hard cap on the input slice to
   prevent allocation before bounds checking.

2. Add a new error variant to `ProjectionCompromiseError` (after `EmptyReceipts`):
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

3. In `sorted_replay_receipts()` (line 997), add a size check BEFORE the `to_vec()` clone:
   ```rust
   fn sorted_replay_receipts(
       receipts: &[ProjectionReplayReceiptV1],
   ) -> Result<Vec<ProjectionReplayReceiptV1>, ProjectionCompromiseError> {
       if receipts.is_empty() {
           return Err(ProjectionCompromiseError::EmptyReceipts);
       }
       if receipts.len() > MAX_REPLAY_RECEIPTS {
           return Err(ProjectionCompromiseError::TooManyReceipts {
               actual: receipts.len(),
               max: MAX_REPLAY_RECEIPTS,
           });
       }

       let mut sorted = receipts.to_vec();
       sorted.sort_by(|left, right| {
           left.sequence
               .cmp(&right.sequence)
               .then_with(|| left.receipt_id.cmp(&right.receipt_id))
       });
       Ok(sorted)
   }
   ```

4. Add a negative test at the bottom of the `tests` module:
   ```rust
   #[test]
   fn reconstruct_projection_state_rejects_excessive_receipts() {
       let signer = Signer::generate();
       let channel_id = "repo/main";
       let time_authority_ref = hash(0x21);
       let window_ref = hash(0x31);
       let (source_snapshot, sink_snapshot) = make_snapshots(
           channel_id,
           hash(0x41),
           hash(0x55),
           time_authority_ref,
           window_ref,
       );
       let source_digest = source_snapshot.snapshot_digest();
       let sink_digest = sink_snapshot.snapshot_digest();

       // Create a single valid receipt and replicate it beyond the limit.
       let receipt = ProjectionReplayReceiptV1::create_signed(
           "receipt-0",
           channel_id,
           0,
           hash(0x41),
           time_authority_ref,
           window_ref,
           source_digest,
           sink_digest,
           "projector-actor",
           &signer,
       )
       .expect("receipt must be valid");

       let excessive: Vec<_> = (0..super::MAX_REPLAY_RECEIPTS + 1)
           .map(|_| receipt.clone())
           .collect();

       let err = reconstruct_projection_state(
           channel_id,
           &excessive,
           &source_snapshot,
           &sink_snapshot,
           &[authority_binding("projector-actor", &signer)],
           bounds(0, super::MAX_REPLAY_RECEIPTS as u64),
       )
       .expect_err("excessive receipts must be rejected");

       assert!(
           matches!(err, ProjectionCompromiseError::TooManyReceipts { .. }),
           "expected TooManyReceipts, got {err:?}"
       );
   }
   ```

---

## Finding 2 (MAJOR): "Dead code, not wired into daemon" -- FALSE POSITIVE

### Evidence

The reviewer claims the projection compromise detection logic is "dead code" not wired into
the daemon. This is **false**. The evidence:

1. **`crates/apm2-daemon/src/main.rs` lines 1357-1450**: `DivergenceWatchdog` is instantiated
   with `DivergenceWatchdog::new(watchdog_signer, watchdog_config)` at line 1369, and its
   `check_divergence()` method is called at line 1450 inside a `tokio::spawn` background loop.

2. **`crates/apm2-daemon/src/projection/divergence_watchdog.rs` lines 100-101**: The watchdog
   imports and calls `detect_projection_divergence`, `quarantine_channel`, and
   `reconstruct_projection_state` from the `apm2_core::fac` module (the exact functions
   the reviewer says are "dead code").

3. **`crates/apm2-daemon/src/projection/divergence_watchdog.rs` line 2779**: `detect_projection_divergence`
   is called inside `on_divergence()`. Line 2811: `quarantine_channel` is called. Lines 3013,3090:
   `reconstruct_projection_state` is called in `verify_projection_recovery_state` and
   `register_durable_recovery_evidence`.

4. **`crates/apm2-daemon/src/protocol/session_dispatch.rs`**: The PR also adds temporal authority
   references to boundary quarantine channels (the diff shows `time_authority_ref` and `window_ref`
   fields being threaded through quarantine state).

5. **Integration tests exist**: `crates/apm2-daemon/tests/tck_00393_divergence_watchdog.rs`
   exercises the full watchdog lifecycle including `check_divergence` and `create_unfreeze`.

The reviewer likely confused the old TODO comment at the top of `divergence_watchdog.rs`
(lines 4-30, which was written during TCK-00307 and is now stale) with the actual integration
status. The TODO says "not yet wired" but the wiring was completed in a later ticket. The TODO
should be removed as cleanup, but this is cosmetic, not a functional deficiency.

**No code fix required.** However, as optional cleanup, the stale TODO at lines 4-30 of
`divergence_watchdog.rs` could be removed to prevent future reviewer confusion.

---

## Finding 4 (MINOR): Missing `fac/AGENTS.md` -- LEGITIMATE

### Evidence

Every other module directory under `crates/apm2-core/src/` has an `AGENTS.md` file (confirmed:
`adapter/`, `agent/`, `bootstrap/`, `cac/`, `budget/`, `config/`, `consensus/`, `crypto/`,
`determinism/`, `credentials/`, `events/`, `evidence/`, `github/`, `lease/`, `ledger/`, etc.).

The `fac/` directory does NOT have one. This is a legitimate gap in documentation conformance.

### Fix Instructions

Create `crates/apm2-core/src/fac/AGENTS.md` with a brief module overview. Follow the pattern
of `crates/apm2-core/src/cac/AGENTS.md` as a template. Include:

- Module name and one-line description
- Overview paragraph explaining the FAC module's purpose
- Key types and their roles (brief)
- The `projection_compromise` submodule and its RFC-0028 REQ-0009 controls

---

## Optional Cleanup: Remove Stale TODO in divergence_watchdog.rs

**File**: `crates/apm2-daemon/src/projection/divergence_watchdog.rs`

Lines 4-30 contain a TODO block from TCK-00307 stating the watchdog is "not yet wired into
the daemon's main execution path." This is no longer true -- the wiring was completed. Remove
this stale TODO to prevent future reviewer confusion. Replace with a brief note that the
watchdog is wired via `main.rs`.

---

## Pre-Commit Steps (MANDATORY)

After making all changes, run these in order:

```bash
cd /home/ubuntu/Projects/apm2-TCK-00469

# 1. Format
cargo fmt --all

# 2. Clippy (fix ALL warnings)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 3. Doc check
cargo doc --workspace --no-deps

# 4. Run relevant tests
cargo test -p apm2-core -- fac::projection_compromise
cargo test -p apm2-daemon -- projection::divergence_watchdog
```

You MUST pass ALL CI checks.

## Commit and Push

```bash
cd /home/ubuntu/Projects/apm2-TCK-00469

git add crates/apm2-core/src/fac/projection_compromise.rs
git add crates/apm2-core/src/fac/AGENTS.md
# Only if stale TODO cleanup is done:
# git add crates/apm2-daemon/src/projection/divergence_watchdog.rs

git commit -m "fix(TCK-00469): bound replay receipts and add fac AGENTS.md (R4 quality)

- Add MAX_REPLAY_RECEIPTS (4096) to sorted_replay_receipts to prevent
  unbounded allocation and CPU-bound DoS
- Add TooManyReceipts error variant to ProjectionCompromiseError
- Add negative test proving excessive receipts are rejected
- Add crates/apm2-core/src/fac/AGENTS.md for module documentation
- Finding 2 (dead code) is false positive: DivergenceWatchdog IS wired
  into daemon main.rs (line 1369/1450) and calls all projection_compromise
  functions"

git push origin ticket/RFC-0028/TCK-00469
```
