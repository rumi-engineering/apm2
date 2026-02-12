# Codex Fix Agent: PR #599 (TCK-00469) — Round 3

You are working in worktree `/home/ubuntu/Projects/apm2-TCK-00469` on branch `ticket/RFC-0028/TCK-00469`.

Main has already been merged. No merge step needed.

## Step 1: Read the fix prompt

Read `/home/ubuntu/Projects/apm2-TCK-00469/FIX_PROMPT_R3.md` and implement ALL 2 findings described there.

## Step 2: Implement Finding 1 — MAJOR: Post-compromise recovery proof is synthetic/in-memory

In `crates/apm2-daemon/src/projection/divergence_watchdog.rs`:

- Add `has_durable_provenance: bool` field (default `false`) and `durable_evidence_digest: Option<Hash>` to the recovery state stored in the in-memory `projection_recovery_state` HashMap
- Add new error variant `DivergenceError::ProjectionRecoveryNotDurable { freeze_id: String }`
- Modify `verify_projection_recovery_state()` to check `has_durable_provenance == true`; return `ProjectionRecoveryNotDurable` if false
- Add public method `register_durable_recovery_evidence(&self, freeze_id: &str, receipts: Vec<ProjectionReplayReceiptV1>, durable_evidence_digest: Hash, sequence_bounds: ReplaySequenceBoundsV1) -> Result<(), DivergenceError>`
  - Validates freeze_id refers to active freeze
  - Validates durable_evidence_digest is non-zero
  - Validates receipts via `reconstruct_projection_state()` against snapshots and trusted authority bindings
  - Updates recovery state: set `has_durable_provenance = true`, store digest
- Update existing tests `test_watchdog_create_unfreeze` and `test_full_freeze_unfreeze_cycle` to call `register_durable_recovery_evidence()` before `create_unfreeze()`
- Add negative test `test_unfreeze_fails_without_durable_provenance`: trigger divergence, call `create_unfreeze()` WITHOUT registering durable evidence, assert `ProjectionRecoveryNotDurable` error

## Step 3: Implement Finding 2 — MAJOR: Temporal authority is self-attested

In `crates/apm2-daemon/src/projection/divergence_watchdog.rs`:

- Add `trusted_time_authority_bindings: Vec<AuthorityKeyBindingV1>` field to `DivergenceWatchdogConfig`
- Initialize to `Vec::new()` in `DivergenceWatchdogConfig::new()`
- Add builder `with_trusted_time_authority_bindings(mut self, bindings: Vec<AuthorityKeyBindingV1>) -> Result<Self, DivergenceError>`
- Modify `trusted_authority_bindings()`: if `self.config.trusted_time_authority_bindings` is non-empty, return those; else fall back to local signer (backward compat)
- Add `pending_time_authority_envelope: Mutex<Option<TimeAuthorityEnvelopeV1>>` field to `DivergenceWatchdog`
- Add `provide_time_authority_envelope(&self, envelope: TimeAuthorityEnvelopeV1) -> Result<(), DivergenceError>` method
- Modify `resolve_temporal_authority()`: check `pending_time_authority_envelope` first — if present, verify and use it instead of self-issuing
- Add negative test `test_temporal_authority_rejects_self_issued_when_external_configured`: create watchdog with external bindings, attempt `check_divergence()`, assert `InvalidTemporalAuthority` error
- Add positive test `test_temporal_authority_accepts_external_envelope`: create external signer, configure watchdog with external bindings, provide externally-signed envelope, verify success

## CRITICAL PATTERNS

- Transactional state mutations: check admission BEFORE mutating state
- Fail-closed semantics: never default to pass
- Wire production paths: no dead code / unused methods
- Binding test evidence: no zero-count assertions
- Deterministic behavior: domain-separated BLAKE3 with versioned prefixes

## Step 4: Pre-Commit Steps (MANDATORY — do ALL in order)

```bash
cd /home/ubuntu/Projects/apm2-TCK-00469
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core
cargo test -p apm2-daemon
```

You MUST pass ALL CI checks. Fix every warning and error before committing.

## Step 5: Commit and Push

```bash
cd /home/ubuntu/Projects/apm2-TCK-00469
git add -A
git commit -m "fix(TCK-00469): durable recovery provenance gate, external temporal authority bindings"
git push
```
