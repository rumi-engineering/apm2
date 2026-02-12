# Fix Task: PR #599 (TCK-00469) — Round 3: Security Review Findings

Branch: `ticket/RFC-0028/TCK-00469`, worktree: `/home/ubuntu/Projects/apm2-TCK-00469`
HEAD: `edacfdbe`
Quality: PASS. Security: FAIL — 2 MAJORs.

---

## REQUIRED READING (read ALL before editing any code)

- `documents/rfcs/RFC-0028/requirements/REQ-0009.yaml`
- `documents/rfcs/RFC-0028/HOLONIC_EXTERNAL_IO_SECURITY.md` (sections 2.2, 2.3, 2.4)
- `documents/skills/rust-standards/references/42_distributed_security_invariants.md`
- `documents/skills/rust-standards/references/34_security_adjacent_rust.md`
- `documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md`

---

## MAJOR 1: Post-compromise recovery proof is synthetic/in-memory — unfreeze can be satisfied without real durable replay evidence

### Root Cause Analysis (5 Whys)

1. **Why does the unfreeze accept non-durable recovery proof?** Because `create_unfreeze()` (line 2952) calls `verify_projection_recovery_state()` which reads from `projection_recovery_state` — an in-memory `Mutex<HashMap>`.

2. **Why is the recovery state purely in-memory?** Because `on_divergence()` (line 2714-2748) creates a synthetic `ProjectionReplayReceiptV1` from `expected_head` and stores it directly into the in-memory map without any durable persistence step.

3. **Why doesn't the recovery verification require durable evidence?** Because `verify_projection_recovery_state()` (line 2839-2890) trusts whatever is in the in-memory map — there is no check that the receipt was loaded from a durable store (ledger or CAS).

4. **Why is this a security problem?** A compromised daemon instance could forge recovery state in memory (insert synthetic receipts into `projection_recovery_state`) and call `create_unfreeze()` to lift the freeze without actual post-compromise replay recovery. The freeze exists to block admission while the projection surface is compromised — bypassing it re-opens authority paths.

5. **Why wasn't this caught in round 2?** Round 2 addressed the self-attested key problem (receipt signature verification against trusted authority bindings), but the durable provenance problem is orthogonal — even correctly signed receipts that only exist in memory don't prove real replay recovery.

### Affected Code Locations

- `crates/apm2-daemon/src/projection/divergence_watchdog.rs:2714-2728` — `on_divergence()` creates synthetic receipt from `expected_head`
- `crates/apm2-daemon/src/projection/divergence_watchdog.rs:2730-2748` — stores receipt in in-memory `projection_recovery_state` only
- `crates/apm2-daemon/src/projection/divergence_watchdog.rs:2839-2890` — `verify_projection_recovery_state()` trusts in-memory state
- `crates/apm2-daemon/src/projection/divergence_watchdog.rs:2930-2952` — `create_unfreeze()` gates on in-memory verification only

### Required Fix

The core issue is that recovery state is stored only in-memory and the initial receipt is synthetic (created from `expected_head` at divergence detection time, not from an actual post-compromise replay). The fix must ensure unfreeze requires evidence of real replay recovery, not just in-memory reconstruction.

#### Part A: Add a `PostCompromiseRecoveryReceiptV1` type with durable provenance marker

Create a new struct `PostCompromiseRecoveryReceiptV1` (or extend the existing `ProjectionRecoveryState`) that includes:
- A `durable_evidence_digest: Hash` — BLAKE3 digest of the CAS/ledger entry containing the recovery evidence.
- A `recovery_replay_coverage: ReplaySequenceBoundsV1` — the actual replay window that was covered.
- A boolean flag `has_durable_provenance: bool` that defaults to `false` in the initial state and can only be set to `true` by an explicit `register_durable_recovery_evidence()` method.

#### Part B: Gate unfreeze on durable provenance

Modify `verify_projection_recovery_state()` to check that the recovery state has `has_durable_provenance == true`. If the recovery state exists but lacks durable provenance, return a new error variant:

```rust
DivergenceError::ProjectionRecoveryNotDurable {
    freeze_id: String,
}
```

with message: `"recovery state exists but lacks durable provenance — unfreeze requires CAS/ledger-backed replay evidence"`.

This means the flow becomes:
1. `on_divergence()` creates the freeze and stores initial (non-durable) recovery state — unchanged
2. External replay recovery process runs, produces durable receipts
3. Caller calls `register_durable_recovery_evidence(freeze_id, receipts, durable_evidence_digest)` to upgrade recovery state to durable
4. `create_unfreeze()` now succeeds because `has_durable_provenance == true`

#### Part C: Implement `register_durable_recovery_evidence()`

Add a new public method on `DivergenceWatchdog`:

```rust
pub fn register_durable_recovery_evidence(
    &self,
    freeze_id: &str,
    receipts: Vec<ProjectionReplayReceiptV1>,
    durable_evidence_digest: Hash,
    sequence_bounds: ReplaySequenceBoundsV1,
) -> Result<(), DivergenceError>
```

This method:
1. Validates `freeze_id` refers to an active freeze
2. Validates `durable_evidence_digest` is non-zero
3. Validates receipts via `reconstruct_projection_state()` against the existing snapshots and trusted authority bindings
4. Updates the in-memory recovery state to set `has_durable_provenance = true`, replace receipts with the durable ones, and store `durable_evidence_digest`
5. Returns error if freeze not found or reconstruction fails

#### Part D: Update test `test_watchdog_create_unfreeze` and `test_full_freeze_unfreeze_cycle`

Update existing tests to call `register_durable_recovery_evidence()` before `create_unfreeze()`. The test should:
1. Trigger divergence (unchanged)
2. Call `register_durable_recovery_evidence()` with the existing receipt + a non-zero durable_evidence_digest
3. Then call `create_unfreeze()` (now succeeds)
4. Verify unfreeze works

#### Part E: Add negative test — unfreeze fails without durable provenance

Add a new test `test_unfreeze_fails_without_durable_provenance`:
1. Trigger divergence
2. Call `create_unfreeze()` WITHOUT calling `register_durable_recovery_evidence()` first
3. Assert it returns `DivergenceError::ProjectionRecoveryNotDurable`

---

## MAJOR 2: Temporal authority validation is self-attested (no independent authority root)

### Root Cause Analysis (5 Whys)

1. **Why does temporal authority collapse to self-attestation?** Because `trusted_authority_bindings()` (line 2418-2448) returns only the watchdog's own `(actor_id, signer.public_key_bytes())` — a single binding to its own key.

2. **Why does `resolve_temporal_authority()` accept self-issued envelopes?** Because it calls `TimeAuthorityEnvelopeV1::create_signed()` with `self.signer` (line 2476-2483), then verifies it against `trusted_authority_bindings` (line 2484) — which contains only the same signer's key.

3. **Why is this a security problem?** A compromised daemon instance controls both the signing key and the trusted authority set. It can create temporal envelopes with arbitrary freshness windows and they will verify successfully. This undermines all temporal controls in compromise/quarantine/recovery flows.

4. **Why must temporal authority be externally rooted?** REQ-0009 states: "Promotion-critical compromise handling MUST resolve temporal authority via signed `TimeAuthorityEnvelopeV1` and declared HTF window references." The HOLONIC_EXTERNAL_IO_SECURITY.md section 2.3 defines shared temporal contract ownership rooted in RFC-0016 temporal substrate, not local daemon keys.

5. **Why wasn't the self-attestation caught in round 2?** Round 2 added the `TimeAuthorityEnvelopeV1` with signature verification (addressing the BLOCKER that there was no envelope at all). But the trusted authority set was populated from the local signer only, collapsing trust separation.

### Affected Code Locations

- `crates/apm2-daemon/src/projection/divergence_watchdog.rs:2418-2448` — `trusted_authority_bindings()` returns only local signer
- `crates/apm2-daemon/src/projection/divergence_watchdog.rs:2463-2485` — `resolve_temporal_authority()` creates AND verifies with same key
- `crates/apm2-daemon/src/projection/divergence_watchdog.rs:2450-2461` — `verify_temporal_authority_envelope()` takes authority bindings parameter

### Required Fix

The fix must separate the temporal authority signer from the watchdog's own operational signer. The watchdog must accept external time-authority bindings (from CAC/HTF configuration) rather than self-generating them.

#### Part A: Add `trusted_time_authority_bindings` to `DivergenceWatchdogConfig`

Add a new field to `DivergenceWatchdogConfig` (line 1665):

```rust
pub struct DivergenceWatchdogConfig {
    pub repo_id: String,
    pub poll_interval: Duration,
    pub actor_id: String,
    pub time_envelope_pattern: String,
    /// External trusted time authority key bindings (from CAC/HTF configuration).
    /// When non-empty, temporal authority envelopes MUST be signed by a key in
    /// this set. When empty, the watchdog's own signer is trusted as a fallback
    /// for single-daemon deployments. This preserves backward compatibility
    /// while enabling trust separation in multi-daemon setups.
    pub trusted_time_authority_bindings: Vec<AuthorityKeyBindingV1>,
}
```

Add a builder method:
```rust
pub fn with_trusted_time_authority_bindings(
    mut self,
    bindings: Vec<AuthorityKeyBindingV1>,
) -> Result<Self, DivergenceError>
```

that validates each binding's key is parseable and the count does not exceed `MAX_TRUSTED_AUTHORITY_BINDINGS`.

Update `DivergenceWatchdogConfig::new()` to initialize `trusted_time_authority_bindings: Vec::new()`.

#### Part B: Modify `trusted_authority_bindings()` to use external bindings when available

Change `trusted_authority_bindings()` (line 2418) to:
1. If `self.config.trusted_time_authority_bindings` is non-empty, return those bindings (they are the external authority root)
2. If empty, fall back to the current behavior (local signer) — this preserves backward compatibility for single-daemon mode but we should log/document that this is a degraded trust mode

This ensures that when external authority bindings are configured, the watchdog cannot self-attest temporal authority.

#### Part C: Add negative test — self-issued envelope rejected when external authority configured

Add a new test `test_temporal_authority_rejects_self_issued_when_external_configured`:

1. Create a watchdog with an **external** trusted time authority binding (using a separate signer/keypair)
2. Attempt `check_divergence()` — this internally calls `resolve_temporal_authority()` which signs with the watchdog's own signer
3. The envelope verification will fail because the watchdog's signer key is NOT in the external trusted authority set
4. Assert that `check_divergence()` returns `DivergenceError::InvalidTemporalAuthority` (not a successful divergence result)

This proves that when external trust is configured, the watchdog cannot forge its own temporal authority.

#### Part D: Add positive test — externally-signed envelope accepted

Add a test `test_temporal_authority_accepts_external_envelope`:

1. Create an external signer (separate keypair)
2. Configure watchdog with external trusted time authority bindings for that signer
3. Override `resolve_temporal_authority()` behavior (or refactor to accept an external envelope) so the envelope is signed by the external signer
4. Verify `check_divergence()` succeeds with the externally-signed temporal authority

**Note on approach**: The simplest approach is to add an optional `time_authority_envelope_provider` callback or make `resolve_temporal_authority()` check config for an externally-provided envelope. However, for this iteration, the negative test (Part C) is the critical one — it proves trust separation is enforced. The positive test may require a `set_time_authority_envelope()` injection method on the watchdog for testing.

A practical approach: add a `pending_time_authority_envelope: Mutex<Option<TimeAuthorityEnvelopeV1>>` field to `DivergenceWatchdog`. Add a method `provide_time_authority_envelope(&self, envelope: TimeAuthorityEnvelopeV1) -> Result<(), DivergenceError>`. Then `resolve_temporal_authority()` checks this field first — if a pre-provided envelope exists, verify and use it instead of self-issuing. This models the real-world flow where an external HTF process provides the envelope.

---

## CRITICAL PATTERNS (from /rust-standards)

- **Fail-closed semantics**: Missing durable provenance or missing external authority MUST fail closed (deny unfreeze / deny divergence handling). Never default to pass.
- **Binding test evidence**: Tests MUST assert specific error variants and messages, not just `is_err()`.
- **Wire production paths**: Every new code branch (durable provenance check, external authority rejection) MUST be exercised by a test that reaches it.
- **Transactional state mutations**: The `register_durable_recovery_evidence()` method must validate BEFORE mutating the in-memory map.
- **Deterministic behavior**: All new Hash derivations must use domain-separated BLAKE3 with versioned prefixes.

---

## Pre-Commit Steps (MANDATORY — do ALL of these in order)

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core
cargo test -p apm2-daemon
```

You MUST pass ALL CI checks. Fix every warning and error before committing.

---

## Push Workflow

```bash
git add -A && git commit -m "fix(TCK-00469): durable recovery provenance gate, external temporal authority bindings" && git push
```
