# Implementation Task: TCK-00469 — Projection Compromise Detection, Containment, and Replay Recovery

Worktree: `/home/ubuntu/Projects/apm2-TCK-00469`
Branch: `ticket/RFC-0028/TCK-00469`
Base: `main` (HEAD `dec8f93b`)

## REQUIRED READING (read ALL before editing any code)

Read these files thoroughly before writing any code:
- `documents/security/AGENTS.cac.json`
- `documents/security/THREAT_MODEL.cac.json`
- `documents/rfcs/RFC-0028/requirements/REQ-0009.yaml`
- `documents/rfcs/RFC-0028/evidence_artifacts/EVID-0009.yaml`
- `documents/skills/rust-standards/references/15_errors_panics_diagnostics.md`
- `documents/skills/rust-standards/references/20_testing_evidence_and_ci.md`
- `documents/skills/rust-standards/references/25_api_design_stdlib_quality.md`
- `documents/skills/rust-standards/references/27_collections_allocation_models.md`
- `documents/skills/rust-standards/references/31_io_protocol_boundaries.md`
- `documents/skills/rust-standards/references/34_security_adjacent_rust.md`
- `documents/skills/rust-standards/references/39_hazard_catalog_checklists.md`
- `documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md`
- `documents/skills/modes-of-reasoning/assets/07-type-theoretic.json`
- `documents/skills/modes-of-reasoning/assets/49-robust-worst-case.json`
- `documents/skills/modes-of-reasoning/assets/08-counterexample-guided.json`
- `documents/skills/modes-of-reasoning/assets/65-deontic.json`

## Requirement: RFC-0028 REQ-0009

**Title:** Public projection compromise detection and containment

**Statement:** Compromise of public projection surfaces (e.g., GitHub repository takeover, unauthorized state mutation, or projection endpoint forgery) MUST be detected as divergence against CAS+ledger-derived expected projection state.

Authoritative FAC decisions MUST remain pinned to CAS+ledger trust roots and MUST continue when projection channels are quarantined. Projection channels MUST be replay-recoverable from durable receipts after compromise adjudication.

Promotion-critical compromise handling MUST resolve temporal authority via signed `TimeAuthorityEnvelopeV1` and declared HTF window references. Unknown/stale/missing/invalid temporal authority MUST fail closed.

**Acceptance Criteria:**
1. Projection divergence detection emits structured defects with digest-bound evidence.
2. Compromised projection channels are quarantined without halting authoritative FAC progression.
3. Authoritative admission and gate decisions remain derivable from CAS+ledger only.
4. Projection state can be reconstructed from trusted receipts after containment.
5. Compromise and quarantine decisions include signed `time_authority_ref` and `window_ref` fields.
6. Temporal-authority ambiguity in compromise flows fails closed.

**Evidence Artifact (EVID-0009):** Projection divergence detector traces, trust-root snapshots, projection channel quarantine/unblock traces, post-containment replay/reconstruction receipts.

## Ticket Scope

**In scope:**
- Implement projection divergence detection as observed-vs-expected digest mismatch against CAS+ledger-derived state.
- Quarantine compromised projection channels while preserving authoritative lifecycle progression.
- Require signed temporal authority references for compromise and quarantine decisions.
- Implement replay-recovery workflow to reconstruct projection state from trusted receipts after adjudication.

**Out of scope:**
- Generalized non-projection incident response playbooks.
- Cross-organization source-control recovery governance.

## Implementation Plan

### Step 1: Define Projection Types

In `crates/apm2-core/src/` (new `projection` module or extend existing):

```rust
/// A projection channel represents a downstream view of authoritative state
/// (e.g., a GitHub repository, a CI pipeline, a deployment endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionChannel {
    /// Unique identifier for this projection channel.
    pub channel_id: String,
    /// Type of projection surface.
    pub surface_type: ProjectionSurfaceType,
    /// Current expected state digest (derived from CAS+ledger).
    pub expected_state_digest: Hash,
    /// Current quarantine status.
    pub quarantine_status: QuarantineStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectionSurfaceType {
    GitRepository,
    CiPipeline,
    DeploymentEndpoint,
    ApiProjection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuarantineStatus {
    /// Channel is active and verified.
    Active,
    /// Channel is quarantined due to detected compromise.
    Quarantined {
        /// When the quarantine was imposed.
        quarantined_at_ns: u64,
        /// Time authority reference for the quarantine decision.
        time_authority_ref: Hash,
        /// HTF window reference.
        window_ref: Hash,
        /// Reason for quarantine.
        reason: String,
    },
}

/// Divergence detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionDivergence {
    /// Channel that diverged.
    pub channel_id: String,
    /// Expected digest from CAS+ledger.
    pub expected_digest: Hash,
    /// Observed digest from the projection surface.
    pub observed_digest: Hash,
    /// Time authority envelope for this detection.
    pub time_authority_ref: Hash,
    /// HTF window reference for temporal binding.
    pub window_ref: Hash,
    /// Structured evidence for the divergence.
    pub evidence: DivergenceEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceEvidence {
    /// Digest of the CAS-derived expected state.
    pub cas_state_digest: Hash,
    /// Digest of the ledger-derived expected state.
    pub ledger_state_digest: Hash,
    /// Raw observed state summary.
    pub observed_summary: String,
}
```

### Step 2: Implement Divergence Detection

```rust
/// Detect projection divergence by comparing observed state against
/// CAS+ledger-derived expected state.
pub fn detect_projection_divergence(
    channel: &ProjectionChannel,
    observed_digest: Hash,
    time_authority_ref: Hash,
    window_ref: Hash,
) -> Option<ProjectionDivergence> {
    if channel.expected_state_digest == observed_digest {
        return None; // No divergence
    }

    // Validate temporal authority (fail closed on missing/invalid)
    if time_authority_ref == [0u8; 32] || window_ref == [0u8; 32] {
        // Even in the "no divergence check possible" case, we don't
        // silently pass — we must report the inability to verify.
    }

    Some(ProjectionDivergence {
        channel_id: channel.channel_id.clone(),
        expected_digest: channel.expected_state_digest,
        observed_digest,
        time_authority_ref,
        window_ref,
        evidence: DivergenceEvidence {
            cas_state_digest: channel.expected_state_digest,
            ledger_state_digest: channel.expected_state_digest,
            observed_summary: format!("digest mismatch: expected {}, observed {}",
                hex::encode(channel.expected_state_digest),
                hex::encode(observed_digest)),
        },
    })
}
```

### Step 3: Implement Quarantine State Machine

```rust
/// Quarantine a projection channel due to detected compromise.
/// Returns the quarantine event for ledger recording.
pub fn quarantine_channel(
    channel: &mut ProjectionChannel,
    divergence: &ProjectionDivergence,
    time_authority_ref: Hash,
    window_ref: Hash,
    current_time_ns: u64,
) -> Result<QuarantineEvent, QuarantineError> {
    // Validate temporal authority (fail closed)
    if time_authority_ref == [0u8; 32] {
        return Err(QuarantineError::MissingTemporalAuthority);
    }
    if window_ref == [0u8; 32] {
        return Err(QuarantineError::MissingWindowRef);
    }

    // Transition to quarantined state
    channel.quarantine_status = QuarantineStatus::Quarantined {
        quarantined_at_ns: current_time_ns,
        time_authority_ref,
        window_ref,
        reason: format!("projection divergence detected: {}", divergence.channel_id),
    };

    Ok(QuarantineEvent { /* ... */ })
}
```

**Critical invariant:** Quarantine must NOT halt authoritative FAC progression. The FAC continues using CAS+ledger as trust roots even while projection channels are quarantined.

### Step 4: Implement Replay Recovery

```rust
/// Reconstruct projection state from trusted receipts after compromise adjudication.
pub fn reconstruct_projection_state(
    channel_id: &str,
    receipts: &[DurableReceipt],
    cas: &dyn ContentAddressedStore,
    ledger: &dyn LedgerEventEmitter,
) -> Result<ReconstructedState, ReconstructionError> {
    // 1. Verify all receipt signatures
    // 2. Order receipts by temporal authority
    // 3. Replay receipts to derive expected state
    // 4. Compute state digest from replayed state
    // 5. Return reconstructed state with new expected_state_digest
}
```

### Step 5: Wire into Daemon

In `session_dispatch.rs`:
1. Add projection divergence check at the appropriate lifecycle points
2. Emit structured defects via the standard defect recording path when divergence is detected
3. Ensure FAC gate decisions continue to derive from CAS+ledger even during quarantine
4. Add quarantine/unquarantine handling to the boundary flow enforcement block

### Step 6: Tests

1. **Divergence detection tests:**
   - Matching digests → no divergence
   - Mismatched digests → divergence with evidence
   - Missing temporal authority → fail closed

2. **Quarantine tests:**
   - Quarantine on divergence → channel quarantined
   - Missing time_authority_ref → error (fail closed)
   - Missing window_ref → error (fail closed)
   - FAC continues during quarantine (CAS+ledger still accessible)

3. **Replay recovery tests:**
   - Reconstruct from valid receipts → correct state digest
   - Missing receipt → reconstruction fails
   - Invalid receipt signature → reconstruction fails

4. **Integration test:**
   - Simulate projection compromise → detect → quarantine → recover
   - Verify FAC decisions unaffected during quarantine window

## CRITICAL: Daemon Implementation Patterns (MUST FOLLOW)

- **Transactional state mutations**: Check admission BEFORE mutating state.
- **Atomic event emission**: Use per-invocation Vec, no shared buffers.
- **Fail-closed semantics**: NEVER default to pass/admit on error/ambiguity.
- **Deterministic SQL ordering**: Always use `ORDER BY rowid` as tiebreaker.
- **Unified signing keys**: One signing key per daemon lifecycle.
- **HTF timestamps**: Never use `SystemTime::now()` in event paths — use TimeAuthorityEnvelopeV1.
- **Wire production paths**: No dead code, no unused methods.
- **Binding test evidence**: No zero-count assertions (`assert_eq!(count, 3)` not `assert!(count > 0)`).

## Common Review Finding Patterns to Avoid

- Every `with_X()` builder method MUST be called in production `state.rs` / `main.rs`
- Every state mutation calls `persist()` with error propagation
- Every collection has a `MAX_*` cap enforced on all write paths
- Every error/unknown state resolves to DENY/FAIL, not PASS/ACTIVE
- Integration tests exercise real production wiring, not manual injection
- No `#[serde(default)]` on security-critical enum fields
- Every IPC handler checks caller authorization

## MANDATORY Pre-Commit Steps (run IN ORDER)

You MUST pass ALL CI checks. After ALL implementation:

1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix ALL warnings
3. `cargo doc --workspace --no-deps` — fix any doc warnings
4. `cargo test -p apm2-core` — core tests
5. `cargo test -p apm2-daemon` — daemon tests (timeout 260s)
6. `git add -A && git commit -m "feat(TCK-00469): projection compromise detection, containment, and replay recovery" && git push`
