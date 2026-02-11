# Implementation Task: TCK-00466 — Portable Acceptance Evidence + Deterministic Reverification

Worktree: `/home/ubuntu/Projects/apm2-TCK-00466`
Branch: `ticket/RFC-0028/TCK-00466`
Base: `main` (HEAD `dec8f93b`)

## REQUIRED READING (read ALL before editing any code)

Read these files thoroughly before writing any code:
- `documents/security/AGENTS.cac.json`
- `documents/security/THREAT_MODEL.cac.json`
- `documents/rfcs/RFC-0028/requirements/REQ-0005.yaml`
- `documents/rfcs/RFC-0028/evidence_artifacts/EVID-0005.yaml`
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

## Requirement: RFC-0028 REQ-0005

**Title:** Portable acceptance evidence and deterministic third-party reverification

**Statement:** Authoritative external claims MUST be backed by portable, receipt-addressed evidence that independent counterparties can deterministically re-verify without ambient state.

**Acceptance Criteria:**
1. Acceptance evidence can be independently re-verified across at least two verifier implementations.
2. Portable replay package includes all required receipt pointers and verification metadata.
3. Unverifiable imported authority claims are denied.

**Evidence Artifact (EVID-0005):** Effect-stage acceptance-fact and declassification conformance — acceptance-fact completeness checks, declassification receipt linkage checks.

## Ticket Scope

**In scope:**
- Define portable acceptance package contract with complete receipt pointers and verification metadata.
- Guarantee deterministic replay/reverification by at least two independent verifier implementations.
- Fail closed on missing, stale, or unverifiable imported authority claims.
- Add replay fixture generation and verifier-concordance reporting for promotion-critical traces.

**Out of scope:**
- Cross-organization key governance policy.
- Non-authoritative observability export formats.

## Implementation Plan

### Step 1: Define AcceptancePackageV1 Schema

In `crates/apm2-core/src/pcac/` or a new `crates/apm2-core/src/evidence/` module, define:

```rust
/// Portable acceptance evidence package containing all receipt pointers
/// and verification metadata needed for deterministic third-party reverification.
///
/// This is the self-contained evidence bundle that proves an authoritative
/// effect was properly admitted. It must be verifiable without ambient runtime state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptancePackageV1 {
    /// Package format version for forward compatibility.
    pub version: u32,
    /// Unique identifier for this acceptance package.
    pub package_id: Hash,
    /// The effect/decision this package provides evidence for.
    pub subject_effect_id: Hash,
    /// Digest of the complete receipt set (Merkle root or hash-list digest).
    pub receipt_set_digest: Hash,
    /// Individual receipt pointers with their verification metadata.
    pub receipt_pointers: Vec<ReceiptPointer>,
    /// Policy snapshot hash that was active when the decision was made.
    pub policy_snapshot_hash: Hash,
    /// Timestamp envelope reference for temporal binding.
    pub time_authority_ref: Hash,
    /// The admission verdict this evidence supports.
    pub verdict: AdmissionVerdict,
    /// Signature over the canonical package bytes by the issuing authority.
    pub issuer_signature: Vec<u8>,
    /// Verifying key of the issuer (for portable verification).
    pub issuer_verifying_key: [u8; 32],
}

/// Individual receipt pointer within an acceptance package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptPointer {
    /// Type of receipt (delegation, consume, effect, boundary, declassification).
    pub receipt_type: ReceiptType,
    /// Content-addressed digest of the receipt.
    pub receipt_digest: Hash,
    /// CAS address where the receipt can be retrieved.
    pub cas_address: Option<String>,
    /// Ledger event ID that records this receipt.
    pub ledger_event_id: Option<String>,
}

/// Receipt types that can appear in an acceptance package.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceiptType {
    Delegation,
    Consume,
    Effect,
    Boundary,
    Declassification,
    GateAdmission,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdmissionVerdict {
    Admitted,
    Denied,
}
```

### Step 2: Implement Deterministic Verifier

Create a verification function that can verify an `AcceptancePackageV1` without ambient state:

```rust
/// Verification result from deterministic reverification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub package_id: Hash,
    pub verified: bool,
    pub findings: Vec<VerificationFinding>,
}

#[derive(Debug, Clone)]
pub struct VerificationFinding {
    pub severity: FindingSeverity,
    pub code: &'static str,
    pub message: String,
}

/// Deterministic verifier that checks acceptance package integrity
/// without ambient runtime state.
pub fn verify_acceptance_package(
    package: &AcceptancePackageV1,
    receipt_provider: &dyn ReceiptProvider,
) -> VerificationResult {
    // 1. Verify package signature
    // 2. Verify receipt_set_digest matches recomputed digest from receipt_pointers
    // 3. For each receipt_pointer, resolve and verify the receipt content
    // 4. Verify policy_snapshot_hash is non-zero
    // 5. Verify time_authority_ref is non-zero
    // 6. Fail closed on any missing receipt
}

/// Trait for resolving receipt content from receipt pointers.
/// Different verifier implementations can use different backends
/// (CAS, ledger, file system) while producing identical results.
pub trait ReceiptProvider: Send + Sync {
    fn resolve_receipt(&self, pointer: &ReceiptPointer) -> Option<Vec<u8>>;
}
```

### Step 3: Implement Two Independent Verifier Backends

1. **CAS-based verifier** — resolves receipts via content-addressed storage
2. **Ledger-based verifier** — resolves receipts via ledger event lookups

Both must produce identical verification results for the same package.

### Step 4: Wire into Daemon

In `session_dispatch.rs`, at the boundary flow enforcement block where acceptance decisions are made:
- Build an `AcceptancePackageV1` from the admission evidence
- Store it in the ledger and/or CAS
- Ensure the package includes ALL receipt pointers from the admission decision

### Step 5: Add Fail-Closed Behavior

- Missing receipt pointers → deny
- Unverifiable receipt content → deny
- Signature verification failure → deny
- Receipt set digest mismatch → deny
- Zero/empty policy_snapshot_hash → deny
- Zero/empty time_authority_ref → deny

### Step 6: Tests

1. **Unit tests** for `verify_acceptance_package`:
   - Valid package → verified
   - Missing receipt → deny
   - Bad signature → deny
   - Receipt digest mismatch → deny
   - Zero policy hash → deny

2. **Cross-verifier concordance test:**
   - Create a package, verify with CAS verifier → result A
   - Verify same package with ledger verifier → result B
   - Assert A == B (deterministic)

3. **Replay fixture test:**
   - Serialize a verified package to disk
   - Load and re-verify in a clean context (no ambient state)
   - Assert verification passes

## CRITICAL: Daemon Implementation Patterns (MUST FOLLOW)

- **Transactional state mutations**: Check admission BEFORE mutating state.
- **Atomic event emission**: Use per-invocation Vec, no shared buffers.
- **Fail-closed semantics**: NEVER default to pass/admit on error/ambiguity.
- **Deterministic SQL ordering**: Always use `ORDER BY rowid` as tiebreaker.
- **Unified signing keys**: One signing key per daemon lifecycle.
- **HTF timestamps**: Never use `SystemTime::now()` in event paths.
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
6. `git add -A && git commit -m "feat(TCK-00466): portable acceptance evidence and deterministic reverification" && git push`
