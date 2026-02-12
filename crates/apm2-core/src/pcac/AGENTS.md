# PCAC Module

> Proof-Carrying Authority Continuity (RFC-0027) -- single-use authority lifecycle for gating all side effects.

## Overview

The `apm2_core::pcac` module implements the authority lifecycle contract that governs all authority-bearing side effects in APM2. Every side effect (tool execution, file write, network access) must pass through the PCAC gate: `join -> revalidate -> consume -> effect`.

The core primitive is the **Authority Join Certificate (AJC)** -- a single-use, copy-tolerant witness that cryptographically binds intent, capability, identity, freshness, and time to a specific side effect.

```text
AuthorityJoinInputV1 --> AuthorityJoinKernel::join() --> AJC
                              |
                         ::revalidate()  (pre-actuation check)
                              |
                         ::consume()     (single-use gate)
                              |
                         Side Effect Execution
                              |
                     Lifecycle Receipts (Join/Revalidate/Consume/Deny)
```

### Semantic Laws (RFC-0027 section 4)

1. **Linear Consumption**: each AJC authorizes at most one side effect.
2. **Intent Equality**: consume requires exact intent digest equality.
3. **Freshness Dominance**: Tier2+ consume denies on stale/missing/ambiguous freshness.
4. **Revocation Dominance**: revocation frontier advancement denies consume.
5. **Delegation Narrowing**: delegated joins must be strict-subset of parent.
6. **Boundary Monotonicity**: `join < revalidate <= consume <= effect`.
7. **Evidence Sufficiency**: authoritative outcomes require replay-resolvable receipts.

### Trust Boundaries

- **Protocol boundary**: All string and collection fields enforce deserialization-time size limits via bounded deserializers. Oversized payloads are rejected before `validate()`.
- **Cryptographic boundary**: Sovereignty epochs require Ed25519 signature verification. Receipt authentication supports Direct, PointerUnbatched, and PointerBatched shapes with mandatory Merkle proof for batched paths.
- **Temporal boundary**: Temporal arbitration receipts are signed and verified against a trusted signer set. Deadline misses escalate transient disagreement to persistent.

## Key Types

### `AuthorityJoinInputV1`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityJoinInputV1 {
    pub session_id: String,
    pub holon_id: Option<String>,
    pub intent_digest: Hash,
    pub boundary_intent_class: BoundaryIntentClass,
    pub capability_manifest_hash: Hash,
    pub scope_witness_hashes: Vec<Hash>,
    pub lease_id: String,
    pub permeability_receipt_hash: Option<Hash>,
    pub identity_proof_hash: Hash,
    pub identity_evidence_level: IdentityEvidenceLevel,
    pub pointer_only_waiver_hash: Option<Hash>,
    pub directory_head_hash: Hash,
    pub freshness_policy_hash: Hash,
    pub freshness_witness_tick: u64,
    pub stop_budget_profile_digest: Hash,
    pub pre_actuation_receipt_hashes: Vec<Hash>,
    pub risk_tier: RiskTier,
    pub determinism_class: DeterminismClass,
    pub time_envelope_ref: Hash,
    pub as_of_ledger_anchor: Hash,
}
```

Canonical input set for computing admissible authority. All hash fields are 32-byte BLAKE3 digests. The authority join hash is computed over the canonical encoding of these fields.

**Invariants:**

- [INV-PC01] **Fail-closed validation**: `validate()` MUST reject empty required strings, zero hashes, oversized collections, and zero-valued elements within hash vectors. The first violation encountered produces a deterministic `PcacValidationError`.
- [INV-PC02] **Intent binding**: `intent_digest` cryptographically binds the specific effect being authorized; zero-hash MUST be rejected.
- [INV-PC03] **Freshness binding**: `freshness_witness_tick` MUST be strictly positive; zero values are rejected.

**Contracts:**

- [CTR-PC01] `validate()` returns `Ok(())` only when all string, hash, collection, and coherence constraints are satisfied. Any violation returns `Err(PcacValidationError)`.
- [CTR-PC02] String fields are bounded by `MAX_STRING_LENGTH` (256 bytes). Collections are bounded by `MAX_SCOPE_WITNESS_HASHES` (64) and `MAX_PRE_ACTUATION_RECEIPT_HASHES` (64).

### `AuthorityJoinCertificateV1` (AJC)

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityJoinCertificateV1 {
    pub ajc_id: Hash,
    pub authority_join_hash: Hash,
    pub intent_digest: Hash,
    pub boundary_intent_class: BoundaryIntentClass,
    pub risk_tier: RiskTier,
    pub issued_time_envelope_ref: Hash,
    pub issued_at_tick: u64,
    pub as_of_ledger_anchor: Hash,
    pub expires_at_tick: u64,
    pub revocation_head_hash: Hash,
    pub identity_evidence_level: IdentityEvidenceLevel,
    pub admission_capacity_token: Option<Hash>,
}
```

Single-use authority witness. Copy-tolerant semantics: certificate bytes MAY be copied, but only one authoritative consume is admissible per `ajc_id`.

**Invariants:**

- [INV-PC04] **Single-use enforcement**: Each AJC authorizes at most one side effect (Law 1). The durable consume record MUST be written before the effect is accepted.
- [INV-PC05] **Expiry enforcement**: `expires_at_tick` and `issued_at_tick` MUST be strictly positive. Consumption after expiry MUST be denied.

**Contracts:**

- [CTR-PC03] `validate()` checks all hash fields are non-zero, tick fields are positive, and optional `admission_capacity_token` is non-zero when present.

### `AuthorityJoinKernel` (trait)

```rust
pub trait AuthorityJoinKernel: Send + Sync {
    fn join(
        &self,
        input: &AuthorityJoinInputV1,
        policy: &PcacPolicyKnobs,
    ) -> Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>>;

    fn revalidate(
        &self,
        cert: &AuthorityJoinCertificateV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
        policy: &PcacPolicyKnobs,
    ) -> Result<(), Box<AuthorityDenyV1>>;

    fn consume(
        &self,
        cert: &AuthorityJoinCertificateV1,
        intent_digest: Hash,
        boundary_intent_class: BoundaryIntentClass,
        requires_authoritative_acceptance: bool,
        current_time_envelope_ref: Hash,
        current_revocation_head_hash: Hash,
        policy: &PcacPolicyKnobs,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>>;
}
```

Minimal kernel API implementing the three lifecycle operations.

**Invariants:**

- [INV-PC06] **Replay order**: For any side-effectful operation: `AuthorityJoin < AuthorityRevalidate < AuthorityConsume <= EffectReceipt`.
- [INV-PC07] **Intent equality**: `consume()` MUST verify exact intent digest equality between AJC and consume-time binding (Law 2).
- [INV-PC08] **Revocation dominance**: `consume()` MUST deny if revocation head has advanced since AJC issuance (Law 4).

**Contracts:**

- [CTR-PC04] All operations return `Box<AuthorityDenyV1>` on failure with machine-checkable deny class, time witness, and audit context.

### `AuthorityDenyV1`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDenyV1 {
    pub deny_class: AuthorityDenyClass,
    pub ajc_id: Option<Hash>,
    pub time_envelope_ref: Hash,
    pub ledger_anchor: Hash,
    pub denied_at_tick: u64,
    pub containment_action: Option<FreezeAction>,
}
```

Complete authority denial with all context needed for replay verification and audit. `AuthorityDenyClass` is a `#[non_exhaustive]` enum with ~30 variants covering join, revalidation, consume, sovereignty, policy, delegation, and verifier economics failures.

**Invariants:**

- [INV-PC09] **Fail-closed taxonomy**: Unknown or missing authority state always maps to a denial class. There is no "unknown -> allow" path.
- [INV-PC10] **Replay-critical bindings**: `time_envelope_ref` and `ledger_anchor` MUST be non-zero on every denial.

### Lifecycle Receipts

```rust
pub struct AuthorityJoinReceiptV1 { /* digest_meta, ajc_id, authority_join_hash, risk_tier, ... */ }
pub struct AuthorityRevalidateReceiptV1 { /* digest_meta, ajc_id, checkpoint, ... */ }
pub struct AuthorityConsumeReceiptV1 { /* digest_meta, ajc_id, intent_digest, acceptance_fact_class, ... */ }
pub struct AuthorityDenyReceiptV1 { /* digest_meta, deny_class, denied_at_stage, ... */ }
```

All receipts include `ReceiptDigestMeta` (canonicalizer + content digest), time envelope references, and optional `AuthoritativeBindings` for authoritative acceptance paths.

**Invariants:**

- [INV-PC11] **Authoritative completeness**: When `authoritative_bindings` is present, `episode_envelope_hash`, `view_commitment_hash`, `time_envelope_ref`, and `authentication` MUST all be populated and valid.
- [INV-PC12] **Time envelope coherence**: The receipt-level `time_envelope_ref` MUST equal `authoritative_bindings.time_envelope_ref` when both are present.
- [INV-PC13] **Delegated-path coherence**: `permeability_receipt_hash` and `delegation_chain_hash` MUST both be present or both absent.

**Contracts:**

- [CTR-PC05] `validate()` checks structural constraints. `validate_authoritative()` additionally requires authoritative bindings. `validate_authoritative_with_digest(canonical_bytes)` adds BLAKE3 digest verification.

### `TemporalArbitrationReceiptV1`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalArbitrationReceiptV1 {
    pub predicate_id: TemporalPredicateId,
    pub evaluators: Vec<EvaluatorTuple>,
    pub aggregate_outcome: ArbitrationOutcome,
    pub time_envelope_ref: [u8; 32],
    pub arbitrated_at_tick: u64,
    pub deadline_tick: Option<u64>,
    pub content_digest: [u8; 32],
    pub signer_id: [u8; 32],
    pub signature: [u8; 64],
}
```

Signed temporal arbitration receipt for RFC-0028 REQ-0002 shared temporal predicates.

**Invariants:**

- [INV-PC14] **Deterministic ordering**: Evaluator tuples MUST be sorted by strictly increasing `evaluator_id`.
- [INV-PC15] **Context coherence**: All evaluator tuples MUST share identical `contract_digest_set`, `canonicalizer_tuple`, `time_authority_ref`, and `window_ref`.
- [INV-PC16] **Deadline escalation**: Transient disagreement requires `deadline_tick`. After deadline miss, transient escalates to persistent.
- [INV-PC17] **Signature integrity**: Receipt payload is Ed25519-signed. Tampered receipts fail validation. Signers must be in the trusted set.

**Contracts:**

- [CTR-PC06] `validate(allowed_signers)` verifies shape, ordering, coherence, aggregate outcome derivation, and cryptographic signature.

### Supporting Types

- **`RiskTier`**: `Tier0` | `Tier1` | `Tier2Plus` -- risk classification with `Ord` ordering.
- **`DeterminismClass`**: `Deterministic` | `BoundedNondeterministic`.
- **`IdentityEvidenceLevel`**: `Verified` | `PointerOnly` -- Tier2+ defaults to `Verified`.
- **`BoundaryIntentClass`**: `Observe` | `Assert` | `Delegate` | `Actuate` | `Govern`.
- **`AcceptanceFactClass`**: `Authoritative` | `Observational` -- derived from intent class.
- **`SovereigntyEpoch`**: Ed25519-signed epoch evidence with principal scope binding.
- **`FreezeAction`**: `NoAction` | `SoftFreeze` | `HardFreeze`.
- **`PcacPolicyKnobs`**: Policy configuration for lifecycle enforcement, identity evidence, freshness, and sovereignty mode.
- **`ReceiptAuthentication`**: `Direct` | `PointerUnbatched` | `PointerBatched` (with Merkle proof).

## Public API

### Authority Lifecycle

- `AuthorityJoinKernel::join(input, policy) -> Result<AJC, Box<AuthorityDenyV1>>`
- `AuthorityJoinKernel::revalidate(cert, ...) -> Result<(), Box<AuthorityDenyV1>>`
- `AuthorityJoinKernel::consume(cert, ...) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>>`

### Verification

- `verify_receipt_authentication(receipt_auth, ...) -> Result<(), PcacValidationError>`
- `validate_authoritative_bindings(bindings) -> Result<(), PcacValidationError>`
- `classify_fact(fact) -> FactClass`
- `validate_replay_lifecycle_order(entries) -> Result<(), String>`

### Temporal Arbitration

- `check_freshness_dominance(witness_tick, current_tick, max_age) -> Result<(), FreshnessViolation>`
- `check_revocation_dominance(ajc_head, current_head) -> Result<(), RevocationViolation>`
- `map_arbitration_outcome(outcome, predicate_id) -> ArbitrationAction`

### Evidence Export

- `export_pcac_evidence_bundle(state) -> PcacEvidenceBundle`
- `evaluate_exported_predicates(bundle) -> PcacPredicateEvaluationReport`
- `maybe_export_runtime_bundle(state) -> Option<PcacRuntimeExportOutcome>`

### Verifier Economics

- `VerifierEconomicsChecker::check_timing(operation, duration) -> Result<(), String>`
- `VerifierEconomicsChecker::check_proof_count(count, tier) -> Result<(), String>`

### Metrics

- `record_verifier_metrics(result)`
- `record_anti_entropy_event_metrics(event)`

## Examples

### Issuing and Consuming an AJC

```rust
use apm2_core::pcac::{
    AuthorityJoinInputV1, AuthorityJoinKernel, PcacPolicyKnobs,
    BoundaryIntentClass, RiskTier, DeterminismClass, IdentityEvidenceLevel,
};

// Build join inputs with all required bindings
let input = AuthorityJoinInputV1 {
    session_id: "session-001".to_string(),
    holon_id: None,
    intent_digest: intent_hash,
    boundary_intent_class: BoundaryIntentClass::Actuate,
    capability_manifest_hash: manifest_hash,
    scope_witness_hashes: vec![],
    lease_id: "lease-001".to_string(),
    permeability_receipt_hash: None,
    identity_proof_hash: identity_hash,
    identity_evidence_level: IdentityEvidenceLevel::Verified,
    pointer_only_waiver_hash: None,
    directory_head_hash: dir_hash,
    freshness_policy_hash: freshness_hash,
    freshness_witness_tick: 42,
    stop_budget_profile_digest: budget_hash,
    pre_actuation_receipt_hashes: vec![],
    risk_tier: RiskTier::Tier1,
    determinism_class: DeterminismClass::Deterministic,
    time_envelope_ref: time_hash,
    as_of_ledger_anchor: anchor_hash,
};
input.validate().expect("inputs must be valid");

let policy = PcacPolicyKnobs::default();
let ajc = kernel.join(&input, &policy)?;

// Later, consume the AJC for the authorized effect
let (consumed, record) = kernel.consume(
    &ajc,
    intent_hash,
    BoundaryIntentClass::Actuate,
    true,  // requires_authoritative_acceptance
    current_time_ref,
    current_revocation_head,
    &policy,
)?;
```

### Checking Temporal Predicates

```rust
use apm2_core::pcac::{
    check_freshness_dominance, check_revocation_dominance,
    map_arbitration_outcome, ArbitrationOutcome, TemporalPredicateId, ArbitrationAction,
};

// Freshness check: witness must be within max_age of current tick
check_freshness_dominance(95, 100, 10)?; // OK: age 5 <= 10

// Revocation check: heads must be equal (constant-time comparison)
check_revocation_dominance(&ajc_head, &current_head)?;

// Map arbitration outcome to admission action
let action = map_arbitration_outcome(
    ArbitrationOutcome::AgreedAllow,
    TemporalPredicateId::TpEio29001,
);
assert_eq!(action, ArbitrationAction::Continue);
```

## Related Modules

- [`apm2_core::policy`](../policy/AGENTS.md) - Policy evaluation engine (provides PcacPolicyKnobs resolution)
- [`apm2_core::policy::permeability`](../policy/AGENTS.md) - Authority delegation meet for delegated paths
- [`apm2_core::fac`](../fac/AGENTS.md) - Forge Admission Cycle (consumes PCAC receipts for gate evidence)
- [`apm2_core::crypto`](../crypto/) - BLAKE3 hashing and Ed25519 signing primitives
- [`apm2_core::ledger`](../ledger/AGENTS.md) - Append-only event storage for lifecycle receipts

## References

- [RFC-0027] Proof-Carrying Authority Continuity -- authority lifecycle contract, semantic laws, sovereignty enforcement
- [RFC-0028] Boundary-flow integrity -- temporal arbitration (REQ-0002), intent classification (REQ-0001)
- [APM2 Rust Standards] [Time, Monotonicity, Determinism](/documents/skills/rust-standards/references/40_time_monotonicity_determinism.md)
