# Economics Module

> Canonical economics profiles, deterministic budget admission (REQ-0001), and HTF-bound queue admission with anti-entropy anti-starvation enforcement (REQ-0004) for RFC-0029.

## Overview

The `apm2_core::economics` module implements budget economics for the APM2 kernel. It provides content-addressed economics profiles keyed by `(RiskTier, BoundaryIntentClass)` and a deterministic admission evaluator that enforces fail-closed deny behavior for all budget decisions.

Economics profiles define per-cell budget limits (tokens, tool calls, wall-clock time, I/O bytes) across the full risk-tier and boundary-intent-class matrix. Profiles are stored in the Content-Addressed Store (CAS) with a domain-separated BLAKE3 hash for tamper detection and canonical addressing.

```text
EconomicsProfile (CAS)
       |
       v
BudgetAdmissionEvaluator
       |
       +--- resolve_profile() --> load from CAS, verify hash, check staleness
       |
       +--- evaluate(tier, class, usage) --> BudgetAdmissionDecision
                |
                +--- Allow (usage within limits)
                +--- Deny  (fail-closed, with stable deny reason)
```

All admission decisions produce a deterministic `BudgetAdmissionTrace` that can be serialized to canonical JSON for replay verification.

## Key Types

### `EconomicsProfile`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicsProfile {
    pub lifecycle_cost_vector: LifecycleCostVector,
    pub input_state: EconomicsProfileInputState,
    pub budget_matrix: BTreeMap<(RiskTier, BoundaryIntentClass), BudgetEntry>,
}
```

**Invariants:**

- [INV-EC01] Profile hash is deterministic: construction order of the `BTreeMap` does not affect the computed hash.
- [INV-EC02] Profile payload is domain-separated: `BLAKE3(b"apm2-economics-profile-v1" || canonical_json)`.
- [INV-EC03] Budget matrix keys are bounded to `3 * 5 = 15` maximum entries (3 risk tiers, 5 intent classes).
- [INV-EC04] CAS round-trip is lossless: `load_from_cas(store_in_cas(profile))` returns an identical profile.

**Contracts:**

- [CTR-EC01] `new()` validates schema, version, and duplicate budget entries before returning `Ok`.
- [CTR-EC02] `from_framed_bytes()` rejects payloads missing the domain prefix (`ECONOMICS_PROFILE_HASH_DOMAIN`).
- [CTR-EC03] `load_from_cas()` rejects profiles whose recomputed hash does not match the expected hash.
- [CTR-EC04] `canonical_bytes()` produces deterministic canonical JSON suitable for hashing and signing.

### `LifecycleCostVector`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleCostVector {
    pub c_join: u64,
    pub c_revalidate: u64,
    pub c_consume: u64,
    pub c_effect: u64,
    pub c_replay: u64,
    pub c_recovery: u64,
}
```

Lifecycle-stage cost vector from RFC-0029. Captures per-stage costs for join, revalidation, consumption, effect, replay, and recovery.

### `BudgetEntry`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEntry {
    pub max_tokens: u64,
    pub max_tool_calls: u32,
    pub max_time_ms: u64,
    pub max_io_bytes: u64,
}
```

Per-cell budget limits for a single `(RiskTier, BoundaryIntentClass)` key.

### `EconomicsProfileInputState`

```rust
#[non_exhaustive]
pub enum EconomicsProfileInputState {
    Current,
    Stale,
    Unresolved,
}
```

**Invariants:**

- [INV-EC05] Only `Current` profiles are admitted for evaluation; `Stale` and `Unresolved` result in deterministic deny.

### `BudgetAdmissionEvaluator`

```rust
pub struct BudgetAdmissionEvaluator<'a> {
    cas: &'a dyn ContentAddressedStore,
    profile_hash: Hash,
}
```

**Invariants:**

- [INV-EC06] Fail-closed: all unknown, missing, stale, unresolved, or corrupt profile states return `Deny`.
- [INV-EC07] Admission traces are deterministic for identical inputs (profile hash + tier + class + usage).
- [INV-EC08] Exceedance checks are ordered: tokens, tool calls, time, I/O bytes. The first exceedance is reported.

**Contracts:**

- [CTR-EC05] `evaluate()` returns a `BudgetAdmissionDecision` with a stable `deny_reason` string for every non-Allow verdict.
- [CTR-EC06] Zero profile hash (`[0u8; 32]`) always returns `Deny` with reason `economics_profile_hash_zero`.

### `BudgetAdmissionDecision`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetAdmissionDecision {
    pub verdict: BudgetAdmissionVerdict,
    pub deny_reason: Option<String>,
    pub trace: BudgetAdmissionTrace,
}
```

### `BudgetAdmissionVerdict`

```rust
#[non_exhaustive]
pub enum BudgetAdmissionVerdict {
    Allow,
    Deny,
    Freeze,
    Escalate,
}
```

### `BudgetAdmissionTrace`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetAdmissionTrace {
    pub profile_hash: Hash,
    pub tier: RiskTier,
    pub intent_class: BoundaryIntentClass,
    pub observed: ObservedUsage,
    pub limits: Option<BudgetEntry>,
    pub verdict: BudgetAdmissionVerdict,
    pub deny_reason: Option<String>,
}
```

**Contracts:**

- [CTR-EC07] `canonical_bytes()` returns deterministic canonical JSON bytes for replay verification.

### `ObservedUsage`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedUsage {
    pub tokens_used: u64,
    pub tool_calls_used: u32,
    pub time_ms_used: u64,
    pub io_bytes_used: u64,
}
```

### `EconomicsProfileError`

```rust
#[non_exhaustive]
pub enum EconomicsProfileError {
    InvalidSchema { expected: String, actual: String },
    InvalidSchemaVersion { expected: String, actual: String },
    DuplicateBudgetEntry { tier: String, intent_class: String },
    BudgetEntriesTooLarge { count: usize, max: usize },
    Serialization { message: String },
    InvalidFrame,
    Cas(CasError),
    HashMismatch { expected: String, actual: String },
}
```

### `BudgetAdmissionError`

```rust
#[non_exhaustive]
pub enum BudgetAdmissionError {
    Serialization { message: String },
}
```

## Public API

### Profile Construction and Storage

- `EconomicsProfile::new(lifecycle_cost_vector, input_state, budget_matrix) -> Result<Self, EconomicsProfileError>` -- Creates a validated economics profile.
- `EconomicsProfile::budget_entry(tier, intent_class) -> Option<&BudgetEntry>` -- Looks up the budget entry for a `(tier, class)` key.
- `EconomicsProfile::validate() -> Result<(), EconomicsProfileError>` -- Validates schema and structure.
- `EconomicsProfile::canonical_bytes() -> Result<Vec<u8>, EconomicsProfileError>` -- Returns canonical JSON bytes.
- `EconomicsProfile::framed_bytes() -> Result<Vec<u8>, EconomicsProfileError>` -- Returns domain-prefixed bytes for CAS storage.
- `EconomicsProfile::profile_hash() -> Result<[u8; 32], EconomicsProfileError>` -- Computes the canonical profile hash.
- `EconomicsProfile::store_in_cas(cas) -> Result<[u8; 32], EconomicsProfileError>` -- Stores in CAS and returns the profile hash.
- `EconomicsProfile::load_from_cas(cas, profile_hash) -> Result<Self, EconomicsProfileError>` -- Loads and validates from CAS.
- `EconomicsProfile::from_framed_bytes(bytes) -> Result<Self, EconomicsProfileError>` -- Decodes a framed profile payload.

### Admission Evaluation

- `BudgetAdmissionEvaluator::new(cas, profile_hash) -> Self` -- Creates a new evaluator bound to a CAS and profile hash.
- `BudgetAdmissionEvaluator::evaluate(tier, intent_class, observed_usage) -> BudgetAdmissionDecision` -- Evaluates budget admission (fail-closed).
- `BudgetAdmissionTrace::canonical_bytes() -> Result<Vec<u8>, BudgetAdmissionError>` -- Returns canonical JSON for replay verification.

## Examples

### Creating and Storing an Economics Profile

```rust
use std::collections::BTreeMap;
use apm2_core::economics::{
    EconomicsProfile, EconomicsProfileInputState,
    BudgetEntry, LifecycleCostVector,
};
use apm2_core::evidence::MemoryCas;
use apm2_core::pcac::{RiskTier, BoundaryIntentClass};

let mut matrix = BTreeMap::new();
matrix.insert(
    (RiskTier::Tier0, BoundaryIntentClass::Observe),
    BudgetEntry {
        max_tokens: 100_000,
        max_tool_calls: 50,
        max_time_ms: 60_000,
        max_io_bytes: 10_000_000,
    },
);

let costs = LifecycleCostVector {
    c_join: 1, c_revalidate: 2, c_consume: 3,
    c_effect: 4, c_replay: 5, c_recovery: 6,
};

let profile = EconomicsProfile::new(costs, EconomicsProfileInputState::Current, matrix)
    .expect("valid profile");

let cas = MemoryCas::new();
let profile_hash = profile.store_in_cas(&cas).expect("stored");
```

### Evaluating Budget Admission

```rust
use apm2_core::economics::{
    BudgetAdmissionEvaluator, BudgetAdmissionVerdict, ObservedUsage,
};
use apm2_core::pcac::{RiskTier, BoundaryIntentClass};

let evaluator = BudgetAdmissionEvaluator::new(&cas, profile_hash);
let decision = evaluator.evaluate(
    RiskTier::Tier0,
    BoundaryIntentClass::Observe,
    &ObservedUsage {
        tokens_used: 50_000,
        tool_calls_used: 10,
        time_ms_used: 30_000,
        io_bytes_used: 1_000_000,
    },
);

assert_eq!(decision.verdict, BudgetAdmissionVerdict::Allow);
```

## Queue Admission (REQ-0004)

The `queue_admission` submodule implements HTF-bound queue admission and anti-entropy anti-starvation enforcement (RFC-0029 REQ-0004).

### Queue Lane Model

Queue lanes are ordered by priority: `StopRevoke > Control > Consume > Replay > ProjectionReplay > Bulk`.

- **StopRevoke**: strict priority, 200 permille reservation, 100-tick floor guarantee
- **Control**: guaranteed minimum, 150 permille reservation, 500-tick floor guarantee
- **Consume/Replay/ProjectionReplay/Bulk**: weighted deficit round-robin, no reservations

### Temporal Predicates

All admission decisions require valid temporal authority:

- **TP-EIO29-001**: `TimeAuthorityEnvelopeV1` must be present, signed, fresh, boundary-bound, and `deny_on_unknown=true`
- **TP-EIO29-002**: Freshness horizon must resolve; current window must not exceed horizon; revocation frontier must be current
- **TP-EIO29-003**: All required authority sets must have matching, converged receipts with valid proof hashes

### Key Types

- `QueueLane` -- 6-variant enum with priority ordering and lane reservations
- `TimeAuthorityEnvelopeV1` -- Signed temporal authority envelope with boundary binding
- `HtfEvaluationWindow` -- Evaluation window (boundary_id, authority_clock, tick range)
- `QueueAdmissionRequest` / `AntiEntropyAdmissionRequest` -- Admission request inputs
- `QueueAdmissionDecision` -- Verdict + trace output; defect accessed via `decision.defect()` (delegating to `trace.defect`)
- `QueueSchedulerState` -- Per-lane backlog and max-wait tracking (not internally synchronized)
- `AntiEntropyBudget` -- Budget tracker for anti-entropy admission (not internally synchronized)
- `SignatureVerifier` -- Trait for cryptographic signature verification; injected into TP-EIO29-001 evaluation
- `NoOpVerifier` -- Default fail-closed verifier; always denies (`DENY_SIGNATURE_VERIFICATION_NOT_CONFIGURED`)

### Invariants

- [INV-QA01] All unknown, missing, stale, unsigned, or invalid temporal authority states deny fail-closed.
- [INV-QA02] Stop/revoke and control lanes preserve declared tick floors and reserved capacity under adversarial load. High-priority lanes (StopRevoke, Control) admit items even when total queue is at capacity, as long as lane backlog is below reserved capacity.
- [INV-QA03] Anti-entropy is pull-only; push requests are unconditionally denied.
- [INV-QA04] Anti-entropy is budget-bound; oversized proof ranges are denied.
- [INV-QA05] Lane backlog and total queue capacity are hard-capped (MAX_LANE_BACKLOG=4096, MAX_TOTAL_QUEUE_ITEMS=16384).
- [INV-QA06] Envelope signature comparison uses constant-time equality (`subtle::ConstantTimeEq`).
- [INV-QA07] Emergency stop/revoke carve-out: tp001 failure alone does not block stop_revoke lane (authority-reducing operations), but tp002/tp003 failures still deny.
- [INV-QA08] All protocol-boundary `String` and `Vec` fields use bounded serde deserializers to prevent OOM during deserialization from untrusted input.
- [INV-QA09] `tp001_passed` is never `true` without real cryptographic signature verification via an injected `SignatureVerifier`. The default `NoOpVerifier` denies fail-closed.

### Contracts

- [CTR-QA01] `evaluate_queue_admission()` enforces TP-001/002/003, tick-floor invariants, and capacity checks (with lane-reservation bypass for high-priority lanes) in order.
- [CTR-QA02] `evaluate_anti_entropy_admission()` enforces pull-only, proof size, TP-001, TP-003, and budget in order.
- [CTR-QA03] `validate_envelope_tp001()` rejects empty boundary_id, empty authority_clock, inverted tick ranges, zero TTL, excessive TTL, zero content hash, unsigned envelopes, zero-byte signatures, `deny_on_unknown=false`, and cryptographic verification failure.
- [CTR-QA04] All deny decisions produce a `QueueDenyDefect` with stable reason code, lane, predicate_id, denied_at_tick, envelope_hash, and boundary_id.
- [CTR-QA05] `QueueSchedulerState` and `AntiEntropyBudget` require exclusive access (not internally synchronized); callers must hold appropriate locks.

### Public API

#### Temporal Predicate Validators

- `validate_envelope_tp001(envelope, eval_window, verifier) -> Result<(), &str>` -- TP-EIO29-001 validation (structural + crypto via injected verifier)
- `validate_freshness_horizon_tp002(horizon, frontier, window) -> Result<(), &str>` -- TP-EIO29-002 validation
- `validate_convergence_horizon_tp003(horizon, receipts, sets) -> Result<(), &str>` -- TP-EIO29-003 validation

#### Admission Evaluators

- `evaluate_queue_admission(request, scheduler, verifier) -> QueueAdmissionDecision` -- Queue admission (must_use)
- `evaluate_anti_entropy_admission(request, budget, verifier) -> QueueAdmissionDecision` -- Anti-entropy admission (must_use)

## Replay-Recovery Bounds (REQ-0005)

The `replay_recovery` submodule implements replay-recovery bounds and idempotency closure (RFC-0029 REQ-0005).

### Receipt Types

- `ReplayConvergenceReceiptV1` -- Signed receipt proving bounded idempotent convergence of a replay within an HTF window. Carries `time_authority_ref` and `window_ref` hash bindings.
- `RecoveryAdmissibilityReceiptV1` -- Signed receipt proving recovery admissibility for a partial-loss rebuild within an HTF window.

Both receipt types use domain-separated Ed25519 signatures (`REPLAY_CONVERGENCE_RECEIPT:` and `RECOVERY_ADMISSIBILITY_RECEIPT:` prefixes).

### Temporal Predicates

- **TP-EIO29-004** (`replay_convergence_horizon_satisfied`): Replay convergence horizon must be resolved; backlog must be resolved; all receipts must be structurally valid, boundary-matched, within horizon, and converged. Duplicate receipt IDs are rejected to prevent signature amplification attacks.
- **TP-EIO29-007** (`replay_idempotency_monotone`): Adjacent windows must have no duplicate authoritative effects and no revoked effects in later window. All effect identity digests must be non-zero. Uses `HashSet`-based O(N) lookups instead of O(N^2) nested loops.
- **TP-EIO29-009** (`recovery_admissibility`): Recovery admissibility gate. When recovery is active, at least one valid, admitted `RecoveryAdmissibilityReceiptV1` must be present with correct signature, trusted signer, and context binding.

### Key Types

- `ReplayConvergenceHorizonRef` -- Horizon reference for TP-EIO29-004 evaluation
- `BacklogState` -- Backlog state snapshot for TP-EIO29-004
- `AdjacentWindowPair` -- Adjacent-window pair for TP-EIO29-007
- `IdempotencyCheckInput` -- Complete input for TP-EIO29-007 evaluation
- `IdempotencyMode` -- Typed enum (`NotAdjacent` / `Adjacent(&IdempotencyCheckInput)`) replacing `Option<&IdempotencyCheckInput>` to prevent fail-open bypass of TP-EIO29-007
- `RecoveryCheckInput` -- Input for TP-EIO29-009 recovery admissibility check
- `RecoveryMode` -- Typed enum (`NotRecovering` / `Active(RecoveryCheckInput)`) to prevent fail-open bypass of TP-EIO29-009
- `ReplayRecoveryDecision` -- Combined verdict with structured deny defect
- `ReplayRecoveryDenyDefect` -- Auditable deny defect with reason, predicate ID, boundary, tick, and envelope/window hashes

### Invariants

- [INV-RR01] All unknown, missing, stale, unsigned, or invalid replay/recovery states deny fail-closed.
- [INV-RR02] Revoked effects must not appear in the later window.
- [INV-RR03] Authoritative effects must not duplicate across adjacent windows.
- [INV-RR04] Zero effect identity digests deny fail-closed.
- [INV-RR05] Receipt and effect collections are hard-capped (MAX_REPLAY_RECEIPTS=256, MAX_EFFECT_IDENTITIES=4096, MAX_REVOKED_EFFECTS=4096).
- [INV-RR06] Domain-separated signatures prevent cross-receipt-type replay.
- [INV-RR07] TP-EIO29-004 verifies Ed25519 signatures on all receipts (not just structural form).
- [INV-RR08] TP-EIO29-004 enforces trusted signer set via constant-time comparison; untrusted signers deny.
- [INV-RR09] TP-EIO29-004 binds receipt `time_authority_ref`, `window_ref`, and `backlog_digest` to evaluation context via constant-time comparison to prevent cross-context replay.
- [INV-RR10] `IdempotencyMode` forces callers to explicitly declare adjacency intent; `Option`-based bypass is eliminated.
- [INV-RR11] Receipt `create_signed` methods accept `&str` and validate length BEFORE allocation to prevent DoS via oversized input.
- [INV-RR12] All `String` fields on receipt structs and `ReplayRecoveryDenyDefect` use bounded serde deserializers (`#[serde(deserialize_with = "...")]`) to prevent OOM during deserialization from untrusted input (Check-Before-Allocate pattern).
- [INV-RR13] Duplicate receipt IDs in TP-EIO29-004 are rejected to prevent signature amplification attacks.
- [INV-RR14] `boundary_id` validation uses distinct error codes from `receipt_id` validation for precise diagnostics.
- [INV-RR15] `RecoveryMode` forces callers to explicitly declare recovery intent; `Option`-based bypass is eliminated.
- [INV-RR16] `canonical_bytes()` uses `Vec::with_capacity()` for pre-sized allocation.
- [INV-RR17] `content_hash` on receipt structs is caller-provided (external content digest, not self-referential); integrity is protected by the Ed25519 signature over canonical bytes.
- [INV-RR18] `MAX_DENY_REASON_LENGTH` re-uses `MAX_REASON_LENGTH` from PCAC types for consistent bounds.

### Contracts

- [CTR-RR01] `validate_replay_convergence_tp004()` enforces horizon resolution, backlog resolution, receipt structural validity, Ed25519 signature verification, trusted signer enforcement, boundary match, context binding (time_authority_ref, window_ref, backlog_digest), horizon bounds, and convergence.
- [CTR-RR02] `validate_replay_idempotency_tp007()` enforces window adjacency, revoked-effect exclusion, authoritative-effect dedup, and zero-digest rejection.
- [CTR-RR03] `evaluate_replay_recovery()` combines TP-EIO29-004, TP-EIO29-007 (via `IdempotencyMode`), and TP-EIO29-009 (via `RecoveryMode`) into a single admission decision with structured deny defects.
- [CTR-RR04] All deny decisions produce a `ReplayRecoveryDenyDefect` with stable reason code, predicate ID, boundary, tick, and hash bindings.
- [CTR-RR05] `create_signed` methods validate string field lengths BEFORE allocating to prevent unbounded memory allocation.
- [CTR-RR06] `validate_recovery_admissibility()` enforces receipt presence, structural validity, Ed25519 signature verification, trusted signer enforcement, context binding (boundary, time_authority_ref, window_ref), and admitted status.

### Public API

- `ReplayConvergenceReceiptV1::create_signed(receipt_id: &str, ...)` -- Create and sign a replay convergence receipt (validates before allocating)
- `ReplayConvergenceReceiptV1::verify_signature()` -- Verify receipt Ed25519 signature
- `ReplayConvergenceReceiptV1::validate()` -- Structural validation (no signature check)
- `RecoveryAdmissibilityReceiptV1::create_signed(receipt_id: &str, ...)` -- Create and sign a recovery admissibility receipt (validates before allocating)
- `RecoveryAdmissibilityReceiptV1::verify_signature()` -- Verify receipt Ed25519 signature
- `RecoveryAdmissibilityReceiptV1::validate()` -- Structural validation
- `validate_replay_convergence_tp004(horizon, backlog, receipts, boundary_id, trusted_signers, expected_time_authority_ref, expected_window_ref)` -- TP-EIO29-004 validation (with signature verification, trusted signer enforcement, and context binding)
- `validate_replay_idempotency_tp007(windows, effects_t, effects_t1, revoked_t1)` -- TP-EIO29-007 validation
- `validate_recovery_admissibility(input, eval_boundary_id)` -- TP-EIO29-009 validation (recovery admissibility gate)
- `evaluate_replay_recovery(..., trusted_signers, idempotency: IdempotencyMode, recovery: &RecoveryMode)` -- Combined TP-EIO29-004 + TP-EIO29-007 + TP-EIO29-009 evaluation

## Optimization Gates (REQ-0006)

The `optimization_gate` submodule implements security-interlocked optimization gates and quantitative evidence quality enforcement (RFC-0029 REQ-0006).

### Gate Evaluation Order

1. **KPI/countermetric completeness** -- every optimization KPI must have a required countermetric mapping.
2. **Canonical evaluator binding** -- all TP-EIO29 predicates must use `TemporalPredicateEvaluatorV1` (ID: `temporal_predicate_evaluator_v1`).
3. **Arbitration outcome** -- temporal arbitration must produce `AgreedAllow`.
4. **Evidence quality thresholds** -- power >= 0.90, alpha <= 0.01, sample size > 0, >= 3 distinct runtime classes.
5. **Evidence freshness** -- evidence must not exceed the maximum age window (produces BLOCKED, not DENY).
6. **Throughput dominance** -- throughput ratio must be >= 1.0 (no regression below baseline).

### Key Types

- `CountermetricProfile` -- KPI-to-countermetric mapping for optimization gate policy
- `OptimizationProposal` -- Proposal declaring target KPIs and evaluator bindings
- `EvidenceQualityReport` -- Quantitative evidence with power, alpha, sample size, reproducibility, freshness, and throughput
- `TemporalSloProfileV1` -- Temporal SLO tuple (baseline, target, window, owner locus, falsification predicate, countermetrics, boundary authority)
- `OptimizationGateDecision` -- Verdict + trace for auditing; defect accessed via `decision.defect()`
- `OptimizationGateTrace` -- Per-gate pass/fail status and proposal digest
- `OptimizationGateVerdict` -- Allow / Deny / Blocked enum

### Invariants

- [INV-OG01] All unknown, missing, stale, sub-threshold, or incomplete evidence/countermetric states deny fail-closed.
- [INV-OG02] Stale evidence produces BLOCKED (not DENY) to distinguish recoverable freshness from structural rejection.
- [INV-OG03] NaN values in statistical fields (power, alpha, throughput) are denied fail-closed.
- [INV-OG04] All `String` and `Vec` fields use bounded serde deserializers to prevent OOM from untrusted input.
- [INV-OG05] `TemporalSloProfileV1` requires non-empty countermetrics for every objective (KPI/countermetric pairing).
- [INV-OG06] Hash field zero checks use constant-time comparison (`subtle::ConstantTimeEq`).

### Contracts

- [CTR-OG01] `validate_kpi_countermetric_completeness()` rejects proposals with KPIs not present in the countermetric profile.
- [CTR-OG02] `validate_canonical_evaluator_binding()` rejects evaluator bindings with non-canonical evaluator IDs.
- [CTR-OG03] `validate_evidence_quality()` enforces power, alpha, sample size, and reproducibility thresholds.
- [CTR-OG04] `validate_evidence_freshness()` rejects stale or future-ticked evidence.
- [CTR-OG05] `validate_throughput_dominance()` rejects throughput ratios below baseline.
- [CTR-OG06] `evaluate_optimization_gate()` combines all gates in order, producing `OptimizationGateDecision` with full trace.

### Public API

- `validate_kpi_countermetric_completeness(proposal, profile)` -- KPI/countermetric completeness gate
- `validate_canonical_evaluator_binding(proposal)` -- Canonical evaluator binding gate
- `validate_evidence_quality(report)` -- Evidence quality threshold gate
- `validate_evidence_freshness(evidence_tick, current_tick, max_age_ticks)` -- Evidence freshness gate
- `validate_throughput_dominance(throughput_ratio)` -- Throughput dominance gate
- `validate_arbitration_outcome(outcome)` -- Arbitration binding gate
- `evaluate_optimization_gate(proposal, countermetric_profile, evidence_quality, arbitration_outcome, current_tick, max_evidence_age_ticks)` -- Combined gate evaluation

## Related Modules

- [`apm2_core::evidence`](../evidence/AGENTS.md) -- CAS (`ContentAddressedStore`, `MemoryCas`) used for profile storage
- [`apm2_core::crypto`](../crypto/AGENTS.md) -- BLAKE3 hashing for profile content addressing; Ed25519 signing for receipt signatures
- [`apm2_core::determinism`](../determinism/AGENTS.md) -- `canonicalize_json` used for deterministic serialization
- [`apm2_core::budget`](../budget/AGENTS.md) -- Budget tracking and enforcement at the session level
- [`apm2_core::pcac::temporal_arbitration`](../pcac/AGENTS.md) -- `TemporalPredicateId` enum (TpEio29001/002/003/004/007/008/009) used for predicate tracking in admission traces
- [`apm2_core::fac::domain_separator`](../fac/AGENTS.md) -- `sign_with_domain` / `verify_with_domain` for domain-separated receipt signatures

## References

- RFC-0029: Holonic External I/O Efficiency Profile over PCAC
- RFC-0028: Holonic External I/O Security Profile over PCAC
- [40 -- Time, Monotonicity, Determinism](/documents/skills/rust-standards/references/40_time_monotonicity_determinism.md)
