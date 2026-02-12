# Economics Module

> Canonical economics profiles and deterministic budget admission for RFC-0029 REQ-0001.

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

## Related Modules

- [`apm2_core::evidence`](../evidence/AGENTS.md) -- CAS (`ContentAddressedStore`, `MemoryCas`) used for profile storage
- [`apm2_core::crypto`](../crypto/AGENTS.md) -- BLAKE3 hashing for profile content addressing
- [`apm2_core::determinism`](../determinism/AGENTS.md) -- `canonicalize_json` used for deterministic serialization
- [`apm2_core::budget`](../budget/AGENTS.md) -- Budget tracking and enforcement at the session level

## References

- RFC-0029: Holonic External I/O Efficiency Profile over PCAC
- RFC-0028: Holonic External I/O Security Profile over PCAC
- [40 -- Time, Monotonicity, Determinism](/documents/skills/rust-standards/references/40_time_monotonicity_determinism.md)
