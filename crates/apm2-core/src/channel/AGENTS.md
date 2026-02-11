# Channel Module

> Markov-blanket channel boundary enforcement for typed tool-intent classification, fail-closed actuation gating, and declassification receipt validation.

## Overview

The `apm2_core::channel` module implements the channel boundary enforcement primitives specified in RFC-0003 and RFC-0028. It provides fail-closed validation surfaces that prevent non-authoritative actuation inputs from crossing holonic boundaries.

The core principle is that only **typed tool-intent channel events** (broker-mediated, structured) are authoritative for actuation. Free-form model output, direct manifest invocations, and unknown sources are rejected at the boundary.

```text
  Agent Session                         Holonic Boundary
  ─────────────                         ────────────────
  ┌────────────┐     ┌──────────┐     ┌─────────────────────────┐
  │ Tool Call  │────>│ Broker   │────>│ validate_channel_boundary│
  │ (Typed     │     │ Mediated │     │                         │
  │  Intent)   │     │          │     │  ChannelSource?         │
  └────────────┘     └──────────┘     │  ├─ TypedToolIntent ──> ALLOW
                                      │  ├─ FreeFormOutput ───> DEFECT
  ┌────────────┐                      │  ├─ DirectManifest ───> DEFECT
  │ Free-form  │─────────────────────>│  └─ Unknown ──────────> DEFECT
  │ Output     │                      │                         │
  └────────────┘                      │  + broker_verified?     │
                                      │  + capability_verified? │
                                      │  + context_firewall?    │
                                      │  + policy_ledger?       │
                                      │  + taint_allow?         │
                                      │  + classification?      │
                                      │  + declass_receipt?     │
                                      │  + leakage_budget?      │
                                      │  + timing_channel?      │
                                      └─────────────────────────┘
```

## Key Types

### `ChannelSource`

```rust
#[non_exhaustive]
pub enum ChannelSource {
    TypedToolIntent,  // Structured, broker-mediated (authoritative)
    FreeFormOutput,   // Unstructured text (non-authoritative)
    DirectManifest,   // Bypass attempt
    Unknown,          // Missing channel metadata
}
```

Classification of the actuation input source. Only `TypedToolIntent` is authoritative.

**Invariants:**

- [INV-CH01] Only `TypedToolIntent` may drive authoritative actuation
- [INV-CH02] All other sources produce `ChannelBoundaryDefect` when used for actuation

### `ChannelBoundaryCheck`

```rust
pub struct ChannelBoundaryCheck {
    pub source: ChannelSource,
    pub channel_source_witness: Option<[u8; 32]>,
    pub broker_verified: bool,
    pub capability_verified: bool,
    pub context_firewall_verified: bool,
    pub policy_ledger_verified: bool,
    pub taint_allow: bool,
    pub classification_allow: bool,
    pub declass_receipt_valid: bool,
    pub declassification_intent: DeclassificationIntentScope,
    pub redundancy_declassification_receipt: Option<RedundancyDeclassificationReceipt>,
    pub boundary_flow_policy_binding: Option<BoundaryFlowPolicyBinding>,
    pub leakage_budget_receipt: Option<LeakageBudgetReceipt>,
    pub timing_channel_budget: Option<TimingChannelBudget>,
    pub leakage_budget_policy_max_bits: Option<u64>,
    pub declared_leakage_budget_bits: Option<u64>,
    pub timing_budget_policy_max_ticks: Option<u64>,
    pub declared_timing_budget_ticks: Option<u64>,
}
```

Full boundary enforcement result carrying all verification flags and optional receipts.

**Invariants:**

- [INV-CH03] All boolean verification flags default to `false` (fail-closed)
- [INV-CH04] `channel_source_witness` must match the BLAKE3 witness for the claimed `source`

**Contracts:**

- [CTR-CH01] A passing boundary check requires `source == TypedToolIntent` AND all relevant verification flags true
- [CTR-CH02] Missing or mismatched witness produces a defect

### `ChannelBoundaryDefect`

```rust
pub struct ChannelBoundaryDefect {
    pub violation_class: ChannelViolationClass,
    pub detail: String,
}
```

Structured defect emitted when a boundary violation is detected. `detail` is bounded to `MAX_CHANNEL_DETAIL_LENGTH` (512 bytes).

### `ChannelViolationClass`

```rust
#[non_exhaustive]
pub enum ChannelViolationClass {
    UntypedChannelSource,
    BrokerBypassDetected,
    CapabilityNotVerified,
    ContextFirewallNotVerified,
    MissingChannelMetadata,
    UnknownChannelSource,
    PolicyNotLedgerVerified,
    TaintNotAdmitted,
    ClassificationNotAdmitted,
    DeclassificationReceiptInvalid,
    UnknownOrUnscopedDeclassificationIntent,
    PolicyDigestBindingMismatch,
    CanonicalizerTupleBindingMismatch,
    LeakageBudgetExceeded,
    TimingChannelBudgetExceeded,
}
```

**Contracts:**

- [CTR-CH03] `requires_quarantine()` returns `true` for `LeakageBudgetExceeded` and `TimingChannelBudgetExceeded`

### `DeclassificationIntentScope`

```rust
pub enum DeclassificationIntentScope {
    None,                // No downgrade requested
    RedundancyPurpose,   // Downgrade for recoverability fragments only
    Unknown,             // Explicit fail-closed deny
}
```

**Invariants:**

- [INV-CH05] Default is `Unknown` (fail-closed)

### `BoundaryFlowPolicyBinding`

```rust
pub struct BoundaryFlowPolicyBinding {
    pub policy_digest: [u8; 32],
    pub admitted_policy_root_digest: [u8; 32],
    pub canonicalizer_tuple_digest: [u8; 32],
    pub admitted_canonicalizer_tuple_digest: [u8; 32],
}
```

Digest/coherence binding for RFC-0028 boundary-flow policy checks. Validates that the flow policy and canonicalizer tuple match the admitted authoritative state.

**Invariants:**

- [INV-CH06] All four digests must be non-zero
- [INV-CH07] `policy_digest` must match `admitted_policy_root_digest` (constant-time comparison)
- [INV-CH08] `canonicalizer_tuple_digest` must match `admitted_canonicalizer_tuple_digest`

### `LeakageBudgetReceipt`

```rust
pub struct LeakageBudgetReceipt {
    pub leakage_bits: u64,
    pub budget_bits: u64,
    pub estimator_family: LeakageEstimatorFamily,
    pub confidence_bps: u16,
    pub confidence_label: String,
}
```

**Invariants:**

- [INV-CH09] `budget_bits > 0`
- [INV-CH10] `confidence_bps` in `0..=10000` (basis points)
- [INV-CH11] `confidence_label` bounded by `MAX_LEAKAGE_CONFIDENCE_LABEL_LENGTH` (128 bytes)

### `TimingChannelBudget`

```rust
pub struct TimingChannelBudget {
    pub release_bucket_ticks: u64,
    pub observed_variance_ticks: u64,
    pub budget_ticks: u64,
}
```

**Invariants:**

- [INV-CH12] `release_bucket_ticks > 0` and `budget_ticks > 0`

### `RedundancyDeclassificationReceipt`

```rust
pub struct RedundancyDeclassificationReceipt {
    pub receipt_id: String,
    pub scoped_fragment_only: bool,
    pub plaintext_semantics_exposed: bool,
}
```

**Invariants:**

- [INV-CH13] `receipt_id` is non-empty and bounded by `MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH` (128 bytes)
- [INV-CH14] Well-formed receipts require `scoped_fragment_only == true` and `plaintext_semantics_exposed == false`

### `ChannelContextTokenError`

```rust
#[non_exhaustive]
pub enum ChannelContextTokenError {
    TokenTooLong { max_len },
    InvalidBase64 { detail },
    InvalidJson { detail },
    SchemaMismatch { expected, actual },
    MissingWitness,
    WitnessVerificationFailed,
    InvalidSignature { detail },
    SignatureVerificationFailed,
    LeaseMismatch { expected, actual },
    RequestIdMismatch { expected, actual },
    ExpiredToken { issued_at_secs, expires_after_secs, current_time_secs },
}
```

## Public API

### `validate_channel_boundary(check) -> Vec<ChannelBoundaryDefect>`

Validates a `ChannelBoundaryCheck` and returns a list of defects. Empty list means the boundary check passes.

### `derive_channel_source_witness(source) -> [u8; 32]`

Deterministically derives a BLAKE3 witness token for a channel source. Used by the daemon to bind channel-source classification into replay-stable tokens.

### `verify_channel_source_witness(source, witness, payload, signature, key) -> bool`

Validates a channel source witness token and daemon signature. Returns `true` only if witness matches and signature verifies.

### `issue_channel_context_token(check, lease_id, request_id, issued_at, signer) -> Result<String, ChannelContextTokenError>`

Issues a base64-encoded, signed channel context token from a boundary check. Encodes the full boundary state for downstream fail-closed reconstruction.

### `decode_channel_context_token(token, key, lease_id, current_time, request_id) -> Result<ChannelBoundaryCheck, ChannelContextTokenError>`

Decodes and verifies a signed channel context token. Validates schema, signature, lease binding, request binding, witness, and expiry.

## Resource Limit Constants

| Constant | Value | Purpose |
|---|---|---|
| `MAX_CHANNEL_DETAIL_LENGTH` | 512 | Truncation for defect detail strings |
| `MAX_DECLASSIFICATION_RECEIPT_ID_LENGTH` | 128 | Bound on receipt identifiers |
| `MAX_LEAKAGE_CONFIDENCE_LABEL_LENGTH` | 128 | Bound on confidence labels |

## Examples

### Channel Boundary Validation

```rust
use apm2_core::channel::{
    ChannelBoundaryCheck, ChannelSource, DeclassificationIntentScope,
    validate_channel_boundary,
};

let check = ChannelBoundaryCheck {
    source: ChannelSource::TypedToolIntent,
    channel_source_witness: Some(derive_channel_source_witness(ChannelSource::TypedToolIntent)),
    broker_verified: true,
    capability_verified: true,
    context_firewall_verified: true,
    policy_ledger_verified: true,
    taint_allow: true,
    classification_allow: true,
    declass_receipt_valid: true,
    declassification_intent: DeclassificationIntentScope::None,
    // ... remaining fields
};

let defects = validate_channel_boundary(&check);
assert!(defects.is_empty()); // All checks pass
```

### Witness Derivation

```rust
use apm2_core::channel::{ChannelSource, derive_channel_source_witness};

let witness = derive_channel_source_witness(ChannelSource::TypedToolIntent);
assert_ne!(witness, [0u8; 32]); // Non-zero witness
```

## Related Modules

- [`apm2_core::crypto`](../crypto/AGENTS.md) - `Signer`, `VerifyingKey`, `Signature` used for token signing/verification
- [`apm2_core::context`](../context/AGENTS.md) - Context firewall verified flag in `ChannelBoundaryCheck`
- [`apm2_core::htf`](../htf/AGENTS.md) - Tick-based timing channel budgets

## References

- [RFC-0003: Holonic Coordination Framework](../../../../documents/rfcs/RFC-0003/) - Typed boundary channels
- [RFC-0028: Holonic External I/O Security Profile over PCAC](../../../../documents/rfcs/RFC-0028/) - Boundary-flow integrity, declassification receipts, leakage budgets
- [RFC-0020: Holonic Substrate Interface (HSI)](../../../../documents/rfcs/RFC-0020/) - Markov-blanket enforcement
