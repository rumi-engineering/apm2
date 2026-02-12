# HTF Module

> Holonic Time Fabric: hierarchical time types with explicit authority, uncertainty, and denial-of-service protection for distributed ordering.

## Overview

The `apm2_core::htf` module implements the Holonic Time Fabric as specified in RFC-0016. HTF provides a consistent model for tracking time across distributed nodes by distinguishing three categories of time:

1. **Authoritative time** (`LedgerTime`): Consensus-backed ordering tuples used for truth decisions
2. **Local tick time** (`HtfTick`): Node-local monotonic counters for deadlines and durations
3. **Wall time** (`BoundedWallInterval`): Never authoritative, only for display and external coordination

The module also provides epoch sealing (`EpochSealV1`), freshness policy evaluation (`FreshnessPolicyV1`), VDF delay profiles (`VdfProfileV1`), and canonicalization (`Canonicalizable`) for deterministic hashing and signing.

```text
                    HTF Time Authority Model
                    ========================

  ┌─────────────────────┐
  │    LedgerTime       │  Authoritative ordering (cross-node)
  │  (ledger_id,epoch,  │  Backed by consensus ledger
  │   seq)              │
  └─────────┬───────────┘
            │ anchors
  ┌─────────▼───────────┐
  │   TimeEnvelope      │  Binds mono + wall + HLC to ledger anchor
  │   (content-addressed│
  │    via CAS)         │
  └─────────┬───────────┘
            │ references
  ┌─────────▼───────────┐     ┌──────────────────────┐
  │  TimeEnvelopeRef    │     │  HtfTick             │
  │  (32-byte hash)     │     │  Node-local monotonic│
  │  Hot-path events    │     │  Deadlines/durations │
  └─────────────────────┘     └──────────────────────┘

  ┌──────────────────────┐    ┌──────────────────────┐
  │ BoundedWallInterval  │    │  EpochSealV1         │
  │ [t_min, t_max] + src │    │  Monotonic sealing   │
  │ NEVER authoritative  │    │  Anti-equivocation   │
  └──────────────────────┘    └──────────────────────┘
```

## Key Types

### `LedgerTime`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LedgerTime {
    ledger_id: String,
    epoch: u64,
    seq: u64,
}
```

Authoritative ordering tuple from a consensus-backed ledger. Implements total ordering lexicographically: `ledger_id` > `epoch` > `seq`.

**Invariants:**

- [INV-HT01] `ledger_id` must not exceed `MAX_STRING_LENGTH` (4096 bytes)
- [INV-HT02] Ordering is total and lexicographic: `ledger_id`, then `epoch`, then `seq`
- [INV-HT03] Cross-node time comparison MUST use `LedgerTime`, never ticks or wall time

**Contracts:**

- [CTR-HT01] `new()` panics if `ledger_id` exceeds `MAX_STRING_LENGTH`; use `try_new()` for fallible construction
- [CTR-HT02] `next_seq()` panics on overflow; use `checked_next_seq()` for fallible increment
- [CTR-HT03] `next_epoch()` resets `seq` to zero and increments `epoch`
- [CTR-HT04] Deserialization rejects oversized `ledger_id` via bounded deserializer

### `HtfTick`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HtfTick {
    value: u64,
    tick_rate_hz: u64,
}
```

Node-local monotonic tick counter. Authoritative for deadlines and durations within a single node. NOT comparable across nodes.

**Invariants:**

- [INV-HT04] Tick values are node-local; cross-node comparison is undefined
- [INV-HT05] Tick rate (`tick_rate_hz`) defines the temporal resolution (e.g., 1MHz = 1us/tick)

**Contracts:**

- [CTR-HT05] `saturating_add` / `saturating_sub` clamp at `u64::MAX` / `0` respectively
- [CTR-HT06] `checked_add` / `checked_sub` return `None` on overflow/underflow
- [CTR-HT07] `nanos_to_ticks` / `ticks_to_nanos` return `None` on overflow or zero tick rate

### `TimeEnvelopeRef`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TimeEnvelopeRef {
    hash: [u8; 32],
}
```

Lightweight 32-byte content hash reference to a full `TimeEnvelope` in CAS. Used on hot paths to avoid embedding full envelopes in events.

**Invariants:**

- [INV-HT06] `from_slice` returns `None` if input is not exactly 32 bytes
- [INV-HT07] `zero()` is the sentinel value (all bytes zero); `is_zero()` detects it

### `BoundedWallInterval`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct BoundedWallInterval {
    t_min_utc_ns: u64,
    t_max_utc_ns: u64,
    source: WallTimeSource,
    confidence: String,
}
```

Wall time interval with explicit uncertainty bounds. NEVER authoritative for ordering or truth decisions.

**Invariants:**

- [INV-HT08] `t_max_utc_ns >= t_min_utc_ns` always enforced (construction and deserialization)
- [INV-HT09] `confidence` must not exceed `MAX_STRING_LENGTH`

**Contracts:**

- [CTR-HT08] `new()` returns `BoundedWallIntervalError::InvalidInterval` if `t_max < t_min`
- [CTR-HT09] `point()` creates a zero-uncertainty interval (`t_min == t_max`)

### `WallTimeSource`

```rust
#[non_exhaustive]
pub enum WallTimeSource {
    None, BestEffortNtp, AuthenticatedNts, Roughtime, CloudBounded, ManualOperator,
}
```

Identifies how wall clock bounds were obtained. Different sources have different trust characteristics.

### `TimeEnvelope`

```rust
pub struct TimeEnvelope {
    pub clock_profile_hash: String,
    pub hlc: Hlc,
    pub ledger_anchor: LedgerTime,
    pub mono: MonotonicReading,
    pub notes: Option<String>,
    pub wall: BoundedWallInterval,
}
```

Verifiable time assertion binding a monotonic reading, wall time bounds, and HLC state to a ledger anchor.

### `ClockProfile`

```rust
pub struct ClockProfile {
    pub attestation: Option<serde_json::Value>,
    pub build_fingerprint: String,
    pub hlc_enabled: bool,
    pub max_wall_uncertainty_ns: u64,
    pub monotonic_source: MonotonicSource,
    pub profile_policy_id: String,
    pub tick_rate_hz: u64,
    pub wall_time_source: WallTimeSource,
}
```

CAC artifact defining a node's clock configuration. Bounded fields prevent DoS.

**Invariants:**

- [INV-HT10] `attestation` bounded by `MAX_ATTESTATION_SIZE` (65536 bytes) during deserialization
- [INV-HT11] String fields bounded by `MAX_STRING_LENGTH` (4096 bytes)

### `Canonicalizable` (trait)

```rust
pub trait Canonicalizable {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalizationError>;
    fn canonical_hash(&self) -> Result<[u8; 32], CanonicalizationError>;
}
```

Blanket-implemented for all `Serialize` types. Produces deterministic byte sequences following RFC 8785 (JSON Canonicalization Scheme) principles: sorted keys, no whitespace, deterministic number formatting. Hash is BLAKE3.

**Invariants:**

- [INV-HT12] Same input always produces identical canonical bytes (deterministic)
- [INV-HT13] Keys are sorted lexicographically via `serde_json::Value` (`BTreeMap`)

### `EpochSealV1`

```rust
pub struct EpochSealV1 {
    epoch_number: u64,
    sealed_root_hash: [u8; 32],
    issuer_cell_id: String,
    cell_id: String,
    // ... signature, vdf_profile, authority_seal_hash, etc.
}
```

Monotonic epoch seal binding an artifact root to an epoch number with cryptographic signature.

**Invariants:**

- [INV-HT14] `epoch_number > 0` (zero reserved as "no seal")
- [INV-HT15] Epoch numbers must strictly increase per issuer (monotonicity)
- [INV-HT16] Two seals from the same issuer at same epoch with different root hashes are rejected (anti-equivocation)

**Contracts:**

- [CTR-HT10] Fail-closed: when no `SignatureVerifier` is configured, ALL seals are rejected
- [CTR-HT11] Tier2+ authority admissions deny on missing or invalid seals

### `FreshnessPolicyV1`

```rust
pub struct FreshnessPolicyV1 {
    tiers: [TierFreshnessConfig; 5], // Tier0..Tier4
}
```

Risk-tier-specific freshness policy. Uses only ledger-anchor lag and local HTF ticks (never wall-clock).

**Invariants:**

- [INV-HT17] Tier2+ MUST use `StalenessAction::Deny` and a positive threshold
- [INV-HT18] Thresholds are monotonically non-increasing from Tier0 to Tier4

### `VdfProfileV1`

```rust
pub struct VdfProfileV1 {
    scheme: VdfScheme,
    input_hash: [u8; 32],
    output: Vec<u8>,
    difficulty: u64,
}
```

VDF delay profile for adversarial federation links. Attached to epoch seals.

**Invariants:**

- [INV-HT19] `input_hash` must be non-zero
- [INV-HT20] `output` must be non-empty and <= `MAX_VDF_OUTPUT_LENGTH` (256 bytes)
- [INV-HT21] `difficulty` must be in `[MIN_VDF_DIFFICULTY, MAX_VDF_DIFFICULTY]` (1..1,000,000)

## Public API

### LedgerTime

- `LedgerTime::new(ledger_id, epoch, seq)` - Create with panic on oversized ID
- `LedgerTime::try_new(ledger_id, epoch, seq)` - Fallible creation
- `ledger_id()`, `epoch()`, `seq()` - Accessors
- `next_seq()` / `checked_next_seq()` - Increment sequence
- `next_epoch()` / `checked_next_epoch()` - Increment epoch, reset seq to 0

### HtfTick

- `HtfTick::new(value, tick_rate_hz)` - Create a tick
- `value()`, `tick_rate_hz()` - Accessors
- `saturating_add(delta)` / `saturating_sub(earlier)` - Arithmetic
- `checked_add(delta)` / `checked_sub(earlier)` - Fallible arithmetic
- `nanos_to_ticks(nanos)` / `ticks_to_nanos(ticks)` - Conversion

### BoundedWallInterval

- `BoundedWallInterval::new(t_min, t_max, source, confidence)` - Validated construction
- `BoundedWallInterval::point(t, source, confidence)` - Zero-uncertainty
- `contains(t)`, `overlaps(other)`, `midpoint_ns()`, `uncertainty_ns()` - Queries

### Canonicalizable

- `canonical_bytes()` - RFC 8785 canonical JSON bytes
- `canonical_hash()` - BLAKE3 hash of canonical bytes

### EpochSealV1

- `EpochSealV1::new(...)` - Validated construction
- `verify()` / `verify_with_policy()` - Signature and monotonicity verification
- `EpochSealVerifier` - Stateful verifier tracking per-issuer epoch state

### FreshnessPolicyV1

- `FreshnessPolicyV1::new(tiers)` / `Default::default()` - Construction
- `FreshnessPolicyEvaluator::evaluate(tier, current_tick, head_epoch_tick)` - Freshness check

### VdfProfileV1

- `VdfProfileV1::new(scheme, input_hash, output, difficulty)` - Validated construction
- `VdfProfileV1::derive_challenge(cell_id, prior_root, quorum_anchor)` - Deterministic challenge
- `VdfVerifier::verify(profile)` - Scheme-dispatch verification

## Resource Limit Constants

| Constant | Value | Purpose |
|---|---|---|
| `MAX_STRING_LENGTH` | 4096 | DoS protection for string fields |
| `MAX_OBSERVATIONS` | 1000 | DoS protection for `TimeSyncObservation` arrays |
| `MAX_ATTESTATION_SIZE` | 65536 | DoS protection for `ClockProfile.attestation` |
| `MAX_SEAL_STRING_LENGTH` | 4096 | DoS protection for epoch seal strings |
| `MAX_TRACKED_ISSUERS` | 1024 | DoS protection for verifier state |
| `MAX_SEAL_AUDIT_EVENTS` | 16 | DoS protection for audit event retention |
| `MAX_VDF_OUTPUT_LENGTH` | 256 | DoS protection for VDF output bytes |
| `MAX_VDF_DIFFICULTY` | 1,000,000 | Upper bound on VDF sequential work |

## Examples

### Authoritative Ordering with LedgerTime

```rust
use apm2_core::htf::LedgerTime;

let t1 = LedgerTime::new("ledger-main", 1, 100);
let t2 = LedgerTime::new("ledger-main", 1, 101);
assert!(t1 < t2); // Same ledger, same epoch: compare by seq

let t3 = LedgerTime::new("ledger-main", 2, 1);
assert!(t2 < t3); // Epoch takes precedence over seq
```

### Node-Local Tick Deadlines

```rust
use apm2_core::htf::HtfTick;

let start = HtfTick::new(1000, 1_000_000); // 1MHz tick rate
let deadline = start.saturating_add(5000);  // 5000 ticks = 5ms
assert_eq!(deadline.saturating_sub(&start), 5000);
assert_eq!(start.nanos_to_ticks(1_000_000), Some(1000)); // 1ms = 1000 ticks
```

## Related Modules

- [`apm2_core::ledger`](../ledger/AGENTS.md) - Append-only event storage anchoring `LedgerTime`
- [`apm2_core::crypto`](../crypto/AGENTS.md) - BLAKE3 hashing used by canonicalization and epoch seals
- [`apm2_core::evidence`](../evidence/AGENTS.md) - CAS for storing `TimeEnvelope` artifacts
- [`apm2_core::determinism`](../determinism/AGENTS.md) - Determinism requirements shared with HTF

## References

- [RFC-0016: Holonic Time Fabric (HTF)](../../../../documents/rfcs/RFC-0016/)
- [RFC-0020: Holonic Substrate Interface (HSI)](../../../../documents/rfcs/RFC-0020/) - Epoch seal integration
- [APM2 Rust Standards: Time, Monotonicity, Determinism](/documents/skills/rust-standards/references/40_time_monotonicity_determinism.md)
- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785) - Canonical JSON strategy
