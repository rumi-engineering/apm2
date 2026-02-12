# HTF Module

> Holonic Time Framework (HTF) daemon module -- clock service for time envelope stamping.

## Overview

The `htf` module provides the daemon-side implementation of the Holonic Time Fabric as specified in RFC-0016. The `HolonicClock` service is the daemon's authoritative time source, providing three time surfaces:

1. **Monotonic ticks** (`now_mono_tick()`): Node-local monotonic time for deadlines and ordering
2. **HLC stamps** (`now_hlc()`): Hybrid logical clock for cross-node causality
3. **Ledger head** (`observed_ledger_head()`): Current ledger position for ordering

The clock stamps `TimeEnvelope` objects that are attached to all episode events, providing temporal context for audit and causality tracking. Clock regressions are treated as security defects and fail closed.

## Key Types

### `HolonicClock`

```rust
pub struct HolonicClock { /* internal state: monotonic source, HLC state, ledger backend, config */ }
```

Built via `HolonicClockBuilder`.

**Invariants:**

- [INV-HT01] Monotonic ticks never regress within a process lifetime.
- [INV-HT02] HLC wall time is monotonically non-decreasing.
- [INV-HT03] `TimeEnvelope` objects reference a pinned `ClockProfile` by hash.
- [INV-HT04] Remote HLC timestamps exceeding `MAX_HLC_OFFSET_NS` are rejected (anti-drift).

**Contracts:**

- [CTR-HT01] `now_mono_tick()` returns the current monotonic tick value.
- [CTR-HT02] `now_hlc()` advances HLC on each call (if HLC is enabled).
- [CTR-HT03] `observed_ledger_head()` queries the ledger backend.
- [CTR-HT04] `stamp_envelope()` creates a complete `TimeEnvelope`.
- [CTR-HT05] Clock regression emits `CLOCK_REGRESSION` defect and fails closed.

### `ClockConfig`

```rust
pub struct ClockConfig { /* tick rate, namespace, ledger ID, HLC settings, build fingerprint */ }
```

Built via `ClockConfigBuilder`. All string fields bounded per CTR-1303.

### `ClockError`

```rust
pub enum ClockError {
    ClockRegression { current: u64, previous: u64 },
    LedgerQuery(LedgerError),
    InvalidConfig(String),
    StringTooLong { field: &'static str, length: usize, max: usize },
    HlcNotEnabled,
    HlcDriftExceeded { remote_wall_ns: u64, physical_now: u64, offset_ns: u64, max_allowed_ns: u64 },
    Canonicalization(CanonicalizationError),
}
```

### `ClockRegression`

Records a regression event for defect emission.

## Public API

```rust
impl HolonicClock {
    pub fn now_mono_tick(&self) -> Result<u64, ClockError>;
    pub fn now_hlc(&self) -> Result<Hlc, ClockError>;
    pub fn observed_ledger_head(&self) -> Result<LedgerTime, ClockError>;
    pub fn stamp_envelope(&self) -> Result<TimeEnvelope, ClockError>;
}
```

### Constants

- `MAX_BUILD_FINGERPRINT_LEN`: 256
- `MAX_POLICY_ID_LEN`: 128
- `MAX_NAMESPACE_LEN`: 128
- `MAX_HLC_OFFSET_NS`: 5,000,000,000 (5 seconds)

## Related Modules

- [`apm2_daemon::episode`](../episode/AGENTS.md) -- Episodes attach time envelopes to events
- [`apm2_daemon::pcac`](../pcac/AGENTS.md) -- PCAC lifecycle gate uses clock ticks for certificate expiry
- [`apm2_core::htf`](../../../apm2-core/src/htf/AGENTS.md) -- Core HTF types (`TimeEnvelope`, `Hlc`, `ClockProfile`)

## References

- RFC-0016: Holonic Time Fabric
- TCK-00240: `HolonicClock` service implementation
