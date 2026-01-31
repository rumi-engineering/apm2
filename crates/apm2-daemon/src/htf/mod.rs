// AGENT-AUTHORED
//! Holonic Time Framework (HTF) daemon module.
//!
//! This module provides the daemon-side implementation of the HTF time model
//! as specified in RFC-0016. It includes:
//!
//! - **[`HolonicClock`]**: Service for stamping time envelopes at runtime
//!   boundaries
//! - **[`ClockConfig`]**: Configuration for clock behavior and sources
//!
//! # Architecture
//!
//! The `HolonicClock` service provides three time surfaces:
//!
//! 1. **Monotonic ticks** (`now_mono_tick()`): Node-local monotonic time for
//!    deadlines
//! 2. **HLC stamps** (`now_hlc()`): Hybrid logical clock for cross-node
//!    causality
//! 3. **Ledger head** (`observed_ledger_head()`): Current ledger position for
//!    ordering
//!
//! # Invariants
//!
//! - [INV-HC001] Monotonic ticks never regress within a process lifetime
//! - [INV-HC002] HLC wall time is monotonically non-decreasing
//! - [INV-HC003] `TimeEnvelope`s reference a pinned `ClockProfile` by hash
//!
//! # Contracts
//!
//! - [CTR-HC001] `now_mono_tick()` returns the current monotonic tick value
//! - [CTR-HC002] `now_hlc()` advances HLC on each call (if enabled)
//! - [CTR-HC003] `observed_ledger_head()` queries the ledger backend
//! - [CTR-HC004] `stamp_envelope()` creates a complete `TimeEnvelope`
//!
//! # References
//!
//! - RFC-0016: Holonic Time Fabric
//! - TCK-00240: `HolonicClock` service implementation

mod clock;

pub use clock::{
    ClockConfig, ClockConfigBuilder, ClockError, ClockRegression, HolonicClock,
    HolonicClockBuilder, MAX_BUILD_FINGERPRINT_LEN, MAX_NAMESPACE_LEN, MAX_POLICY_ID_LEN,
};
