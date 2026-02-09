// AGENT-AUTHORED
//! Hierarchical Time Framework (HTF) module.
//!
//! This module implements the core time types for the Hierarchical Time
//! Framework as specified in RFC-0016. HTF provides a consistent model for
//! tracking time across distributed nodes with explicit handling of
//! uncertainty and authority.
//!
//! # Components
//!
//! - **[`LedgerTime`]**: Authoritative ordering tuple (`ledger_id`, `epoch`,
//!   `seq`)
//! - **[`HtfTick`]**: Node-local monotonic tick counter for durations
//! - **[`TimeEnvelopeRef`]**: Content hash reference to full time envelopes
//! - **[`BoundedWallInterval`]**: Wall time interval with uncertainty bounds
//!
//! # Time Authority Model
//!
//! The HTF distinguishes between:
//!
//! 1. **Authoritative time** ([`LedgerTime`]): Used for ordering and truth
//!    decisions. Provided by consensus-backed ledgers.
//! 2. **Local tick time** ([`HtfTick`]): Used for deadlines and durations on a
//!    single node. Not comparable across nodes.
//! 3. **Wall time** ([`BoundedWallInterval`]): Never authoritative, only for
//!    display and external system coordination.
//!
//! # Invariants
//!
//! - `mono.end_tick >= mono.start_tick` for all monotonic spans
//! - `BoundedWallInterval: t_max_utc_ns >= t_min_utc_ns`
//! - Tick arithmetic is authoritative for deadlines within a node
//! - Cross-node time comparison MUST use [`LedgerTime`]
//!
//! # Resource Limits (Denial-of-Service Protection)
//!
//! - [`MAX_STRING_LENGTH`]: Maximum length for string fields (4096 bytes)
//! - [`MAX_OBSERVATIONS`]: Maximum observations in `TimeSyncObservation` (1000)
//! - [`MAX_ATTESTATION_SIZE`]: Maximum serialized size for attestation (65536
//!   bytes)
//!
//! # Example
//!
//! ```rust
//! use apm2_core::htf::{
//!     BoundedWallInterval, HtfTick, LedgerTime, TimeEnvelopeRef, WallTimeSource,
//! };
//!
//! // Create authoritative ledger time for ordering
//! let t1 = LedgerTime::new("ledger-main", 1, 100);
//! let t2 = LedgerTime::new("ledger-main", 1, 101);
//! assert!(t1 < t2);
//!
//! // Create node-local tick for deadline calculation
//! let start = HtfTick::new(1000, 1_000_000); // 1MHz tick rate
//! let end = start.saturating_add(5000); // 5000 ticks = 5ms
//! assert_eq!(end.saturating_sub(&start), 5000);
//!
//! // Reference a time envelope by content hash
//! let envelope_ref = TimeEnvelopeRef::new([0x42; 32]);
//!
//! // Wall time interval with uncertainty
//! let wall = BoundedWallInterval::new(
//!     1704067200_000_000_000, // min: 2024-01-01 00:00:00 UTC
//!     1704067200_100_000_000, // max: +100ms uncertainty
//!     WallTimeSource::BestEffortNtp,
//!     "95%",
//! )
//! .expect("valid interval");
//! ```

pub mod canonical;
pub mod epoch_seal;
pub mod freshness;
mod types;

// Re-export all public types
pub use canonical::{Canonicalizable, CanonicalizationError};
pub use epoch_seal::{
    EpochSealAuditEvent, EpochSealError, EpochSealIssuanceError, EpochSealIssuer, EpochSealV1,
    EpochSealVerdict, EpochSealVerificationError, EpochSealVerifier, MAX_EVICTION_HIGH_WATER_MARKS,
    MAX_SEAL_AUDIT_EVENTS, MAX_SEAL_STRING_LENGTH, MAX_TRACKED_ISSUERS, SignatureVerificationError,
    SignatureVerifier, is_seal_required_tier,
};
pub use freshness::{
    DEFAULT_TIER0_MAX_HEAD_AGE_TICKS, DEFAULT_TIER1_MAX_HEAD_AGE_TICKS,
    DEFAULT_TIER2_MAX_HEAD_AGE_TICKS, DEFAULT_TIER3_MAX_HEAD_AGE_TICKS,
    DEFAULT_TIER4_MAX_HEAD_AGE_TICKS, FreshnessAuditEvent, FreshnessEvaluationError,
    FreshnessPolicyError, FreshnessPolicyEvaluator, FreshnessPolicyV1, MAX_AUDIT_EVENTS,
    StalenessAction, StalenessVerdict, TierFreshnessConfig,
};
pub use types::{
    BoundedWallInterval,
    BoundedWallIntervalError,
    ClockProfile,
    Hlc,
    HtfTick,
    LedgerTime,
    LedgerTimeError,
    // Resource limit constants (DoS protection)
    MAX_ATTESTATION_SIZE,
    MAX_OBSERVATIONS,
    MAX_STRING_LENGTH,
    MonotonicReading,
    MonotonicSource,
    ObservationRecord,
    TimeEnvelope,
    TimeEnvelopeRef,
    TimeSyncObservation,
    WallTimeSource,
};
