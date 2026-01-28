//! Episode runtime module.
//!
//! This module manages bounded execution episodes for agent processes,
//! providing lifecycle management, state machine transitions, and
//! envelope construction for episode context.
//!
//! # Architecture
//!
//! Per AD-EPISODE-001 and AD-LAYER-001, the episode module provides:
//!
//! - **`EpisodeEnvelope`**: Immutable episode configuration, referenced by
//!   digest and bound into all receipts.
//! - **`EpisodeBudget`**: Resource limits (tokens, tool calls, time, I/O).
//! - **`PinnedSnapshot`**: Reproducibility digests (repo, lockfile, policy).
//! - **`StopConditions`**: Termination predicates.
//! - **`RiskTier`**: Security tier determining gates and evidence strength.
//! - **`DeterminismClass`**: Declared reproducibility level.
//!
//! # Canonicalization
//!
//! Per AD-VERIFY-001, all types support deterministic serialization:
//!
//! ```rust,ignore
//! use apm2_daemon::episode::EpisodeEnvelope;
//!
//! let envelope = EpisodeEnvelope::builder()
//!     .episode_id("ep-001")
//!     // ... other required fields
//!     .build()?;
//!
//! let bytes = envelope.canonical_bytes();
//! let digest = envelope.digest();
//! ```
//!
//! # Contract References
//!
//! - AD-EPISODE-001: Immutable episode envelope
//! - AD-VERIFY-001: Deterministic Protobuf serialization
//! - AD-LAYER-001: `EpisodeRuntime` extends `EpisodeController`
//! - REQ-EPISODE-001: Episode envelope requirements

pub mod budget;
pub mod envelope;
pub mod golden_vectors;
pub mod snapshot;

// Re-export primary types at module level
pub use budget::{EpisodeBudget, EpisodeBudgetBuilder};
pub use envelope::{
    ContextRefs, DeterminismClass, EnvelopeError, EpisodeEnvelope, EpisodeEnvelopeBuilder,
    RiskTier, StopConditions,
};
pub use snapshot::{PinnedSnapshot, PinnedSnapshotBuilder};
