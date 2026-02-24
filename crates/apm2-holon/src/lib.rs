//! # apm2-holon
//!
//! Holon trait and core types for holonic agent coordination.
//!
//! This crate defines the fundamental contract surface for agents participating
//! in the APM2 holonic coordination framework. A *holon* is an autonomous agent
//! unit that can:
//!
//! - Accept work requests via [`Holon::intake`]
//! - Execute bounded episodes via [`Holon::execute_episode`]
//! - Produce evidence artifacts via [`Holon::emit_artifact`]
//! - Escalate work to supervisors via [`Holon::escalate`]
//! - Evaluate stop conditions via [`Holon::should_stop`]
//!
//! ## Core Concepts
//!
//! - **Episode**: A bounded execution unit with a context, budget, and result
//! - **Stop Condition**: A predicate that determines when execution should halt
//! - **Artifact**: Evidence produced during execution (logged to ledger)
//! - **Escalation**: Forwarding work to a supervisor when unable to complete
//!
//! ## Example
//!
//! ```rust
//! use apm2_holon::{Artifact, EpisodeContext, EpisodeResult, Holon, HolonError, StopCondition};
//!
//! // Define a simple holon that processes text
//! struct EchoHolon;
//!
//! impl Holon for EchoHolon {
//!     type Input = String;
//!     type Output = String;
//!     type State = ();
//!
//!     fn intake(&mut self, input: Self::Input, _lease_id: &str) -> Result<(), HolonError> {
//!         // Validate input and prepare for execution
//!         Ok(())
//!     }
//!
//!     fn execute_episode(
//!         &mut self,
//!         ctx: &EpisodeContext,
//!     ) -> Result<EpisodeResult<Self::Output>, HolonError> {
//!         // Execute one episode of work
//!         Ok(EpisodeResult::completed("echo".to_string()))
//!     }
//!
//!     fn emit_artifact(&self, artifact: Artifact) -> Result<(), HolonError> {
//!         // Log artifact to ledger (stub for now)
//!         Ok(())
//!     }
//!
//!     fn escalate(&mut self, reason: &str) -> Result<(), HolonError> {
//!         // Forward to supervisor
//!         Ok(())
//!     }
//!
//!     fn should_stop(&self, ctx: &EpisodeContext) -> StopCondition {
//!         // Check if we should stop
//!         StopCondition::GoalSatisfied
//!     }
//!
//!     fn state(&self) -> &Self::State {
//!         &()
//!     }
//! }
//! ```
//!
//! ## Resource Management
//!
//! Holons operate under resource constraints defined by leases. The
//! [`resource`] module provides:
//!
//! - [`resource::Lease`]: Time-bounded, scoped authorization for work
//! - [`resource::Budget`]: Multi-dimensional resource limits (episodes, tokens,
//!   time)
//! - [`resource::LeaseScope`]: Authority boundaries for operations
//!
//! ## Design Notes
//!
//! This crate embodies Axiom I (Markov Blanket) from the Principia Holonica:
//! each holon defines a clear boundary through its trait contract, with
//! well-defined interfaces for communication across that boundary.
//!
//! The resource module implements Axiom III (Bounded Authority): leases
//! constrain what operations holons can perform and how many resources they can
//! consume.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

pub mod artifact;
pub mod context;
/// Core ledger adapter: writes holon events into apm2-core ledger+CAS
/// substrate (TCK-00670 / HL-001).
///
/// This module is always compiled (the envelope types and mapping functions
/// are pure data with no apm2-core dependency). The `core-ledger` feature
/// gates the concrete `apm2-core` integration paths used at runtime.
pub mod core_ledger_adapter;
pub mod defect;
pub mod episode;
pub mod error;
/// Legacy holon ledger types (event chain, hash chain verification).
///
/// **Deprecation (TCK-00670 / HL-002):** Direct use of this module for
/// persistence is deprecated. New code should use [`core_ledger_adapter`]
/// to write holon events into the `apm2-core` ledger substrate.
///
/// When the `legacy_holon_ledger` feature is enabled the module is `pub`
/// for migration reads and replay verification. Otherwise it is
/// `pub(crate)` — internal types like `EpisodeEvent`, `validate_id`, and
/// `EventHash` remain available within the crate.
#[cfg(feature = "legacy_holon_ledger")]
pub mod ledger;
#[cfg(not(feature = "legacy_holon_ledger"))]
pub(crate) mod ledger;
pub mod orchestration;
pub mod receipt;
pub mod resource;
pub mod result;
pub mod skill;
pub mod spawn;
pub mod stop;
pub mod traits;
pub mod work;

#[cfg(test)]
mod tests;

// Re-export main types at crate root for convenience
pub use artifact::Artifact;
pub use context::EpisodeContext;
#[cfg(feature = "core-ledger")]
pub use core_ledger_adapter::CoreLedgerWriter;
pub use core_ledger_adapter::{
    CoreLedgerAdapterError, FinalitySignal, HexDigest, HolonEventEnvelope, ReplayStats,
};
pub use defect::{
    DefectContext, DefectError, DefectRecord, DefectRecordBuilder, DefectSeverity, DefectSignal,
    SignalType,
};
pub use episode::{
    ContextPackConfig, EpisodeController, EpisodeControllerConfig, EpisodeLoopOutcome,
    EpisodeLoopResult,
};
pub use error::HolonError;
// Legacy ledger types (chain verification, lifecycle events) are only
// re-exported when the `legacy_holon_ledger` feature is enabled.
#[cfg(feature = "legacy_holon_ledger")]
pub use ledger::{ChainError, EpisodeOutcome, EventType, LedgerEvent, verify_chain};
// Shared ledger types (episode events, validation, hashes) are always
// re-exported. These are needed by downstream consumers regardless of
// whether legacy ledger event persistence is enabled.
pub use ledger::{
    EpisodeCompleted, EpisodeCompletionReason, EpisodeEvent, EpisodeStarted, EventHash,
    EventHashError, MAX_GOAL_SPEC_LENGTH, MAX_ID_LENGTH,
};
pub use orchestration::{
    BlockedReasonCode, IterationCompleted, IterationOutcome, OrchestrationConfig,
    OrchestrationDriver, OrchestrationEvent, OrchestrationStarted, OrchestrationStateV1,
    OrchestrationTerminated, TerminationReason,
};
pub use receipt::{BudgetDelta, PackMiss, ReceiptError, RunReceipt, RunReceiptBuilder};
pub use resource::{Budget, Lease, LeaseScope, ResourceError};
pub use result::EpisodeResult;
pub use skill::{
    HolonConfig, HolonContract, SkillFrontmatter, SkillParseError, StopConditionsConfig,
    parse_frontmatter, parse_skill_file,
};
pub use spawn::{SpawnConfig, SpawnOutcome, SpawnResult, spawn_holon};
pub use stop::StopCondition;
pub use traits::Holon;

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::artifact::Artifact;
    pub use crate::context::EpisodeContext;
    #[cfg(feature = "core-ledger")]
    pub use crate::core_ledger_adapter::CoreLedgerWriter;
    pub use crate::core_ledger_adapter::{
        CoreLedgerAdapterError, FinalitySignal, HexDigest, HolonEventEnvelope, ReplayStats,
    };
    pub use crate::defect::{
        DefectContext, DefectError, DefectRecord, DefectRecordBuilder, DefectSeverity,
        DefectSignal, SignalType,
    };
    pub use crate::episode::{
        ContextPackConfig, EpisodeController, EpisodeControllerConfig, EpisodeLoopOutcome,
        EpisodeLoopResult,
    };
    pub use crate::error::HolonError;
    #[cfg(feature = "legacy_holon_ledger")]
    pub use crate::ledger::{ChainError, EpisodeOutcome, EventType, LedgerEvent, verify_chain};
    pub use crate::ledger::{
        EpisodeCompleted, EpisodeCompletionReason, EpisodeEvent, EpisodeStarted, EventHash,
    };
    pub use crate::orchestration::{
        BlockedReasonCode, IterationCompleted, IterationOutcome, OrchestrationConfig,
        OrchestrationDriver, OrchestrationEvent, OrchestrationStarted, OrchestrationStateV1,
        OrchestrationTerminated, TerminationReason,
    };
    pub use crate::receipt::{BudgetDelta, PackMiss, ReceiptError, RunReceipt, RunReceiptBuilder};
    pub use crate::resource::{Budget, Lease, LeaseScope, ResourceError};
    pub use crate::result::EpisodeResult;
    pub use crate::skill::{HolonConfig, HolonContract, SkillFrontmatter, StopConditionsConfig};
    pub use crate::spawn::{SpawnConfig, SpawnOutcome, SpawnResult, spawn_holon};
    pub use crate::stop::StopCondition;
    pub use crate::traits::Holon;
    pub use crate::work::{AttemptOutcome, AttemptRecord, WorkLifecycle, WorkObject};
}
