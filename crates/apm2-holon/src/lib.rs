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
//! use apm2_holon::{
//!     Artifact, EpisodeContext, EpisodeResult, Holon, HolonError,
//!     StopCondition,
//! };
//!
//! // Define a simple holon that processes text
//! struct EchoHolon;
//!
//! impl Holon for EchoHolon {
//!     type Input = String;
//!     type Output = String;
//!     type State = ();
//!
//!     fn intake(
//!         &mut self,
//!         input: Self::Input,
//!         _lease_id: &str,
//!     ) -> Result<(), HolonError> {
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
pub mod error;
pub mod resource;
pub mod result;
pub mod skill;
pub mod stop;
pub mod traits;
pub mod work;

#[cfg(test)]
mod tests;

// Re-export main types at crate root for convenience
pub use artifact::Artifact;
pub use context::EpisodeContext;
pub use error::HolonError;
pub use resource::{Budget, Lease, LeaseScope, ResourceError};
pub use result::EpisodeResult;
pub use skill::{
    HolonConfig, HolonContract, SkillFrontmatter, SkillParseError, StopConditionsConfig,
    parse_frontmatter, parse_skill_file,
};
pub use stop::StopCondition;
pub use traits::Holon;

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::artifact::Artifact;
    pub use crate::context::EpisodeContext;
    pub use crate::error::HolonError;
    pub use crate::resource::{Budget, Lease, LeaseScope, ResourceError};
    pub use crate::result::EpisodeResult;
    pub use crate::skill::{HolonConfig, HolonContract, SkillFrontmatter, StopConditionsConfig};
    pub use crate::stop::StopCondition;
    pub use crate::traits::Holon;
    pub use crate::work::{AttemptOutcome, AttemptRecord, WorkLifecycle, WorkObject};
}
