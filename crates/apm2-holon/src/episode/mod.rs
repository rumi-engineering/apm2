//! Episode controller for bounded holon execution.
//!
//! This module implements the episode controller that manages the execution
//! loop for holons. It handles:
//!
//! - Constructing [`crate::EpisodeContext`] from work state and constraints
//! - Executing bounded episodes via [`crate::Holon::execute_episode`]
//! - Evaluating stop conditions after each episode
//! - Emitting ledger events for episode lifecycle
//! - Enforcing budget limits within episodes
//!
//! # Design
//!
//! The episode controller follows the Active Inference pattern (Axiom V from
//! Principia Holonica): episodes are bounded units of execution that minimize
//! free energy through iterative refinement until a stop condition is met.
//!
//! # Stop Conditions
//!
//! The controller evaluates stop conditions in priority order:
//!
//! 1. **Budget Exhausted**: Any resource dimension is depleted
//! 2. **Goal Satisfied**: The holon signals work is complete
//! 3. **Blocked**: The holon cannot make progress
//! 4. **Escalated**: Work needs supervisor intervention
//! 5. **Error**: An unrecoverable error occurred
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::episode::{EpisodeController, EpisodeControllerConfig};
//! use apm2_holon::resource::{Budget, Lease, LeaseScope};
//!
//! // Create a controller with configuration
//! let config = EpisodeControllerConfig::default();
//! let controller = EpisodeController::new(config);
//!
//! // The controller can be used with any Holon implementation
//! // via the run_episode_loop method
//! ```

mod controller;

pub use controller::{
    EpisodeController, EpisodeControllerConfig, EpisodeLoopOutcome, EpisodeLoopResult,
};

/// Default maximum number of episodes per execution loop.
pub const DEFAULT_MAX_EPISODES: u64 = 100;

/// Default timeout per episode in milliseconds.
pub const DEFAULT_EPISODE_TIMEOUT_MS: u64 = 300_000; // 5 minutes
