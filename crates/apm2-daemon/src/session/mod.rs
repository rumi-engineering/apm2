// AGENT-AUTHORED (TCK-00211)
//! Session handling for the APM2 daemon.
//!
//! This module provides session management functionality for the daemon,
//! including CONSUME mode sessions with context firewall integration.
//!
//! # Modules
//!
//! - [`consume`]: CONSUME mode session handler with context firewall
//!   integration

pub mod consume;

// Re-export main types
pub use consume::{
    ConsumeSessionContext, ConsumeSessionError, ConsumeSessionHandler,
    EXIT_CLASSIFICATION_CONTEXT_MISS, MAX_REFINEMENT_ATTEMPTS, SessionTerminationInfo,
    TERMINATION_RATIONALE_CONTEXT_MISS, validate_tool_request,
};
