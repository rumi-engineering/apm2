//! Agent protocol definitions and lifecycle management.
//!
//! This module contains protocol definitions for agent communication with the
//! APM2 runtime, including exit signals for clean session handoff.
//!
//! # Modules
//!
//! - [`exit`]: Agent exit signal protocol for phase completion signaling.
//!
//! # Overview
//!
//! Agents are language-model-driven workers that execute work phases within
//! the APM2 holonic runtime. This module provides the protocol definitions
//! that enable structured communication between agents and the runtime.
//!
//! ## Exit Protocol
//!
//! When an agent completes a work phase, it emits a structured exit signal
//! rather than polling for status or attempting to continue. This enables:
//!
//! - Clean handoff between agent sessions
//! - Fresh context for the next agent
//! - Audit trail of phase completions
//! - Prevention of CI status gaming
//!
//! See [`exit::ExitSignal`] for the protocol definition.

pub mod exit;

// Re-export main types for convenience
pub use exit::{
    AGENT_EXIT_PROTOCOL_ENABLED_ENV, AgentExitConfig, AgentSessionCompleted, EXIT_SIGNAL_PROTOCOL,
    EXIT_SIGNAL_VERSION, ExitReason, ExitSignal, ExitSignalError, WorkPhase,
    is_agent_exit_protocol_enabled,
};
