//! Factory commands for AI-assisted code generation.
//!
//! This module provides commands for the factory pipeline, which orchestrates
//! AI CLI processes (like Claude Code) to implement specifications.
//!
//! # Subcommands
//!
//! - `run` - Run a Markdown spec with an agent CLI
//! - `ccp` - CCP (Code Context Protocol) operations
//! - `impact-map` - Impact Map generation (PRD to CCP mapping)
//! - `rfc` - RFC framing from Impact Map and CCP
//! - `tickets` - Ticket emission from RFC decomposition
//! - `compile` - End-to-end compile pipeline (CCP -> Impact Map -> RFC ->
//!   Tickets)

pub mod ccp;
pub mod compile;
pub mod impact_map;
pub mod rfc;
mod run;
pub mod tickets;

// Re-export the run function for backward compatibility
pub use run::run;
