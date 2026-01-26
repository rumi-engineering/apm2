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

pub mod ccp;
pub mod impact_map;
mod run;

// Re-export the run function for backward compatibility
pub use run::run;
