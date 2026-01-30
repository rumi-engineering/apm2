//! Agent Acceptance Testing (AAT) module.
//!
//! This module provides types and utilities for implementing the AAT protocol
//! as defined in PRD-0003. The AAT system verifies PRs through
//! hypothesis-driven testing before they can merge.

pub mod anti_gaming;
pub mod cac_harness;
pub mod evidence;
pub mod executor;
pub mod parser;
pub mod tool_config;
pub mod types;
pub mod ux_verifier;
pub mod validation;
pub mod variation;
