//! CCP (Code Context Protocol) module for semantic codebase discovery.
//!
//! This module provides the foundation for the CCP compiler pipeline, which
//! generates a semantic inventory of the codebase to ground RFC file path
//! references.
//!
//! # Components
//!
//! - **Component Atlas**: Discovers AGENTS.md files, parses
//!   invariants/contracts/ extension points, and generates stable component
//!   IDs.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::path::Path;
//!
//! use apm2_core::ccp::build_component_atlas;
//!
//! let atlas = build_component_atlas(Path::new("/repo/root")).unwrap();
//! for component in &atlas.components {
//!     println!(
//!         "{}: {} invariants, {} extension points",
//!         component.id,
//!         component.invariants.len(),
//!         component.extension_points.len()
//!     );
//! }
//! ```

pub mod component_atlas;

// Re-export primary API
pub use component_atlas::{
    CcpError, Component, ComponentAtlas, ComponentType, Contract, ExtensionPoint, Invariant,
    Stability, build_component_atlas, generate_component_id,
};
