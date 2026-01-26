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
//! - **Crate Graph**: Builds a deterministic dependency graph of workspace
//!   crates using cargo metadata.
//! - **CCP Index**: Combines component atlas and crate graph into a unified,
//!   content-addressed artifact with BLAKE3 hashing for incremental rebuild
//!   detection.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::path::Path;
//!
//! use apm2_core::ccp::{build_component_atlas, build_crate_graph};
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
//!
//! let graph = build_crate_graph(Path::new("/repo/root")).unwrap();
//! println!("Workspace has {} crates", graph.crates.len());
//! for edge in &graph.edges {
//!     println!("{} -> {}", edge.from, edge.to);
//! }
//! ```

pub mod component_atlas;
pub mod crate_graph;
pub mod index;

// Re-export primary API
pub use component_atlas::{
    CcpError, Component, ComponentAtlas, ComponentType, Contract, ExtensionPoint, Invariant,
    Stability, build_component_atlas, generate_component_id,
};
pub use crate_graph::{
    CrateGraph, CrateGraphError, CrateNode, CrateType, DependencyEdge, DependencyType,
    build_crate_graph, find_dependencies, find_dependents, generate_crate_id,
};
