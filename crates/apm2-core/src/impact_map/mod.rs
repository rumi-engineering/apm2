//! Impact Map generation for PRD requirement-to-codebase mapping.
//!
//! This module provides the foundation for mapping PRD requirements to existing
//! codebase components identified in the CCP (Code Context Protocol) index.
//! The Impact Map bridges the gap between requirements and implementation by:
//!
//! - Parsing PRD requirement YAML files
//! - Matching requirements to CCP components via keyword similarity
//! - Detecting duplication risks when multiple extension points are viable
//! - Classifying unmapped requirements as "net-new substrate"
//! - Generating deterministic YAML output for downstream RFC framing
//!
//! # Invariants
//!
//! - [INV-0001] Impact map output is deterministic: same inputs produce
//!   identical YAML
//! - [INV-0002] All requirements are either mapped to components or classified
//!   as net-new
//! - [INV-0003] Duplication risks are flagged when multiple extension points
//!   match
//! - [INV-0004] Output files use canonical YAML formatting with sorted keys
//!
//! # Contracts
//!
//! - [CTR-0001] `build_impact_map` requires a valid CCP index to exist
//! - [CTR-0002] PRD requirements directory must exist and contain YAML files
//! - [CTR-0003] Output directory is created if it doesn't exist
//! - [CTR-0004] Atomic writes ensure no partial/corrupt files on crash
//!
//! # Security
//!
//! - [SEC-0001] File reads are bounded to prevent denial-of-service
//! - [SEC-0002] Path traversal is prevented by canonicalization
//! - [SEC-0003] Only files within repo root are processed
//!
//! # Example
//!
//! ```rust,no_run
//! use std::path::Path;
//!
//! use apm2_core::impact_map::{ImpactMapBuildOptions, build_impact_map};
//!
//! let result = build_impact_map(
//!     Path::new("/repo/root"),
//!     "PRD-0005",
//!     &ImpactMapBuildOptions::default(),
//! )
//! .unwrap();
//!
//! println!(
//!     "Mapped {} requirements",
//!     result.impact_map.requirement_mappings.len()
//! );
//! for mapping in &result.impact_map.requirement_mappings {
//!     println!(
//!         "  {}: {} candidates",
//!         mapping.requirement_id,
//!         mapping.candidates.len()
//!     );
//! }
//! ```

pub mod adjudication;
pub mod mapper;
pub mod output;

// Re-export primary API
pub use adjudication::{
    AdjudicationResult, DuplicationRisk, DuplicationSeverity, NetNewClassification,
    adjudicate_mappings,
};
pub use mapper::{
    CandidateComponent, FitScore, ImpactMapError, MappedRequirement, RequirementMatcher,
    parse_requirements,
};
pub use output::{
    ImpactMap, ImpactMapBuildOptions, ImpactMapBuildResult, ImpactMapSummary, build_impact_map,
    write_impact_map,
};
