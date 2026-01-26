//! RFC Framer module for generating RFC skeletons from Impact Map and CCP.
//!
//! This module provides the foundation for generating RFC (Request for
//! Comments) documents that are grounded in the existing codebase via CCP (Code
//! Context Protocol) artifacts. The RFC framer ensures all generated RFCs
//! reference valid codebase paths and include cryptographic proof of CCP state.
//!
//! # Overview
//!
//! The RFC framer takes two primary inputs:
//! - An Impact Map that maps PRD requirements to CCP components
//! - The CCP index that provides the authoritative codebase inventory
//!
//! It produces a complete RFC directory structure following the template:
//! - `00_meta.yaml` (metadata with CCP grounding section)
//! - `01_problem_and_imports.yaml` (problem statement from PRD)
//! - `02_design_decisions.yaml` (populated from Impact Map)
//! - `03_trust_boundaries.yaml` (security model)
//! - `04_contracts_and_versioning.yaml` (API contracts)
//! - `05_rollout_and_ops.yaml` (deployment considerations)
//! - `06_ticket_decomposition.yaml` (generated from mapped requirements)
//! - `07_test_and_evidence.yaml` (test strategy)
//! - `08_risks_and_open_questions.yaml` (risk assessment)
//! - `09_governance_and_gates.yaml` (approval gates)
//!
//! # Invariants
//!
//! - [INV-FRAMER-001] All file paths in RFC must exist in CCP or be marked as
//!   net-new
//! - [INV-FRAMER-002] CCP index hash is captured at frame time for staleness
//!   detection
//! - [INV-FRAMER-003] Generated RFC sections use deterministic YAML output
//! - [INV-FRAMER-004] Invalid path references fail compilation (fail-closed)
//!
//! # Contracts
//!
//! - [CTR-FRAMER-001] `frame_rfc` requires valid Impact Map and CCP index
//! - [CTR-FRAMER-002] Output directory is created atomically
//! - [CTR-FRAMER-003] All writes use atomic file operations
//! - [CTR-FRAMER-004] Path validation rejects parent directory traversal
//!
//! # Security
//!
//! - [SEC-FRAMER-001] File reads are bounded to prevent denial-of-service
//! - [SEC-FRAMER-002] Path traversal is prevented by validation
//! - [SEC-FRAMER-003] Only files within repo root are processed
//!
//! # Example
//!
//! ```rust,no_run
//! use std::path::Path;
//!
//! use apm2_core::rfc_framer::{RfcFrameOptions, frame_rfc};
//!
//! let result = frame_rfc(
//!     Path::new("/repo/root"),
//!     "PRD-0005",
//!     "RFC-0011",
//!     &RfcFrameOptions::default(),
//! )
//! .unwrap();
//!
//! println!("RFC framed at: {}", result.output_dir.display());
//! println!("CCP index hash: {}", result.ccp_grounding.ccp_index_hash);
//! ```

pub mod framer;
pub mod grounding;

// Re-export primary API
pub use framer::{
    RfcFrame, RfcFrameError, RfcFrameOptions, RfcFrameResult, RfcSection, RfcSectionType, frame_rfc,
};
pub use grounding::{
    CcpGrounding, ComponentReference, GroundingError, PathValidationError, validate_paths,
};
