//! Evidence bundle publisher for artifact storage and verification.
//!
//! This module provides the evidence bundle infrastructure for the APM2
//! kernel. Evidence bundles contain artifacts that prove work completion
//! and are stored in a content-addressed store (CAS).
//!
//! # Architecture
//!
//! ```text
//! ArtifactPublish (tool request)
//!        |
//!        v
//! EvidencePublisher.publish()
//!        |
//!        v
//! ContentAddressedStore.store(content)
//!        |
//!        v
//! EvidencePublished (kernel event)
//!        |
//!        v
//! EvidenceReducer.apply(event)
//!        |
//!        v
//! Evidence (projection)
//! ```
//!
//! # Key Concepts
//!
//! - **Content-Addressed Store (CAS)**: Artifacts are stored and retrieved by
//!   their BLAKE3 hash, ensuring integrity and deduplication
//! - **Evidence**: A published artifact linked to a work item with metadata
//! - **Evidence Bundle**: A collection of evidence artifacts for a work item
//! - **Data Classification**: Artifacts are classified as PUBLIC, INTERNAL,
//!   CONFIDENTIAL, or RESTRICTED
//!
//! # Security Properties
//!
//! - **Hash verification**: Content is verified on storage and retrieval
//! - **Classification enforcement**: Data handling follows classification rules
//! - **Progressive disclosure**: Only hashes are stored in events; content is
//!   fetched on demand
//! - **Immutability**: Published artifacts cannot be modified
//!
//! # Example
//!
//! ```rust
//! use apm2_core::evidence::{
//!     ContentAddressedStore, DataClassification, EvidenceCategory,
//!     EvidencePublisher, MemoryCas,
//! };
//!
//! // Create an in-memory CAS for testing
//! let cas = MemoryCas::new();
//!
//! // Create the publisher
//! let publisher = EvidencePublisher::new(cas);
//!
//! // Publish an artifact
//! let artifact_id = "test-results-001";
//! let content = b"test output: all tests passed";
//! let category = EvidenceCategory::TestResults;
//! let classification = DataClassification::Internal;
//!
//! let result = publisher.publish(
//!     artifact_id,
//!     "work-123",
//!     content,
//!     category,
//!     classification,
//!     &[],
//! );
//!
//! assert!(result.is_ok());
//! ```

mod cas;
mod category;
mod classification;
mod error;
mod publisher;
mod reducer;
mod state;

#[cfg(test)]
mod tests;

pub use cas::{CasError, ContentAddressedStore, MemoryCas};
pub use category::EvidenceCategory;
pub use classification::DataClassification;
pub use error::EvidenceError;
pub use publisher::{EvidencePublisher, PublishResult};
pub use reducer::{EvidenceReducer, EvidenceReducerState};
pub use state::{Evidence, EvidenceBundle, EvidenceSummary};
