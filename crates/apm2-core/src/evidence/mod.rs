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
//!     ContentAddressedStore, DataClassification, EvidenceCategory, EvidencePublisher, MemoryCas,
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

pub mod aat_receipt;
mod acceptance_package;
mod cas;
mod category;
mod classification;
mod error;
mod publisher;
mod receipt;
mod reducer;
mod state;
pub mod strictly_ordered;

#[cfg(test)]
mod tests;

pub use aat_receipt::{
    AATReceipt, AATReceiptError, AATReceiptGenerator, BudgetConsumed as AATBudgetConsumed,
    TestSummary, verify_aat_receipt,
};
pub use acceptance_package::{
    AcceptancePackageError, AcceptancePackageV1, AdmissionVerdict, CasReceiptProvider,
    FindingSeverity, LedgerReceiptProvider, ReceiptPointer, ReceiptProvider, ReceiptType,
    TrustedIssuerSet, VerificationFinding, VerificationResult, verify_acceptance_package,
};
pub use cas::{CasError, ContentAddressedStore, MemoryCas, StoreResult};
pub use category::EvidenceCategory;
pub use classification::DataClassification;
pub use error::EvidenceError;
pub use publisher::{EvidencePublisher, PublishResult};
pub use receipt::{
    GateReasonCode, GateReceipt, GateReceiptGenerator, GateRequirements, GateResult,
};
pub use reducer::{EvidenceReducer, EvidenceReducerState};
pub use state::{Evidence, EvidenceBundle, EvidenceSummary};
// StrictlyOrderedEvidence and Gate Predicates (TCK-00198)
pub use strictly_ordered::{
    EvidencePredicate, GatePredicateReceipt, MAX_EVIDENCE_HASHES, MAX_EVIDENCE_ID_LEN,
    MAX_EVIDENCE_PREDICATES, MAX_PREDICATE_NAME_LEN, MAX_PREDICATE_VALUE_LEN,
    MAX_TOTAL_ORDER_SIGNATURES, MAX_WORK_ID_LEN, MIN_QUORUM_SIGNATURES, StrictlyOrderedError,
    StrictlyOrderedEvidence, TotalOrderProof,
};
