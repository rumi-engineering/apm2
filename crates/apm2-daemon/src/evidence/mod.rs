//! Evidence economics module.
//!
//! This module handles tool receipts, evidence binding, flight recording,
//! ring buffer management, and evidence retention policies for audit and
//! debugging purposes.
//!
//! # Architecture
//!
//! ```text
//! evidence/
//!     |-- receipt.rs      - ToolReceipt, ReceiptKind, and core types
//!     |-- receipt_builder.rs - Builder pattern for receipt construction
//!     |-- binding.rs      - Evidence binding for CAS hash collection
//!     `-- (future: recorder.rs, ttl.rs, compaction.rs)
//! ```
//!
//! # Security Model
//!
//! Per AD-RECEIPT-001:
//! - Receipts bind envelope hash, policy hash, and evidence refs
//! - `canonical_bytes()` provides deterministic serialization for signing
//! - Evidence refs are sorted for determinism per AD-VERIFY-001
//!
//! # Contract References
//!
//! - AD-RECEIPT-001: Tool receipt generation
//! - AD-VERIFY-001: Deterministic serialization
//! - REQ-RECEIPT-001: Receipt requirements
//! - CTR-1303: Bounded collections with MAX_* constants

// TCK-00166: Tool receipt generation
pub mod binding;
pub mod golden_vectors;
pub mod receipt;
pub mod receipt_builder;

// Re-export core receipt types
// Re-export binding types
pub use binding::{EvidenceBinding, ToolEvidenceCollector};
pub use receipt::{
    CanonicalizerId, EpisodeId, Hash, MAX_CANONICALIZER_ID_LEN, MAX_CAPABILITY_ID_LEN,
    MAX_EPISODE_ID_LEN, MAX_EVIDENCE_REFS, MAX_REQUEST_ID_LEN, MAX_RESULT_MESSAGE_LEN,
    MAX_SIGNER_IDENTITY_LEN, ReceiptError, ReceiptKind, Signature, SignerIdentity,
    ToolExecutionDetails, ToolReceipt,
};
// Re-export builder
pub use receipt_builder::{ReceiptBuilder, ReceiptSigning};

// Placeholder exports for future evidence types.
// TODO(TCK-00170): Implement FlightRecorder, RingBuffer, and retention types.
// TODO(TCK-00171): Implement TTL and pinning types.
// TODO(TCK-00172): Implement compaction types.
