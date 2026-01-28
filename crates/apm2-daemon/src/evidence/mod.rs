//! Evidence economics module.
//!
//! This module handles tool receipts, evidence binding, receipt signing and
//! verification, keychain integration, flight recording, ring buffer
//! management, and evidence retention policies for audit and debugging
//! purposes.
//!
//! # Architecture
//!
//! ```text
//! evidence/
//!     |-- receipt.rs         - ToolReceipt, ReceiptKind, and core types
//!     |-- receipt_builder.rs - Builder pattern for receipt construction
//!     |-- binding.rs         - Evidence binding for CAS hash collection
//!     |-- signer.rs          - ReceiptSigner using Ed25519 (TCK-00167)
//!     |-- verifier.rs        - Receipt verification predicate (TCK-00167)
//!     |-- keychain.rs        - OS keychain integration for keys (TCK-00167)
//!     `-- (future: recorder.rs, ttl.rs, compaction.rs)
//! ```
//!
//! # Security Model
//!
//! Per AD-RECEIPT-001:
//! - Receipts bind envelope hash, policy hash, and evidence refs
//! - `canonical_bytes()` provides deterministic serialization for signing
//! - Evidence refs are sorted for determinism per AD-VERIFY-001
//! - Signature verification uses constant-time Ed25519 (CTR-1909)
//! - Signing keys are stored in OS keychain (AD-KEY-001)
//!
//! # Contract References
//!
//! - AD-RECEIPT-001: Tool receipt generation
//! - AD-VERIFY-001: Deterministic serialization
//! - AD-KEY-001: Key lifecycle management
//! - REQ-RECEIPT-001: Receipt requirements
//! - CTR-1303: Bounded collections with MAX_* constants
//! - CTR-1909: Constant-time operations for sensitive comparisons

// TCK-00166: Tool receipt generation
pub mod binding;
pub mod golden_vectors;
pub mod receipt;
pub mod receipt_builder;

// TCK-00167: Receipt signing and verification
pub mod keychain;
pub mod signer;
pub mod verifier;

// Re-export core receipt types
// Re-export binding types
pub use binding::{EvidenceBinding, ToolEvidenceCollector};
// Re-export keychain types (TCK-00167)
pub use keychain::{
    InMemoryKeyStore, KEYCHAIN_SERVICE_NAME, KeyInfo, KeychainError, MAX_STORED_KEYS, OsKeychain,
    SigningKeyStore, generate_and_store_key,
};
pub use receipt::{
    CanonicalizerId, EpisodeId, Hash, MAX_CANONICALIZER_ID_LEN, MAX_CAPABILITY_ID_LEN,
    MAX_EPISODE_ID_LEN, MAX_EVIDENCE_REFS, MAX_REQUEST_ID_LEN, MAX_RESULT_MESSAGE_LEN,
    MAX_SIGNER_IDENTITY_LEN, ReceiptError, ReceiptKind, Signature, SignerIdentity,
    ToolExecutionDetails, ToolReceipt,
};
// Re-export builder
pub use receipt_builder::{ReceiptBuilder, ReceiptSigning};
// Re-export signer types (TCK-00167)
pub use signer::{INITIAL_KEY_VERSION, KeyId, MAX_KEY_ID_LEN, ReceiptSigner, SignerError};
// Re-export verifier types (TCK-00167)
pub use verifier::{
    VerificationError, VerificationResult, verify_receipt, verify_receipt_integrity,
    verify_receipt_self_signed, verify_receipt_with_bytes, verify_receipts_batch,
};

// Placeholder exports for future evidence types.
// TODO(TCK-00170): Implement FlightRecorder, RingBuffer, and retention types.
// TODO(TCK-00171): Implement TTL and pinning types.
// TODO(TCK-00172): Implement compaction types.
