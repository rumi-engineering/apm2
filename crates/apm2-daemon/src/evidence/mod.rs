//! Evidence economics module.
//!
//! This module handles tool receipts, evidence binding, receipt signing and
//! verification, keychain integration, flight recording, ring buffer
//! management, evidence compaction, and evidence retention policies for
//! audit and debugging purposes.
//!
//! # Architecture
//!
//! ```text
//! evidence/
//!     |-- receipt.rs         - ToolReceipt, ReceiptKind, and core types
//!     |-- receipt_builder.rs - Builder pattern for receipt construction
//!     |-- binding.rs         - Evidence binding for CAS hash collection
//!     |-- signer.rs          - ReceiptSigner using Ed25519 (RFC-0033::REQ-0034)
//!     |-- verifier.rs        - Receipt verification predicate (RFC-0033::REQ-0034)
//!     |-- keychain.rs        - OS keychain integration for keys (RFC-0033::REQ-0034)
//!     |-- config.rs          - RecorderConfig per risk tier (RFC-0033::REQ-0036)
//!     |-- trigger.rs         - Persistence trigger conditions (RFC-0033::REQ-0036)
//!     |-- recorder.rs        - FlightRecorder implementation (RFC-0033::REQ-0036)
//!     |-- artifact.rs        - EvidenceArtifact with TTL and class (RFC-0033::REQ-0037)
//!     |-- ttl.rs             - TTL enforcement and eviction (RFC-0033::REQ-0037)
//!     |-- pin.rs             - Pin API for evidence retention (RFC-0033::REQ-0037)
//!     |-- tombstone.rs       - Tombstone tracking for compacted artifacts (RFC-0033::REQ-0038)
//!     |-- compaction.rs      - Evidence compaction strategy and jobs (RFC-0033::REQ-0038)
//!     `-- summary.rs         - Compaction receipt generation (RFC-0033::REQ-0038)
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

// RFC-0033::REQ-0033: Tool receipt generation
pub mod binding;
pub mod golden_vectors;
pub mod receipt;
pub mod receipt_builder;

// RFC-0033::REQ-0034: Receipt signing and verification
pub mod keychain;
pub mod signer;
pub mod verifier;

// RFC-0033::REQ-0036: Flight recorder with ring buffers
pub mod config;
pub mod recorder;
pub mod trigger;

// RFC-0033::REQ-0037: Evidence TTL and pinning
pub mod artifact;
pub mod pin;
pub mod ttl;

// RFC-0033::REQ-0038: Evidence compaction
pub mod compaction;
pub mod summary;
pub mod tombstone;

// RFC-0032::REQ-0108: CAS access control
pub mod cas_access;

// Re-export core receipt types
// Re-export binding types
// Re-export artifact types (RFC-0033::REQ-0037)
pub use artifact::{
    ARCHIVAL_TTL_SECS, ArtifactError, ArtifactId, EPHEMERAL_TTL_SECS, EvidenceArtifact,
    EvidenceClass, MAX_ARTIFACT_ID_LEN, MAX_DEFECT_RECORD_ID_LEN, MAX_PIN_ACTOR_LEN,
    MAX_PIN_REASON_LEN, PinReason, PinState, STANDARD_TTL_SECS, Timestamp,
};
pub use binding::{EvidenceBinding, ToolEvidenceCollector};
// Re-export CAS access facade types (RFC-0032::REQ-0108)
pub use cas_access::{CasAccessError, CasAccessFacade, CasAccessType};
// Re-export compaction types (RFC-0033::REQ-0038)
// Note: ArtifactId and MAX_ARTIFACT_ID_LEN are re-exported from artifact module (RFC-0033::REQ-0037)
pub use compaction::{
    CompactionCounts, CompactionError, CompactionJob, CompactionJobBuilder, CompactionResult,
    CompactionStrategy, CompactionSummary, DEFAULT_COMPACTION_THRESHOLD_NS,
    MAX_COMPACTION_ARTIFACTS, MIN_COMPACTION_THRESHOLD_NS,
};
// Re-export flight recorder types (RFC-0033::REQ-0036)
pub use config::{
    ESTIMATED_PTY_CHUNK_SIZE, ESTIMATED_TELEMETRY_FRAME_SIZE, ESTIMATED_TOOL_EVENT_SIZE,
    MAX_BUFFER_CAPACITY, MIN_BUFFER_CAPACITY, RecorderConfig, RecorderConfigBuilder,
    TIER_1_PTY_CAPACITY, TIER_1_TELEMETRY_CAPACITY, TIER_1_TOOL_CAPACITY, TIER_2_PTY_CAPACITY,
    TIER_2_TELEMETRY_CAPACITY, TIER_2_TOOL_CAPACITY, TIER_3_PLUS_PTY_CAPACITY,
    TIER_3_PLUS_TELEMETRY_CAPACITY, TIER_3_PLUS_TOOL_CAPACITY,
};
// Re-export keychain types (RFC-0033::REQ-0034)
pub use keychain::{
    InMemoryKeyStore, KEYCHAIN_SERVICE_NAME, KeyInfo, KeychainError, MAX_STORED_KEYS, OsKeychain,
    SigningKeyStore, generate_and_store_key,
};
// Re-export pin types (RFC-0033::REQ-0037)
pub use pin::{
    DEFAULT_DEFECT_GRACE_PERIOD_SECS, DefectBinding, MAX_GRACE_PERIOD_SECS, MAX_PINS_PER_ARTIFACT,
    PinError, PinEvent, PinManager, PinReceipt,
};
pub use receipt::{
    CanonicalizerId, EpisodeId, Hash, MAX_CANONICALIZER_ID_LEN, MAX_CAPABILITY_ID_LEN,
    MAX_EPISODE_ID_LEN, MAX_EVIDENCE_REFS, MAX_REQUEST_ID_LEN, MAX_RESULT_MESSAGE_LEN,
    MAX_SIGNER_IDENTITY_LEN, ReceiptError, ReceiptKind, Signature, SignerIdentity,
    ToolExecutionDetails, ToolReceipt,
};
// Re-export builder
pub use receipt_builder::{ReceiptBuilder, ReceiptSigning};
pub use recorder::{EvidenceBundle, FlightRecorder, PersistResult, ToolEvent};
// Re-export signer types (RFC-0033::REQ-0034)
pub use signer::{INITIAL_KEY_VERSION, KeyId, MAX_KEY_ID_LEN, ReceiptSigner, SignerError};
pub use summary::{
    CompactionReceipt, CompactionReceiptBuilder, CompactionReceiptError, CompactionStats,
    MAX_COMPACTED_HASHES,
};
pub use tombstone::{
    ArtifactKind, MAX_ARTIFACT_KIND_LEN, MAX_TOMBSTONES, Tombstone, TombstoneError, TombstoneList,
};
pub use trigger::{
    MAX_ACTOR_LEN, MAX_GATE_ID_LEN, MAX_REASON_LEN, MAX_RESOURCE_LEN,
    MAX_RULE_ID_LEN as MAX_TRIGGER_RULE_ID_LEN, MAX_VIOLATION_LEN, PersistTrigger, TriggerCategory,
};
// Re-export TTL enforcer types (RFC-0033::REQ-0037)
pub use ttl::{
    DEFAULT_ENFORCEMENT_INTERVAL_SECS, EnforcementStats, EvictionEvent, EvictionReason,
    MAX_ARTIFACTS, MAX_ENFORCEMENT_INTERVAL_SECS, MAX_EVICTIONS_PER_RUN,
    MIN_ENFORCEMENT_INTERVAL_SECS, TtlEnforcer, TtlEnforcerConfig,
};
// Re-export verifier types (RFC-0033::REQ-0034)
pub use verifier::{
    VerificationError, VerificationResult, verify_receipt, verify_receipt_integrity,
    verify_receipt_self_signed, verify_receipt_with_bytes, verify_receipts_batch,
};

// Both RFC-0033::REQ-0037 (TTL/pinning) and RFC-0033::REQ-0038 (compaction) are now implemented.
