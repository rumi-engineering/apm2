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
//!     |-- signer.rs          - ReceiptSigner using Ed25519 (TCK-00167)
//!     |-- verifier.rs        - Receipt verification predicate (TCK-00167)
//!     |-- keychain.rs        - OS keychain integration for keys (TCK-00167)
//!     |-- config.rs          - RecorderConfig per risk tier (TCK-00170)
//!     |-- trigger.rs         - Persistence trigger conditions (TCK-00170)
//!     |-- recorder.rs        - FlightRecorder implementation (TCK-00170)
//!     |-- artifact.rs        - EvidenceArtifact with TTL and class (TCK-00171)
//!     |-- ttl.rs             - TTL enforcement and eviction (TCK-00171)
//!     |-- pin.rs             - Pin API for evidence retention (TCK-00171)
//!     |-- tombstone.rs       - Tombstone tracking for compacted artifacts (TCK-00172)
//!     |-- compaction.rs      - Evidence compaction strategy and jobs (TCK-00172)
//!     `-- summary.rs         - Compaction receipt generation (TCK-00172)
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

// TCK-00170: Flight recorder with ring buffers
pub mod config;
pub mod recorder;
pub mod trigger;

// TCK-00171: Evidence TTL and pinning
pub mod artifact;
pub mod pin;
pub mod ttl;

// TCK-00172: Evidence compaction
pub mod compaction;
pub mod summary;
pub mod tombstone;

// Re-export core receipt types
// Re-export binding types
// Re-export artifact types (TCK-00171)
pub use artifact::{
    ARCHIVAL_TTL_SECS, ArtifactError, ArtifactId, EPHEMERAL_TTL_SECS, EvidenceArtifact,
    EvidenceClass, MAX_ARTIFACT_ID_LEN, MAX_DEFECT_RECORD_ID_LEN, MAX_PIN_ACTOR_LEN,
    MAX_PIN_REASON_LEN, PinReason, PinState, STANDARD_TTL_SECS, Timestamp,
};
pub use binding::{EvidenceBinding, ToolEvidenceCollector};
// Re-export compaction types (TCK-00172)
// Note: ArtifactId and MAX_ARTIFACT_ID_LEN are re-exported from artifact module (TCK-00171)
pub use compaction::{
    CompactionCounts, CompactionError, CompactionJob, CompactionJobBuilder, CompactionResult,
    CompactionStrategy, CompactionSummary, DEFAULT_COMPACTION_THRESHOLD_NS,
    MAX_COMPACTION_ARTIFACTS, MIN_COMPACTION_THRESHOLD_NS,
};
// Re-export flight recorder types (TCK-00170)
pub use config::{
    ESTIMATED_PTY_CHUNK_SIZE, ESTIMATED_TELEMETRY_FRAME_SIZE, ESTIMATED_TOOL_EVENT_SIZE,
    MAX_BUFFER_CAPACITY, MIN_BUFFER_CAPACITY, RecorderConfig, RecorderConfigBuilder,
    TIER_1_PTY_CAPACITY, TIER_1_TELEMETRY_CAPACITY, TIER_1_TOOL_CAPACITY, TIER_2_PTY_CAPACITY,
    TIER_2_TELEMETRY_CAPACITY, TIER_2_TOOL_CAPACITY, TIER_3_PLUS_PTY_CAPACITY,
    TIER_3_PLUS_TELEMETRY_CAPACITY, TIER_3_PLUS_TOOL_CAPACITY,
};
// Re-export keychain types (TCK-00167)
pub use keychain::{
    InMemoryKeyStore, KEYCHAIN_SERVICE_NAME, KeyInfo, KeychainError, MAX_STORED_KEYS, OsKeychain,
    SigningKeyStore, generate_and_store_key,
};
// Re-export pin types (TCK-00171)
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
// Re-export signer types (TCK-00167)
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
// Re-export TTL enforcer types (TCK-00171)
pub use ttl::{
    DEFAULT_ENFORCEMENT_INTERVAL_SECS, EnforcementStats, EvictionEvent, EvictionReason,
    MAX_ARTIFACTS, MAX_ENFORCEMENT_INTERVAL_SECS, MAX_EVICTIONS_PER_RUN,
    MIN_ENFORCEMENT_INTERVAL_SECS, TtlEnforcer, TtlEnforcerConfig,
};
// Re-export verifier types (TCK-00167)
pub use verifier::{
    VerificationError, VerificationResult, verify_receipt, verify_receipt_integrity,
    verify_receipt_self_signed, verify_receipt_with_bytes, verify_receipts_batch,
};

// Both TCK-00171 (TTL/pinning) and TCK-00172 (compaction) are now implemented.
