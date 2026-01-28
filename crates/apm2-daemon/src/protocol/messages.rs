//! Protocol buffer message types for daemon-client communication.
//!
//! This module provides the generated Protocol Buffer message types for the
//! daemon runtime protocol, along with helper methods for canonical encoding
//! and type conversions.
//!
//! # Message Categories
//!
//! Messages are organized per AD-DAEMON-003 and CTR-PROTO contracts:
//!
//! - **CTR-PROTO-001 (Handshake)**: [`Hello`], [`HelloAck`], [`ClientInfo`],
//!   [`ServerInfo`]
//! - **CTR-PROTO-002 (Episode Control)**: [`CreateEpisode`],
//!   [`EpisodeCreated`], [`StartEpisode`], [`EpisodeStarted`], [`StopEpisode`],
//!   [`EpisodeStopped`], [`SignalEpisode`], [`ResizePty`],
//!   [`EpisodeQuarantined`]
//! - **CTR-PROTO-003 (I/O)**: [`SendInput`], [`StreamOutput`], [`StreamKind`]
//! - **CTR-PROTO-004 (Tool Mediation)**: [`ToolRequest`], [`ToolDecision`],
//!   [`ToolResult`], [`DecisionType`], [`ToolOutcome`], [`BudgetDelta`]
//! - **CTR-PROTO-005 (Telemetry)**: [`TelemetryFrame`], [`TelemetryPolicy`],
//!   [`CgroupStats`], [`PromoteTrigger`], [`RingBufferLimits`]
//! - **CTR-PROTO-006 (Receipts/Evidence)**: [`Receipt`], [`PublishEvidence`],
//!   [`EvidencePinned`], [`EvidenceTtlExpired`], [`CompactionCompleted`],
//!   [`ReceiptKind`], [`EvidenceKind`], [`RetentionHint`]
//!
//! # Canonical Encoding
//!
//! Per AD-DAEMON-003 and AD-VERIFY-001, signed messages require deterministic
//! serialization. The [`Canonicalize`] trait is implemented for messages that
//! participate in signing workflows:
//!
//! ```rust,ignore
//! use apm2_daemon::protocol::messages::{Receipt, Canonicalize};
//! use prost::Message;
//!
//! let mut receipt = Receipt {
//!     kind: 0,
//!     unsigned_bytes_hash: vec![0u8; 32],
//!     signature: vec![],  // Empty for unsigned canonical bytes
//!     // ... other fields
//!     ..Default::default()
//! };
//!
//! receipt.canonicalize();
//! let canonical_bytes = receipt.canonical_bytes();
//! // Use canonical_bytes for signing
//! ```
//!
//! # The Unsigned Canonical Bytes Rule
//!
//! Per AD-VERIFY-001, authoritative signing is performed over the "Unsigned
//! Canonical Bytes" of a message. This is defined as the Protobuf-encoded bytes
//! of the message where the `signature` and any `issuer_signature` fields are
//! set to their default (empty) values.

#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::doc_markdown,
    clippy::match_single_binding,
    clippy::missing_const_for_fn,
    clippy::redundant_closure,
    clippy::struct_field_names,
    missing_docs
)]
mod generated {
    include!("apm2.daemon.v1.rs");
}

pub use generated::*;
use prost::Message;

/// Trait for canonicalizing messages before signing.
///
/// Types implementing this trait have repeated fields that must be sorted
/// to ensure deterministic encoding. Call `canonicalize()` before computing
/// signatures or hashes.
pub trait Canonicalize {
    /// Sorts all repeated fields to ensure canonical encoding.
    ///
    /// This method modifies the message in place, sorting any repeated fields
    /// in lexicographic order (for strings) or ascending order (for byte
    /// arrays).
    fn canonicalize(&mut self);
}

/// Trait for messages that support unsigned canonical bytes extraction.
///
/// This trait is implemented by messages that participate in signing workflows.
/// Per AD-VERIFY-001, the canonical bytes exclude signature fields.
pub trait CanonicalBytes: Message + Clone {
    /// Returns the unsigned canonical bytes for signing.
    ///
    /// This method returns the Protobuf-encoded bytes with signature fields
    /// cleared (set to empty), ensuring a stable fixpoint for verification.
    fn canonical_bytes(&self) -> Vec<u8>;
}

// ============================================================================
// Canonicalize implementations
// ============================================================================

impl Canonicalize for Hello {
    fn canonicalize(&mut self) {
        self.requested_caps.sort();
    }
}

impl Canonicalize for HelloAck {
    fn canonicalize(&mut self) {
        self.granted_caps.sort();
        // Note: BTreeMap is already sorted by key, so canonicalizer_versions
        // is deterministically ordered.
    }
}

impl Canonicalize for EpisodeQuarantined {
    fn canonicalize(&mut self) {
        self.evidence_pinned.sort();
    }
}

impl Canonicalize for Receipt {
    fn canonicalize(&mut self) {
        self.evidence_refs.sort();
    }
}

impl Canonicalize for CompactionCompleted {
    fn canonicalize(&mut self) {
        self.tombstoned_hashes.sort();
    }
}

impl Canonicalize for TelemetryPolicy {
    fn canonicalize(&mut self) {
        // Sort promote_triggers by metric name for determinism
        self.promote_triggers
            .sort_by(|a, b| a.metric.cmp(&b.metric));
    }
}

// ============================================================================
// CanonicalBytes implementations
// ============================================================================

impl CanonicalBytes for Receipt {
    fn canonical_bytes(&self) -> Vec<u8> {
        // Create a copy with signature fields cleared
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned.issuer_signature = None;
        unsigned.encode_to_vec()
    }
}

impl CanonicalBytes for Hello {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl CanonicalBytes for HelloAck {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl CanonicalBytes for TelemetryFrame {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl CanonicalBytes for ToolRequest {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl CanonicalBytes for ToolDecision {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl CanonicalBytes for ToolResult {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

// Note: From<Enum> for i32 implementations are provided by prost::Enumeration
// derive

// ============================================================================
// Builder helpers
// ============================================================================

impl Hello {
    /// Creates a new `Hello` message with the given protocol version.
    #[must_use]
    pub const fn new(protocol_version: u32) -> Self {
        Self {
            protocol_version,
            client_info: None,
            requested_caps: Vec::new(),
        }
    }

    /// Sets the client info.
    #[must_use]
    pub fn with_client_info(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.client_info = Some(ClientInfo {
            name: name.into(),
            version: version.into(),
        });
        self
    }

    /// Adds a requested capability.
    #[must_use]
    pub fn with_capability(mut self, cap: impl Into<String>) -> Self {
        self.requested_caps.push(cap.into());
        self
    }
}

impl HelloAck {
    /// Creates a new `HelloAck` message.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the server info.
    #[must_use]
    pub fn with_server_info(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.server_info = Some(ServerInfo {
            name: name.into(),
            version: version.into(),
        });
        self
    }

    /// Adds a granted capability.
    #[must_use]
    pub fn with_granted_cap(mut self, cap: impl Into<String>) -> Self {
        self.granted_caps.push(cap.into());
        self
    }

    /// Sets the policy hash.
    #[must_use]
    pub fn with_policy_hash(mut self, hash: Vec<u8>) -> Self {
        self.policy_hash = hash;
        self
    }
}

impl Receipt {
    /// Creates a new Receipt with the given kind.
    #[must_use]
    pub fn new(kind: ReceiptKind) -> Self {
        Self {
            kind: kind.into(),
            unsigned_bytes_hash: Vec::new(),
            signature: Vec::new(),
            evidence_refs: Vec::new(),
            policy_hash: Vec::new(),
            envelope_hash: Vec::new(),
            issuer_id: None,
            issuer_signature: None,
        }
    }

    /// Sets the envelope hash.
    #[must_use]
    pub fn with_envelope_hash(mut self, hash: Vec<u8>) -> Self {
        self.envelope_hash = hash;
        self
    }

    /// Sets the policy hash.
    #[must_use]
    pub fn with_policy_hash(mut self, hash: Vec<u8>) -> Self {
        self.policy_hash = hash;
        self
    }

    /// Adds an evidence reference.
    #[must_use]
    pub fn with_evidence_ref(mut self, evidence_ref: Vec<u8>) -> Self {
        self.evidence_refs.push(evidence_ref);
        self
    }

    /// Computes and sets the unsigned bytes hash using BLAKE3.
    ///
    /// This should be called after all other fields are set but before signing.
    #[must_use]
    pub fn compute_unsigned_bytes_hash(mut self) -> Self {
        let canonical = self.canonical_bytes();
        self.unsigned_bytes_hash = blake3::hash(&canonical).as_bytes().to_vec();
        self
    }
}

impl TelemetryFrame {
    /// Creates a new `TelemetryFrame` for the given episode.
    #[must_use]
    pub fn new(episode_id: impl Into<String>, seq: u64, ts_mono: u64) -> Self {
        Self {
            episode_id: episode_id.into(),
            seq,
            ts_mono,
            cpu_ns: 0,
            mem_rss_bytes: 0,
            io_read_bytes: 0,
            io_write_bytes: 0,
            cgroup_stats: None,
            o11y_flags: 0,
        }
    }

    /// Sets CPU nanoseconds.
    #[must_use]
    pub const fn with_cpu_ns(mut self, cpu_ns: u64) -> Self {
        self.cpu_ns = cpu_ns;
        self
    }

    /// Sets memory RSS bytes.
    #[must_use]
    pub const fn with_mem_rss_bytes(mut self, mem_rss_bytes: u64) -> Self {
        self.mem_rss_bytes = mem_rss_bytes;
        self
    }

    /// Sets I/O read/write bytes.
    #[must_use]
    pub const fn with_io_bytes(mut self, read_bytes: u64, write_bytes: u64) -> Self {
        self.io_read_bytes = read_bytes;
        self.io_write_bytes = write_bytes;
        self
    }

    /// Sets cgroup stats.
    #[must_use]
    pub const fn with_cgroup_stats(mut self, stats: CgroupStats) -> Self {
        self.cgroup_stats = Some(stats);
        self
    }
}

impl StreamOutput {
    /// Creates a new stdout output chunk.
    #[must_use]
    pub fn stdout(chunk: Vec<u8>, seq: u64, ts: u64) -> Self {
        Self {
            chunk,
            kind: StreamKind::Stdout.into(),
            seq,
            ts,
        }
    }

    /// Creates a new stderr output chunk.
    #[must_use]
    pub fn stderr(chunk: Vec<u8>, seq: u64, ts: u64) -> Self {
        Self {
            chunk,
            kind: StreamKind::Stderr.into(),
            seq,
            ts,
        }
    }
}

impl BudgetDelta {
    /// Creates a new `BudgetDelta`.
    #[must_use]
    pub const fn new(tokens: u64, tool_calls: u32, cpu_ms: u64) -> Self {
        Self {
            tokens,
            tool_calls,
            cpu_ms,
        }
    }
}

#[cfg(test)]
mod tests;
