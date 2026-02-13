// AGENT-AUTHORED
//! Tool log index types for canonical ordering and audit indexing.
//!
//! This module implements [`ToolLogIndexV1`] per TCK-00327 and RFC-0019.
//! The index provides a single-pointer audit surface for tool executions
//! within an episode.
//!
//! # Design Overview
//!
//! Per DEC-0002 in RFC-0019, `ToolLogIndexV1` indexes `ToolExecutionReceipt`
//! hashes with canonical ordering. This enables:
//! - Single-pointer audit (`tool_log_index_hash`)
//! - Per-call retrieval by hash
//! - Bounded metadata and chunking support
//!
//! # Security Model
//!
//! - **Hash Integrity**: All receipt hashes must resolve to valid CAS artifacts
//! - **Canonical Ordering**: Receipts are ordered by sequence number
//! - **Chunking Support**: Large indices can be split into Merkle-friendly
//!   chunks
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::ToolLogIndexV1Builder;
//!
//! let index = ToolLogIndexV1Builder::new()
//!     .episode_id("ep-001")
//!     .add_receipt_hash([0x11; 32])
//!     .add_receipt_hash([0x22; 32])
//!     .build()
//!     .expect("valid index");
//!
//! assert_eq!(index.tool_execution_receipt_hashes.len(), 2);
//! let cas_hash = index.compute_cas_hash();
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length for episode ID.
pub const MAX_EPISODE_ID_LENGTH: usize = 128;

/// Maximum number of receipt hashes per index.
///
/// Per CTR-0002 in RFC-0019, indices support chunking for large episodes.
/// This limit ensures a single index chunk is bounded for memory safety.
pub const MAX_RECEIPT_HASHES_PER_INDEX: usize = 10_000;

/// Maximum number of continuation hashes (for chunked indices).
pub const MAX_CONTINUATION_HASHES: usize = 256;

/// Schema identifier for `ToolLogIndexV1`.
pub const TOOL_LOG_INDEX_V1_SCHEMA: &str = "apm2.tool_log_index.v1";

/// Current schema version.
pub const TOOL_LOG_INDEX_V1_VERSION: &str = "1.0.0";

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during tool log index operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ToolLogIndexError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Collection size exceeds limit.
    #[error("collection size exceeds limit: {field} has {actual} items, max is {max}")]
    CollectionTooLarge {
        /// The field name.
        field: &'static str,
        /// Actual size.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Invalid data in conversion.
    #[error("invalid data: {0}")]
    InvalidData(String),
}

// =============================================================================
// ToolLogCounts
// =============================================================================

/// Budget consumption and count summary for tool log index.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolLogCounts {
    /// Total number of tool executions.
    pub total_executions: u64,
    /// Number of successful executions.
    pub successful_executions: u64,
    /// Number of failed executions.
    pub failed_executions: u64,
    /// Total tokens consumed.
    pub total_tokens: u64,
    /// Total I/O bytes consumed.
    pub total_bytes_io: u64,
    /// Total wall clock time in milliseconds.
    pub total_wall_ms: u64,
}

impl ToolLogCounts {
    /// Creates a new counts instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            total_executions: 0,
            successful_executions: 0,
            failed_executions: 0,
            total_tokens: 0,
            total_bytes_io: 0,
            total_wall_ms: 0,
        }
    }

    /// Increments execution count.
    #[allow(clippy::missing_const_for_fn)]
    pub fn record_execution(&mut self, success: bool, tokens: u64, bytes_io: u64, wall_ms: u64) {
        self.total_executions += 1;
        if success {
            self.successful_executions += 1;
        } else {
            self.failed_executions += 1;
        }
        self.total_tokens = self.total_tokens.saturating_add(tokens);
        self.total_bytes_io = self.total_bytes_io.saturating_add(bytes_io);
        self.total_wall_ms = self.total_wall_ms.saturating_add(wall_ms);
    }
}

// =============================================================================
// ToolLogIndexV1
// =============================================================================

/// Index of tool execution receipt hashes with canonical ordering.
///
/// This structure provides a single-pointer audit surface for all tool
/// executions within an episode. The receipts are ordered by execution
/// sequence and can be independently verified via CAS lookup.
///
/// # Chunking
///
/// For episodes with many tool executions, the index supports chunking:
/// - Each chunk contains up to `MAX_RECEIPT_HASHES_PER_INDEX` receipts
/// - `continuation_hashes` references additional chunks (Merkle-friendly)
/// - `is_final_chunk` indicates the last chunk in the sequence
///
/// # Fields
///
/// - `schema`: Schema identifier
/// - `schema_version`: Schema version
/// - `episode_id`: Episode this index belongs to
/// - `tool_execution_receipt_hashes`: Ordered list of receipt hashes
/// - `counts`: Budget consumption and count summary
/// - `first_sequence`: First sequence number in this chunk (0-indexed)
/// - `continuation_hashes`: Hashes of continuation chunks (if any)
/// - `is_final_chunk`: Whether this is the last chunk
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolLogIndexV1 {
    /// Schema identifier.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Episode this index belongs to.
    pub episode_id: String,
    /// Ordered list of `ToolExecutionReceipt` hashes (each 32 bytes,
    /// hex-encoded).
    pub tool_execution_receipt_hashes: Vec<String>,
    /// Budget consumption and count summary.
    pub counts: ToolLogCounts,
    /// First sequence number in this chunk (0-indexed).
    pub first_sequence: u64,
    /// Hashes of continuation chunks (hex-encoded, if any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub continuation_hashes: Vec<String>,
    /// Whether this is the last chunk in the sequence.
    pub is_final_chunk: bool,
}

impl ToolLogIndexV1 {
    /// Creates a builder for constructing a `ToolLogIndexV1`.
    #[must_use]
    pub fn builder() -> ToolLogIndexV1Builder {
        ToolLogIndexV1Builder::default()
    }

    /// Computes the CAS hash of this index.
    ///
    /// # Panics
    ///
    /// Panics if JSON serialization fails, which should not happen for valid
    /// indices.
    #[must_use]
    pub fn compute_cas_hash(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("ToolLogIndexV1 is always serializable");
        *blake3::hash(&json).as_bytes()
    }

    /// Validates the index structure.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails.
    pub fn validate(&self) -> Result<(), ToolLogIndexError> {
        // Validate schema
        if self.schema != TOOL_LOG_INDEX_V1_SCHEMA {
            return Err(ToolLogIndexError::InvalidData(format!(
                "invalid schema: expected {TOOL_LOG_INDEX_V1_SCHEMA}, got {}",
                self.schema
            )));
        }

        // Validate episode_id
        if self.episode_id.is_empty() {
            return Err(ToolLogIndexError::MissingField("episode_id"));
        }
        if self.episode_id.len() > MAX_EPISODE_ID_LENGTH {
            return Err(ToolLogIndexError::StringTooLong {
                field: "episode_id",
                len: self.episode_id.len(),
                max: MAX_EPISODE_ID_LENGTH,
            });
        }

        // Validate receipt hashes count
        if self.tool_execution_receipt_hashes.len() > MAX_RECEIPT_HASHES_PER_INDEX {
            return Err(ToolLogIndexError::CollectionTooLarge {
                field: "tool_execution_receipt_hashes",
                actual: self.tool_execution_receipt_hashes.len(),
                max: MAX_RECEIPT_HASHES_PER_INDEX,
            });
        }

        // Validate continuation hashes count
        if self.continuation_hashes.len() > MAX_CONTINUATION_HASHES {
            return Err(ToolLogIndexError::CollectionTooLarge {
                field: "continuation_hashes",
                actual: self.continuation_hashes.len(),
                max: MAX_CONTINUATION_HASHES,
            });
        }

        // Validate hash formats (64 hex chars each)
        for (i, hash) in self.tool_execution_receipt_hashes.iter().enumerate() {
            if hash.len() != 64 {
                return Err(ToolLogIndexError::InvalidData(format!(
                    "tool_execution_receipt_hashes[{i}] must be 64 hex characters"
                )));
            }
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ToolLogIndexError::InvalidData(format!(
                    "tool_execution_receipt_hashes[{i}] must be hex-encoded"
                )));
            }
        }

        for (i, hash) in self.continuation_hashes.iter().enumerate() {
            if hash.len() != 64 {
                return Err(ToolLogIndexError::InvalidData(format!(
                    "continuation_hashes[{i}] must be 64 hex characters"
                )));
            }
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ToolLogIndexError::InvalidData(format!(
                    "continuation_hashes[{i}] must be hex-encoded"
                )));
            }
        }

        Ok(())
    }

    /// Returns the total number of receipts referenced by this index.
    #[must_use]
    pub fn receipt_count(&self) -> usize {
        self.tool_execution_receipt_hashes.len()
    }

    /// Returns `true` if this index is chunked (has continuation).
    #[must_use]
    pub fn is_chunked(&self) -> bool {
        !self.continuation_hashes.is_empty() || !self.is_final_chunk
    }
}

// =============================================================================
// ToolLogIndexV1Builder
// =============================================================================

/// Builder for constructing a `ToolLogIndexV1`.
#[derive(Debug, Default)]
pub struct ToolLogIndexV1Builder {
    episode_id: Option<String>,
    receipt_hashes: Vec<[u8; 32]>,
    counts: ToolLogCounts,
    first_sequence: u64,
    continuation_hashes: Vec<[u8; 32]>,
    is_final_chunk: bool,
}

#[allow(clippy::missing_const_for_fn)]
impl ToolLogIndexV1Builder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            is_final_chunk: true, // Default to final chunk for single-chunk indices
            ..Default::default()
        }
    }

    /// Sets the episode ID.
    #[must_use]
    pub fn episode_id(mut self, id: impl Into<String>) -> Self {
        self.episode_id = Some(id.into());
        self
    }

    /// Adds a receipt hash.
    #[must_use]
    pub fn add_receipt_hash(mut self, hash: [u8; 32]) -> Self {
        self.receipt_hashes.push(hash);
        self
    }

    /// Sets all receipt hashes at once.
    #[must_use]
    pub fn receipt_hashes(mut self, hashes: Vec<[u8; 32]>) -> Self {
        self.receipt_hashes = hashes;
        self
    }

    /// Sets the counts.
    #[must_use]
    pub fn counts(mut self, counts: ToolLogCounts) -> Self {
        self.counts = counts;
        self
    }

    /// Sets the first sequence number.
    #[must_use]
    pub fn first_sequence(mut self, seq: u64) -> Self {
        self.first_sequence = seq;
        self
    }

    /// Adds a continuation hash (for chunked indices).
    #[must_use]
    pub fn add_continuation_hash(mut self, hash: [u8; 32]) -> Self {
        self.continuation_hashes.push(hash);
        self
    }

    /// Sets whether this is the final chunk.
    #[must_use]
    pub fn is_final_chunk(mut self, is_final: bool) -> Self {
        self.is_final_chunk = is_final;
        self
    }

    /// Builds the `ToolLogIndexV1`.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build(self) -> Result<ToolLogIndexV1, ToolLogIndexError> {
        let episode_id = self
            .episode_id
            .ok_or(ToolLogIndexError::MissingField("episode_id"))?;

        // Validate lengths
        if episode_id.len() > MAX_EPISODE_ID_LENGTH {
            return Err(ToolLogIndexError::StringTooLong {
                field: "episode_id",
                len: episode_id.len(),
                max: MAX_EPISODE_ID_LENGTH,
            });
        }

        if self.receipt_hashes.len() > MAX_RECEIPT_HASHES_PER_INDEX {
            return Err(ToolLogIndexError::CollectionTooLarge {
                field: "tool_execution_receipt_hashes",
                actual: self.receipt_hashes.len(),
                max: MAX_RECEIPT_HASHES_PER_INDEX,
            });
        }

        if self.continuation_hashes.len() > MAX_CONTINUATION_HASHES {
            return Err(ToolLogIndexError::CollectionTooLarge {
                field: "continuation_hashes",
                actual: self.continuation_hashes.len(),
                max: MAX_CONTINUATION_HASHES,
            });
        }

        let index = ToolLogIndexV1 {
            schema: TOOL_LOG_INDEX_V1_SCHEMA.to_string(),
            schema_version: TOOL_LOG_INDEX_V1_VERSION.to_string(),
            episode_id,
            tool_execution_receipt_hashes: self.receipt_hashes.iter().map(hex::encode).collect(),
            counts: self.counts,
            first_sequence: self.first_sequence,
            continuation_hashes: self.continuation_hashes.iter().map(hex::encode).collect(),
            is_final_chunk: self.is_final_chunk,
        };

        index.validate()?;
        Ok(index)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_index() -> ToolLogIndexV1 {
        ToolLogIndexV1Builder::new()
            .episode_id("ep-001")
            .add_receipt_hash([0x11; 32])
            .add_receipt_hash([0x22; 32])
            .add_receipt_hash([0x33; 32])
            .counts(ToolLogCounts {
                total_executions: 3,
                successful_executions: 2,
                failed_executions: 1,
                total_tokens: 1000,
                total_bytes_io: 50000,
                total_wall_ms: 500,
            })
            .build()
            .expect("valid index")
    }

    #[test]
    fn test_build_index() {
        let index = create_test_index();

        assert_eq!(index.schema, TOOL_LOG_INDEX_V1_SCHEMA);
        assert_eq!(index.episode_id, "ep-001");
        assert_eq!(index.tool_execution_receipt_hashes.len(), 3);
        assert_eq!(index.counts.total_executions, 3);
        assert!(index.is_final_chunk);
    }

    #[test]
    fn test_validate() {
        let index = create_test_index();
        assert!(index.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_schema() {
        let mut index = create_test_index();
        index.schema = "invalid.schema".to_string();
        assert!(index.validate().is_err());
    }

    #[test]
    fn test_cas_hash_deterministic() {
        let index1 = create_test_index();
        let index2 = create_test_index();

        assert_eq!(index1.compute_cas_hash(), index2.compute_cas_hash());
    }

    #[test]
    fn test_receipt_count() {
        let index = create_test_index();
        assert_eq!(index.receipt_count(), 3);
    }

    #[test]
    fn test_is_chunked() {
        let single_chunk = create_test_index();
        assert!(!single_chunk.is_chunked());

        let chunked = ToolLogIndexV1Builder::new()
            .episode_id("ep-001")
            .add_receipt_hash([0x11; 32])
            .is_final_chunk(false)
            .build()
            .expect("valid index");
        assert!(chunked.is_chunked());
    }

    #[test]
    fn test_missing_field() {
        let result = ToolLogIndexV1Builder::new()
            // Missing episode_id
            .add_receipt_hash([0x11; 32])
            .build();

        assert!(matches!(
            result,
            Err(ToolLogIndexError::MissingField("episode_id"))
        ));
    }

    #[test]
    fn test_string_too_long() {
        let long_id = "x".repeat(MAX_EPISODE_ID_LENGTH + 1);
        let result = ToolLogIndexV1Builder::new().episode_id(long_id).build();

        assert!(matches!(
            result,
            Err(ToolLogIndexError::StringTooLong {
                field: "episode_id",
                ..
            })
        ));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_collection_too_large() {
        let hashes: Vec<[u8; 32]> = (0..=MAX_RECEIPT_HASHES_PER_INDEX)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xff) as u8;
                h
            })
            .collect();

        let result = ToolLogIndexV1Builder::new()
            .episode_id("ep-001")
            .receipt_hashes(hashes)
            .build();

        assert!(matches!(
            result,
            Err(ToolLogIndexError::CollectionTooLarge {
                field: "tool_execution_receipt_hashes",
                ..
            })
        ));
    }

    #[test]
    fn test_continuation_hashes() {
        let index = ToolLogIndexV1Builder::new()
            .episode_id("ep-001")
            .add_receipt_hash([0x11; 32])
            .add_continuation_hash([0xAA; 32])
            .add_continuation_hash([0xBB; 32])
            .is_final_chunk(false)
            .build()
            .expect("valid index");

        assert_eq!(index.continuation_hashes.len(), 2);
        assert!(!index.is_final_chunk);
        assert!(index.is_chunked());
    }

    #[test]
    fn test_tool_log_counts_record_execution() {
        let mut counts = ToolLogCounts::new();
        counts.record_execution(true, 100, 5000, 50);
        counts.record_execution(false, 50, 2000, 25);

        assert_eq!(counts.total_executions, 2);
        assert_eq!(counts.successful_executions, 1);
        assert_eq!(counts.failed_executions, 1);
        assert_eq!(counts.total_tokens, 150);
        assert_eq!(counts.total_bytes_io, 7000);
        assert_eq!(counts.total_wall_ms, 75);
    }

    #[test]
    fn test_empty_index() {
        // Empty index (no receipts) is valid
        let index = ToolLogIndexV1Builder::new()
            .episode_id("ep-empty")
            .build()
            .expect("valid empty index");

        assert!(index.tool_execution_receipt_hashes.is_empty());
        assert_eq!(index.receipt_count(), 0);
    }
}
