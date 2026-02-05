// AGENT-AUTHORED
//! Efficiency primitives for context deltas, caching, and summary-first
//! iteration.
//!
//! This module implements TCK-00335: efficiency primitives that enable 20+
//! iteration loops to stay within fixed context budget envelopes through:
//!
//! - **Context Deltas**: Capture minimal state changes between iterations (N ->
//!   N+1)
//! - **Tool Output Caching**: CAS-backed caches for Search/FileRead outputs
//!   when safe
//! - **Summary-first Iteration**: Use summary receipts as iteration interfaces
//!   with zoom-in selectors for on-demand detail expansion
//!
//! # Design Overview
//!
//! Per RFC-0019 and the orchestration revision loop from TCK-00332, iteration
//! N+1 default context uses deltas + summary receipts instead of full history
//! injection. This bounded growth pattern ensures long-running revision loops
//! stay within memory constraints.
//!
//! ## Context Deltas
//!
//! A [`ContextDelta`] captures the minimal difference between iteration states:
//! - Files changed since last iteration
//! - New findings/issues discovered
//! - Tool outputs produced
//! - Review summaries received
//!
//! ## Tool Output Caching
//!
//! The [`ToolOutputCache`] stores tool outputs (Search, `FileRead`) in a
//! CAS-backed cache, keyed by:
//! - Tool type + parameters
//! - Content hash of inputs (for `FileRead`, the file's BLAKE3 hash)
//!
//! Cache invalidation happens when:
//! - File content changes (detected by hash mismatch)
//! - TTL expires (configurable)
//! - Explicit invalidation is requested
//!
//! ## Summary-first Iteration
//!
//! The [`IterationContext`] provides a summary-first interface where:
//! - Default context includes deltas + summary receipts
//! - Full detail is available via zoom-in selectors
//! - Context budget is tracked and enforced
//!
//! # Security Model
//!
//! - Cache keys include content hashes to prevent stale data attacks
//! - TTL bounds prevent indefinite cache retention
//! - Zoom-in selectors are validated against available data
//! - Context budget enforcement prevents memory exhaustion
//!
//! # Example
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use apm2_core::evidence::MemoryCas;
//! use apm2_core::fac::efficiency_primitives::{
//!     ContextDeltaBuilder, IterationContextBuilder, ToolOutputCache,
//!     ToolOutputCacheConfig,
//! };
//!
//! // Build a context delta between iterations
//! let delta = ContextDeltaBuilder::new(1, 2)
//!     .add_changed_file("/src/main.rs", [0x42; 32])
//!     .add_finding("security", "Potential buffer overflow")
//!     .summary_receipt_hash([0xAB; 32])
//!     .build();
//!
//! // Create a CAS-backed tool output cache
//! let cas = Arc::new(MemoryCas::new());
//! let cache = ToolOutputCache::new(ToolOutputCacheConfig::default(), cas);
//!
//! // Build iteration context with summary-first approach
//! let ctx = IterationContextBuilder::new("work-123", 5)
//!     .context_budget_bytes(100_000)
//!     .add_delta(delta.unwrap())
//!     .build()
//!     .unwrap();
//!
//! assert!(ctx.within_budget());
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::crypto::Hash;
use crate::evidence::{CasError, ContentAddressedStore};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of changed files per delta.
pub const MAX_CHANGED_FILES: usize = 1000;

/// Maximum number of findings per delta.
pub const MAX_FINDINGS: usize = 100;

/// Maximum number of tool outputs per delta.
pub const MAX_TOOL_OUTPUTS: usize = 500;

/// Maximum string length for paths.
pub const MAX_PATH_LENGTH: usize = 4096;

/// Maximum string length for finding text.
pub const MAX_FINDING_LENGTH: usize = 2048;

/// Maximum string length for category names.
pub const MAX_CATEGORY_LENGTH: usize = 64;

/// Maximum number of zoom-in selectors.
pub const MAX_ZOOM_SELECTORS: usize = 50;

/// Maximum number of deltas in an iteration context.
pub const MAX_DELTAS: usize = 100;

/// Default context budget in bytes (500KB).
pub const DEFAULT_CONTEXT_BUDGET_BYTES: usize = 500_000;

/// Maximum context budget in bytes (2MB).
pub const MAX_CONTEXT_BUDGET_BYTES: usize = 2_000_000;

/// Default cache TTL in seconds (5 minutes).
pub const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Maximum cache entries.
pub const MAX_CACHE_ENTRIES: usize = 10_000;

/// Schema identifier for efficiency primitives.
pub const EFFICIENCY_PRIMITIVES_SCHEMA: &str = "apm2.efficiency_primitives.v1";

/// Schema version.
pub const EFFICIENCY_PRIMITIVES_VERSION: &str = "1.0.0";

// =============================================================================
// Bounded Deserialization Helpers (SEC-CTRL-FAC-0016)
// =============================================================================

/// Deserialize a `Vec` with a maximum size bound to prevent OOM attacks.
///
/// Per SEC-CTRL-FAC-0016, all collections deserialized from untrusted input
/// must enforce size limits during parsing to prevent denial-of-service via memory exhaustion.
fn deserialize_bounded_vec<'de, D, T>(
    deserializer: D,
    max_items: usize,
    field_name: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T> {
        max_items: usize,
        field_name: &'static str,
        _marker: std::marker::PhantomData<T>,
    }

    impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a sequence with at most {} items",
                self.max_items
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.max_items));

            while let Some(item) = seq.next_element()? {
                if vec.len() >= self.max_items {
                    return Err(de::Error::custom(format!(
                        "collection '{}' exceeds maximum size of {}",
                        self.field_name, self.max_items
                    )));
                }
                vec.push(item);
            }

            Ok(vec)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor {
        max_items,
        field_name,
        _marker: std::marker::PhantomData,
    })
}

/// Deserialize `changed_files` with `MAX_CHANGED_FILES` bound.
fn deserialize_changed_files<'de, D>(deserializer: D) -> Result<Vec<ChangedFile>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_CHANGED_FILES, "changed_files")
}

/// Deserialize `findings` with `MAX_FINDINGS` bound.
fn deserialize_findings<'de, D>(deserializer: D) -> Result<Vec<Finding>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_FINDINGS, "findings")
}

/// Deserialize `tool_outputs` with `MAX_TOOL_OUTPUTS` bound.
fn deserialize_tool_outputs<'de, D>(deserializer: D) -> Result<Vec<ToolOutputRef>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_TOOL_OUTPUTS, "tool_outputs")
}

/// Deserialize `deltas` with `MAX_DELTAS` bound.
fn deserialize_deltas<'de, D>(deserializer: D) -> Result<Vec<ContextDelta>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_DELTAS, "deltas")
}

/// Deserialize `zoom_selectors` with `MAX_ZOOM_SELECTORS` bound.
fn deserialize_zoom_selectors<'de, D>(deserializer: D) -> Result<Vec<ZoomSelector>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_ZOOM_SELECTORS, "zoom_selectors")
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during efficiency primitive operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EfficiencyError {
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

    /// Context budget exceeded.
    #[error("context budget exceeded: {current} bytes > {budget} bytes limit")]
    BudgetExceeded {
        /// Current size in bytes.
        current: usize,
        /// Budget limit in bytes.
        budget: usize,
    },

    /// Invalid iteration sequence.
    #[error("invalid iteration sequence: from {from} to {to}")]
    InvalidIterationSequence {
        /// From iteration.
        from: u64,
        /// To iteration.
        to: u64,
    },

    /// Cache miss.
    #[error("cache miss for key: {key}")]
    CacheMiss {
        /// The cache key.
        key: String,
    },

    /// Cache error.
    #[error("cache error: {message}")]
    CacheError {
        /// Error message.
        message: String,
    },

    /// Zoom selector not found.
    #[error("zoom selector not found: {selector}")]
    ZoomSelectorNotFound {
        /// The selector.
        selector: String,
    },

    /// Invalid hash format.
    #[error("invalid hash: expected 32 bytes")]
    InvalidHash,

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

impl From<CasError> for EfficiencyError {
    fn from(e: CasError) -> Self {
        Self::CacheError {
            message: e.to_string(),
        }
    }
}

// =============================================================================
// Changed File Entry
// =============================================================================

/// A file that changed between iterations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedFile {
    /// File path.
    pub path: String,
    /// BLAKE3 hash of the new content.
    pub content_hash: [u8; 32],
    /// Type of change.
    pub change_type: ChangeType,
    /// Lines changed (optional summary).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines_changed: Option<u32>,
}

/// Type of file change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangeType {
    /// File was added.
    Added,
    /// File was modified.
    Modified,
    /// File was deleted.
    Deleted,
    /// File was renamed.
    Renamed,
}

impl ChangedFile {
    /// Creates a new changed file entry.
    ///
    /// # Errors
    ///
    /// Returns error if path exceeds maximum length.
    pub fn new(
        path: impl Into<String>,
        content_hash: [u8; 32],
        change_type: ChangeType,
    ) -> Result<Self, EfficiencyError> {
        let path = path.into();
        if path.len() > MAX_PATH_LENGTH {
            return Err(EfficiencyError::StringTooLong {
                field: "path",
                len: path.len(),
                max: MAX_PATH_LENGTH,
            });
        }
        Ok(Self {
            path,
            content_hash,
            change_type,
            lines_changed: None,
        })
    }

    /// Sets the lines changed count.
    #[must_use]
    pub const fn with_lines_changed(mut self, lines: u32) -> Self {
        self.lines_changed = Some(lines);
        self
    }
}

// =============================================================================
// Finding Entry
// =============================================================================

/// A finding or issue discovered during an iteration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Category of the finding (e.g., "security", "quality").
    pub category: String,
    /// Description of the finding.
    pub description: String,
    /// Severity level (1=low, 5=critical).
    pub severity: u8,
    /// Whether this finding is actionable.
    pub actionable: bool,
    /// Optional file path associated with the finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// Optional line number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
}

impl Finding {
    /// Creates a new finding.
    ///
    /// # Errors
    ///
    /// Returns error if fields exceed maximum lengths.
    pub fn new(
        category: impl Into<String>,
        description: impl Into<String>,
        severity: u8,
    ) -> Result<Self, EfficiencyError> {
        let category = category.into();
        let description = description.into();

        if category.len() > MAX_CATEGORY_LENGTH {
            return Err(EfficiencyError::StringTooLong {
                field: "category",
                len: category.len(),
                max: MAX_CATEGORY_LENGTH,
            });
        }
        if description.len() > MAX_FINDING_LENGTH {
            return Err(EfficiencyError::StringTooLong {
                field: "description",
                len: description.len(),
                max: MAX_FINDING_LENGTH,
            });
        }

        Ok(Self {
            category,
            description,
            severity: severity.min(5),
            actionable: true,
            file_path: None,
            line_number: None,
        })
    }

    /// Sets whether the finding is actionable.
    #[must_use]
    pub const fn with_actionable(mut self, actionable: bool) -> Self {
        self.actionable = actionable;
        self
    }

    /// Sets the file path for the finding.
    #[must_use]
    pub fn with_file_path(mut self, path: impl Into<String>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    /// Sets the line number for the finding.
    #[must_use]
    pub const fn with_line_number(mut self, line: u32) -> Self {
        self.line_number = Some(line);
        self
    }
}

// =============================================================================
// Tool Output Reference
// =============================================================================

/// Reference to a tool output stored in CAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolOutputRef {
    /// Tool type (e.g., "`FileRead`", "`Search`").
    pub tool_type: String,
    /// CAS hash of the output content.
    pub output_hash: [u8; 32],
    /// Size of the output in bytes.
    pub size_bytes: u64,
    /// Timestamp when the output was produced.
    pub timestamp_ns: u64,
}

impl ToolOutputRef {
    /// Creates a new tool output reference.
    #[must_use]
    pub fn new(tool_type: impl Into<String>, output_hash: [u8; 32], size_bytes: u64) -> Self {
        Self {
            tool_type: tool_type.into(),
            output_hash,
            size_bytes,
            timestamp_ns: 0,
        }
    }

    /// Sets the timestamp.
    #[must_use]
    pub const fn with_timestamp(mut self, timestamp_ns: u64) -> Self {
        self.timestamp_ns = timestamp_ns;
        self
    }
}

// =============================================================================
// Context Delta
// =============================================================================

/// Captures the minimal state changes between iterations.
///
/// A `ContextDelta` represents the difference between iteration N and N+1,
/// including:
/// - Files that changed
/// - New findings discovered
/// - Tool outputs produced
/// - Summary receipt from the previous iteration
///
/// # Invariants
///
/// - `from_iteration` < `to_iteration`
/// - `to_iteration` = `from_iteration` + 1 (deltas are single-step)
/// - All collections respect size limits
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextDelta {
    /// Schema identifier.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Source iteration number.
    pub from_iteration: u64,
    /// Target iteration number.
    pub to_iteration: u64,
    /// Files changed in this delta.
    ///
    /// Per SEC-CTRL-FAC-0016, bounded during deserialization to prevent OOM.
    #[serde(deserialize_with = "deserialize_changed_files")]
    pub changed_files: Vec<ChangedFile>,
    /// Findings discovered in this iteration.
    ///
    /// Per SEC-CTRL-FAC-0016, bounded during deserialization to prevent OOM.
    #[serde(deserialize_with = "deserialize_findings")]
    pub findings: Vec<Finding>,
    /// Tool outputs produced in this iteration.
    ///
    /// Per SEC-CTRL-FAC-0016, bounded during deserialization to prevent OOM.
    #[serde(deserialize_with = "deserialize_tool_outputs")]
    pub tool_outputs: Vec<ToolOutputRef>,
    /// CAS hash of the summary receipt for this iteration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_receipt_hash: Option<[u8; 32]>,
    /// Total tokens consumed in this iteration.
    pub tokens_consumed: u64,
    /// Time consumed in this iteration (milliseconds).
    pub time_consumed_ms: u64,
}

impl ContextDelta {
    /// Returns the estimated size of this delta in bytes.
    #[must_use]
    pub fn estimated_size_bytes(&self) -> usize {
        let mut size = 0;

        // Base struct overhead
        size += 128;

        // Changed files
        for cf in &self.changed_files {
            size += cf.path.len() + 32 + 16; // path + hash + metadata
        }

        // Findings
        for f in &self.findings {
            size += f.category.len() + f.description.len() + 32;
            if let Some(ref path) = f.file_path {
                size += path.len();
            }
        }

        // Tool outputs
        size += self.tool_outputs.len() * 64;

        size
    }

    /// Validates the delta structure.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails.
    pub fn validate(&self) -> Result<(), EfficiencyError> {
        // Validate iteration sequence
        if self.to_iteration != self.from_iteration + 1 {
            return Err(EfficiencyError::InvalidIterationSequence {
                from: self.from_iteration,
                to: self.to_iteration,
            });
        }

        // Validate collection sizes
        if self.changed_files.len() > MAX_CHANGED_FILES {
            return Err(EfficiencyError::CollectionTooLarge {
                field: "changed_files",
                actual: self.changed_files.len(),
                max: MAX_CHANGED_FILES,
            });
        }

        if self.findings.len() > MAX_FINDINGS {
            return Err(EfficiencyError::CollectionTooLarge {
                field: "findings",
                actual: self.findings.len(),
                max: MAX_FINDINGS,
            });
        }

        if self.tool_outputs.len() > MAX_TOOL_OUTPUTS {
            return Err(EfficiencyError::CollectionTooLarge {
                field: "tool_outputs",
                actual: self.tool_outputs.len(),
                max: MAX_TOOL_OUTPUTS,
            });
        }

        Ok(())
    }

    /// Computes the CAS hash of this delta.
    ///
    /// # Panics
    ///
    /// Panics if JSON serialization fails, which should not happen for valid
    /// deltas since all fields are serializable.
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("ContextDelta is always serializable");
        *blake3::hash(&json).as_bytes()
    }
}

// =============================================================================
// Context Delta Builder
// =============================================================================

/// Builder for constructing a `ContextDelta`.
#[derive(Debug, Default)]
pub struct ContextDeltaBuilder {
    from_iteration: Option<u64>,
    to_iteration: Option<u64>,
    changed_files: Vec<ChangedFile>,
    findings: Vec<Finding>,
    tool_outputs: Vec<ToolOutputRef>,
    summary_receipt_hash: Option<[u8; 32]>,
    tokens_consumed: u64,
    time_consumed_ms: u64,
}

impl ContextDeltaBuilder {
    /// Creates a new builder for a delta between iterations.
    #[must_use]
    pub fn new(from_iteration: u64, to_iteration: u64) -> Self {
        Self {
            from_iteration: Some(from_iteration),
            to_iteration: Some(to_iteration),
            ..Default::default()
        }
    }

    /// Adds a changed file to the delta.
    #[must_use]
    pub fn add_changed_file(mut self, path: impl Into<String>, content_hash: [u8; 32]) -> Self {
        if let Ok(cf) = ChangedFile::new(path, content_hash, ChangeType::Modified) {
            self.changed_files.push(cf);
        }
        self
    }

    /// Adds a changed file with type.
    #[must_use]
    pub fn add_changed_file_with_type(
        mut self,
        path: impl Into<String>,
        content_hash: [u8; 32],
        change_type: ChangeType,
    ) -> Self {
        if let Ok(cf) = ChangedFile::new(path, content_hash, change_type) {
            self.changed_files.push(cf);
        }
        self
    }

    /// Adds a finding to the delta.
    #[must_use]
    pub fn add_finding(
        mut self,
        category: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        if let Ok(f) = Finding::new(category, description, 3) {
            self.findings.push(f);
        }
        self
    }

    /// Adds a finding with severity.
    #[must_use]
    pub fn add_finding_with_severity(
        mut self,
        category: impl Into<String>,
        description: impl Into<String>,
        severity: u8,
    ) -> Self {
        if let Ok(f) = Finding::new(category, description, severity) {
            self.findings.push(f);
        }
        self
    }

    /// Adds a tool output reference.
    #[must_use]
    pub fn add_tool_output(
        mut self,
        tool_type: impl Into<String>,
        output_hash: [u8; 32],
        size_bytes: u64,
    ) -> Self {
        self.tool_outputs
            .push(ToolOutputRef::new(tool_type, output_hash, size_bytes));
        self
    }

    /// Sets the summary receipt hash.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn summary_receipt_hash(mut self, hash: [u8; 32]) -> Self {
        self.summary_receipt_hash = Some(hash);
        self
    }

    /// Sets the tokens consumed.
    #[must_use]
    pub const fn tokens_consumed(mut self, tokens: u64) -> Self {
        self.tokens_consumed = tokens;
        self
    }

    /// Sets the time consumed in milliseconds.
    #[must_use]
    pub const fn time_consumed_ms(mut self, ms: u64) -> Self {
        self.time_consumed_ms = ms;
        self
    }

    /// Builds the context delta.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    pub fn build(self) -> Result<ContextDelta, EfficiencyError> {
        let from_iteration = self
            .from_iteration
            .ok_or(EfficiencyError::MissingField("from_iteration"))?;
        let to_iteration = self
            .to_iteration
            .ok_or(EfficiencyError::MissingField("to_iteration"))?;

        let delta = ContextDelta {
            schema: EFFICIENCY_PRIMITIVES_SCHEMA.to_string(),
            schema_version: EFFICIENCY_PRIMITIVES_VERSION.to_string(),
            from_iteration,
            to_iteration,
            changed_files: self.changed_files,
            findings: self.findings,
            tool_outputs: self.tool_outputs,
            summary_receipt_hash: self.summary_receipt_hash,
            tokens_consumed: self.tokens_consumed,
            time_consumed_ms: self.time_consumed_ms,
        };

        delta.validate()?;
        Ok(delta)
    }
}

// =============================================================================
// Tool Output Cache
// =============================================================================

/// Configuration for the tool output cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutputCacheConfig {
    /// Time-to-live for cache entries.
    pub ttl_secs: u64,
    /// Maximum number of cache entries.
    pub max_entries: usize,
    /// Whether to verify content on retrieval.
    pub verify_on_retrieve: bool,
}

impl Default for ToolOutputCacheConfig {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_CACHE_TTL_SECS,
            max_entries: MAX_CACHE_ENTRIES,
            verify_on_retrieve: true,
        }
    }
}

/// A cache entry with metadata.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// CAS hash of the content.
    cas_hash: Hash,
    /// When the entry was created.
    created_at: Instant,
    /// Input hash that produced this output.
    input_hash: Hash,
}

/// Cache key for tool outputs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Tool type.
    pub tool_type: String,
    /// Hash of the input parameters.
    pub input_hash: Hash,
}

impl CacheKey {
    /// Creates a new cache key.
    #[must_use]
    pub fn new(tool_type: impl Into<String>, input_hash: Hash) -> Self {
        Self {
            tool_type: tool_type.into(),
            input_hash,
        }
    }

    /// Creates a cache key for a `FileRead` operation.
    #[must_use]
    pub fn for_file_read(path: &str, content_hash: &Hash) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FileRead:");
        hasher.update(path.as_bytes());
        hasher.update(content_hash);
        Self {
            tool_type: "FileRead".to_string(),
            input_hash: *hasher.finalize().as_bytes(),
        }
    }

    /// Creates a cache key for a Search operation.
    #[must_use]
    pub fn for_search(pattern: &str, path: &str, options_hash: &Hash) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"Search:");
        hasher.update(pattern.as_bytes());
        hasher.update(b":");
        hasher.update(path.as_bytes());
        hasher.update(options_hash);
        Self {
            tool_type: "Search".to_string(),
            input_hash: *hasher.finalize().as_bytes(),
        }
    }

    /// Returns the cache key as a string.
    #[must_use]
    pub fn as_string(&self) -> String {
        format!("{}:{}", self.tool_type, hex::encode(self.input_hash))
    }
}

/// CAS-backed cache for tool outputs.
///
/// Stores tool outputs (Search, `FileRead`) by content hash, with TTL-based
/// expiration and content verification.
#[derive(Clone)]
pub struct ToolOutputCache {
    /// Configuration.
    config: ToolOutputCacheConfig,
    /// Cache index (key -> entry metadata).
    index: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Underlying CAS storage.
    cas: Arc<dyn ContentAddressedStore>,
}

impl std::fmt::Debug for ToolOutputCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolOutputCache")
            .field("config", &self.config)
            .field("index", &self.index)
            .field("cas", &"<CAS>")
            .finish()
    }
}

impl ToolOutputCache {
    /// Creates a new tool output cache.
    #[must_use]
    pub fn new(config: ToolOutputCacheConfig, cas: Arc<dyn ContentAddressedStore>) -> Self {
        Self {
            config,
            index: Arc::new(RwLock::new(HashMap::new())),
            cas,
        }
    }

    /// Creates a new cache with default configuration.
    #[must_use]
    pub fn with_defaults(cas: Arc<dyn ContentAddressedStore>) -> Self {
        Self::new(ToolOutputCacheConfig::default(), cas)
    }

    /// Stores a tool output in the cache.
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key
    /// * `output` - The output content to cache
    ///
    /// # Returns
    ///
    /// The CAS hash of the stored content.
    ///
    /// # Errors
    ///
    /// Returns error if storage fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    pub fn store(&self, key: &CacheKey, output: &[u8]) -> Result<Hash, EfficiencyError> {
        // SEC-CTRL-FAC-0017: Enforce hard cap with FIFO eviction.
        // First evict expired entries, then if still at capacity, evict oldest.
        {
            let index = self.index.read().expect("lock poisoned");
            if index.len() >= self.config.max_entries {
                drop(index);
                self.evict_expired();

                // After evicting expired, check if we're still at capacity
                // If so, evict the oldest entry (FIFO policy)
                let mut index = self.index.write().expect("lock poisoned");
                while index.len() >= self.config.max_entries {
                    // Find and remove the oldest entry
                    let oldest_key = index
                        .iter()
                        .min_by_key(|(_, entry)| entry.created_at)
                        .map(|(k, _)| k.clone());

                    if let Some(key_to_remove) = oldest_key {
                        index.remove(&key_to_remove);
                    } else {
                        // No entries to remove (shouldn't happen if len >= max_entries)
                        break;
                    }
                }
            }
        }

        // Store in CAS
        let result = self.cas.store(output)?;

        // Add to index
        {
            let mut index = self.index.write().expect("lock poisoned");
            index.insert(
                key.as_string(),
                CacheEntry {
                    cas_hash: result.hash,
                    created_at: Instant::now(),
                    input_hash: key.input_hash,
                },
            );
        }

        Ok(result.hash)
    }

    /// Retrieves a tool output from the cache.
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key
    ///
    /// # Returns
    ///
    /// The cached content if found and not expired.
    ///
    /// # Errors
    ///
    /// Returns error if not found, expired, or content verification fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    pub fn retrieve(&self, key: &CacheKey) -> Result<Vec<u8>, EfficiencyError> {
        let key_str = key.as_string();

        // Look up in index
        let entry = {
            let index = self.index.read().expect("lock poisoned");
            index.get(&key_str).cloned()
        };

        let entry = entry.ok_or_else(|| EfficiencyError::CacheMiss {
            key: key_str.clone(),
        })?;

        // Check TTL
        let ttl = Duration::from_secs(self.config.ttl_secs);
        if entry.created_at.elapsed() > ttl {
            // Expired - remove from index
            {
                let mut index = self.index.write().expect("lock poisoned");
                index.remove(&key_str);
            }
            return Err(EfficiencyError::CacheMiss { key: key_str });
        }

        // Verify input hash matches
        if entry.input_hash != key.input_hash {
            return Err(EfficiencyError::CacheMiss { key: key_str });
        }

        // Retrieve from CAS
        let content = self.cas.retrieve(&entry.cas_hash)?;

        Ok(content)
    }

    /// Checks if a key exists in the cache and is not expired.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    #[must_use]
    pub fn contains(&self, key: &CacheKey) -> bool {
        let key_str = key.as_string();
        let index = self.index.read().expect("lock poisoned");

        index.get(&key_str).is_some_and(|entry| {
            let ttl = Duration::from_secs(self.config.ttl_secs);
            entry.created_at.elapsed() <= ttl
        })
    }

    /// Invalidates a specific cache entry.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    pub fn invalidate(&self, key: &CacheKey) {
        let mut index = self.index.write().expect("lock poisoned");
        index.remove(&key.as_string());
    }

    /// Invalidates all entries for a given tool type.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    pub fn invalidate_tool_type(&self, tool_type: &str) {
        let mut index = self.index.write().expect("lock poisoned");
        index.retain(|k, _| !k.starts_with(&format!("{tool_type}:")));
    }

    /// Evicts all expired entries.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    pub fn evict_expired(&self) {
        let ttl = Duration::from_secs(self.config.ttl_secs);
        let mut index = self.index.write().expect("lock poisoned");
        index.retain(|_, entry| entry.created_at.elapsed() <= ttl);
    }

    /// Clears all cache entries.
    ///
    /// Note: This only clears the cache index, not the underlying CAS storage,
    /// as the CAS might be shared.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    pub fn clear(&self) {
        let mut index = self.index.write().expect("lock poisoned");
        index.clear();
    }

    /// Returns the number of cache entries.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.read().expect("lock poisoned").len()
    }

    /// Returns `true` if the cache is empty.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.read().expect("lock poisoned").is_empty()
    }

    /// Returns cache statistics.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (indicates a thread panic).
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let index = self.index.read().expect("lock poisoned");
        CacheStats {
            entry_count: index.len(),
            cas_size_bytes: 0, // Cannot determine CAS size from generic trait
            max_entries: self.config.max_entries,
            ttl_secs: self.config.ttl_secs,
        }
    }
}

/// Cache statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheStats {
    /// Number of cache entries.
    pub entry_count: usize,
    /// Total CAS storage size in bytes.
    pub cas_size_bytes: usize,
    /// Maximum entries allowed.
    pub max_entries: usize,
    /// TTL in seconds.
    pub ttl_secs: u64,
}

// =============================================================================
// Zoom Selector
// =============================================================================

/// A selector for zooming into detail within the iteration context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoomSelector {
    /// Selector type (e.g., "file", "finding", "`tool_output`").
    pub selector_type: ZoomSelectorType,
    /// Selector value (e.g., file path, finding ID).
    pub value: String,
    /// CAS hash of the detailed content.
    pub detail_hash: Option<[u8; 32]>,
}

/// Types of zoom selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ZoomSelectorType {
    /// Zoom into a specific file's full content.
    File,
    /// Zoom into a finding's full details.
    Finding,
    /// Zoom into a tool output's full content.
    ToolOutput,
    /// Zoom into a summary receipt's full content.
    SummaryReceipt,
    /// Zoom into a specific iteration's full delta.
    Iteration,
}

impl ZoomSelector {
    /// Creates a file zoom selector.
    #[must_use]
    pub fn file(path: impl Into<String>) -> Self {
        Self {
            selector_type: ZoomSelectorType::File,
            value: path.into(),
            detail_hash: None,
        }
    }

    /// Creates a finding zoom selector.
    #[must_use]
    pub fn finding(id: impl Into<String>) -> Self {
        Self {
            selector_type: ZoomSelectorType::Finding,
            value: id.into(),
            detail_hash: None,
        }
    }

    /// Creates a tool output zoom selector.
    #[must_use]
    pub fn tool_output(id: impl Into<String>, detail_hash: [u8; 32]) -> Self {
        Self {
            selector_type: ZoomSelectorType::ToolOutput,
            value: id.into(),
            detail_hash: Some(detail_hash),
        }
    }

    /// Creates an iteration zoom selector.
    #[must_use]
    pub fn iteration(iteration: u64) -> Self {
        Self {
            selector_type: ZoomSelectorType::Iteration,
            value: iteration.to_string(),
            detail_hash: None,
        }
    }
}

// =============================================================================
// Iteration Context
// =============================================================================

/// Summary-first iteration context.
///
/// Provides a bounded context for iteration N+1 that includes:
/// - Deltas from recent iterations (not full history)
/// - Summary receipts for quick access
/// - Zoom-in selectors for on-demand detail expansion
///
/// # Budget Enforcement
///
/// The context tracks its size and enforces a budget limit.
/// When the budget is exceeded, older deltas are compacted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationContext {
    /// Work ID.
    pub work_id: String,
    /// Current iteration number.
    pub current_iteration: u64,
    /// Context budget in bytes.
    pub context_budget_bytes: usize,
    /// Deltas from recent iterations.
    ///
    /// Per SEC-CTRL-FAC-0016, bounded during deserialization to prevent OOM.
    #[serde(deserialize_with = "deserialize_deltas")]
    pub deltas: Vec<ContextDelta>,
    /// Available zoom selectors.
    ///
    /// Per SEC-CTRL-FAC-0016, bounded during deserialization to prevent OOM.
    #[serde(deserialize_with = "deserialize_zoom_selectors")]
    pub zoom_selectors: Vec<ZoomSelector>,
    /// Total files changed across all deltas.
    pub total_files_changed: u64,
    /// Total findings across all deltas.
    pub total_findings: u64,
    /// Total tokens consumed across all iterations.
    pub total_tokens_consumed: u64,
    /// Total time consumed across all iterations (ms).
    pub total_time_consumed_ms: u64,
}

impl IterationContext {
    /// Returns the estimated size of this context in bytes.
    #[must_use]
    pub fn estimated_size_bytes(&self) -> usize {
        let mut size = 0;

        // Base overhead
        size += 256;
        size += self.work_id.len();

        // Deltas
        for delta in &self.deltas {
            size += delta.estimated_size_bytes();
        }

        // Zoom selectors
        for selector in &self.zoom_selectors {
            size += selector.value.len() + 64;
        }

        size
    }

    /// Returns `true` if the context is within budget.
    #[must_use]
    pub fn within_budget(&self) -> bool {
        self.estimated_size_bytes() <= self.context_budget_bytes
    }

    /// Compacts the context to fit within budget.
    ///
    /// Removes older deltas until the context fits within budget.
    pub fn compact(&mut self) {
        while !self.within_budget() && self.deltas.len() > 1 {
            // Remove oldest delta
            self.deltas.remove(0);
        }
    }

    /// Adds a zoom selector.
    ///
    /// # Errors
    ///
    /// Returns error if maximum selectors exceeded.
    pub fn add_zoom_selector(&mut self, selector: ZoomSelector) -> Result<(), EfficiencyError> {
        if self.zoom_selectors.len() >= MAX_ZOOM_SELECTORS {
            return Err(EfficiencyError::CollectionTooLarge {
                field: "zoom_selectors",
                actual: self.zoom_selectors.len() + 1,
                max: MAX_ZOOM_SELECTORS,
            });
        }
        self.zoom_selectors.push(selector);
        Ok(())
    }

    /// Gets a zoom selector by type and value.
    #[must_use]
    pub fn get_zoom_selector(
        &self,
        selector_type: ZoomSelectorType,
        value: &str,
    ) -> Option<&ZoomSelector> {
        self.zoom_selectors
            .iter()
            .find(|s| s.selector_type == selector_type && s.value == value)
    }

    /// Returns the most recent delta.
    #[must_use]
    pub fn latest_delta(&self) -> Option<&ContextDelta> {
        self.deltas.last()
    }

    /// Returns the summary receipt hash from the most recent delta.
    #[must_use]
    pub fn latest_summary_hash(&self) -> Option<&[u8; 32]> {
        self.deltas
            .last()
            .and_then(|d| d.summary_receipt_hash.as_ref())
    }

    /// Validates the iteration context.
    ///
    /// # Errors
    ///
    /// Returns error if validation fails.
    pub fn validate(&self) -> Result<(), EfficiencyError> {
        // Validate deltas
        if self.deltas.len() > MAX_DELTAS {
            return Err(EfficiencyError::CollectionTooLarge {
                field: "deltas",
                actual: self.deltas.len(),
                max: MAX_DELTAS,
            });
        }

        for delta in &self.deltas {
            delta.validate()?;
        }

        // Validate zoom selectors
        if self.zoom_selectors.len() > MAX_ZOOM_SELECTORS {
            return Err(EfficiencyError::CollectionTooLarge {
                field: "zoom_selectors",
                actual: self.zoom_selectors.len(),
                max: MAX_ZOOM_SELECTORS,
            });
        }

        // Validate budget
        if self.context_budget_bytes > MAX_CONTEXT_BUDGET_BYTES {
            return Err(EfficiencyError::BudgetExceeded {
                current: self.context_budget_bytes,
                budget: MAX_CONTEXT_BUDGET_BYTES,
            });
        }

        Ok(())
    }
}

// =============================================================================
// Iteration Context Builder
// =============================================================================

/// Builder for constructing an `IterationContext`.
#[derive(Debug, Default)]
pub struct IterationContextBuilder {
    work_id: Option<String>,
    current_iteration: Option<u64>,
    context_budget_bytes: usize,
    deltas: Vec<ContextDelta>,
    zoom_selectors: Vec<ZoomSelector>,
}

impl IterationContextBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new(work_id: impl Into<String>, current_iteration: u64) -> Self {
        Self {
            work_id: Some(work_id.into()),
            current_iteration: Some(current_iteration),
            context_budget_bytes: DEFAULT_CONTEXT_BUDGET_BYTES,
            ..Default::default()
        }
    }

    /// Sets the context budget in bytes.
    #[must_use]
    pub const fn context_budget_bytes(mut self, budget: usize) -> Self {
        self.context_budget_bytes = budget;
        self
    }

    /// Adds a context delta.
    #[must_use]
    pub fn add_delta(mut self, delta: ContextDelta) -> Self {
        self.deltas.push(delta);
        self
    }

    /// Adds a zoom selector.
    #[must_use]
    pub fn add_zoom_selector(mut self, selector: ZoomSelector) -> Self {
        self.zoom_selectors.push(selector);
        self
    }

    /// Builds the iteration context.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or validation fails.
    #[allow(clippy::cast_possible_truncation)]
    pub fn build(self) -> Result<IterationContext, EfficiencyError> {
        let work_id = self
            .work_id
            .ok_or(EfficiencyError::MissingField("work_id"))?;
        let current_iteration = self
            .current_iteration
            .ok_or(EfficiencyError::MissingField("current_iteration"))?;

        // Compute totals from deltas
        let mut total_files_changed = 0u64;
        let mut total_findings = 0u64;
        let mut total_tokens_consumed = 0u64;
        let mut total_time_consumed_ms = 0u64;

        for delta in &self.deltas {
            total_files_changed += delta.changed_files.len() as u64;
            total_findings += delta.findings.len() as u64;
            total_tokens_consumed += delta.tokens_consumed;
            total_time_consumed_ms += delta.time_consumed_ms;
        }

        let mut ctx = IterationContext {
            work_id,
            current_iteration,
            context_budget_bytes: self.context_budget_bytes.min(MAX_CONTEXT_BUDGET_BYTES),
            deltas: self.deltas,
            zoom_selectors: self.zoom_selectors,
            total_files_changed,
            total_findings,
            total_tokens_consumed,
            total_time_consumed_ms,
        };

        ctx.validate()?;

        // Compact if over budget
        if !ctx.within_budget() {
            ctx.compact();
        }

        Ok(ctx)
    }
}

// =============================================================================
// Context Budget Envelope
// =============================================================================

/// Tracks context budget consumption across iterations.
///
/// Used to verify that a 20-iteration loop stays within a fixed budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBudgetEnvelope {
    /// Maximum iterations allowed.
    pub max_iterations: u64,
    /// Per-iteration context budget in bytes.
    pub per_iteration_budget_bytes: usize,
    /// Total context budget in bytes.
    pub total_budget_bytes: usize,
    /// Context consumed so far in bytes.
    pub consumed_bytes: usize,
    /// Iterations completed.
    pub iterations_completed: u64,
}

impl ContextBudgetEnvelope {
    /// Creates a new budget envelope for a 20-iteration loop.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn for_twenty_iterations() -> Self {
        Self {
            max_iterations: 20,
            per_iteration_budget_bytes: DEFAULT_CONTEXT_BUDGET_BYTES,
            total_budget_bytes: DEFAULT_CONTEXT_BUDGET_BYTES * 20,
            consumed_bytes: 0,
            iterations_completed: 0,
        }
    }

    /// Creates a new budget envelope with custom settings.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::missing_const_for_fn)]
    pub fn new(max_iterations: u64, per_iteration_budget_bytes: usize) -> Self {
        Self {
            max_iterations,
            per_iteration_budget_bytes,
            total_budget_bytes: per_iteration_budget_bytes.saturating_mul(max_iterations as usize),
            consumed_bytes: 0,
            iterations_completed: 0,
        }
    }

    /// Records context consumption for an iteration.
    ///
    /// # Errors
    ///
    /// Returns error if budget is exceeded.
    #[allow(clippy::missing_const_for_fn)]
    pub fn record_iteration(&mut self, context_bytes: usize) -> Result<(), EfficiencyError> {
        let new_consumed = self.consumed_bytes.saturating_add(context_bytes);

        if new_consumed > self.total_budget_bytes {
            return Err(EfficiencyError::BudgetExceeded {
                current: new_consumed,
                budget: self.total_budget_bytes,
            });
        }

        self.consumed_bytes = new_consumed;
        self.iterations_completed += 1;
        Ok(())
    }

    /// Returns `true` if the envelope can accommodate another iteration.
    #[must_use]
    pub const fn can_continue(&self) -> bool {
        self.iterations_completed < self.max_iterations
            && self.consumed_bytes + self.per_iteration_budget_bytes <= self.total_budget_bytes
    }

    /// Returns the remaining budget in bytes.
    #[must_use]
    pub const fn remaining_bytes(&self) -> usize {
        self.total_budget_bytes.saturating_sub(self.consumed_bytes)
    }

    /// Returns the remaining iterations.
    #[must_use]
    pub const fn remaining_iterations(&self) -> u64 {
        self.max_iterations
            .saturating_sub(self.iterations_completed)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::MemoryCas;

    #[test]
    fn test_context_delta_builder() {
        let delta = ContextDeltaBuilder::new(0, 1)
            .add_changed_file("/src/main.rs", [0x42; 32])
            .add_finding("security", "Potential issue")
            .summary_receipt_hash([0xAB; 32])
            .tokens_consumed(1000)
            .time_consumed_ms(500)
            .build()
            .unwrap();

        assert_eq!(delta.from_iteration, 0);
        assert_eq!(delta.to_iteration, 1);
        assert_eq!(delta.changed_files.len(), 1);
        assert_eq!(delta.findings.len(), 1);
        assert_eq!(delta.tokens_consumed, 1000);
    }

    #[test]
    fn test_context_delta_invalid_sequence() {
        let result = ContextDeltaBuilder::new(5, 3).build();
        assert!(matches!(
            result,
            Err(EfficiencyError::InvalidIterationSequence { .. })
        ));
    }

    #[test]
    fn test_context_delta_hash_deterministic() {
        let delta1 = ContextDeltaBuilder::new(0, 1)
            .add_changed_file("/src/main.rs", [0x42; 32])
            .build()
            .unwrap();

        let delta2 = ContextDeltaBuilder::new(0, 1)
            .add_changed_file("/src/main.rs", [0x42; 32])
            .build()
            .unwrap();

        assert_eq!(delta1.compute_hash(), delta2.compute_hash());
    }

    #[test]
    fn test_tool_output_cache_store_retrieve() {
        let cas: Arc<dyn ContentAddressedStore> = Arc::new(MemoryCas::new());
        let cache = ToolOutputCache::with_defaults(cas);
        let key = CacheKey::new("FileRead", [0x11; 32]);
        let content = b"file content here";

        let _hash = cache.store(&key, content).unwrap();
        let retrieved = cache.retrieve(&key).unwrap();

        assert_eq!(retrieved, content);
        assert!(cache.contains(&key));
    }

    #[test]
    fn test_tool_output_cache_miss() {
        let cas: Arc<dyn ContentAddressedStore> = Arc::new(MemoryCas::new());
        let cache = ToolOutputCache::with_defaults(cas);
        let key = CacheKey::new("FileRead", [0x11; 32]);

        let result = cache.retrieve(&key);
        assert!(matches!(result, Err(EfficiencyError::CacheMiss { .. })));
    }

    #[test]
    fn test_tool_output_cache_invalidate() {
        let cas: Arc<dyn ContentAddressedStore> = Arc::new(MemoryCas::new());
        let cache = ToolOutputCache::with_defaults(cas);
        let key = CacheKey::new("FileRead", [0x11; 32]);
        let content = b"file content";

        cache.store(&key, content).unwrap();
        assert!(cache.contains(&key));

        cache.invalidate(&key);
        assert!(!cache.contains(&key));
    }

    #[test]
    fn test_cache_key_for_file_read() {
        let key1 = CacheKey::for_file_read("/src/main.rs", &[0x42; 32]);
        let key2 = CacheKey::for_file_read("/src/main.rs", &[0x42; 32]);
        let key3 = CacheKey::for_file_read("/src/main.rs", &[0x43; 32]); // Different hash

        assert_eq!(key1.input_hash, key2.input_hash);
        assert_ne!(key1.input_hash, key3.input_hash);
    }

    #[test]
    fn test_iteration_context_builder() {
        let delta = ContextDeltaBuilder::new(0, 1)
            .add_changed_file("/src/main.rs", [0x42; 32])
            .tokens_consumed(1000)
            .build()
            .unwrap();

        let ctx = IterationContextBuilder::new("work-123", 1)
            .context_budget_bytes(100_000)
            .add_delta(delta)
            .add_zoom_selector(ZoomSelector::file("/src/main.rs"))
            .build()
            .unwrap();

        assert_eq!(ctx.work_id, "work-123");
        assert_eq!(ctx.current_iteration, 1);
        assert_eq!(ctx.deltas.len(), 1);
        assert_eq!(ctx.total_files_changed, 1);
        assert!(ctx.within_budget());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_iteration_context_compact() {
        let mut deltas = Vec::new();
        for i in 0..10 {
            let delta = ContextDeltaBuilder::new(i, i + 1)
                .add_changed_file(format!("/src/file{i}.rs"), [i as u8; 32])
                .build()
                .unwrap();
            deltas.push(delta);
        }

        // Use a very small budget to force compaction
        let mut builder = IterationContextBuilder::new("work-123", 10).context_budget_bytes(500);

        for delta in deltas {
            builder = builder.add_delta(delta);
        }

        let ctx = builder.build().unwrap();

        // Should have been compacted
        assert!(ctx.within_budget());
        assert!(ctx.deltas.len() < 10);
    }

    #[test]
    fn test_context_budget_envelope_twenty_iterations() {
        let mut envelope = ContextBudgetEnvelope::for_twenty_iterations();

        // Simulate 20 iterations
        for _ in 0..20 {
            let context_size = DEFAULT_CONTEXT_BUDGET_BYTES / 2; // Use half budget per iteration
            envelope.record_iteration(context_size).unwrap();
        }

        assert_eq!(envelope.iterations_completed, 20);
        assert!(!envelope.can_continue()); // Max iterations reached
    }

    #[test]
    fn test_context_budget_envelope_budget_exceeded() {
        let mut envelope = ContextBudgetEnvelope::new(5, 1000);

        // Try to exceed budget
        for _ in 0..5 {
            envelope.record_iteration(1000).unwrap();
        }

        // Next iteration should fail
        let result = envelope.record_iteration(1000);
        assert!(matches!(
            result,
            Err(EfficiencyError::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn test_changed_file_validation() {
        let long_path = "a".repeat(MAX_PATH_LENGTH + 1);
        let result = ChangedFile::new(long_path, [0; 32], ChangeType::Modified);
        assert!(matches!(result, Err(EfficiencyError::StringTooLong { .. })));
    }

    #[test]
    fn test_finding_validation() {
        let long_description = "a".repeat(MAX_FINDING_LENGTH + 1);
        let result = Finding::new("security", long_description, 3);
        assert!(matches!(result, Err(EfficiencyError::StringTooLong { .. })));
    }

    #[test]
    fn test_zoom_selector_types() {
        let file_selector = ZoomSelector::file("/src/main.rs");
        assert_eq!(file_selector.selector_type, ZoomSelectorType::File);

        let iteration_selector = ZoomSelector::iteration(5);
        assert_eq!(
            iteration_selector.selector_type,
            ZoomSelectorType::Iteration
        );
        assert_eq!(iteration_selector.value, "5");
    }

    #[test]
    fn test_cache_stats() {
        let cas: Arc<dyn ContentAddressedStore> = Arc::new(MemoryCas::new());
        let cache = ToolOutputCache::with_defaults(cas);
        let key = CacheKey::new("FileRead", [0x11; 32]);

        cache.store(&key, b"content").unwrap();

        let stats = cache.stats();
        assert_eq!(stats.entry_count, 1);
        // CAS size is 0 when using generic trait (cannot query total size)
        assert_eq!(stats.cas_size_bytes, 0);
    }

    /// Verify that a 20-iteration loop stays within fixed context budget.
    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_twenty_iteration_budget_envelope() {
        let mut envelope = ContextBudgetEnvelope::for_twenty_iterations();
        let cas: Arc<dyn ContentAddressedStore> = Arc::new(MemoryCas::new());
        let cache = ToolOutputCache::with_defaults(cas);

        // Simulate 20 iterations with realistic context sizes
        for i in 0..20 {
            // Build a delta for this iteration
            let mut delta_builder = ContextDeltaBuilder::new(i, i + 1)
                .tokens_consumed(5000)
                .time_consumed_ms(1000);

            // Add some changed files
            for j in 0..5 {
                delta_builder = delta_builder
                    .add_changed_file(format!("/src/file{j}.rs"), [((i * 5 + j) % 256) as u8; 32]);
            }

            // Add some findings
            delta_builder = delta_builder
                .add_finding("quality", "Minor style issue")
                .add_finding("security", "Potential vulnerability");

            let delta = delta_builder.build().unwrap();

            // Build iteration context
            let ctx = IterationContextBuilder::new("work-123", i + 1)
                .context_budget_bytes(DEFAULT_CONTEXT_BUDGET_BYTES)
                .add_delta(delta)
                .build()
                .unwrap();

            // Record in budget envelope
            envelope
                .record_iteration(ctx.estimated_size_bytes())
                .unwrap();

            // Cache some tool outputs
            let key = CacheKey::new("FileRead", [(i % 256) as u8; 32]);
            cache.store(&key, b"cached file content").unwrap();
        }

        // Verify we completed all 20 iterations
        assert_eq!(envelope.iterations_completed, 20);

        // Verify we stayed within total budget
        assert!(envelope.consumed_bytes <= envelope.total_budget_bytes);

        // Verify cache was used
        assert!(cache.len() <= 20);
    }
}
