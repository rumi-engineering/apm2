//! Tool broker decision types.
//!
//! This module defines the request, decision, and result types for the
//! `ToolBroker` per CTR-DAEMON-004. These types enable capability-validated
//! tool execution with policy enforcement and dedupe caching.
//!
//! # Architecture
//!
//! ```text
//! BrokerToolRequest
//!     │
//!     ▼
//! ToolBroker::request()
//!     │
//!     ├──► DedupeCache lookup
//!     │         │
//!     │         ├── hit ──► DedupeCacheHit
//!     │         │
//!     │         └── miss ──┐
//!     │                    │
//!     ├──► CapabilityValidator
//!     │         │
//!     │         ├── deny ──► Deny
//!     │         │
//!     │         └── allow ──┐
//!     │                     │
//!     └──► PolicyEngine ────┤
//!               │           │
//!               ├── deny ──► Deny
//!               │
//!               └── allow ──► Allow
//! ```
//!
//! # Contract References
//!
//! - CTR-DAEMON-004: `ToolBroker` structure
//! - CTR-1303: Bounded collections with MAX_* constants
//! - AD-TOOL-002: Capability manifests as sealed references
//! - AD-VERIFY-001: Deterministic serialization

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use apm2_core::htf::{TimeEnvelope, TimeEnvelopeRef};
use prost::Message;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::budget::EpisodeBudget;
use super::capability::DenyReason;
use super::envelope::RiskTier;
use super::error::EpisodeId;
use super::runtime::Hash;
use super::scope::MAX_PATH_LEN;
use super::tool_class::ToolClass;

// =============================================================================
// Limits (CTR-1303)
// =============================================================================

/// Maximum length for request ID.
pub const MAX_REQUEST_ID_LEN: usize = 256;

/// Maximum length for dedupe key.
pub const MAX_DEDUPE_KEY_LEN: usize = 512;

/// Maximum length for rule ID.
pub const MAX_RULE_ID_LEN: usize = 256;

/// Maximum size for inline tool arguments (bytes).
pub const MAX_INLINE_ARGS_SIZE: usize = 64 * 1024; // 64 KB

/// Maximum size for tool output (bytes).
pub const MAX_TOOL_OUTPUT_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Maximum size for tool error message.
pub const MAX_ERROR_MESSAGE_LEN: usize = 4096;

/// Maximum length for network host names.
///
/// RFC 1035 specifies 253 characters max for fully-qualified domain names.
/// We use 255 to allow for some flexibility while still preventing abuse.
pub const MAX_HOST_LEN: usize = 255;

// =============================================================================
// BrokerToolRequest
// =============================================================================

/// A tool request for the broker.
///
/// This is an enhanced version of `ToolRequest` (from capability.rs) that
/// includes additional fields required for broker operations:
/// - Unique request ID for tracking
/// - Dedupe key for idempotent replay
/// - Args hash for CAS-based argument storage
/// - Optional inline args for small payloads
///
/// # Security
///
/// Per CTR-1303, all string/byte fields are bounded by MAX_* constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerToolRequest {
    /// Unique identifier for this request.
    pub request_id: String,

    /// Episode this request belongs to.
    pub episode_id: EpisodeId,

    /// The tool class being requested.
    pub tool_class: ToolClass,

    /// Dedupe key for idempotent replay.
    ///
    /// Requests with the same dedupe key within an episode return cached
    /// results instead of re-executing.
    pub dedupe_key: DedupeKey,

    /// BLAKE3 hash of the full tool arguments (for CAS retrieval).
    pub args_hash: Hash,

    /// Inline tool arguments for small payloads.
    ///
    /// If present, the broker can use these directly instead of fetching
    /// from CAS. Limited to `MAX_INLINE_ARGS_SIZE` bytes.
    pub inline_args: Option<Vec<u8>>,

    /// Optional path for filesystem operations.
    pub path: Option<PathBuf>,

    /// Optional size for read/write operations.
    pub size: Option<u64>,

    /// Optional network target (host, port).
    pub network: Option<(String, u16)>,

    /// The risk tier of the current episode.
    pub risk_tier: RiskTier,
}

/// Error type for request validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestValidationError {
    /// Request ID exceeds maximum length.
    RequestIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Request ID is empty.
    RequestIdEmpty,

    /// Dedupe key exceeds maximum length.
    DedupeKeyTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Inline args exceed maximum size.
    InlineArgsTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Path exceeds maximum length.
    PathTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Network host exceeds maximum length.
    HostTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
}

impl std::fmt::Display for RequestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestIdTooLong { len, max } => {
                write!(f, "request ID too long: {len} bytes (max {max})")
            },
            Self::RequestIdEmpty => write!(f, "request ID cannot be empty"),
            Self::DedupeKeyTooLong { len, max } => {
                write!(f, "dedupe key too long: {len} bytes (max {max})")
            },
            Self::InlineArgsTooLarge { size, max } => {
                write!(f, "inline args too large: {size} bytes (max {max})")
            },
            Self::PathTooLong { len, max } => {
                write!(f, "path too long: {len} bytes (max {max})")
            },
            Self::HostTooLong { len, max } => {
                write!(f, "network host too long: {len} bytes (max {max})")
            },
        }
    }
}

impl std::error::Error for RequestValidationError {}

impl BrokerToolRequest {
    /// Creates a new broker tool request.
    ///
    /// # Arguments
    ///
    /// * `request_id` - Unique identifier for tracking
    /// * `episode_id` - Episode this request belongs to
    /// * `tool_class` - The tool class being requested
    /// * `dedupe_key` - Key for idempotent replay
    /// * `args_hash` - BLAKE3 hash of full arguments
    /// * `risk_tier` - Risk tier of the episode
    #[must_use]
    pub fn new(
        request_id: impl Into<String>,
        episode_id: EpisodeId,
        tool_class: ToolClass,
        dedupe_key: DedupeKey,
        args_hash: Hash,
        risk_tier: RiskTier,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            episode_id,
            tool_class,
            dedupe_key,
            args_hash,
            inline_args: None,
            path: None,
            size: None,
            network: None,
            risk_tier,
        }
    }

    /// Sets the inline arguments.
    #[must_use]
    pub fn with_inline_args(mut self, args: Vec<u8>) -> Self {
        self.inline_args = Some(args);
        self
    }

    /// Sets the path for filesystem operations.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the size for read/write operations.
    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Sets the network target.
    #[must_use]
    pub fn with_network(mut self, host: impl Into<String>, port: u16) -> Self {
        self.network = Some((host.into(), port));
        self
    }

    /// Validates the request against size limits.
    ///
    /// # Errors
    ///
    /// Returns an error if any field exceeds its maximum size.
    pub fn validate(&self) -> Result<(), RequestValidationError> {
        if self.request_id.is_empty() {
            return Err(RequestValidationError::RequestIdEmpty);
        }
        if self.request_id.len() > MAX_REQUEST_ID_LEN {
            return Err(RequestValidationError::RequestIdTooLong {
                len: self.request_id.len(),
                max: MAX_REQUEST_ID_LEN,
            });
        }
        if self.dedupe_key.0.len() > MAX_DEDUPE_KEY_LEN {
            return Err(RequestValidationError::DedupeKeyTooLong {
                len: self.dedupe_key.0.len(),
                max: MAX_DEDUPE_KEY_LEN,
            });
        }
        if let Some(ref args) = self.inline_args {
            if args.len() > MAX_INLINE_ARGS_SIZE {
                return Err(RequestValidationError::InlineArgsTooLarge {
                    size: args.len(),
                    max: MAX_INLINE_ARGS_SIZE,
                });
            }
        }
        // Validate path length (F09: boundedness check)
        if let Some(ref path) = self.path {
            let path_str = path.to_string_lossy();
            if path_str.len() > MAX_PATH_LEN {
                return Err(RequestValidationError::PathTooLong {
                    len: path_str.len(),
                    max: MAX_PATH_LEN,
                });
            }
        }
        // Validate network host length (F09: boundedness check)
        if let Some((ref host, _)) = self.network {
            if host.len() > MAX_HOST_LEN {
                return Err(RequestValidationError::HostTooLong {
                    len: host.len(),
                    max: MAX_HOST_LEN,
                });
            }
        }
        Ok(())
    }

    /// Converts to a capability `ToolRequest` for validation.
    #[must_use]
    pub fn to_capability_request(&self) -> super::capability::ToolRequest {
        let mut req = super::capability::ToolRequest::new(self.tool_class, self.risk_tier);
        if let Some(ref path) = self.path {
            req = req.with_path(path.clone());
        }
        if let Some(size) = self.size {
            req = req.with_size(size);
        }
        if let Some((ref host, port)) = self.network {
            req = req.with_network(host.clone(), port);
        }
        req
    }
}

// =============================================================================
// DedupeKey
// =============================================================================

/// Error type for `DedupeKey` creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupeKeyError {
    /// Key exceeds maximum length.
    TooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
}

impl std::fmt::Display for DedupeKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong { len, max } => {
                write!(f, "dedupe key too long: {len} bytes (max {max})")
            },
        }
    }
}

impl std::error::Error for DedupeKeyError {}

/// Key for dedupe cache lookup.
///
/// The dedupe key uniquely identifies a tool invocation within an episode.
/// Requests with the same dedupe key return cached results instead of
/// re-executing, enabling idempotent tool replay.
///
/// # Format
///
/// A dedupe key typically includes:
/// - Episode ID
/// - Tool class
/// - Relevant arguments (normalized)
///
/// # Security
///
/// Per CTR-1303, the key is bounded by `MAX_DEDUPE_KEY_LEN` (512 bytes).
/// The constructor and `Deserialize` implementation both enforce this bound.
///
/// Uses a custom `Deserialize` implementation that validates length to prevent
/// resource exhaustion from untrusted input.
///
/// **IMPORTANT:** Although the dedupe key is a user-controlled string, the
/// `DedupeCache` enforces episode isolation by verifying the `episode_id`
/// stored with each cache entry matches the requesting episode. This
/// prevents cross-episode cache collisions even if two episodes use the
/// same dedupe key string. See `DedupeCache::get` for the isolation check.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct DedupeKey(String);

/// Custom `Deserialize` implementation that enforces `MAX_DEDUPE_KEY_LEN`.
///
/// Per F01 security review finding, this prevents unbounded string allocation
/// during deserialization from untrusted input.
impl<'de> Deserialize<'de> for DedupeKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DedupeKeyVisitor;

        impl Visitor<'_> for DedupeKeyVisitor {
            type Value = DedupeKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "a string with at most {MAX_DEDUPE_KEY_LEN} bytes"
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_DEDUPE_KEY_LEN {
                    return Err(E::custom(format!(
                        "dedupe key too long: {} bytes (max {})",
                        value.len(),
                        MAX_DEDUPE_KEY_LEN
                    )));
                }
                Ok(DedupeKey(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_DEDUPE_KEY_LEN {
                    return Err(E::custom(format!(
                        "dedupe key too long: {} bytes (max {})",
                        value.len(),
                        MAX_DEDUPE_KEY_LEN
                    )));
                }
                Ok(DedupeKey(value))
            }
        }

        deserializer.deserialize_string(DedupeKeyVisitor)
    }
}

impl DedupeKey {
    /// Creates a new dedupe key with length validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the key exceeds `MAX_DEDUPE_KEY_LEN` bytes.
    pub fn try_new(key: impl Into<String>) -> Result<Self, DedupeKeyError> {
        let key = key.into();
        if key.len() > MAX_DEDUPE_KEY_LEN {
            return Err(DedupeKeyError::TooLong {
                len: key.len(),
                max: MAX_DEDUPE_KEY_LEN,
            });
        }
        Ok(Self(key))
    }

    /// Creates a new dedupe key, truncating if necessary.
    ///
    /// If the key exceeds `MAX_DEDUPE_KEY_LEN`, it is truncated at a valid
    /// UTF-8 boundary. This is useful for cases where truncation is acceptable
    /// (e.g., constructing keys from potentially long inputs).
    ///
    /// # Note
    ///
    /// Prefer `try_new()` when validation errors should be propagated.
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        let key = key.into();
        if key.len() <= MAX_DEDUPE_KEY_LEN {
            Self(key)
        } else {
            // Find a valid UTF-8 boundary at or before MAX_DEDUPE_KEY_LEN
            let mut end = MAX_DEDUPE_KEY_LEN;
            while end > 0 && !key.is_char_boundary(end) {
                end -= 1;
            }
            Self(key[..end].to_owned())
        }
    }

    /// Returns the key as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the length of the key.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the key is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Computes the BLAKE3 digest of this key.
    #[must_use]
    pub fn digest(&self) -> Hash {
        *blake3::hash(self.0.as_bytes()).as_bytes()
    }
}

impl std::fmt::Display for DedupeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for DedupeKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// ToolDecision
// =============================================================================

/// Decision result from the tool broker.
///
/// This enum represents the outcome of a tool request evaluation:
/// - `Allow`: Request is permitted, proceed with execution
/// - `Deny`: Request is denied with a reason
/// - `DedupeCacheHit`: Request matches a cached result (idempotent replay)
#[derive(Debug, Clone)]
pub enum ToolDecision {
    /// Request is allowed. Proceed with execution.
    Allow {
        /// The request ID being allowed.
        request_id: String,

        /// The capability ID that authorized this request.
        capability_id: String,

        /// Optional policy rule that matched (for audit).
        rule_id: Option<String>,

        /// Hash of the policy version used for evaluation.
        policy_hash: Hash,

        /// Resource budget to charge for this operation.
        budget_delta: BudgetDelta,
    },

    /// Request is denied.
    Deny {
        /// The request ID being denied.
        request_id: String,

        /// Reason for denial.
        reason: DenyReason,

        /// Optional policy rule that caused denial.
        rule_id: Option<String>,

        /// Hash of the policy version used for evaluation.
        policy_hash: Hash,
    },

    /// Request matched a cached result (idempotent replay).
    DedupeCacheHit {
        /// The request ID for this cache hit.
        request_id: String,

        /// The cached result.
        result: Box<ToolResult>,
    },
}

impl ToolDecision {
    /// Returns `true` if this is an Allow decision.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Returns `true` if this is a Deny decision.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns `true` if this is a dedupe cache hit.
    #[must_use]
    pub const fn is_cache_hit(&self) -> bool {
        matches!(self, Self::DedupeCacheHit { .. })
    }

    /// Returns the request ID for this decision.
    #[must_use]
    pub fn request_id(&self) -> &str {
        match self {
            Self::Allow { request_id, .. }
            | Self::Deny { request_id, .. }
            | Self::DedupeCacheHit { request_id, .. } => request_id,
        }
    }
}

// =============================================================================
// BudgetDelta
// =============================================================================

/// Resource budget to charge for a tool operation.
///
/// This represents the estimated or actual resource consumption for a tool
/// invocation, used for budget enforcement.
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks when
/// deserializing from untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetDelta {
    /// Tokens consumed (for inference operations).
    pub tokens: u64,

    /// Tool calls consumed (always 1 for a single tool invocation).
    pub tool_calls: u32,

    /// Wall clock time consumed in milliseconds.
    pub wall_ms: u64,

    /// CPU time consumed in milliseconds.
    pub cpu_ms: u64,

    /// I/O bytes consumed (read + write).
    pub bytes_io: u64,
}

impl BudgetDelta {
    /// Creates a minimal budget delta for a single tool call.
    #[must_use]
    pub const fn single_call() -> Self {
        Self {
            tokens: 0,
            tool_calls: 1,
            wall_ms: 0,
            cpu_ms: 0,
            bytes_io: 0,
        }
    }

    /// Sets the tokens consumed.
    #[must_use]
    pub const fn with_tokens(mut self, tokens: u64) -> Self {
        self.tokens = tokens;
        self
    }

    /// Sets the wall clock time consumed.
    #[must_use]
    pub const fn with_wall_ms(mut self, wall_ms: u64) -> Self {
        self.wall_ms = wall_ms;
        self
    }

    /// Sets the I/O bytes consumed.
    #[must_use]
    pub const fn with_bytes_io(mut self, bytes_io: u64) -> Self {
        self.bytes_io = bytes_io;
        self
    }

    /// Checks if this delta would exceed the remaining budget.
    #[must_use]
    pub const fn would_exceed(&self, remaining: &EpisodeBudget) -> bool {
        // Zero in budget means unlimited
        (remaining.tokens() > 0 && self.tokens > remaining.tokens())
            || (remaining.tool_calls() > 0 && self.tool_calls > remaining.tool_calls())
            || (remaining.wall_ms() > 0 && self.wall_ms > remaining.wall_ms())
            || (remaining.cpu_ms() > 0 && self.cpu_ms > remaining.cpu_ms())
            || (remaining.bytes_io() > 0 && self.bytes_io > remaining.bytes_io())
    }
}

// =============================================================================
// ToolResult
// =============================================================================

/// Result of a tool execution.
///
/// This captures the output, timing, and resource usage of a completed tool
/// invocation. Results are stored in the dedupe cache for idempotent replay.
///
/// Per RFC-0016 (HTF) and TCK-00240, tool results include an optional
/// `time_envelope_ref` for temporal ordering and causality tracking.
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks when
/// deserializing from untrusted input.
///
/// # Time Envelope Preimage Preservation
///
/// The `time_envelope` field contains the full `TimeEnvelope` preimage
/// alongside the `time_envelope_ref` hash. This ensures the envelope data
/// (monotonic ticks, wall bounds, ledger anchor) is persisted and verifiable.
/// Without the preimage, the hash reference would be unresolvable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResult {
    /// The request ID this result corresponds to.
    pub request_id: String,

    /// Whether the tool execution succeeded.
    pub success: bool,

    /// Tool output (stdout for shell commands, response for API calls).
    ///
    /// Bounded by `MAX_TOOL_OUTPUT_SIZE`.
    pub output: Vec<u8>,

    /// Hash of the full output if truncated.
    pub output_hash: Option<Hash>,

    /// Error message if execution failed.
    pub error_message: Option<String>,

    /// Exit code for shell commands.
    pub exit_code: Option<i32>,

    /// Actual resources consumed.
    pub budget_consumed: BudgetDelta,

    /// Wall clock duration of execution.
    pub duration: Duration,

    /// Timestamp when execution completed (nanoseconds since epoch).
    pub completed_at_ns: u64,

    /// Reference to the `TimeEnvelope` for this result (RFC-0016 HTF).
    ///
    /// Per TCK-00240, tool results include a time envelope reference for
    /// temporal ordering and causality tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_envelope_ref: Option<TimeEnvelopeRef>,

    /// The full `TimeEnvelope` preimage for verification.
    ///
    /// Per security review, the preimage is stored alongside the reference
    /// to ensure the temporal data is persisted and verifiable. Without this,
    /// the hash reference would be unresolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_envelope: Option<TimeEnvelope>,
}

impl ToolResult {
    /// Creates a successful tool result.
    #[must_use]
    pub fn success(
        request_id: impl Into<String>,
        output: Vec<u8>,
        budget_consumed: BudgetDelta,
        duration: Duration,
        completed_at_ns: u64,
    ) -> Self {
        let (output, output_hash) = if output.len() > MAX_TOOL_OUTPUT_SIZE {
            let hash = *blake3::hash(&output).as_bytes();
            (output[..MAX_TOOL_OUTPUT_SIZE].to_vec(), Some(hash))
        } else {
            (output, None)
        };

        Self {
            request_id: request_id.into(),
            success: true,
            output,
            output_hash,
            error_message: None,
            exit_code: Some(0),
            budget_consumed,
            duration,
            completed_at_ns,
            time_envelope_ref: None,
            time_envelope: None,
        }
    }

    /// Creates a failed tool result.
    #[must_use]
    pub fn failure(
        request_id: impl Into<String>,
        error_message: impl Into<String>,
        exit_code: Option<i32>,
        budget_consumed: BudgetDelta,
        duration: Duration,
        completed_at_ns: u64,
    ) -> Self {
        let mut error = error_message.into();
        if error.len() > MAX_ERROR_MESSAGE_LEN {
            error.truncate(MAX_ERROR_MESSAGE_LEN);
        }

        Self {
            request_id: request_id.into(),
            success: false,
            output: Vec::new(),
            output_hash: None,
            error_message: Some(error),
            exit_code,
            budget_consumed,
            duration,
            completed_at_ns,
            time_envelope_ref: None,
            time_envelope: None,
        }
    }

    /// Sets the time envelope for this result (RFC-0016 HTF).
    ///
    /// Per TCK-00240, tool results include a time envelope reference for
    /// temporal ordering and causality tracking. Both the preimage and
    /// reference are stored for verifiability.
    #[must_use]
    pub fn with_time_envelope(
        mut self,
        envelope: TimeEnvelope,
        envelope_ref: TimeEnvelopeRef,
    ) -> Self {
        self.time_envelope = Some(envelope);
        self.time_envelope_ref = Some(envelope_ref);
        self
    }

    /// Returns the output as a string if valid UTF-8.
    #[must_use]
    pub fn output_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.output).ok()
    }

    /// Returns the time envelope reference for this result (RFC-0016 HTF).
    #[must_use]
    pub const fn time_envelope_ref(&self) -> Option<&TimeEnvelopeRef> {
        self.time_envelope_ref.as_ref()
    }

    /// Returns the time envelope preimage for this result (RFC-0016 HTF).
    #[must_use]
    pub const fn time_envelope(&self) -> Option<&TimeEnvelope> {
        self.time_envelope.as_ref()
    }
}

/// Internal protobuf representation for `ToolResult`.
#[derive(Clone, PartialEq, Message)]
struct ToolResultProto {
    #[prost(string, tag = "1")]
    request_id: String,
    #[prost(bool, optional, tag = "2")]
    success: Option<bool>,
    #[prost(bytes = "vec", tag = "3")]
    output: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "4")]
    output_hash: Option<Vec<u8>>,
    #[prost(string, optional, tag = "5")]
    error_message: Option<String>,
    #[prost(int32, optional, tag = "6")]
    exit_code: Option<i32>,
    #[prost(uint64, optional, tag = "7")]
    duration_ns: Option<u64>,
    #[prost(uint64, optional, tag = "8")]
    completed_at_ns: Option<u64>,
    // Tag 9: time_envelope_ref - INCLUDED for temporal ordering (RFC-0016 HTF)
    #[prost(bytes = "vec", optional, tag = "9")]
    time_envelope_ref: Option<Vec<u8>>,
}

impl ToolResult {
    /// Returns the canonical bytes for this result.
    ///
    /// Per AD-VERIFY-001, this provides deterministic serialization
    /// for use in digests and signatures.
    ///
    /// # Determinism Guarantee
    ///
    /// This encoding is deterministic because:
    /// 1. All fields in `ToolResultProto` are scalar types (no repeated fields)
    /// 2. Prost encodes scalar fields in a deterministic order (by tag number)
    /// 3. No map fields are present (maps are non-deterministic in protobuf)
    ///
    /// If repeated fields are ever added to `ToolResultProto`, they MUST be
    /// sorted before encoding to maintain determinism (see
    /// `CapabilityManifest::canonical_bytes` for the pattern).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // SECURITY: All fields are scalar types, ensuring deterministic encoding.
        // If repeated fields are added, they must be sorted before encoding.
        let proto = ToolResultProto {
            request_id: self.request_id.clone(),
            success: Some(self.success),
            output: self.output.clone(),
            output_hash: self.output_hash.map(|h| h.to_vec()),
            error_message: self.error_message.clone(),
            exit_code: self.exit_code,
            // Truncate to u64::MAX for extremely long durations (> 584 years).
            // This is acceptable since such durations are unrealistic for tool execution.
            #[allow(clippy::cast_possible_truncation)]
            duration_ns: Some(self.duration.as_nanos().min(u128::from(u64::MAX)) as u64),
            completed_at_ns: Some(self.completed_at_ns),
            // Include time_envelope_ref for temporal ordering (RFC-0016 HTF)
            time_envelope_ref: self
                .time_envelope_ref
                .as_ref()
                .map(|r| r.as_bytes().to_vec()),
        };
        proto.encode_to_vec()
    }

    /// Computes the BLAKE3 digest of this result.
    #[must_use]
    pub fn digest(&self) -> Hash {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_episode_id() -> EpisodeId {
        EpisodeId::new("ep-test-123").unwrap()
    }

    fn make_dedupe_key() -> DedupeKey {
        DedupeKey::new("test-key")
    }

    fn test_args_hash() -> Hash {
        [42u8; 32]
    }

    #[test]
    fn test_broker_request_new() {
        let request = BrokerToolRequest::new(
            "req-001",
            test_episode_id(),
            ToolClass::Read,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        );

        assert_eq!(request.request_id, "req-001");
        assert_eq!(request.tool_class, ToolClass::Read);
        assert!(request.inline_args.is_none());
        assert!(request.path.is_none());
    }

    #[test]
    fn test_broker_request_with_options() {
        let request = BrokerToolRequest::new(
            "req-002",
            test_episode_id(),
            ToolClass::Write,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier1,
        )
        .with_path("/workspace/file.rs")
        .with_size(1024)
        .with_inline_args(vec![1, 2, 3]);

        assert!(request.path.is_some());
        assert_eq!(request.size, Some(1024));
        assert!(request.inline_args.is_some());
    }

    #[test]
    fn test_broker_request_validation_empty_id() {
        let request = BrokerToolRequest::new(
            "",
            test_episode_id(),
            ToolClass::Read,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        );

        assert!(matches!(
            request.validate(),
            Err(RequestValidationError::RequestIdEmpty)
        ));
    }

    #[test]
    fn test_broker_request_validation_id_too_long() {
        let long_id = "x".repeat(MAX_REQUEST_ID_LEN + 1);
        let request = BrokerToolRequest::new(
            long_id,
            test_episode_id(),
            ToolClass::Read,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        );

        assert!(matches!(
            request.validate(),
            Err(RequestValidationError::RequestIdTooLong { .. })
        ));
    }

    #[test]
    fn test_broker_request_validation_inline_args_too_large() {
        let large_args = vec![0u8; MAX_INLINE_ARGS_SIZE + 1];
        let request = BrokerToolRequest::new(
            "req-003",
            test_episode_id(),
            ToolClass::Read,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_inline_args(large_args);

        assert!(matches!(
            request.validate(),
            Err(RequestValidationError::InlineArgsTooLarge { .. })
        ));
    }

    #[test]
    fn test_dedupe_key_creation() {
        let key = DedupeKey::new("test-dedupe-key");
        assert_eq!(key.as_str(), "test-dedupe-key");
        assert_eq!(key.len(), 15);
        assert!(!key.is_empty());

        let digest = key.digest();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_dedupe_key_digest_determinism() {
        let key1 = DedupeKey::new("same-key");
        let key2 = DedupeKey::new("same-key");
        assert_eq!(key1.digest(), key2.digest());

        let key3 = DedupeKey::new("different-key");
        assert_ne!(key1.digest(), key3.digest());
    }

    #[test]
    fn test_tool_decision_allow() {
        let decision = ToolDecision::Allow {
            request_id: "req-001".to_string(),
            capability_id: "cap-read".to_string(),
            rule_id: Some("rule-1".to_string()),
            policy_hash: [0u8; 32],
            budget_delta: BudgetDelta::single_call(),
        };

        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert!(!decision.is_cache_hit());
        assert_eq!(decision.request_id(), "req-001");
    }

    #[test]
    fn test_tool_decision_deny() {
        let decision = ToolDecision::Deny {
            request_id: "req-002".to_string(),
            reason: DenyReason::NoMatchingCapability {
                tool_class: ToolClass::Execute,
            },
            rule_id: None,
            policy_hash: [0u8; 32],
        };

        assert!(!decision.is_allowed());
        assert!(decision.is_denied());
        assert_eq!(decision.request_id(), "req-002");
    }

    #[test]
    fn test_tool_decision_cache_hit() {
        let result = ToolResult::success(
            "req-003",
            b"output".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            1000,
        );

        let decision = ToolDecision::DedupeCacheHit {
            request_id: "req-003".to_string(),
            result: Box::new(result),
        };

        assert!(!decision.is_allowed());
        assert!(!decision.is_denied());
        assert!(decision.is_cache_hit());
    }

    #[test]
    fn test_budget_delta() {
        let delta = BudgetDelta::single_call()
            .with_tokens(100)
            .with_wall_ms(50)
            .with_bytes_io(1024);

        assert_eq!(delta.tool_calls, 1);
        assert_eq!(delta.tokens, 100);
        assert_eq!(delta.wall_ms, 50);
        assert_eq!(delta.bytes_io, 1024);
    }

    #[test]
    fn test_budget_delta_would_exceed() {
        let delta = BudgetDelta::single_call().with_tokens(100);

        // Budget with tokens limit
        let limited = EpisodeBudget::builder().tokens(50).build();
        assert!(delta.would_exceed(&limited));

        // Budget with higher limit
        let sufficient = EpisodeBudget::builder().tokens(200).build();
        assert!(!delta.would_exceed(&sufficient));

        // Unlimited budget
        let unlimited = EpisodeBudget::unlimited();
        assert!(!delta.would_exceed(&unlimited));
    }

    #[test]
    fn test_tool_result_success() {
        let result = ToolResult::success(
            "req-001",
            b"hello world".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            1_704_067_200_000_000_000,
        );

        assert!(result.success);
        assert_eq!(result.output, b"hello world");
        assert_eq!(result.output_str(), Some("hello world"));
        assert!(result.error_message.is_none());
        assert_eq!(result.exit_code, Some(0));
    }

    #[test]
    fn test_tool_result_failure() {
        let result = ToolResult::failure(
            "req-002",
            "command not found",
            Some(127),
            BudgetDelta::single_call(),
            Duration::from_millis(10),
            1_704_067_200_000_000_000,
        );

        assert!(!result.success);
        assert!(result.output.is_empty());
        assert_eq!(result.error_message.as_deref(), Some("command not found"));
        assert_eq!(result.exit_code, Some(127));
    }

    #[test]
    fn test_tool_result_output_truncation() {
        let large_output = vec![0u8; MAX_TOOL_OUTPUT_SIZE + 1000];
        let result = ToolResult::success(
            "req-003",
            large_output,
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            1000,
        );

        assert_eq!(result.output.len(), MAX_TOOL_OUTPUT_SIZE);
        assert!(result.output_hash.is_some());
    }

    #[test]
    fn test_tool_result_canonical_bytes_determinism() {
        let result1 = ToolResult::success(
            "req-001",
            b"output".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            1000,
        );
        let result2 = ToolResult::success(
            "req-001",
            b"output".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            1000,
        );

        assert_eq!(result1.canonical_bytes(), result2.canonical_bytes());
        assert_eq!(result1.digest(), result2.digest());
    }

    #[test]
    fn test_broker_request_to_capability_request() {
        let request = BrokerToolRequest::new(
            "req-001",
            test_episode_id(),
            ToolClass::Read,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier1,
        )
        .with_path("/workspace/file.rs")
        .with_size(1024);

        let cap_request = request.to_capability_request();
        assert_eq!(cap_request.tool_class, ToolClass::Read);
        assert_eq!(cap_request.risk_tier, RiskTier::Tier1);
        assert!(cap_request.path.is_some());
        assert_eq!(cap_request.size, Some(1024));
    }

    // =========================================================================
    // F01: DedupeKey Boundedness Tests
    // =========================================================================

    #[test]
    fn test_dedupe_key_try_new_valid() {
        let key = DedupeKey::try_new("valid-key").unwrap();
        assert_eq!(key.as_str(), "valid-key");
    }

    #[test]
    fn test_dedupe_key_try_new_too_long() {
        let long_key = "x".repeat(MAX_DEDUPE_KEY_LEN + 1);
        let result = DedupeKey::try_new(long_key);
        assert!(matches!(result, Err(DedupeKeyError::TooLong { .. })));
    }

    #[test]
    fn test_dedupe_key_try_new_at_limit() {
        let key = "x".repeat(MAX_DEDUPE_KEY_LEN);
        let result = DedupeKey::try_new(&key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), MAX_DEDUPE_KEY_LEN);
    }

    #[test]
    fn test_dedupe_key_new_truncates() {
        let long_key = "x".repeat(MAX_DEDUPE_KEY_LEN + 100);
        let key = DedupeKey::new(long_key);
        assert!(key.len() <= MAX_DEDUPE_KEY_LEN);
    }

    #[test]
    fn test_dedupe_key_new_truncates_utf8_safe() {
        // Create a string with multi-byte UTF-8 characters that would be split
        // at the boundary if we naively truncate
        let emoji = "\u{1F600}"; // 4 bytes
        let filler = "x".repeat(MAX_DEDUPE_KEY_LEN - 2);
        let long_key = format!("{filler}{emoji}{emoji}{emoji}");
        let key = DedupeKey::new(long_key);

        // Key should be valid UTF-8 and within bounds
        assert!(key.len() <= MAX_DEDUPE_KEY_LEN);
        // Verify it's valid UTF-8 by converting to str
        let _s = key.as_str();
    }

    #[test]
    fn test_dedupe_key_deserialize_valid() {
        let json = r#""valid-key""#;
        let key: DedupeKey = serde_json::from_str(json).unwrap();
        assert_eq!(key.as_str(), "valid-key");
    }

    #[test]
    fn test_dedupe_key_deserialize_too_long() {
        let long_key = "x".repeat(MAX_DEDUPE_KEY_LEN + 1);
        let json = format!(r#""{long_key}""#);
        let result: Result<DedupeKey, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too long"),
            "error should mention 'too long': {err}"
        );
    }

    #[test]
    fn test_dedupe_key_deserialize_at_limit() {
        let key = "x".repeat(MAX_DEDUPE_KEY_LEN);
        let json = format!(r#""{key}""#);
        let result: DedupeKey = serde_json::from_str(&json).unwrap();
        assert_eq!(result.len(), MAX_DEDUPE_KEY_LEN);
    }

    #[test]
    fn test_dedupe_key_serialize_roundtrip() {
        let original = DedupeKey::new("test-key-123");
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: DedupeKey = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    // =========================================================================
    // F09: Path and Network Host Boundedness Tests
    // =========================================================================

    #[test]
    fn test_broker_request_validation_path_too_long() {
        let long_path = "/".to_owned() + &"x".repeat(MAX_PATH_LEN + 1);
        let request = BrokerToolRequest::new(
            "req-path",
            test_episode_id(),
            ToolClass::Read,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path(long_path);

        assert!(matches!(
            request.validate(),
            Err(RequestValidationError::PathTooLong { .. })
        ));
    }

    #[test]
    fn test_broker_request_validation_path_at_limit() {
        let path = "/".to_owned() + &"x".repeat(MAX_PATH_LEN - 1);
        assert_eq!(path.len(), MAX_PATH_LEN);
        let request = BrokerToolRequest::new(
            "req-path",
            test_episode_id(),
            ToolClass::Read,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path(path);

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_broker_request_validation_host_too_long() {
        let long_host = "x".repeat(MAX_HOST_LEN + 1);
        let request = BrokerToolRequest::new(
            "req-net",
            test_episode_id(),
            ToolClass::Network,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_network(long_host, 443);

        assert!(matches!(
            request.validate(),
            Err(RequestValidationError::HostTooLong { .. })
        ));
    }

    #[test]
    fn test_broker_request_validation_host_at_limit() {
        let host = "x".repeat(MAX_HOST_LEN);
        let request = BrokerToolRequest::new(
            "req-net",
            test_episode_id(),
            ToolClass::Network,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_network(host, 443);

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_broker_request_validation_valid_with_path_and_network() {
        let request = BrokerToolRequest::new(
            "req-full",
            test_episode_id(),
            ToolClass::Network,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/file.txt")
        .with_network("example.com", 443)
        .with_inline_args(vec![1, 2, 3]);

        assert!(request.validate().is_ok());
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_dedupe_key_error_display() {
        let err = DedupeKeyError::TooLong { len: 600, max: 512 };
        let msg = err.to_string();
        assert!(msg.contains("600"));
        assert!(msg.contains("512"));
    }

    #[test]
    fn test_request_validation_error_display_path() {
        let err = RequestValidationError::PathTooLong {
            len: 5000,
            max: 4096,
        };
        let msg = err.to_string();
        assert!(msg.contains("path"));
        assert!(msg.contains("5000"));
        assert!(msg.contains("4096"));
    }

    #[test]
    fn test_request_validation_error_display_host() {
        let err = RequestValidationError::HostTooLong { len: 300, max: 255 };
        let msg = err.to_string();
        assert!(msg.contains("host"));
        assert!(msg.contains("300"));
        assert!(msg.contains("255"));
    }
}
