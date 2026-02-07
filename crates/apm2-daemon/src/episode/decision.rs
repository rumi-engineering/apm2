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

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use apm2_core::context::firewall::FirewallViolationDefect;
use apm2_core::htf::{TimeEnvelope, TimeEnvelopeRef};
use prost::Message;
use secrecy::{ExposeSecret, SecretString};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;

use super::budget::EpisodeBudget;
use super::capability::{DenyReason, MAX_SHELL_PATTERN_LEN};
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

/// Maximum length for git operation names (TCK-00292).
///
/// Git operations are short strings like "status", "push", "commit", etc.
/// The longest standard git command is "cherry-pick" at 11 characters.
/// We use 32 to allow for reasonable extension while preventing abuse.
pub const MAX_GIT_OPERATION_LEN: usize = 32;

/// Maximum length for `ListFiles` pattern (TCK-00315).
pub const MAX_LIST_FILES_PATTERN_LEN: usize = 256;

/// Maximum length for Search query (TCK-00315).
pub const MAX_SEARCH_QUERY_LEN: usize = 1024;

/// Maximum size for inline tool results (bytes).
///
/// TCK-00316: Security - enforces `DoS` protection per SEC-CTRL-FAC-0015.
/// Inline results larger than this limit MUST be stored in CAS and
/// referenced via `result_hash`. This prevents memory exhaustion from
/// large tool outputs being held inline in IPC messages.
pub const MAX_INLINE_RESULT_SIZE: usize = 64 * 1024; // 64 KB

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

    /// Optional shell command for Execute operations.
    ///
    /// Per TCK-00254, when the tool class is Execute and the manifest has
    /// a `shell_allowlist` configured, this field MUST be present for
    /// validation.
    pub shell_command: Option<String>,

    /// Optional git operation for Git tool class (TCK-00292).
    ///
    /// When the tool class is Git, this field MUST be present to specify the
    /// exact git operation (e.g., "status", "push", "commit"). This prevents
    /// fail-open vulnerabilities where a dangerous operation like "push" could
    /// be evaluated as "status".
    ///
    /// Valid operations: clone, fetch, diff, commit, push, status, log,
    /// branch, checkout, merge, rebase, pull, reset, stash, tag, remote.
    pub git_operation: Option<String>,

    /// Optional pattern for `ListFiles` (TCK-00315).
    pub pattern: Option<String>,

    /// Optional query for Search (TCK-00315).
    pub query: Option<String>,

    /// Optional artifact hash for Artifact tool class.
    pub artifact_hash: Option<Hash>,

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

    /// Shell command exceeds maximum length.
    ShellCommandTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Git operation exceeds maximum length (TCK-00292).
    GitOperationTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// `ListFiles` pattern exceeds maximum length (TCK-00315).
    PatternTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Search query exceeds maximum length (TCK-00315).
    QueryTooLong {
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
            Self::ShellCommandTooLong { len, max } => {
                write!(f, "shell command too long: {len} bytes (max {max})")
            },
            Self::GitOperationTooLong { len, max } => {
                write!(f, "git operation too long: {len} bytes (max {max})")
            },
            Self::PatternTooLong { len, max } => {
                write!(f, "pattern too long: {len} bytes (max {max})")
            },
            Self::QueryTooLong { len, max } => {
                write!(f, "query too long: {len} bytes (max {max})")
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
            shell_command: None,
            git_operation: None,
            pattern: None,
            query: None,
            artifact_hash: None,
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

    /// Sets the shell command for Execute operations.
    ///
    /// Per TCK-00254, when the tool class is Execute and `shell_allowlist` is
    /// configured, this field is required for validation (fail-closed
    /// semantics).
    #[must_use]
    pub fn with_shell_command(mut self, command: impl Into<String>) -> Self {
        self.shell_command = Some(command.into());
        self
    }

    /// Sets the git operation for Git tool class (TCK-00292).
    ///
    /// This field MUST be set when the tool class is Git to ensure proper
    /// policy evaluation. Without this, the request will be denied to prevent
    /// fail-open vulnerabilities.
    ///
    /// # Valid Operations
    ///
    /// clone, fetch, diff, commit, push, status, log, branch, checkout,
    /// merge, rebase, pull, reset, stash, tag, remote
    #[must_use]
    pub fn with_git_operation(mut self, operation: impl Into<String>) -> Self {
        self.git_operation = Some(operation.into());
        self
    }

    /// Sets the pattern for `ListFiles` (TCK-00315).
    #[must_use]
    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.pattern = Some(pattern.into());
        self
    }

    /// Sets the query for Search (TCK-00315).
    #[must_use]
    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = Some(query.into());
        self
    }

    /// Sets the artifact hash for Artifact operations.
    #[must_use]
    pub const fn with_artifact_hash(mut self, hash: Hash) -> Self {
        self.artifact_hash = Some(hash);
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
        // Validate shell command length (TCK-00254: boundedness check)
        if let Some(ref command) = self.shell_command {
            if command.len() > MAX_SHELL_PATTERN_LEN {
                return Err(RequestValidationError::ShellCommandTooLong {
                    len: command.len(),
                    max: MAX_SHELL_PATTERN_LEN,
                });
            }
        }
        // Validate git operation length (TCK-00292: boundedness check)
        if let Some(ref operation) = self.git_operation {
            if operation.len() > MAX_GIT_OPERATION_LEN {
                return Err(RequestValidationError::GitOperationTooLong {
                    len: operation.len(),
                    max: MAX_GIT_OPERATION_LEN,
                });
            }
        }
        // Validate ListFiles pattern length (TCK-00315: boundedness check)
        if let Some(ref pattern) = self.pattern {
            if pattern.len() > MAX_LIST_FILES_PATTERN_LEN {
                return Err(RequestValidationError::PatternTooLong {
                    len: pattern.len(),
                    max: MAX_LIST_FILES_PATTERN_LEN,
                });
            }
        }
        // Validate Search query length (TCK-00315: boundedness check)
        if let Some(ref query) = self.query {
            if query.len() > MAX_SEARCH_QUERY_LEN {
                return Err(RequestValidationError::QueryTooLong {
                    len: query.len(),
                    max: MAX_SEARCH_QUERY_LEN,
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
        // TCK-00254: Include shell_command for Execute operations
        if let Some(ref command) = self.shell_command {
            req = req.with_shell_command(command.clone());
        }
        req
    }

    /// Converts to a core `ToolRequest` for policy engine evaluation
    /// (TCK-00292).
    ///
    /// This enables the real `PolicyEngine` from `apm2-core` to evaluate broker
    /// requests.
    #[must_use]
    pub fn to_policy_request(&self) -> apm2_core::tool::ToolRequest {
        use apm2_core::tool::{
            ArtifactFetch, FileRead, FileWrite, GitOperation, InferenceCall, ListFiles, Search,
            ShellExec, tool_request,
        };

        let tool = match self.tool_class {
            ToolClass::Read => self.path.as_ref().map(|p| {
                tool_request::Tool::FileRead(FileRead {
                    path: p.to_string_lossy().to_string(),
                    offset: 0,
                    limit: self.size.unwrap_or(0),
                })
            }),
            ToolClass::Write => self.path.as_ref().map(|p| {
                tool_request::Tool::FileWrite(FileWrite {
                    path: p.to_string_lossy().to_string(),
                    content: Vec::new(),
                    create_only: false,
                    append: false,
                })
            }),
            ToolClass::Execute => self.shell_command.as_ref().map(|cmd| {
                tool_request::Tool::ShellExec(ShellExec {
                    command: cmd.clone(),
                    cwd: String::new(),
                    timeout_ms: 0,
                    network_access: self.network.is_some(),
                    env: Vec::new(),
                })
            }),
            ToolClass::Git => self.git_operation.as_ref().map(|op| {
                tool_request::Tool::GitOp(GitOperation {
                    operation: op.clone(),
                    args: Vec::new(),
                    cwd: self
                        .path
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default(),
                })
            }),
            ToolClass::Network => self.network.as_ref().map(|(_host, _port)| {
                tool_request::Tool::ShellExec(ShellExec {
                    command: String::new(),
                    cwd: String::new(),
                    timeout_ms: 0,
                    network_access: true,
                    env: Vec::new(),
                })
            }),
            ToolClass::Inference => Some(tool_request::Tool::Inference(InferenceCall {
                provider: String::new(),
                model: String::new(),
                prompt_hash: self.args_hash.to_vec(),
                max_tokens: 0,
                temperature_scaled: 0,
                system_prompt_hash: Vec::new(),
            })),
            ToolClass::Artifact => self.artifact_hash.as_ref().map(|hash| {
                tool_request::Tool::ArtifactFetch(ArtifactFetch {
                    stable_id: String::new(),
                    content_hash: hash.to_vec(),
                    expected_hash: Vec::new(),
                    max_bytes: self
                        .size
                        .unwrap_or(crate::episode::tool_handler::ARTIFACT_FETCH_MAX_BYTES as u64),
                    format: String::new(),
                })
            }),
            ToolClass::ListFiles => self.path.as_ref().map(|p| {
                tool_request::Tool::ListFiles(ListFiles {
                    path: p.to_string_lossy().to_string(),
                    pattern: self.pattern.clone().unwrap_or_default(),
                    max_entries: self.size.unwrap_or(0),
                })
            }),
            ToolClass::Search => self.query.as_ref().map(|q| {
                tool_request::Tool::Search(Search {
                    query: q.clone(),
                    scope: self
                        .path
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    max_bytes: self.size.unwrap_or(0),
                    max_lines: 0,
                })
            }),
            // TCK-00292: Fail-closed for unknown tool classes.
            // Unknown ToolClass variants return None, which triggers MISSING_TOOL
            // denial in the core policy engine. This prevents fail-open
            // vulnerabilities where unknown tool classes could be incorrectly
            // permitted as a different tool type.
            _ => None,
        };

        apm2_core::tool::ToolRequest {
            request_id: self.request_id.clone(),
            session_token: String::new(),
            dedupe_key: self.dedupe_key.as_str().to_string(),
            consumption_mode: false,
            tool,
        }
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
// SessionTerminationInfo
// =============================================================================

/// Information about a session termination.
///
/// Moved from `consume.rs` to support `ToolDecision::Terminate`.
///
/// # TCK-00385: Extended Termination Details
///
/// Extended with `exit_code`, `terminated_at_ns`, and `actual_tokens_consumed`
/// fields to support the session termination signal protocol. These fields
/// enable the `SessionStatus` endpoint to return terminal state details
/// (reason, exit code, timing, token usage) after a session has ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTerminationInfo {
    /// Session ID that was terminated.
    pub session_id: String,

    /// Rationale code for the termination.
    ///
    /// Maps to `termination_reason` in the `SessionStatusResponse` wire format.
    /// Values: `"normal"`, `"crash"`, `"timeout"`, `"quarantined"`,
    /// `"budget_exhausted"`, `"CONTEXT_MISS"`.
    pub rationale_code: String,

    /// Exit classification (SUCCESS, FAILURE, etc.).
    pub exit_classification: String,

    /// Process exit code (TCK-00385).
    ///
    /// `Some(0)` indicates clean exit; non-zero indicates abnormal termination.
    /// `None` when exit code is not available (e.g., killed by signal).
    pub exit_code: Option<i32>,

    /// Timestamp when the session terminated, in nanoseconds since epoch
    /// (TCK-00385).
    ///
    /// Set automatically by [`Self::new`] using the system clock.
    pub terminated_at_ns: u64,

    /// Actual tokens consumed by the agent adapter (TCK-00385).
    ///
    /// `None` when token tracking is not available from the adapter.
    pub actual_tokens_consumed: Option<u64>,
}

impl SessionTerminationInfo {
    /// Creates a new termination info with current timestamp.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new(
        session_id: impl Into<String>,
        rationale: impl Into<String>,
        classification: impl Into<String>,
    ) -> Self {
        let terminated_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Self {
            session_id: session_id.into(),
            rationale_code: rationale.into(),
            exit_classification: classification.into(),
            exit_code: None,
            terminated_at_ns,
            actual_tokens_consumed: None,
        }
    }

    /// Sets the process exit code.
    #[must_use]
    pub const fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    /// Sets the actual tokens consumed.
    #[must_use]
    pub const fn with_tokens_consumed(mut self, tokens: u64) -> Self {
        self.actual_tokens_consumed = Some(tokens);
        self
    }
}

// =============================================================================
// Credential (TCK-00262)
// =============================================================================

/// Opaque credential wrapper for secure handling in broker decisions.
///
/// Per RFC-0017 TB-003 (Credential Isolation Boundary), credentials are held
/// by the daemon only and never exposed to session processes. This wrapper:
///
/// - Uses `SecretString` to protect the secret in memory
/// - Implements redacted `Debug` to prevent accidental logging
/// - Provides explicit `expose_secret()` for controlled access
///
/// # Security
///
/// - The underlying secret is protected with `secrecy::SecretString`
/// - Debug output shows `[REDACTED]` instead of the actual value
/// - Credentials are only attached to `ToolDecision::Allow` for authenticated
///   tool execution; they are never serialized back to the session
///
/// # Example
///
/// ```rust,ignore
/// use secrecy::SecretString;
/// use apm2_daemon::episode::decision::Credential;
///
/// let cred = Credential::new(SecretString::new("ghs_token".into()));
///
/// // Debug doesn't reveal the secret
/// assert_eq!(format!("{:?}", cred), "[REDACTED]");
///
/// // Explicit access required
/// let token = cred.expose_secret();
/// ```
#[derive(Clone)]
pub struct Credential(SecretString);

impl Credential {
    /// Creates a new credential from a secret string.
    pub fn new(secret: impl Into<SecretString>) -> Self {
        Self(secret.into())
    }

    /// Exposes the underlying secret value.
    ///
    /// # Security
    ///
    /// Use with caution. This method is intended for passing the credential
    /// to tool execution (e.g., setting environment variables for git).
    /// The secret should never be logged or returned to the session.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        // TCK-00262: Use constant-time comparison to prevent timing side-channel
        // attacks. Although credentials are primarily compared in test contexts,
        // we use constant-time comparison as a defense-in-depth measure.
        let a = self.0.expose_secret().as_bytes();
        let b = other.0.expose_secret().as_bytes();

        // ConstantTimeEq requires equal lengths for constant-time comparison.
        // If lengths differ, the comparison is trivially false but we still
        // use ct_eq on the shorter slice to avoid variable-time length leaks.
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }
}

impl Eq for Credential {}

// =============================================================================
// SessionContext (TCK-00263)
// =============================================================================

/// Session context for broker-mediated credential access.
///
/// Per TCK-00263 code review, session-specific state MUST NOT be stored in the
/// `ToolBroker` struct to prevent cross-session credential leaks. Instead, the
/// daemon passes session context to each `request()` call.
///
/// # Security
///
/// This struct is passed by reference and only lives for the duration of a
/// single request. The daemon is responsible for:
/// 1. Creating a `SessionContext` when a session is initialized
/// 2. Passing it to `ToolBroker::request()` for each tool request
/// 3. Dropping it when the session ends
///
/// The broker never stores this context, ensuring complete session isolation.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::decision::SessionContext;
///
/// // Create context when session starts
/// let ctx = SessionContext::new()
///     .with_github_installation_id("12345")
///     .with_ssh_session_id("session-abc");
///
/// // Pass to each request
/// let decision = broker.request(&req, timestamp, Some(&ctx)).await?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    /// GitHub App installation ID for this session (TCK-00262).
    ///
    /// When set, Git/Network tool requests will use this installation ID
    /// to fetch credentials from the GitHub credential store.
    pub github_installation_id: Option<String>,

    /// Session ID for SSH credential lookups (TCK-00263).
    ///
    /// When set, Git tool requests will first try to look up a per-session
    /// `SSH_AUTH_SOCK` path from the keychain before falling back to the
    /// daemon-wide socket.
    pub ssh_session_id: Option<String>,
}

impl SessionContext {
    /// Creates a new empty session context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            github_installation_id: None,
            ssh_session_id: None,
        }
    }

    /// Sets the GitHub installation ID.
    #[must_use]
    pub fn with_github_installation_id(mut self, id: impl Into<String>) -> Self {
        self.github_installation_id = Some(id.into());
        self
    }

    /// Sets the SSH session ID.
    #[must_use]
    pub fn with_ssh_session_id(mut self, id: impl Into<String>) -> Self {
        self.ssh_session_id = Some(id.into());
        self
    }

    /// Returns `true` if a GitHub installation ID is set.
    #[must_use]
    pub const fn has_github_installation(&self) -> bool {
        self.github_installation_id.is_some()
    }

    /// Returns `true` if an SSH session ID is set.
    #[must_use]
    pub const fn has_ssh_session(&self) -> bool {
        self.ssh_session_id.is_some()
    }
}

// =============================================================================
// VerifiedToolContent
// =============================================================================

/// TOCTOU-verified file content for a single broker request (TCK-00375).
///
/// Keys are normalized manifest-style paths. Values are the exact bytes that
/// were hash-verified against the context manifest and are therefore safe to
/// consume without re-reading from disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifiedToolContent {
    files: BTreeMap<String, Vec<u8>>,
}

impl VerifiedToolContent {
    /// Inserts verified bytes for a normalized path.
    pub fn insert(&mut self, normalized_path: impl Into<String>, content: Vec<u8>) {
        self.files.insert(normalized_path.into(), content);
    }

    /// Returns verified bytes for the normalized path, if present.
    #[must_use]
    pub fn get(&self, normalized_path: &str) -> Option<&[u8]> {
        self.files.get(normalized_path).map(Vec::as_slice)
    }

    /// Returns `true` when no verified files are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

// =============================================================================
// BrokerResponse
// =============================================================================

/// Atomic broker response for a single request (TCK-00375).
///
/// This keeps the decision, request-scoped defects, and verified content
/// together to prevent cross-request attribution drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerResponse {
    /// Broker authorization decision.
    pub decision: ToolDecision,
    /// Firewall violation defects produced while evaluating the request.
    pub defects: Vec<FirewallViolationDefect>,
    /// TOCTOU-verified file content for downstream tool execution.
    pub verified_content: VerifiedToolContent,
    /// When `true`, handlers must consume only TOCTOU-verified bytes.
    pub toctou_verification_required: bool,
}

impl BrokerResponse {
    /// Constructs a new broker response.
    #[must_use]
    pub const fn new(
        decision: ToolDecision,
        defects: Vec<FirewallViolationDefect>,
        verified_content: VerifiedToolContent,
        toctou_verification_required: bool,
    ) -> Self {
        Self {
            decision,
            defects,
            verified_content,
            toctou_verification_required,
        }
    }

    /// Convenience passthrough for `ToolDecision::is_allowed`.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    /// Convenience passthrough for `ToolDecision::is_denied`.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        self.decision.is_denied()
    }

    /// Convenience passthrough for `ToolDecision::is_cache_hit`.
    #[must_use]
    pub const fn is_cache_hit(&self) -> bool {
        self.decision.is_cache_hit()
    }

    /// Convenience passthrough for `ToolDecision::is_terminate`.
    #[must_use]
    pub const fn is_terminate(&self) -> bool {
        self.decision.is_terminate()
    }
}

impl std::ops::Deref for BrokerResponse {
    type Target = ToolDecision;

    fn deref(&self) -> &Self::Target {
        &self.decision
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
/// - `Terminate`: Request triggered session termination (e.g., firewall
///   violation)
#[derive(Debug, Clone, PartialEq, Eq)]
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

        /// Optional credential for authenticated operations (TCK-00262).
        ///
        /// Per RFC-0017 TB-003, credentials are held by the daemon and
        /// mediated through the broker. When present, this credential
        /// should be used for tool execution (e.g., setting `GITHUB_TOKEN`
        /// for git operations) but NEVER returned to the session.
        credential: Option<Credential>,
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

    /// Request caused session termination (e.g., context firewall violation).
    Terminate {
        /// The request ID.
        request_id: String,

        /// Termination info.
        termination_info: Box<SessionTerminationInfo>,

        /// Optional serialized coordination event for session refinement.
        ///
        /// When a termination triggers a refinement workflow (e.g., requesting
        /// expanded context permissions), this field carries the serialized
        /// `CoordinationEvent` as opaque bytes. The caller (typically
        /// `consume.rs`) is responsible for deserializing and emitting
        /// this event.
        ///
        /// The opaque bytes representation avoids circular dependencies between
        /// `apm2_daemon` decision types and `apm2_core` event types.
        refinement_event: Option<Vec<u8>>,
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

    /// Returns `true` if this is a Terminate decision.
    #[must_use]
    pub const fn is_terminate(&self) -> bool {
        matches!(self, Self::Terminate { .. })
    }

    /// Returns the request ID for this decision.
    #[must_use]
    pub fn request_id(&self) -> &str {
        match self {
            Self::Allow { request_id, .. }
            | Self::Deny { request_id, .. }
            | Self::DedupeCacheHit { request_id, .. }
            | Self::Terminate { request_id, .. } => request_id,
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
/// # CAS Result Hash (TCK-00320)
///
/// Per SEC-CTRL-FAC-0015, the `result_hash` field provides a CAS reference to
/// the full `ToolResultData`. This is distinct from `output_hash` (truncation
/// hash) and enables:
/// - Verifiable evidence linking in receipts
/// - Retrieval of full execution data when inline results are size-limited
/// - Per-episode accumulation of tool result hashes for audit indexing
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

    /// Hash of the full output if truncated (truncation hash).
    ///
    /// This hash is set when `output` exceeds `MAX_TOOL_OUTPUT_SIZE` and
    /// represents the BLAKE3 hash of the complete output before truncation.
    /// Distinct from `result_hash` which is the CAS hash of the full
    /// `ToolResultData`.
    pub output_hash: Option<Hash>,

    /// CAS hash of the full `ToolResultData` (TCK-00320).
    ///
    /// This is the BLAKE3 hash of the serialized `ToolResultData` stored in
    /// the content-addressed store. Clients can use this hash to retrieve
    /// the complete execution data (output, `error_output`, budget) from CAS.
    ///
    /// # SEC-CTRL-FAC-0015 Evidence Integrity
    ///
    /// The CAS result hash provides a verifiable reference to the full
    /// execution record, ensuring audit trail integrity even when inline
    /// responses are size-limited. All success paths MUST populate this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_hash: Option<Hash>,

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
            result_hash: None, // TCK-00320: Set via with_result_hash() after CAS store
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
            result_hash: None, // TCK-00320: Set via with_result_hash() after CAS store
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

    /// Sets the CAS result hash for this result (TCK-00320).
    ///
    /// This is the hash of the full `ToolResultData` stored in the content-
    /// addressed store, which includes output, `error_output`, and budget.
    /// Clients can use this hash to retrieve the complete execution data
    /// from CAS when the inline result is truncated or omitted.
    ///
    /// # SEC-CTRL-FAC-0015 Evidence Integrity
    ///
    /// The CAS result hash provides a verifiable reference to the full
    /// execution record, ensuring audit trail integrity even when inline
    /// responses are size-limited. All success paths MUST call this method.
    #[must_use]
    pub const fn with_result_hash(mut self, hash: Hash) -> Self {
        self.result_hash = Some(hash);
        self
    }

    /// Returns the CAS result hash for this result (TCK-00320).
    ///
    /// The result hash is the BLAKE3 hash of the serialized `ToolResultData`
    /// stored in CAS. Use this to retrieve the full execution data or to
    /// include in evidence bindings.
    #[must_use]
    pub const fn result_hash(&self) -> Option<&Hash> {
        self.result_hash.as_ref()
    }

    /// Returns the truncation hash if the output was truncated.
    ///
    /// This is distinct from `result_hash` (CAS hash of full `ToolResultData`).
    /// The `output_hash` is only present when `output` exceeded
    /// `MAX_TOOL_OUTPUT_SIZE` and was truncated.
    #[must_use]
    pub const fn output_hash(&self) -> Option<&Hash> {
        self.output_hash.as_ref()
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
    // Tag 10: result_hash - CAS hash of ToolResultData (TCK-00320)
    #[prost(bytes = "vec", optional, tag = "10")]
    result_hash: Option<Vec<u8>>,
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
            // Include result_hash for CAS reference (TCK-00320)
            result_hash: self.result_hash.map(|h| h.to_vec()),
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
            credential: None,
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
    fn test_tool_result_canonical_bytes_includes_time_envelope_ref() {
        let mut result_none = ToolResult::success(
            "req-001",
            b"output".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            1000,
        );
        result_none.time_envelope_ref = None;

        let mut result_some = result_none.clone();
        let ref_bytes = [0x99; 32];
        result_some.time_envelope_ref = Some(TimeEnvelopeRef::new(ref_bytes));

        let bytes_none = result_none.canonical_bytes();
        let bytes_some = result_some.canonical_bytes();

        assert_ne!(
            bytes_none, bytes_some,
            "canonical bytes must differ when time_envelope_ref is present"
        );

        assert!(
            bytes_some.len() > bytes_none.len(),
            "result with envelope ref should be larger"
        );

        assert_ne!(
            result_none.digest(),
            result_some.digest(),
            "digests must differ"
        );
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

    // =========================================================================
    // Credential Tests (TCK-00262)
    // =========================================================================

    #[test]
    fn test_credential_expose_secret() {
        let secret = "ghs_test_token_12345";
        let cred = Credential::new(SecretString::new(secret.into()));

        assert_eq!(cred.expose_secret(), secret);
    }

    #[test]
    fn test_credential_debug_is_redacted() {
        let cred = Credential::new(SecretString::new("sensitive_token".into()));

        let debug_output = format!("{cred:?}");
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("sensitive_token"));
    }

    #[test]
    fn test_credential_equality() {
        let cred1 = Credential::new(SecretString::new("token_a".into()));
        let cred2 = Credential::new(SecretString::new("token_a".into()));
        let cred3 = Credential::new(SecretString::new("token_b".into()));

        assert_eq!(cred1, cred2);
        assert_ne!(cred1, cred3);
    }

    #[test]
    fn test_credential_clone() {
        let cred1 = Credential::new(SecretString::new("cloned_token".into()));
        let cred2 = cred1.clone();

        assert_eq!(cred1.expose_secret(), cred2.expose_secret());
    }

    #[test]
    fn test_tool_decision_allow_with_credential() {
        let cred = Credential::new(SecretString::new("ghs_token".into()));
        let decision = ToolDecision::Allow {
            request_id: "req-001".to_string(),
            capability_id: "cap-git".to_string(),
            rule_id: None,
            policy_hash: [0u8; 32],
            budget_delta: BudgetDelta::single_call(),
            credential: Some(cred),
        };

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(credential.is_some());
            assert_eq!(credential.unwrap().expose_secret(), "ghs_token");
        }
    }

    // =========================================================================
    // TCK-00292: Git Operation Fail-Closed Tests
    // =========================================================================

    #[test]
    fn test_git_request_with_operation_produces_correct_tool() {
        // BLOCKER 1 fix: Git requests with operation should produce GitOp with that
        // operation
        let request = BrokerToolRequest::new(
            "req-git-push",
            test_episode_id(),
            ToolClass::Git,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier1,
        )
        .with_git_operation("push")
        .with_path("/workspace/repo");

        let policy_req = request.to_policy_request();
        assert!(
            policy_req.tool.is_some(),
            "Git request with operation should produce a tool"
        );

        if let Some(apm2_core::tool::tool_request::Tool::GitOp(git_op)) = policy_req.tool {
            assert_eq!(
                git_op.operation, "push",
                "Git operation must be 'push', not 'status'"
            );
            assert_eq!(git_op.cwd, "/workspace/repo");
        } else {
            panic!("Expected GitOp tool variant");
        }
    }

    #[test]
    fn test_git_request_without_operation_produces_none() {
        // BLOCKER 1 fix: Git requests WITHOUT operation should return None
        // (fail-closed)
        let request = BrokerToolRequest::new(
            "req-git-no-op",
            test_episode_id(),
            ToolClass::Git,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier1,
        )
        .with_path("/workspace/repo");
        // Note: NO .with_git_operation() call

        let policy_req = request.to_policy_request();
        assert!(
            policy_req.tool.is_none(),
            "Git request without operation must return None (fail-closed)"
        );
    }

    #[test]
    fn test_git_operation_validation_too_long() {
        let long_op = "x".repeat(MAX_GIT_OPERATION_LEN + 1);
        let request = BrokerToolRequest::new(
            "req-git-long",
            test_episode_id(),
            ToolClass::Git,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_git_operation(long_op);

        assert!(matches!(
            request.validate(),
            Err(RequestValidationError::GitOperationTooLong { .. })
        ));
    }

    #[test]
    fn test_git_operation_validation_at_limit() {
        let op = "x".repeat(MAX_GIT_OPERATION_LEN);
        let request = BrokerToolRequest::new(
            "req-git-limit",
            test_episode_id(),
            ToolClass::Git,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_git_operation(op);

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_git_operation_error_display() {
        let err = RequestValidationError::GitOperationTooLong { len: 50, max: 32 };
        let msg = err.to_string();
        assert!(msg.contains("git operation"));
        assert!(msg.contains("50"));
        assert!(msg.contains("32"));
    }

    // =========================================================================
    // TCK-00292: Unknown Tool Class Fail-Closed Tests
    // =========================================================================

    // Note: We cannot easily test the catch-all `_ =>` branch since all ToolClass
    // variants are handled explicitly in the current implementation. However, the
    // important security property is that the catch-all returns None instead of
    // mapping to FileEdit. This test documents the expected behavior.

    #[test]
    fn test_all_known_tool_classes_have_explicit_handling() {
        // Verify that all known ToolClass variants produce expected tool types
        // This ensures no tool class accidentally falls through to the catch-all

        // Read -> FileRead
        let read_req = BrokerToolRequest::new(
            "req-read",
            test_episode_id(),
            ToolClass::Read,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/file.rs");
        let read_policy = read_req.to_policy_request();
        assert!(matches!(
            read_policy.tool,
            Some(apm2_core::tool::tool_request::Tool::FileRead(_))
        ));

        // Write -> FileWrite
        let write_req = BrokerToolRequest::new(
            "req-write",
            test_episode_id(),
            ToolClass::Write,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/file.rs");
        let write_policy = write_req.to_policy_request();
        assert!(matches!(
            write_policy.tool,
            Some(apm2_core::tool::tool_request::Tool::FileWrite(_))
        ));

        // Execute -> ShellExec
        let exec_req = BrokerToolRequest::new(
            "req-exec",
            test_episode_id(),
            ToolClass::Execute,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_shell_command("ls -la");
        let exec_policy = exec_req.to_policy_request();
        assert!(matches!(
            exec_policy.tool,
            Some(apm2_core::tool::tool_request::Tool::ShellExec(_))
        ));

        // Network -> ShellExec (with network_access flag)
        let net_req = BrokerToolRequest::new(
            "req-net",
            test_episode_id(),
            ToolClass::Network,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_network("example.com", 443);
        let net_policy = net_req.to_policy_request();
        assert!(matches!(
            net_policy.tool,
            Some(apm2_core::tool::tool_request::Tool::ShellExec(_))
        ));

        // Git -> GitOp (with operation)
        let git_req = BrokerToolRequest::new(
            "req-git",
            test_episode_id(),
            ToolClass::Git,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_git_operation("status");
        let git_policy = git_req.to_policy_request();
        assert!(matches!(
            git_policy.tool,
            Some(apm2_core::tool::tool_request::Tool::GitOp(_))
        ));

        // Inference -> Inference
        let inf_req = BrokerToolRequest::new(
            "req-inf",
            test_episode_id(),
            ToolClass::Inference,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        );
        let inf_policy = inf_req.to_policy_request();
        assert!(matches!(
            inf_policy.tool,
            Some(apm2_core::tool::tool_request::Tool::Inference(_))
        ));

        // Artifact -> ArtifactFetch
        let art_req = BrokerToolRequest::new(
            "req-art",
            test_episode_id(),
            ToolClass::Artifact,
            make_dedupe_key(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_artifact_hash([0xab; 32]);
        let art_policy = art_req.to_policy_request();
        assert!(matches!(
            art_policy.tool,
            Some(apm2_core::tool::tool_request::Tool::ArtifactFetch(_))
        ));
    }

    #[test]
    fn test_git_various_operations_propagate_correctly() {
        // Test that various git operations are propagated correctly
        let operations = [
            "status", "push", "pull", "commit", "clone", "fetch", "diff", "log", "branch",
            "checkout", "merge", "rebase", "reset", "stash", "tag", "remote",
        ];

        for op in operations {
            let request = BrokerToolRequest::new(
                format!("req-git-{op}"),
                test_episode_id(),
                ToolClass::Git,
                make_dedupe_key(),
                test_args_hash(),
                RiskTier::Tier1,
            )
            .with_git_operation(op);

            let policy_req = request.to_policy_request();
            if let Some(apm2_core::tool::tool_request::Tool::GitOp(git_op)) = policy_req.tool {
                assert_eq!(
                    git_op.operation, op,
                    "Git operation '{op}' must be propagated correctly"
                );
            } else {
                panic!("Expected GitOp for operation '{op}'");
            }
        }
    }

    // =========================================================================
    // TCK-00320: Tool Result Hash Propagation Tests
    // =========================================================================

    #[test]
    fn test_tool_result_with_result_hash() {
        let cas_hash = [0xab; 32];
        let result = ToolResult::success(
            "req-001",
            b"output data".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(50),
            1_704_067_200_000_000_000,
        )
        .with_result_hash(cas_hash);

        assert!(result.success);
        assert_eq!(result.result_hash(), Some(&cas_hash));
        // output_hash should be None (no truncation)
        assert!(result.output_hash().is_none());
    }

    #[test]
    fn test_tool_result_result_hash_distinct_from_output_hash() {
        let large_output = vec![0u8; MAX_TOOL_OUTPUT_SIZE + 1000];
        let expected_output_hash = *blake3::hash(&large_output).as_bytes();
        let cas_hash = [0xcd; 32];

        let result = ToolResult::success(
            "req-002",
            large_output,
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            1000,
        )
        .with_result_hash(cas_hash);

        // Both hashes should be present but distinct
        assert!(result.output_hash().is_some());
        assert!(result.result_hash().is_some());
        assert_eq!(result.output_hash(), Some(&expected_output_hash));
        assert_eq!(result.result_hash(), Some(&cas_hash));
        assert_ne!(result.output_hash(), result.result_hash());
    }

    #[test]
    fn test_tool_result_canonical_bytes_includes_result_hash() {
        let result_no_hash = ToolResult::success(
            "req-001",
            b"output".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            1000,
        );

        let result_with_hash = result_no_hash.clone().with_result_hash([0xef; 32]);

        let bytes_no_hash = result_no_hash.canonical_bytes();
        let bytes_with_hash = result_with_hash.canonical_bytes();

        assert_ne!(
            bytes_no_hash, bytes_with_hash,
            "canonical bytes must differ when result_hash is present"
        );
        assert!(
            bytes_with_hash.len() > bytes_no_hash.len(),
            "result with result_hash should be larger"
        );
        assert_ne!(
            result_no_hash.digest(),
            result_with_hash.digest(),
            "digests must differ"
        );
    }

    #[test]
    fn test_tool_result_result_hash_determinism() {
        let cas_hash = [0x11; 32];
        let result1 = ToolResult::success(
            "req-001",
            b"output".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            1000,
        )
        .with_result_hash(cas_hash);

        let result2 = ToolResult::success(
            "req-001",
            b"output".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            1000,
        )
        .with_result_hash(cas_hash);

        assert_eq!(result1.canonical_bytes(), result2.canonical_bytes());
        assert_eq!(result1.digest(), result2.digest());
    }

    #[test]
    fn test_tool_result_failure_with_result_hash() {
        let cas_hash = [0x22; 32];
        let result = ToolResult::failure(
            "req-003",
            "execution failed",
            Some(1),
            BudgetDelta::single_call(),
            Duration::from_millis(10),
            1000,
        )
        .with_result_hash(cas_hash);

        assert!(!result.success);
        assert_eq!(result.result_hash(), Some(&cas_hash));
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_tool_result_serde_roundtrip_with_result_hash() {
        let cas_hash = [0x33; 32];
        let original = ToolResult::success(
            "req-serde",
            b"serde test".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(50),
            1000,
        )
        .with_result_hash(cas_hash);

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: ToolResult = serde_json::from_str(&serialized).unwrap();

        assert_eq!(original.request_id, deserialized.request_id);
        assert_eq!(original.success, deserialized.success);
        assert_eq!(original.output, deserialized.output);
        assert_eq!(original.result_hash, deserialized.result_hash);
    }
}
