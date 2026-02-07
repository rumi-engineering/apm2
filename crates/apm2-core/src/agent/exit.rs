#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Agent exit signal protocol.
//!
//! This module defines the structured exit protocol that agents use to signal
//! completion of a work phase. The exit signal enables clean handoff between
//! agent sessions without polling.
//!
//! # Protocol Overview
//!
//! When an agent completes a work phase, it MUST emit a structured exit signal
//! as JSON. The system validates the signal and:
//!
//! 1. Emits an `AgentSessionCompleted` event to the ledger
//! 2. Updates the work item phase based on `phase_completed`
//! 3. Releases the session's lease
//! 4. Allows a fresh agent to claim the next phase
//!
//! # JSON Schema
//!
//! ```json
//! {
//!   "protocol": "apm2_agent_exit",
//!   "version": "1.0.0",
//!   "phase_completed": "IMPLEMENTATION",
//!   "exit_reason": "completed",
//!   "pr_url": "https://github.com/org/repo/pull/123",
//!   "evidence_bundle_ref": "evidence/work/W-00042/phase_implementation.yaml",
//!   "notes": "Implementation complete, ready for CI"
//! }
//! ```
//!
//! # Feature Flag
//!
//! Exit signal validation is controlled by the `AGENT_EXIT_PROTOCOL_ENABLED`
//! environment variable. When disabled (default: disabled for fail-closed
//! security), exit signals are not validated. When enabled, invalid exit
//! signals are rejected with clear error messages.
//!
//! # Contracts
//!
//! - [CTR-EXIT001] Exit signals are immutable once emitted.
//! - [CTR-EXIT002] Protocol field must be `apm2_agent_exit`.
//! - [CTR-EXIT003] Version must be semver-compatible with 1.x.
//! - [CTR-EXIT004] Phase completed must be a valid work phase.
//! - [CTR-EXIT005] Exit reason must be one of: completed, blocked, error.
//!
//! # Invariants
//!
//! - [INV-EXIT001] Valid exit signals always emit `AgentSessionCompleted`.
//! - [INV-EXIT002] Invalid exit signals never modify work state.
//! - [INV-EXIT003] Feature flag is cached on first access.

use std::sync::{LazyLock, OnceLock};

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// ============================================================================
// Validation Constants
// ============================================================================

/// Maximum length for the entire JSON input (64KB).
/// Prevents memory exhaustion before JSON parsing begins.
const MAX_INPUT_LENGTH: usize = 64 * 1024;

/// Maximum length for protocol and version fields (64 bytes).
/// These are fixed-format fields that should never exceed this size.
const MAX_PROTOCOL_VERSION_LENGTH: usize = 64;

/// Maximum length for URL and path fields (2KB).
/// Prevents memory exhaustion from oversized payloads.
const MAX_URL_PATH_LENGTH: usize = 2 * 1024;

/// Maximum length for notes field (10KB).
/// Allows for detailed notes while preventing memory exhaustion attacks.
const MAX_NOTES_LENGTH: usize = 10 * 1024;

/// Characters that could enable shell injection if URL is used in CLI commands.
/// Includes: semicolon, pipe, backtick, dollar sign.
const SHELL_INJECTION_CHARS: &[char] = &[';', '|', '`', '$'];

/// Regex for validating semver 1.x.y version strings.
/// Compiled once at first use to avoid repeated compilation.
static VERSION_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^1\.\d+\.\d+$").expect("version regex is valid"));

// ============================================================================
// Work Phase (for exit signal)
// ============================================================================

/// Work phase indicating which phase of work has been completed.
///
/// This enum represents the lifecycle phases that work items progress through.
/// Agents report which phase they completed when exiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum WorkPhase {
    /// Initial drafting phase.
    Draft,
    /// Implementation phase - code is being written.
    Implementation,
    /// CI is running - waiting for automated checks.
    CiPending,
    /// Ready for review - CI passed, awaiting human review.
    ReadyForReview,
    /// Under review - human is reviewing the work.
    Review,
    /// Ready to merge - review approved.
    ReadyForMerge,
    /// Work has been completed and merged.
    Completed,
    /// Work is blocked and cannot proceed.
    Blocked,
}

impl WorkPhase {
    /// Parses a work phase from a string.
    ///
    /// # Errors
    ///
    /// Returns `ExitSignalError::InvalidPhase` if the string is not a
    /// recognized work phase.
    pub fn parse(s: &str) -> Result<Self, ExitSignalError> {
        match s.to_uppercase().as_str() {
            "DRAFT" => Ok(Self::Draft),
            "IMPLEMENTATION" => Ok(Self::Implementation),
            "CI_PENDING" => Ok(Self::CiPending),
            "READY_FOR_REVIEW" => Ok(Self::ReadyForReview),
            "REVIEW" => Ok(Self::Review),
            "READY_FOR_MERGE" => Ok(Self::ReadyForMerge),
            "COMPLETED" => Ok(Self::Completed),
            "BLOCKED" => Ok(Self::Blocked),
            _ => Err(ExitSignalError::InvalidPhase(s.to_string())),
        }
    }

    /// Returns the string representation of this phase.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::Implementation => "IMPLEMENTATION",
            Self::CiPending => "CI_PENDING",
            Self::ReadyForReview => "READY_FOR_REVIEW",
            Self::Review => "REVIEW",
            Self::ReadyForMerge => "READY_FOR_MERGE",
            Self::Completed => "COMPLETED",
            Self::Blocked => "BLOCKED",
        }
    }

    /// Returns true if this is a terminal phase.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Blocked)
    }

    /// Returns the expected next phase after this one completes successfully.
    ///
    /// Returns `None` for terminal phases.
    #[must_use]
    pub const fn next_phase(&self) -> Option<Self> {
        match self {
            Self::Draft => Some(Self::Implementation),
            Self::Implementation => Some(Self::CiPending),
            Self::CiPending => Some(Self::ReadyForReview),
            Self::ReadyForReview => Some(Self::Review),
            Self::Review => Some(Self::ReadyForMerge),
            Self::ReadyForMerge => Some(Self::Completed),
            Self::Completed | Self::Blocked => None,
        }
    }
}

impl std::fmt::Display for WorkPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Exit Reason
// ============================================================================

/// Reason for agent session exit.
///
/// Indicates why the agent is ending its session. This helps the system
/// determine appropriate next actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitReason {
    /// Work phase completed successfully.
    Completed,
    /// Agent is blocked and cannot proceed (external dependency, missing info).
    Blocked,
    /// Agent encountered an error and must exit.
    Error,
}

impl ExitReason {
    /// Returns the string representation of this exit reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Blocked => "blocked",
            Self::Error => "error",
        }
    }

    /// Returns true if this is a successful completion.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl std::fmt::Display for ExitReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Exit Signal Error
// ============================================================================

/// Errors that can occur when validating an exit signal.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ExitSignalError {
    /// Protocol field is not `apm2_agent_exit`.
    #[error("unknown protocol: expected 'apm2_agent_exit', got '{0}'")]
    UnknownProtocol(String),

    /// Version is not compatible with 1.x.
    #[error("unsupported version: expected '1.x.y' format, got '{0}'")]
    UnsupportedVersion(String),

    /// Work phase is not valid.
    #[error("invalid work phase: '{0}'")]
    InvalidPhase(String),

    /// JSON parsing failed.
    #[error("invalid JSON: {0}")]
    InvalidJson(String),

    /// Exit signal validation is disabled.
    #[error("exit signal validation is disabled (AGENT_EXIT_PROTOCOL_ENABLED=false)")]
    ValidationDisabled,

    /// String field exceeds maximum allowed length.
    #[error("{field} exceeds maximum length: {actual} bytes > {max} bytes")]
    FieldTooLong {
        /// Name of the field that exceeded the limit.
        field: String,
        /// Actual length of the field.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Path contains traversal characters or is absolute.
    #[error("path traversal detected in {field}: paths cannot contain '..' or start with '/'")]
    PathTraversal {
        /// Name of the field containing the invalid path.
        field: String,
    },

    /// Input exceeds maximum allowed size.
    #[error("input too large: {actual} bytes > {max} bytes maximum")]
    InputTooLarge {
        /// Actual input size.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// URL contains shell injection characters.
    #[error("pr_url contains potentially dangerous character: '{char}'")]
    UrlInjection {
        /// The dangerous character found.
        char: char,
    },

    /// URL does not use HTTPS scheme.
    #[error("pr_url must start with 'https://': got '{0}'")]
    InsecureUrl(String),
}

// ============================================================================
// Exit Signal
// ============================================================================

/// The expected protocol identifier for exit signals.
pub const EXIT_SIGNAL_PROTOCOL: &str = "apm2_agent_exit";

/// The current protocol version.
pub const EXIT_SIGNAL_VERSION: &str = "1.0.0";

/// A structured exit signal emitted by an agent when completing a work phase.
///
/// This signal enables clean handoff between agent sessions. The agent emits
/// this as JSON when it has finished working on a phase.
///
/// # Example
///
/// ```rust
/// use apm2_core::agent::exit::{ExitReason, ExitSignal, WorkPhase};
///
/// let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
///     .with_pr_url("https://github.com/org/repo/pull/123")
///     .with_notes("Implementation complete, all tests passing");
///
/// // Validate the signal
/// assert!(signal.validate().is_ok());
///
/// // Serialize to JSON for output
/// let json = serde_json::to_string_pretty(&signal).unwrap();
/// println!("{}", json);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExitSignal {
    /// Protocol identifier. Must be `apm2_agent_exit`.
    pub protocol: String,

    /// Protocol version. Must be semver-compatible with 1.x.
    pub version: String,

    /// The work phase that was completed by this agent session.
    pub phase_completed: WorkPhase,

    /// The reason for exiting.
    pub exit_reason: ExitReason,

    /// GitHub PR URL if a PR was created during this phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr_url: Option<String>,

    /// Reference to the evidence bundle for this phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_bundle_ref: Option<String>,

    /// Human-readable notes about the exit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl ExitSignal {
    /// Creates a new exit signal with the required fields.
    ///
    /// Uses the current protocol version automatically.
    #[must_use]
    pub fn new(phase_completed: WorkPhase, exit_reason: ExitReason) -> Self {
        Self {
            protocol: EXIT_SIGNAL_PROTOCOL.to_string(),
            version: EXIT_SIGNAL_VERSION.to_string(),
            phase_completed,
            exit_reason,
            pr_url: None,
            evidence_bundle_ref: None,
            notes: None,
        }
    }

    /// Adds a PR URL to the exit signal.
    #[must_use]
    pub fn with_pr_url(mut self, pr_url: impl Into<String>) -> Self {
        self.pr_url = Some(pr_url.into());
        self
    }

    /// Adds an evidence bundle reference to the exit signal.
    #[must_use]
    pub fn with_evidence_bundle_ref(mut self, evidence_ref: impl Into<String>) -> Self {
        self.evidence_bundle_ref = Some(evidence_ref.into());
        self
    }

    /// Adds notes to the exit signal.
    #[must_use]
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    /// Validates the exit signal.
    ///
    /// # Contracts
    ///
    /// - [CTR-EXIT002] Protocol field must be `apm2_agent_exit`.
    /// - [CTR-EXIT003] Version must be semver-compatible with 1.x (format:
    ///   1.MINOR.PATCH).
    /// - [CTR-EXIT006] String fields must not exceed length limits (memory
    ///   exhaustion prevention).
    /// - [CTR-EXIT007] Path fields must not contain traversal sequences.
    /// - [CTR-EXIT008] Protocol and version fields must not exceed 64 bytes.
    /// - [CTR-EXIT009] PR URLs must use HTTPS and not contain shell characters.
    ///
    /// # Errors
    ///
    /// Returns `ExitSignalError::UnknownProtocol` if the protocol is wrong.
    /// Returns `ExitSignalError::UnsupportedVersion` if the version is
    /// incompatible or malformed.
    /// Returns `ExitSignalError::FieldTooLong` if a string field exceeds
    /// limits.
    /// Returns `ExitSignalError::PathTraversal` if a path contains
    /// `..` or starts with `/`.
    /// Returns `ExitSignalError::InsecureUrl` if `pr_url` doesn't start with
    /// `https://`.
    /// Returns `ExitSignalError::UrlInjection` if `pr_url` contains shell
    /// characters.
    pub fn validate(&self) -> Result<(), ExitSignalError> {
        // [CTR-EXIT008] Validate protocol/version field lengths first (DoS prevention)
        // These fixed-format fields should never exceed 64 bytes
        if self.protocol.len() > MAX_PROTOCOL_VERSION_LENGTH {
            return Err(ExitSignalError::FieldTooLong {
                field: "protocol".to_string(),
                actual: self.protocol.len(),
                max: MAX_PROTOCOL_VERSION_LENGTH,
            });
        }

        if self.version.len() > MAX_PROTOCOL_VERSION_LENGTH {
            return Err(ExitSignalError::FieldTooLong {
                field: "version".to_string(),
                actual: self.version.len(),
                max: MAX_PROTOCOL_VERSION_LENGTH,
            });
        }

        // [CTR-EXIT002] Validate protocol
        if self.protocol != EXIT_SIGNAL_PROTOCOL {
            return Err(ExitSignalError::UnknownProtocol(self.protocol.clone()));
        }

        // [CTR-EXIT003] Validate version (must be 1.x.y format)
        // Use strict regex to prevent malformed versions like "1.", "1.bad",
        // "1.99.99.extra"
        if !VERSION_REGEX.is_match(&self.version) {
            return Err(ExitSignalError::UnsupportedVersion(self.version.clone()));
        }

        // [CTR-EXIT006] Validate string field lengths (DoS prevention)
        if let Some(ref pr_url) = self.pr_url {
            if pr_url.len() > MAX_URL_PATH_LENGTH {
                return Err(ExitSignalError::FieldTooLong {
                    field: "pr_url".to_string(),
                    actual: pr_url.len(),
                    max: MAX_URL_PATH_LENGTH,
                });
            }

            // [CTR-EXIT009] Validate pr_url uses HTTPS scheme
            if !pr_url.starts_with("https://") {
                return Err(ExitSignalError::InsecureUrl(
                    pr_url.chars().take(50).collect::<String>()
                        + if pr_url.len() > 50 { "..." } else { "" },
                ));
            }

            // [CTR-EXIT009] Reject shell injection characters in pr_url
            for c in SHELL_INJECTION_CHARS {
                if pr_url.contains(*c) {
                    return Err(ExitSignalError::UrlInjection { char: *c });
                }
            }
        }

        if let Some(ref evidence_ref) = self.evidence_bundle_ref {
            if evidence_ref.len() > MAX_URL_PATH_LENGTH {
                return Err(ExitSignalError::FieldTooLong {
                    field: "evidence_bundle_ref".to_string(),
                    actual: evidence_ref.len(),
                    max: MAX_URL_PATH_LENGTH,
                });
            }

            // [CTR-EXIT007] Validate path does not contain traversal sequences
            if evidence_ref.contains("..") || evidence_ref.starts_with('/') {
                return Err(ExitSignalError::PathTraversal {
                    field: "evidence_bundle_ref".to_string(),
                });
            }
        }

        if let Some(ref notes) = self.notes {
            if notes.len() > MAX_NOTES_LENGTH {
                return Err(ExitSignalError::FieldTooLong {
                    field: "notes".to_string(),
                    actual: notes.len(),
                    max: MAX_NOTES_LENGTH,
                });
            }
        }

        Ok(())
    }

    /// Parses and validates an exit signal from JSON.
    ///
    /// This is the primary entry point for processing exit signals from agents.
    ///
    /// # Security
    ///
    /// Enforces a maximum input size of 64KB before parsing to prevent memory
    /// exhaustion attacks. Input exceeding this limit is rejected immediately.
    ///
    /// # Errors
    ///
    /// Returns `ExitSignalError::InputTooLarge` if input exceeds 64KB.
    /// Returns `ExitSignalError::InvalidJson` if the JSON is malformed.
    /// Returns `ExitSignalError::UnknownProtocol` if the protocol is wrong.
    /// Returns `ExitSignalError::UnsupportedVersion` if the version is
    /// incompatible.
    pub fn from_json(json: &str) -> Result<Self, ExitSignalError> {
        // [SECURITY] Reject oversized input BEFORE parsing to prevent DoS
        if json.len() > MAX_INPUT_LENGTH {
            return Err(ExitSignalError::InputTooLarge {
                actual: json.len(),
                max: MAX_INPUT_LENGTH,
            });
        }

        let signal: Self =
            serde_json::from_str(json).map_err(|e| ExitSignalError::InvalidJson(e.to_string()))?;
        signal.validate()?;
        Ok(signal)
    }

    /// Parses and validates an exit signal, respecting the feature flag.
    ///
    /// If `AGENT_EXIT_PROTOCOL_ENABLED` is false, returns
    /// `ExitSignalError::ValidationDisabled`.
    ///
    /// # Errors
    ///
    /// Returns `ExitSignalError::ValidationDisabled` if the feature is
    /// disabled. Returns other `ExitSignalError` variants for validation
    /// failures.
    pub fn from_json_if_enabled(json: &str) -> Result<Self, ExitSignalError> {
        if !is_agent_exit_protocol_enabled() {
            return Err(ExitSignalError::ValidationDisabled);
        }
        Self::from_json(json)
    }

    /// Returns the next expected phase based on the exit signal.
    ///
    /// For successful completion, returns the next phase in the workflow.
    /// For blocked/error exits, returns `Blocked` phase.
    #[must_use]
    pub fn next_expected_phase(&self) -> WorkPhase {
        match self.exit_reason {
            ExitReason::Completed => self
                .phase_completed
                .next_phase()
                .unwrap_or(WorkPhase::Completed),
            ExitReason::Blocked | ExitReason::Error => WorkPhase::Blocked,
        }
    }
}

// ============================================================================
// Feature Flag
// ============================================================================

/// Environment variable name for the agent exit protocol feature flag.
pub const AGENT_EXIT_PROTOCOL_ENABLED_ENV: &str = "AGENT_EXIT_PROTOCOL_ENABLED";

/// Cached value of the agent exit protocol enabled flag.
///
/// Using `OnceLock` to read the environment variable only once,
/// avoiding hot-path `env::var` calls which are relatively expensive.
static AGENT_EXIT_PROTOCOL_ENABLED_CACHE: OnceLock<bool> = OnceLock::new();

/// Parses the agent exit protocol enabled flag from an environment variable
/// value.
///
/// Returns `false` (disabled) by default for fail-closed security.
/// Only returns `true` if explicitly set to "true", "1", or "yes".
fn parse_agent_exit_protocol_enabled(value: Option<&str>) -> bool {
    // Disabled by default (fail-closed security), enabled only if explicitly set
    value.is_some_and(|val| {
        let val_lower = val.to_lowercase();
        val_lower == "true" || val_lower == "1" || val_lower == "yes"
    })
}

/// Checks if agent exit protocol validation is enabled.
///
/// Reads and caches the `AGENT_EXIT_PROTOCOL_ENABLED` environment variable on
/// first call. Subsequent calls return the cached value for O(1) performance
/// on hot paths.
///
/// Returns `true` if the variable is set to "true", "1", or "yes"
/// (case-insensitive). Returns `false` by default if the variable is not set
/// (fail-closed security).
#[must_use]
pub fn is_agent_exit_protocol_enabled() -> bool {
    *AGENT_EXIT_PROTOCOL_ENABLED_CACHE.get_or_init(|| {
        let value = std::env::var(AGENT_EXIT_PROTOCOL_ENABLED_ENV).ok();
        parse_agent_exit_protocol_enabled(value.as_deref())
    })
}

/// Configuration for agent exit protocol behavior.
///
/// This struct allows injecting configuration for testing without
/// modifying global environment variables.
#[derive(Debug, Clone)]
pub struct AgentExitConfig {
    /// Whether agent exit protocol validation is enabled.
    pub enabled: bool,
}

impl Default for AgentExitConfig {
    fn default() -> Self {
        Self {
            enabled: is_agent_exit_protocol_enabled(),
        }
    }
}

impl AgentExitConfig {
    /// Creates a new config with validation enabled.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Creates a new config with validation disabled.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }
}

// ============================================================================
// Agent Session Completed Event
// ============================================================================

/// An event emitted when an agent session completes via a valid exit signal.
///
/// This event is persisted to the ledger for audit purposes and triggers
/// downstream work item phase transitions.
///
/// # Example
///
/// ```rust
/// use apm2_core::agent::exit::{AgentSessionCompleted, ExitReason, ExitSignal, WorkPhase};
///
/// let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
///     .with_pr_url("https://github.com/org/repo/pull/123");
///
/// let event = AgentSessionCompleted::from_exit_signal("session-123", "actor-456", signal);
///
/// assert_eq!(event.event_type, AgentSessionCompleted::EVENT_TYPE);
/// assert_eq!(event.phase_completed, WorkPhase::Implementation);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionCompleted {
    /// Unique identifier for this event (UUID v4).
    pub event_id: Uuid,

    /// The type of event (always `AgentSessionCompleted`).
    pub event_type: String,

    /// When the event was created (UTC).
    pub timestamp: DateTime<Utc>,

    /// The source of the event.
    pub source: String,

    /// The session ID that completed.
    pub session_id: String,

    /// The actor ID (agent identity).
    pub actor_id: String,

    /// The work phase that was completed.
    pub phase_completed: WorkPhase,

    /// The reason for session completion.
    pub exit_reason: ExitReason,

    /// The next expected work phase.
    pub next_phase: WorkPhase,

    /// GitHub PR URL if a PR was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr_url: Option<String>,

    /// Reference to the evidence bundle for this phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_bundle_ref: Option<String>,

    /// Agent-provided notes about the completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl AgentSessionCompleted {
    /// The constant event type string.
    pub const EVENT_TYPE: &'static str = "AgentSessionCompleted";

    /// The constant source string.
    pub const SOURCE: &'static str = "agent_exit_protocol";

    /// Creates a new `AgentSessionCompleted` event from an exit signal.
    ///
    /// Generates a new UUID v4 for the event ID and captures the current
    /// UTC timestamp.
    #[must_use]
    pub fn from_exit_signal(session_id: &str, actor_id: &str, signal: ExitSignal) -> Self {
        let next_phase = signal.next_expected_phase();
        Self {
            event_id: Uuid::new_v4(),
            event_type: Self::EVENT_TYPE.to_string(),
            timestamp: Utc::now(),
            source: Self::SOURCE.to_string(),
            session_id: session_id.to_string(),
            actor_id: actor_id.to_string(),
            phase_completed: signal.phase_completed,
            exit_reason: signal.exit_reason,
            next_phase,
            pr_url: signal.pr_url,
            evidence_bundle_ref: signal.evidence_bundle_ref,
            notes: signal.notes,
        }
    }

    /// Creates a new event with a specific timestamp (for testing).
    #[cfg(test)]
    #[must_use]
    pub fn with_timestamp(
        session_id: &str,
        actor_id: &str,
        signal: ExitSignal,
        timestamp: DateTime<Utc>,
    ) -> Self {
        let next_phase = signal.next_expected_phase();
        Self {
            event_id: Uuid::new_v4(),
            event_type: Self::EVENT_TYPE.to_string(),
            timestamp,
            source: Self::SOURCE.to_string(),
            session_id: session_id.to_string(),
            actor_id: actor_id.to_string(),
            phase_completed: signal.phase_completed,
            exit_reason: signal.exit_reason,
            next_phase,
            pr_url: signal.pr_url,
            evidence_bundle_ref: signal.evidence_bundle_ref,
            notes: signal.notes,
        }
    }

    /// Returns true if this completion represents a successful phase
    /// transition.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.exit_reason.is_success()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    mod work_phase_tests {
        use super::*;

        #[test]
        fn test_work_phase_parse() {
            assert_eq!(WorkPhase::parse("DRAFT").unwrap(), WorkPhase::Draft);
            assert_eq!(WorkPhase::parse("draft").unwrap(), WorkPhase::Draft);
            assert_eq!(
                WorkPhase::parse("IMPLEMENTATION").unwrap(),
                WorkPhase::Implementation
            );
            assert_eq!(
                WorkPhase::parse("CI_PENDING").unwrap(),
                WorkPhase::CiPending
            );
            assert_eq!(
                WorkPhase::parse("READY_FOR_REVIEW").unwrap(),
                WorkPhase::ReadyForReview
            );
            assert_eq!(WorkPhase::parse("REVIEW").unwrap(), WorkPhase::Review);
            assert_eq!(
                WorkPhase::parse("READY_FOR_MERGE").unwrap(),
                WorkPhase::ReadyForMerge
            );
            assert_eq!(WorkPhase::parse("COMPLETED").unwrap(), WorkPhase::Completed);
            assert_eq!(WorkPhase::parse("BLOCKED").unwrap(), WorkPhase::Blocked);
        }

        #[test]
        fn test_work_phase_parse_invalid() {
            assert!(matches!(
                WorkPhase::parse("UNKNOWN"),
                Err(ExitSignalError::InvalidPhase(_))
            ));
            assert!(matches!(
                WorkPhase::parse(""),
                Err(ExitSignalError::InvalidPhase(_))
            ));
        }

        #[test]
        fn test_work_phase_as_str() {
            assert_eq!(WorkPhase::Draft.as_str(), "DRAFT");
            assert_eq!(WorkPhase::Implementation.as_str(), "IMPLEMENTATION");
            assert_eq!(WorkPhase::CiPending.as_str(), "CI_PENDING");
            assert_eq!(WorkPhase::ReadyForReview.as_str(), "READY_FOR_REVIEW");
            assert_eq!(WorkPhase::Review.as_str(), "REVIEW");
            assert_eq!(WorkPhase::ReadyForMerge.as_str(), "READY_FOR_MERGE");
            assert_eq!(WorkPhase::Completed.as_str(), "COMPLETED");
            assert_eq!(WorkPhase::Blocked.as_str(), "BLOCKED");
        }

        #[test]
        fn test_work_phase_is_terminal() {
            assert!(!WorkPhase::Draft.is_terminal());
            assert!(!WorkPhase::Implementation.is_terminal());
            assert!(!WorkPhase::CiPending.is_terminal());
            assert!(!WorkPhase::ReadyForReview.is_terminal());
            assert!(!WorkPhase::Review.is_terminal());
            assert!(!WorkPhase::ReadyForMerge.is_terminal());
            assert!(WorkPhase::Completed.is_terminal());
            assert!(WorkPhase::Blocked.is_terminal());
        }

        #[test]
        fn test_work_phase_next_phase() {
            assert_eq!(
                WorkPhase::Draft.next_phase(),
                Some(WorkPhase::Implementation)
            );
            assert_eq!(
                WorkPhase::Implementation.next_phase(),
                Some(WorkPhase::CiPending)
            );
            assert_eq!(
                WorkPhase::CiPending.next_phase(),
                Some(WorkPhase::ReadyForReview)
            );
            assert_eq!(
                WorkPhase::ReadyForReview.next_phase(),
                Some(WorkPhase::Review)
            );
            assert_eq!(
                WorkPhase::Review.next_phase(),
                Some(WorkPhase::ReadyForMerge)
            );
            assert_eq!(
                WorkPhase::ReadyForMerge.next_phase(),
                Some(WorkPhase::Completed)
            );
            assert_eq!(WorkPhase::Completed.next_phase(), None);
            assert_eq!(WorkPhase::Blocked.next_phase(), None);
        }

        #[test]
        fn test_work_phase_display() {
            assert_eq!(format!("{}", WorkPhase::Implementation), "IMPLEMENTATION");
            assert_eq!(format!("{}", WorkPhase::CiPending), "CI_PENDING");
        }

        #[test]
        fn test_work_phase_serialization() {
            let phase = WorkPhase::Implementation;
            let json = serde_json::to_string(&phase).unwrap();
            assert_eq!(json, "\"IMPLEMENTATION\"");

            let deserialized: WorkPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, WorkPhase::Implementation);
        }
    }

    mod exit_reason_tests {
        use super::*;

        #[test]
        fn test_exit_reason_as_str() {
            assert_eq!(ExitReason::Completed.as_str(), "completed");
            assert_eq!(ExitReason::Blocked.as_str(), "blocked");
            assert_eq!(ExitReason::Error.as_str(), "error");
        }

        #[test]
        fn test_exit_reason_is_success() {
            assert!(ExitReason::Completed.is_success());
            assert!(!ExitReason::Blocked.is_success());
            assert!(!ExitReason::Error.is_success());
        }

        #[test]
        fn test_exit_reason_display() {
            assert_eq!(format!("{}", ExitReason::Completed), "completed");
        }

        #[test]
        fn test_exit_reason_serialization() {
            let reason = ExitReason::Completed;
            let json = serde_json::to_string(&reason).unwrap();
            assert_eq!(json, "\"completed\"");

            let deserialized: ExitReason = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, ExitReason::Completed);
        }
    }

    mod exit_signal_tests {
        use super::*;

        #[test]
        fn test_exit_signal_new() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);

            assert_eq!(signal.protocol, EXIT_SIGNAL_PROTOCOL);
            assert_eq!(signal.version, EXIT_SIGNAL_VERSION);
            assert_eq!(signal.phase_completed, WorkPhase::Implementation);
            assert_eq!(signal.exit_reason, ExitReason::Completed);
            assert!(signal.pr_url.is_none());
            assert!(signal.evidence_bundle_ref.is_none());
            assert!(signal.notes.is_none());
        }

        #[test]
        fn test_exit_signal_builders() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url("https://github.com/org/repo/pull/123")
                .with_evidence_bundle_ref("evidence/work/W-00042/phase_implementation.yaml")
                .with_notes("Implementation complete");

            assert_eq!(
                signal.pr_url,
                Some("https://github.com/org/repo/pull/123".to_string())
            );
            assert_eq!(
                signal.evidence_bundle_ref,
                Some("evidence/work/W-00042/phase_implementation.yaml".to_string())
            );
            assert_eq!(signal.notes, Some("Implementation complete".to_string()));
        }

        #[test]
        fn test_exit_signal_validate_success() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
            assert!(signal.validate().is_ok());
        }

        #[test]
        fn test_exit_signal_validate_wrong_protocol() {
            let mut signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
            signal.protocol = "wrong_protocol".to_string();

            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::UnknownProtocol(p)) if p == "wrong_protocol"
            ));
        }

        #[test]
        fn test_exit_signal_validate_wrong_version() {
            let mut signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
            signal.version = "2.0.0".to_string();

            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::UnsupportedVersion(v)) if v == "2.0.0"
            ));
        }

        #[test]
        fn test_exit_signal_validate_version_1x_accepted() {
            let mut signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);

            // 1.0.0 should work
            signal.version = "1.0.0".to_string();
            assert!(signal.validate().is_ok());

            // 1.1.0 should work
            signal.version = "1.1.0".to_string();
            assert!(signal.validate().is_ok());

            // 1.99.99 should work
            signal.version = "1.99.99".to_string();
            assert!(signal.validate().is_ok());
        }

        #[test]
        fn test_exit_signal_from_json_success() {
            let json = r#"{
                "protocol": "apm2_agent_exit",
                "version": "1.0.0",
                "phase_completed": "IMPLEMENTATION",
                "exit_reason": "completed",
                "pr_url": "https://github.com/org/repo/pull/123",
                "notes": "Done"
            }"#;

            let signal = ExitSignal::from_json(json).unwrap();
            assert_eq!(signal.phase_completed, WorkPhase::Implementation);
            assert_eq!(signal.exit_reason, ExitReason::Completed);
            assert_eq!(
                signal.pr_url,
                Some("https://github.com/org/repo/pull/123".to_string())
            );
        }

        #[test]
        fn test_exit_signal_from_json_invalid_json() {
            let json = "not valid json";
            let result = ExitSignal::from_json(json);
            assert!(matches!(result, Err(ExitSignalError::InvalidJson(_))));
        }

        #[test]
        fn test_exit_signal_from_json_missing_required_field() {
            let json = r#"{
                "protocol": "apm2_agent_exit",
                "version": "1.0.0",
                "phase_completed": "IMPLEMENTATION"
            }"#;

            let result = ExitSignal::from_json(json);
            assert!(matches!(result, Err(ExitSignalError::InvalidJson(_))));
        }

        #[test]
        fn test_exit_signal_serialization_roundtrip() {
            let signal = ExitSignal::new(WorkPhase::Review, ExitReason::Completed)
                .with_pr_url("https://github.com/org/repo/pull/456")
                .with_notes("Review approved");

            let json = serde_json::to_string(&signal).unwrap();
            let deserialized = ExitSignal::from_json(&json).unwrap();

            assert_eq!(signal, deserialized);
        }

        #[test]
        fn test_exit_signal_json_omits_none_fields() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
            let json = serde_json::to_string(&signal).unwrap();

            // Should not contain pr_url, evidence_bundle_ref, or notes
            assert!(!json.contains("pr_url"));
            assert!(!json.contains("evidence_bundle_ref"));
            assert!(!json.contains("notes"));
        }

        #[test]
        fn test_exit_signal_deny_unknown_fields() {
            let json = r#"{
                "protocol": "apm2_agent_exit",
                "version": "1.0.0",
                "phase_completed": "IMPLEMENTATION",
                "exit_reason": "completed",
                "unknown_field": "malicious"
            }"#;

            let result = ExitSignal::from_json(json);
            assert!(matches!(result, Err(ExitSignalError::InvalidJson(_))));
        }

        #[test]
        fn test_exit_signal_next_expected_phase_completed() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
            assert_eq!(signal.next_expected_phase(), WorkPhase::CiPending);

            let signal = ExitSignal::new(WorkPhase::Review, ExitReason::Completed);
            assert_eq!(signal.next_expected_phase(), WorkPhase::ReadyForMerge);

            let signal = ExitSignal::new(WorkPhase::ReadyForMerge, ExitReason::Completed);
            assert_eq!(signal.next_expected_phase(), WorkPhase::Completed);
        }

        #[test]
        fn test_exit_signal_next_expected_phase_blocked() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Blocked);
            assert_eq!(signal.next_expected_phase(), WorkPhase::Blocked);
        }

        #[test]
        fn test_exit_signal_next_expected_phase_error() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Error);
            assert_eq!(signal.next_expected_phase(), WorkPhase::Blocked);
        }

        // ====================================================================
        // Security validation tests (TCK-00088)
        // ====================================================================

        #[test]
        fn test_exit_signal_validate_huge_input() {
            // Test pr_url exceeds 2KB limit
            let huge_pr_url = "https://github.com/".to_string() + &"x".repeat(3000);
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url(&huge_pr_url);
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::FieldTooLong { field, max, .. })
                if field == "pr_url" && max == 2 * 1024
            ));

            // Test evidence_bundle_ref exceeds 2KB limit
            let huge_evidence_ref = "evidence/".to_string() + &"x".repeat(3000);
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_evidence_bundle_ref(&huge_evidence_ref);
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::FieldTooLong { field, max, .. })
                if field == "evidence_bundle_ref" && max == 2 * 1024
            ));

            // Test notes exceeds 10KB limit
            let huge_notes = "x".repeat(11 * 1024);
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_notes(&huge_notes);
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::FieldTooLong { field, max, .. })
                if field == "notes" && max == 10 * 1024
            ));

            // Test that values at the limit are accepted
            let max_url = "https://".to_string() + &"x".repeat(2 * 1024 - 8);
            assert_eq!(max_url.len(), 2 * 1024);
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url(&max_url);
            assert!(signal.validate().is_ok());

            let max_notes = "x".repeat(10 * 1024);
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_notes(&max_notes);
            assert!(signal.validate().is_ok());
        }

        #[test]
        fn test_exit_signal_validate_version_strict() {
            let mut signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);

            // Valid versions
            signal.version = "1.0.0".to_string();
            assert!(signal.validate().is_ok());

            signal.version = "1.1.0".to_string();
            assert!(signal.validate().is_ok());

            signal.version = "1.99.99".to_string();
            assert!(signal.validate().is_ok());

            // Invalid versions that would have passed with starts_with("1.")
            signal.version = "1.".to_string();
            assert!(matches!(
                signal.validate(),
                Err(ExitSignalError::UnsupportedVersion(v)) if v == "1."
            ));

            signal.version = "1.bad".to_string();
            assert!(matches!(
                signal.validate(),
                Err(ExitSignalError::UnsupportedVersion(v)) if v == "1.bad"
            ));

            signal.version = "1.99.99.extra".to_string();
            assert!(matches!(
                signal.validate(),
                Err(ExitSignalError::UnsupportedVersion(v)) if v == "1.99.99.extra"
            ));

            signal.version = "1.0".to_string();
            assert!(matches!(
                signal.validate(),
                Err(ExitSignalError::UnsupportedVersion(v)) if v == "1.0"
            ));

            signal.version = "1.0.0-beta".to_string();
            assert!(matches!(
                signal.validate(),
                Err(ExitSignalError::UnsupportedVersion(v)) if v == "1.0.0-beta"
            ));
        }

        #[test]
        fn test_exit_signal_validate_path_traversal() {
            // Test path with ".." traversal
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_evidence_bundle_ref("evidence/../../../etc/passwd");
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::PathTraversal { field })
                if field == "evidence_bundle_ref"
            ));

            // Test path with ".." in the middle
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_evidence_bundle_ref("evidence/work/W-00042/../secret.yaml");
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::PathTraversal { field })
                if field == "evidence_bundle_ref"
            ));

            // Test absolute path starting with "/"
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_evidence_bundle_ref("/etc/passwd");
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::PathTraversal { field })
                if field == "evidence_bundle_ref"
            ));

            // Test valid relative path (should pass)
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_evidence_bundle_ref("evidence/work/W-00042/phase_implementation.yaml");
            assert!(signal.validate().is_ok());

            // Test path with "..." (not a traversal, should pass)
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_evidence_bundle_ref("evidence/file...name.yaml");
            // "..." contains ".." so this should fail
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::PathTraversal { field })
                if field == "evidence_bundle_ref"
            ));
        }

        #[test]
        fn test_exit_signal_from_json_rejects_oversized_input() {
            // Create input that exceeds 64KB limit
            let huge_input = format!(
                r#"{{"protocol":"apm2_agent_exit","version":"1.0.0","phase_completed":"IMPLEMENTATION","exit_reason":"completed","notes":"{}"}}"#,
                "x".repeat(70 * 1024)
            );
            assert!(huge_input.len() > 64 * 1024);

            let result = ExitSignal::from_json(&huge_input);
            assert!(matches!(
                result,
                Err(ExitSignalError::InputTooLarge { actual, max })
                if actual == huge_input.len() && max == 64 * 1024
            ));

            // Verify that input at or just under the limit is accepted (parsing may still
            // fail due to field limits)
            let within_limit = format!(
                r#"{{"protocol":"apm2_agent_exit","version":"1.0.0","phase_completed":"IMPLEMENTATION","exit_reason":"completed","notes":"{}"}}"#,
                "x".repeat(60 * 1024)
            );
            assert!(within_limit.len() < 64 * 1024);

            // This should NOT fail with InputTooLarge (may fail with FieldTooLong for
            // notes)
            let result = ExitSignal::from_json(&within_limit);
            assert!(!matches!(
                result,
                Err(ExitSignalError::InputTooLarge { .. })
            ));
        }

        #[test]
        fn test_exit_signal_validate_rejects_oversized_protocol_version() {
            // Test protocol field exceeds 64 byte limit
            let mut signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
            signal.protocol = "x".repeat(65);
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::FieldTooLong { field, max, .. })
                if field == "protocol" && max == 64
            ));

            // Test version field exceeds 64 byte limit
            let mut signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
            signal.version = "1.".to_string() + &"9".repeat(100);
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::FieldTooLong { field, max, .. })
                if field == "version" && max == 64
            ));

            // Verify values at the limit are accepted (though they may fail other
            // validation)
            let mut signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
            signal.protocol = "x".repeat(64);
            let result = signal.validate();
            // Should fail with UnknownProtocol, not FieldTooLong
            assert!(matches!(result, Err(ExitSignalError::UnknownProtocol(_))));
        }

        #[test]
        fn test_exit_signal_validate_pr_url_injection() {
            // Test URL with semicolon (shell command separator)
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url("https://github.com/org/repo/pull/123;rm -rf /");
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::UrlInjection { char: ';' })
            ));

            // Test URL with pipe (shell pipe)
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url("https://github.com/org/repo/pull/123|cat /etc/passwd");
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::UrlInjection { char: '|' })
            ));

            // Test URL with backtick (command substitution)
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url("https://github.com/org/repo/pull/`whoami`");
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::UrlInjection { char: '`' })
            ));

            // Test URL with dollar sign (variable expansion)
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url("https://github.com/org/repo/pull/$HOME");
            let result = signal.validate();
            assert!(matches!(
                result,
                Err(ExitSignalError::UrlInjection { char: '$' })
            ));

            // Test URL without HTTPS scheme
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url("http://github.com/org/repo/pull/123");
            let result = signal.validate();
            assert!(matches!(result, Err(ExitSignalError::InsecureUrl(_))));

            // Test URL with invalid scheme
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url("file:///etc/passwd");
            let result = signal.validate();
            assert!(matches!(result, Err(ExitSignalError::InsecureUrl(_))));

            // Test valid HTTPS URL (should pass)
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url("https://github.com/org/repo/pull/123");
            assert!(signal.validate().is_ok());

            // Test URL with query params (should pass - no shell chars)
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url("https://github.com/org/repo/pull/123?tab=files#diff-abc123");
            assert!(signal.validate().is_ok());
        }
    }

    mod feature_flag_tests {
        use super::*;

        #[test]
        fn test_parse_feature_flag_default_disabled() {
            assert!(!parse_agent_exit_protocol_enabled(None));
        }

        #[test]
        fn test_parse_feature_flag_explicitly_enabled() {
            assert!(parse_agent_exit_protocol_enabled(Some("true")));
            assert!(parse_agent_exit_protocol_enabled(Some("1")));
            assert!(parse_agent_exit_protocol_enabled(Some("yes")));
            assert!(parse_agent_exit_protocol_enabled(Some("TRUE")));
            assert!(parse_agent_exit_protocol_enabled(Some("Yes")));
        }

        #[test]
        fn test_parse_feature_flag_disabled() {
            assert!(!parse_agent_exit_protocol_enabled(Some("")));
            assert!(!parse_agent_exit_protocol_enabled(Some("false")));
            assert!(!parse_agent_exit_protocol_enabled(Some("0")));
            assert!(!parse_agent_exit_protocol_enabled(Some("no")));
            assert!(!parse_agent_exit_protocol_enabled(Some("maybe")));
        }

        #[test]
        fn test_agent_exit_config() {
            let enabled = AgentExitConfig::enabled();
            assert!(enabled.enabled);

            let disabled = AgentExitConfig::disabled();
            assert!(!disabled.enabled);
        }
    }

    mod error_tests {
        use super::*;

        #[test]
        fn test_error_display() {
            let err = ExitSignalError::UnknownProtocol("bad".to_string());
            assert!(err.to_string().contains("apm2_agent_exit"));
            assert!(err.to_string().contains("bad"));

            let err = ExitSignalError::UnsupportedVersion("2.0.0".to_string());
            assert!(err.to_string().contains("1.x"));
            assert!(err.to_string().contains("2.0.0"));

            let err = ExitSignalError::InvalidPhase("UNKNOWN".to_string());
            assert!(err.to_string().contains("UNKNOWN"));

            let err = ExitSignalError::InvalidJson("parse error".to_string());
            assert!(err.to_string().contains("parse error"));

            let err = ExitSignalError::ValidationDisabled;
            assert!(err.to_string().contains("disabled"));
        }
    }

    mod agent_session_completed_tests {
        use super::*;

        #[test]
        fn test_from_exit_signal() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed)
                .with_pr_url("https://github.com/org/repo/pull/123")
                .with_notes("Done");

            let event = AgentSessionCompleted::from_exit_signal("session-1", "actor-1", signal);

            assert_eq!(event.event_type, AgentSessionCompleted::EVENT_TYPE);
            assert_eq!(event.source, AgentSessionCompleted::SOURCE);
            assert_eq!(event.session_id, "session-1");
            assert_eq!(event.actor_id, "actor-1");
            assert_eq!(event.phase_completed, WorkPhase::Implementation);
            assert_eq!(event.exit_reason, ExitReason::Completed);
            assert_eq!(event.next_phase, WorkPhase::CiPending);
            assert_eq!(
                event.pr_url,
                Some("https://github.com/org/repo/pull/123".to_string())
            );
            assert_eq!(event.notes, Some("Done".to_string()));
        }

        #[test]
        fn test_from_exit_signal_blocked() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Blocked)
                .with_notes("Missing requirements");

            let event = AgentSessionCompleted::from_exit_signal("session-1", "actor-1", signal);

            assert_eq!(event.exit_reason, ExitReason::Blocked);
            assert_eq!(event.next_phase, WorkPhase::Blocked);
            assert!(!event.is_success());
        }

        #[test]
        fn test_is_success() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
            let event = AgentSessionCompleted::from_exit_signal("session-1", "actor-1", signal);
            assert!(event.is_success());

            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Error);
            let event = AgentSessionCompleted::from_exit_signal("session-1", "actor-1", signal);
            assert!(!event.is_success());
        }

        #[test]
        fn test_serialization() {
            let signal = ExitSignal::new(WorkPhase::Review, ExitReason::Completed)
                .with_pr_url("https://github.com/org/repo/pull/456");

            let event = AgentSessionCompleted::from_exit_signal("session-1", "actor-1", signal);

            let json = serde_json::to_string(&event).unwrap();
            let deserialized: AgentSessionCompleted = serde_json::from_str(&json).unwrap();

            assert_eq!(event.event_id, deserialized.event_id);
            assert_eq!(event.session_id, deserialized.session_id);
            assert_eq!(event.phase_completed, deserialized.phase_completed);
        }

        #[test]
        fn test_deny_unknown_fields() {
            let json = r#"{
                "event_id": "00000000-0000-0000-0000-000000000000",
                "event_type": "AgentSessionCompleted",
                "timestamp": "2024-01-01T00:00:00Z",
                "source": "agent_exit_protocol",
                "session_id": "session-1",
                "actor_id": "actor-1",
                "phase_completed": "IMPLEMENTATION",
                "exit_reason": "completed",
                "next_phase": "CI_PENDING",
                "unknown_field": "malicious"
            }"#;

            let result: Result<AgentSessionCompleted, _> = serde_json::from_str(json);
            assert!(result.is_err());
        }

        #[test]
        fn test_json_omits_none_fields() {
            let signal = ExitSignal::new(WorkPhase::Implementation, ExitReason::Completed);
            let event = AgentSessionCompleted::from_exit_signal("session-1", "actor-1", signal);

            let json = serde_json::to_string(&event).unwrap();
            assert!(!json.contains("pr_url"));
            assert!(!json.contains("evidence_bundle_ref"));
            assert!(!json.contains("notes"));
        }
    }
}
