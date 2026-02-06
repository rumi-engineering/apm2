// AGENT-AUTHORED (TCK-00211)
//! Session handling for the APM2 daemon.
//!
//! This module provides session management functionality for the daemon,
//! including CONSUME mode sessions with context firewall integration.
//!
//! # Modules
//!
//! - [`consume`]: CONSUME mode session handler with context firewall
//!   integration

pub mod consume;

// Re-export main types
pub use consume::{
    ConsumeSessionContext, ConsumeSessionError, ConsumeSessionHandler,
    EXIT_CLASSIFICATION_CONTEXT_MISS, MAX_REFINEMENT_ATTEMPTS, TERMINATION_RATIONALE_CONTEXT_MISS,
    validate_tool_request,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::episode::decision::SessionTerminationInfo;

/// Ephemeral session handle for IPC authentication.
///
/// Per REQ-DCP-0004, the handle is a bearer token for session-scoped IPC.
/// It MUST NOT contain credentials or long-term secrets.
///
/// # Security
///
/// - Generated using UUID v4 (random)
/// - No embedded user data or secrets
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EphemeralHandle(String);

impl EphemeralHandle {
    /// Generates a new random ephemeral handle.
    ///
    /// Format: `H-{uuid}`
    pub fn generate() -> Self {
        Self(format!("H-{}", Uuid::new_v4()))
    }

    /// Returns the handle string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EphemeralHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for EphemeralHandle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Session state for a spawned episode.
///
/// Per TCK-00256, the session state is persisted when `SpawnEpisode` succeeds
/// to enable subsequent session-scoped IPC calls.
///
/// # Persistence (TCK-00266)
///
/// This struct implements `Serialize` and `Deserialize` to support persistent
/// session registry state files for crash recovery.
///
/// # Security Note
///
/// The `Debug` impl manually redacts `lease_id` to prevent accidental leakage
/// in debug logs. The `lease_id` is a security-sensitive credential that should
/// not appear in logs or error messages.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Unique session identifier.
    pub session_id: String,
    /// Work ID this session is associated with.
    pub work_id: String,
    /// Role claimed for this session.
    pub role: i32, // Using i32 to avoid circular dependency with protocol::messages::WorkRole
    /// Ephemeral handle for IPC communication.
    pub ephemeral_handle: String,
    /// Lease ID authorizing this session.
    ///
    /// **SECURITY**: This field is redacted in Debug output and skipped during
    /// serialization to prevent credential leakage.
    #[serde(skip, default)]
    pub lease_id: String,
    /// Policy resolution reference.
    pub policy_resolved_ref: String,
    /// Hash of the capability manifest for this session.
    pub capability_manifest_hash: Vec<u8>,
    /// Episode ID in the runtime (if created).
    pub episode_id: Option<String>,
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionState")
            .field("session_id", &self.session_id)
            .field("work_id", &self.work_id)
            .field("role", &self.role)
            .field("ephemeral_handle", &self.ephemeral_handle)
            .field("lease_id", &"[REDACTED]")
            .field("policy_resolved_ref", &self.policy_resolved_ref)
            .field(
                "capability_manifest_hash",
                &hex::encode(&self.capability_manifest_hash),
            )
            .field("episode_id", &self.episode_id)
            .finish()
    }
}

/// Trait for persisting and querying session state.
///
/// Per TCK-00256, sessions must be persisted to enable subsequent
/// session-scoped IPC calls.
///
/// # TCK-00385: Termination Tracking
///
/// The registry now supports marking sessions as terminated via
/// [`mark_terminated`](Self::mark_terminated) and querying termination info
/// via [`get_termination_info`](Self::get_termination_info). Terminated
/// sessions are preserved in the registry (with TTL) so that
/// `SessionStatus` queries after termination return useful information
/// instead of "session not found".
pub trait SessionRegistry: Send + Sync {
    /// Registers a new session.
    fn register_session(&self, session: SessionState) -> Result<(), SessionRegistryError>;

    /// Queries a session by session ID.
    fn get_session(&self, session_id: &str) -> Option<SessionState>;

    /// Queries a session by ephemeral handle.
    fn get_session_by_handle(&self, handle: &str) -> Option<SessionState>;

    /// Queries a session by work ID (TCK-00344).
    ///
    /// Returns the first session associated with the given `work_id`, or `None`
    /// if no session matches. This is an O(n) scan; a production implementation
    /// could add a secondary index for efficiency.
    fn get_session_by_work_id(&self, work_id: &str) -> Option<SessionState>;

    /// Marks a session as terminated with the given termination info
    /// (TCK-00385).
    ///
    /// The session entry is preserved in the registry so that subsequent
    /// `SessionStatus` queries return TERMINATED state with exit details.
    /// The entry will be cleaned up after the configured TTL.
    ///
    /// Returns `Ok(true)` if the session was found and marked terminated,
    /// `Ok(false)` if the session was not found. Returns `Err` if the
    /// termination could not be persisted (fail-closed: callers MUST treat
    /// persistence failures as fatal for the session lifecycle).
    fn mark_terminated(
        &self,
        session_id: &str,
        info: SessionTerminationInfo,
    ) -> Result<bool, SessionRegistryError>;

    /// Queries termination info for a session (TCK-00385).
    ///
    /// Returns `Some(info)` if the session has been terminated and the
    /// termination entry has not yet expired (TTL). Returns `None` if the
    /// session is still active or not found.
    fn get_termination_info(&self, session_id: &str) -> Option<SessionTerminationInfo>;

    /// Queries a terminated session's preserved state and termination info
    /// (TCK-00385).
    ///
    /// Returns `Some((session, info))` if the session has been terminated
    /// and the entry has not yet expired. Returns `None` otherwise.
    ///
    /// This is used by the `SessionStatus` handler to return `work_id`, role,
    /// and `episode_id` alongside termination details.
    fn get_terminated_session(
        &self,
        session_id: &str,
    ) -> Option<(SessionState, SessionTerminationInfo)>;

    /// Returns all active sessions for crash recovery (TCK-00387).
    ///
    /// Default implementation returns an empty vec (suitable for in-memory
    /// registries that don't persist across restarts).
    fn all_sessions_for_recovery(&self) -> Vec<SessionState> {
        Vec::new()
    }

    /// Clears all sessions and persists the empty state (TCK-00387).
    ///
    /// Used after crash recovery to make recovery idempotent. A second
    /// startup with the same state file will see no sessions to recover.
    ///
    /// Default implementation is a no-op (suitable for in-memory registries).
    ///
    /// # Errors
    ///
    /// Returns `SessionRegistryError` if persistence fails.
    fn clear_all_sessions(&self) -> Result<(), SessionRegistryError> {
        Ok(())
    }

    /// Removes specific sessions by ID and persists the updated state.
    ///
    /// Used after partial crash recovery (e.g., when session collection was
    /// truncated to `MAX_RECOVERY_SESSIONS`) to clear only the recovered
    /// subset without discarding unrecovered sessions.
    ///
    /// Default implementation is a no-op (suitable for in-memory registries).
    ///
    /// # Errors
    ///
    /// Returns `SessionRegistryError` if persistence fails.
    fn clear_sessions_by_ids(&self, _session_ids: &[String]) -> Result<(), SessionRegistryError> {
        Ok(())
    }
}

/// Error type for session registry operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionRegistryError {
    /// Session ID already exists.
    #[error("duplicate session_id: {session_id}")]
    DuplicateSessionId {
        /// The duplicate session ID.
        session_id: String,
    },

    /// Registration failed.
    #[error("session registration failed: {message}")]
    RegistrationFailed {
        /// Error message.
        message: String,
    },
}
