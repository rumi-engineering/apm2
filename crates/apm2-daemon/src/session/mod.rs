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
    EXIT_CLASSIFICATION_CONTEXT_MISS, MAX_REFINEMENT_ATTEMPTS,
    TERMINATION_RATIONALE_CONTEXT_MISS, validate_tool_request,
};
pub use crate::episode::decision::SessionTerminationInfo;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
/// # Security Note
///
/// The `Debug` impl manually redacts `lease_id` to prevent accidental leakage
/// in debug logs. The `lease_id` is a security-sensitive credential that should
/// not appear in logs or error messages.
#[derive(Clone)]
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
    /// **SECURITY**: This field is redacted in Debug output to prevent
    /// credential leakage in logs.
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
pub trait SessionRegistry: Send + Sync {
    /// Registers a new session.
    fn register_session(&self, session: SessionState) -> Result<(), SessionRegistryError>;

    /// Queries a session by session ID.
    fn get_session(&self, session_id: &str) -> Option<SessionState>;

    /// Queries a session by ephemeral handle.
    fn get_session_by_handle(&self, handle: &str) -> Option<SessionState>;
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
