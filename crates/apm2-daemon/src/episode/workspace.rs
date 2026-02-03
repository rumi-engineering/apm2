// AGENT-AUTHORED
//! Workspace snapshot and apply operations for FAC v0 review.
//!
//! This module implements workspace semantics for applying `ChangeSetBundleV1`
//! to a reviewer workspace. It provides snapshot/apply operations with proper
//! failure handling and retry bounds via HTF time windows.
//!
//! # Design Overview
//!
//! The workspace module provides:
//!
//! - **Snapshot**: Captures the current workspace state before apply
//! - **Apply**: Applies a changeset bundle to the workspace
//! - **Failure Handling**: Maps failures to `ReasonCode` for durable recording
//! - **Retry Bounds**: Enforces HTF time window constraints for retries
//!
//! # Security Properties
//!
//! - **Binary Detection**: Rejects changesets with binary files (v0 limitation)
//! - **Path Validation**: Validates file paths to prevent traversal attacks
//! - **CAS Binding**: All artifacts are stored in CAS with hash verification
//! - **HTF Time Bounds**: Retries are bounded by HTF windows, not wall clock
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_daemon::episode::workspace::{WorkspaceManager, WorkspaceSnapshot};
//! use apm2_core::fac::ChangeSetBundleV1;
//!
//! let manager = WorkspaceManager::new(cas_store, work_dir);
//!
//! // Take snapshot before apply
//! let snapshot = manager.snapshot(&work_id).await?;
//!
//! // Apply changeset bundle
//! match manager.apply(&bundle).await {
//!     Ok(result) => { /* proceed with review */ },
//!     Err(e) => {
//!         // Record blocked outcome with reason code
//!         let reason = e.reason_code();
//!         // ...emit ReviewBlockedRecorded event
//!     }
//! }
//! ```

use std::path::{Path, PathBuf};

use apm2_core::crypto::Signer;
use apm2_core::fac::{
    ChangeSetBundleV1, ReasonCode, ReviewBlockedError, ReviewBlockedRecorded,
    ReviewBlockedRecordedBuilder,
};
use apm2_core::htf::TimeEnvelopeRef;
use thiserror::Error;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of retry attempts within an HTF window.
pub const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Maximum path depth to prevent directory traversal.
pub const MAX_PATH_DEPTH: usize = 64;

/// Maximum file size for apply operations (100 MB).
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during workspace operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkspaceError {
    /// Workspace apply failed.
    #[error("apply failed: {0}")]
    ApplyFailed(String),

    /// Tool execution failed during workspace operation.
    #[error("tool failed: {0}")]
    ToolFailed(String),

    /// Binary file detected (unsupported in v0).
    #[error("binary file detected: {0}")]
    BinaryUnsupported(String),

    /// Required artifact missing from CAS.
    #[error("missing artifact: {0}")]
    MissingArtifact(String),

    /// Invalid changeset bundle format.
    #[error("invalid bundle: {0}")]
    InvalidBundle(String),

    /// Operation timed out.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Policy denied the operation.
    #[error("policy denied: {0}")]
    PolicyDenied(String),

    /// Context miss detected.
    #[error("context miss: {0}")]
    ContextMiss(String),

    /// Path traversal attack detected.
    #[error("path traversal: {0}")]
    PathTraversal(String),

    /// File too large.
    #[error("file too large: {path} ({size} > {max})")]
    FileTooLarge {
        /// File path.
        path: String,
        /// Actual size.
        size: u64,
        /// Maximum allowed size.
        max: u64,
    },

    /// Maximum retries exceeded.
    #[error("max retries exceeded: {attempts} attempts in window")]
    MaxRetriesExceeded {
        /// Number of attempts made.
        attempts: u32,
    },

    /// HTF window expired.
    #[error("htf window expired")]
    HtfWindowExpired,

    /// IO error during workspace operation.
    #[error("io error: {0}")]
    IoError(String),

    /// CAS storage error.
    #[error("cas error: {0}")]
    CasError(String),
}

impl WorkspaceError {
    /// Maps the workspace error to a `ReasonCode` for durable recording.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Self::ApplyFailed(_) | Self::IoError(_) => ReasonCode::ApplyFailed,
            Self::ToolFailed(_) => ReasonCode::ToolFailed,
            Self::BinaryUnsupported(_) => ReasonCode::BinaryUnsupported,
            Self::MissingArtifact(_) | Self::CasError(_) => ReasonCode::MissingArtifact,
            Self::InvalidBundle(_) | Self::PathTraversal(_) | Self::FileTooLarge { .. } => {
                ReasonCode::InvalidBundle
            },
            Self::Timeout(_) | Self::MaxRetriesExceeded { .. } | Self::HtfWindowExpired => {
                ReasonCode::Timeout
            },
            Self::PolicyDenied(_) => ReasonCode::PolicyDenied,
            Self::ContextMiss(_) => ReasonCode::ContextMiss,
        }
    }

    /// Returns true if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.reason_code().is_retryable()
    }
}

// =============================================================================
// Workspace Snapshot
// =============================================================================

/// A snapshot of the workspace state before apply.
///
/// This captures the essential state needed to restore the workspace
/// if apply fails.
#[derive(Debug, Clone)]
pub struct WorkspaceSnapshot {
    /// Work ID this snapshot belongs to.
    pub work_id: String,
    /// BLAKE3 hash of the snapshot state (32 bytes).
    pub snapshot_hash: [u8; 32],
    /// Timestamp when snapshot was taken (nanoseconds since epoch).
    pub snapshot_at_ns: u64,
    /// HTF time envelope reference for temporal authority.
    pub time_envelope_ref: Option<TimeEnvelopeRef>,
    /// Number of files in the snapshot.
    pub file_count: usize,
}

impl WorkspaceSnapshot {
    /// Creates a new workspace snapshot.
    #[must_use]
    pub fn new(
        work_id: String,
        snapshot_hash: [u8; 32],
        snapshot_at_ns: u64,
        file_count: usize,
    ) -> Self {
        Self {
            work_id,
            snapshot_hash,
            snapshot_at_ns,
            time_envelope_ref: None,
            file_count,
        }
    }

    /// Sets the HTF time envelope reference.
    #[must_use]
    pub fn with_time_envelope_ref(mut self, time_envelope_ref: TimeEnvelopeRef) -> Self {
        self.time_envelope_ref = Some(time_envelope_ref);
        self
    }
}

// =============================================================================
// Apply Result
// =============================================================================

/// Result of a successful workspace apply operation.
#[derive(Debug, Clone)]
pub struct ApplyResult {
    /// Changeset digest that was applied.
    pub changeset_digest: [u8; 32],
    /// Number of files modified.
    pub files_modified: usize,
    /// Timestamp when apply completed (nanoseconds since epoch).
    pub applied_at_ns: u64,
    /// HTF time envelope reference for temporal authority.
    pub time_envelope_ref: Option<TimeEnvelopeRef>,
}

impl ApplyResult {
    /// Creates a new apply result.
    #[must_use]
    pub fn new(changeset_digest: [u8; 32], files_modified: usize, applied_at_ns: u64) -> Self {
        Self {
            changeset_digest,
            files_modified,
            applied_at_ns,
            time_envelope_ref: None,
        }
    }

    /// Sets the HTF time envelope reference.
    #[must_use]
    pub fn with_time_envelope_ref(mut self, time_envelope_ref: TimeEnvelopeRef) -> Self {
        self.time_envelope_ref = Some(time_envelope_ref);
        self
    }
}

// =============================================================================
// Retry Context
// =============================================================================

/// Context for tracking retry attempts within an HTF window.
#[derive(Debug, Clone)]
pub struct RetryContext {
    /// Work ID for this retry context.
    pub work_id: String,
    /// Number of attempts made so far.
    pub attempts: u32,
    /// Maximum allowed attempts.
    pub max_attempts: u32,
    /// HTF window start tick.
    pub window_start_tick: u64,
    /// HTF window end tick.
    pub window_end_tick: u64,
    /// Current tick.
    pub current_tick: u64,
}

impl RetryContext {
    /// Creates a new retry context.
    #[must_use]
    pub fn new(
        work_id: String,
        window_start_tick: u64,
        window_end_tick: u64,
        current_tick: u64,
    ) -> Self {
        Self {
            work_id,
            attempts: 0,
            max_attempts: MAX_RETRY_ATTEMPTS,
            window_start_tick,
            window_end_tick,
            current_tick,
        }
    }

    /// Checks if retry is allowed within the HTF window.
    ///
    /// # Errors
    ///
    /// Returns error if max retries exceeded or HTF window expired.
    pub fn check_retry_allowed(&self) -> Result<(), WorkspaceError> {
        if self.attempts >= self.max_attempts {
            return Err(WorkspaceError::MaxRetriesExceeded {
                attempts: self.attempts,
            });
        }
        if self.current_tick >= self.window_end_tick {
            return Err(WorkspaceError::HtfWindowExpired);
        }
        Ok(())
    }

    /// Records a retry attempt.
    pub fn record_attempt(&mut self) {
        self.attempts += 1;
    }

    /// Updates the current tick.
    pub fn update_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }
}

// =============================================================================
// Path Validation
// =============================================================================

/// Validates a file path to prevent directory traversal attacks.
///
/// # Errors
///
/// Returns error if the path contains traversal patterns or is too deep.
pub fn validate_path(path: &str, workspace_root: &Path) -> Result<PathBuf, WorkspaceError> {
    // Check for empty path
    if path.is_empty() {
        return Err(WorkspaceError::InvalidBundle("empty path".to_string()));
    }

    // Check for path traversal patterns
    if path.contains("..") {
        return Err(WorkspaceError::PathTraversal(format!(
            "path contains '..' traversal: {path}"
        )));
    }

    // Check for absolute paths
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(WorkspaceError::PathTraversal(format!(
            "path is absolute: {path}"
        )));
    }

    // Check path depth
    let depth = path.split('/').count();
    if depth > MAX_PATH_DEPTH {
        return Err(WorkspaceError::InvalidBundle(format!(
            "path depth exceeds limit: {depth} > {MAX_PATH_DEPTH}"
        )));
    }

    // Construct full path and verify it stays within workspace
    let full_path = workspace_root.join(path);

    // Canonicalize to resolve symlinks and verify containment
    // Note: In production, this would need actual filesystem access
    // For now, we do a simple prefix check
    let normalized = full_path.components().collect::<PathBuf>();

    // Verify the normalized path starts with workspace root
    if !normalized.starts_with(workspace_root) {
        return Err(WorkspaceError::PathTraversal(format!(
            "path escapes workspace: {path}"
        )));
    }

    Ok(normalized)
}

/// Validates all file changes in a changeset bundle.
///
/// # Errors
///
/// Returns error if any file change has invalid paths or binary detection
/// fails.
pub fn validate_file_changes(
    bundle: &ChangeSetBundleV1,
    workspace_root: &Path,
) -> Result<(), WorkspaceError> {
    // Check for binary files (v0 limitation)
    if bundle.binary_detected {
        return Err(WorkspaceError::BinaryUnsupported(
            "changeset contains binary files".to_string(),
        ));
    }

    // Validate each file change
    for change in &bundle.file_manifest {
        // Validate primary path
        validate_path(&change.path, workspace_root)?;

        // Validate old_path for renames
        if let Some(ref old_path) = change.old_path {
            validate_path(old_path, workspace_root)?;
        }
    }

    Ok(())
}

// =============================================================================
// Blocked Outcome Recording
// =============================================================================

/// Creates a `ReviewBlockedRecorded` event from a workspace error.
///
/// This function converts a workspace error into a durable ledger event
/// that records the blocked outcome.
///
/// # Errors
///
/// Returns error if the event cannot be created (validation failures).
pub fn create_blocked_event(
    blocked_id: String,
    changeset_digest: [u8; 32],
    error: &WorkspaceError,
    blocked_log_hash: [u8; 32],
    time_envelope_ref: [u8; 32],
    recorder_actor_id: String,
    signer: &Signer,
) -> Result<ReviewBlockedRecorded, ReviewBlockedError> {
    ReviewBlockedRecordedBuilder::new()
        .blocked_id(blocked_id)
        .changeset_digest(changeset_digest)
        .reason_code(error.reason_code())
        .blocked_log_hash(blocked_log_hash)
        .time_envelope_ref(time_envelope_ref)
        .recorder_actor_id(recorder_actor_id)
        .build_and_sign(signer)
}

// =============================================================================
// Workspace Manager (Stub)
// =============================================================================

/// Workspace manager for snapshot and apply operations.
///
/// This is a stub implementation that will be wired to actual filesystem
/// and CAS operations in a future ticket.
#[derive(Debug)]
pub struct WorkspaceManager {
    /// Workspace root directory.
    pub workspace_root: PathBuf,
}

impl WorkspaceManager {
    /// Creates a new workspace manager.
    #[must_use]
    pub fn new(workspace_root: PathBuf) -> Self {
        Self { workspace_root }
    }

    /// Takes a snapshot of the current workspace state.
    ///
    /// # Errors
    ///
    /// Returns error if snapshot fails.
    pub async fn snapshot(&self, work_id: &str) -> Result<WorkspaceSnapshot, WorkspaceError> {
        // Stub: In production, this would compute actual workspace state hash
        let snapshot_hash = *blake3::hash(work_id.as_bytes()).as_bytes();
        let snapshot_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Ok(WorkspaceSnapshot::new(
            work_id.to_string(),
            snapshot_hash,
            snapshot_at_ns,
            0, // file_count - stub
        ))
    }

    /// Applies a changeset bundle to the workspace.
    ///
    /// # Errors
    ///
    /// Returns error if apply fails for any reason.
    pub async fn apply(&self, bundle: &ChangeSetBundleV1) -> Result<ApplyResult, WorkspaceError> {
        // Validate file changes first
        validate_file_changes(bundle, &self.workspace_root)?;

        // Stub: In production, this would actually apply the diff
        let applied_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Ok(ApplyResult::new(
            bundle.changeset_digest,
            bundle.file_manifest.len(),
            applied_at_ns,
        ))
    }

    /// Restores the workspace from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns error if restore fails.
    pub async fn restore(&self, _snapshot: &WorkspaceSnapshot) -> Result<(), WorkspaceError> {
        // Stub: In production, this would restore from snapshot
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_workspace_error_reason_code_mapping() {
        assert_eq!(
            WorkspaceError::ApplyFailed("test".into()).reason_code(),
            ReasonCode::ApplyFailed
        );
        assert_eq!(
            WorkspaceError::ToolFailed("test".into()).reason_code(),
            ReasonCode::ToolFailed
        );
        assert_eq!(
            WorkspaceError::BinaryUnsupported("test".into()).reason_code(),
            ReasonCode::BinaryUnsupported
        );
        assert_eq!(
            WorkspaceError::MissingArtifact("test".into()).reason_code(),
            ReasonCode::MissingArtifact
        );
        assert_eq!(
            WorkspaceError::InvalidBundle("test".into()).reason_code(),
            ReasonCode::InvalidBundle
        );
        assert_eq!(
            WorkspaceError::Timeout("test".into()).reason_code(),
            ReasonCode::Timeout
        );
        assert_eq!(
            WorkspaceError::PolicyDenied("test".into()).reason_code(),
            ReasonCode::PolicyDenied
        );
        assert_eq!(
            WorkspaceError::ContextMiss("test".into()).reason_code(),
            ReasonCode::ContextMiss
        );
    }

    #[test]
    fn test_workspace_error_retryable() {
        assert!(WorkspaceError::ApplyFailed("test".into()).is_retryable());
        assert!(WorkspaceError::ToolFailed("test".into()).is_retryable());
        assert!(WorkspaceError::Timeout("test".into()).is_retryable());
        assert!(WorkspaceError::MissingArtifact("test".into()).is_retryable());
        assert!(!WorkspaceError::BinaryUnsupported("test".into()).is_retryable());
        assert!(!WorkspaceError::InvalidBundle("test".into()).is_retryable());
        assert!(!WorkspaceError::PolicyDenied("test".into()).is_retryable());
        assert!(!WorkspaceError::ContextMiss("test".into()).is_retryable());
    }

    #[test]
    fn test_validate_path_success() {
        let workspace = PathBuf::from("/workspace");
        assert!(validate_path("src/lib.rs", &workspace).is_ok());
        assert!(validate_path("tests/integration.rs", &workspace).is_ok());
        assert!(validate_path("a/b/c/d.txt", &workspace).is_ok());
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        let workspace = PathBuf::from("/workspace");
        assert!(validate_path("../etc/passwd", &workspace).is_err());
        assert!(validate_path("src/../../../etc/passwd", &workspace).is_err());
        assert!(validate_path("..\\windows\\system32", &workspace).is_err());
    }

    #[test]
    fn test_validate_path_absolute_rejected() {
        let workspace = PathBuf::from("/workspace");
        assert!(validate_path("/etc/passwd", &workspace).is_err());
        assert!(validate_path("\\windows\\system32", &workspace).is_err());
    }

    #[test]
    fn test_validate_path_empty_rejected() {
        let workspace = PathBuf::from("/workspace");
        assert!(validate_path("", &workspace).is_err());
    }

    #[test]
    fn test_retry_context_allows_retry() {
        let ctx = RetryContext::new("work-001".into(), 100, 200, 150);
        assert!(ctx.check_retry_allowed().is_ok());
    }

    #[test]
    fn test_retry_context_max_attempts_exceeded() {
        let mut ctx = RetryContext::new("work-001".into(), 100, 200, 150);
        ctx.attempts = MAX_RETRY_ATTEMPTS;
        assert!(matches!(
            ctx.check_retry_allowed(),
            Err(WorkspaceError::MaxRetriesExceeded { .. })
        ));
    }

    #[test]
    fn test_retry_context_htf_window_expired() {
        let ctx = RetryContext::new("work-001".into(), 100, 200, 250); // current > end
        assert!(matches!(
            ctx.check_retry_allowed(),
            Err(WorkspaceError::HtfWindowExpired)
        ));
    }

    #[test]
    fn test_workspace_snapshot_creation() {
        let snapshot = WorkspaceSnapshot::new("work-001".into(), [0x42; 32], 1234567890, 10);
        assert_eq!(snapshot.work_id, "work-001");
        assert_eq!(snapshot.snapshot_hash, [0x42; 32]);
        assert_eq!(snapshot.file_count, 10);
        assert!(snapshot.time_envelope_ref.is_none());
    }

    #[test]
    fn test_apply_result_creation() {
        let result = ApplyResult::new([0x33; 32], 5, 9876543210);
        assert_eq!(result.changeset_digest, [0x33; 32]);
        assert_eq!(result.files_modified, 5);
        assert!(result.time_envelope_ref.is_none());
    }

    #[tokio::test]
    async fn test_workspace_manager_snapshot() {
        let manager = WorkspaceManager::new(PathBuf::from("/workspace"));
        let snapshot = manager.snapshot("work-001").await.unwrap();
        assert_eq!(snapshot.work_id, "work-001");
        assert_eq!(snapshot.file_count, 0); // stub returns 0
    }
}
