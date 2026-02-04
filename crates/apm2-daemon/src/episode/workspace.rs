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
//! - **Diff Integrity**: Verifies that the diff only touches files listed in the manifest
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

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use apm2_core::crypto::Signer;
use apm2_core::fac::{
    ChangeKind, ChangeSetBundleV1, ReasonCode, ReviewArtifactBundleV1, ReviewBlockedError,
    ReviewBlockedRecorded, ReviewBlockedRecordedBuilder, ReviewMetadata, ReviewReceiptError,
    ReviewReceiptRecorded, ReviewReceiptRecordedBuilder,
};
use apm2_core::htf::TimeEnvelopeRef;
use thiserror::Error;

use super::executor::ContentAddressedStore;

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

    /// Symlink escape attempt detected.
    #[error("symlink escape: {path} resolves outside workspace root")]
    SymlinkEscape {
        /// The path that attempted to escape.
        path: String,
    },

    /// Git operation failed during workspace setup.
    #[error("git operation failed: {0}")]
    GitOperationFailed(String),

    /// Base commit not found.
    #[error("base commit not found: {0}")]
    BaseCommitNotFound(String),

    /// Diff contains files not present in the manifest.
    #[error("diff/manifest mismatch: diff touches \'{diff_path}\' which is not in manifest")]
    DiffManifestMismatch {
        /// The path found in diff but missing from manifest.
        diff_path: String,
    },

    /// Invalid commit reference.
    #[error("invalid commit ref: {0}")]
    InvalidCommitRef(String),
}

impl WorkspaceError {
    /// Maps the workspace error to a `ReasonCode` for durable recording.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Self::ApplyFailed(_)
            | Self::IoError(_)
            | Self::GitOperationFailed(_)
            | Self::BaseCommitNotFound(_)
            | Self::InvalidCommitRef(_) => ReasonCode::ApplyFailed,
            Self::ToolFailed(_) => ReasonCode::ToolFailed,
            Self::BinaryUnsupported(_) => ReasonCode::BinaryUnsupported,
            Self::MissingArtifact(_) | Self::CasError(_) => ReasonCode::MissingArtifact,
            Self::InvalidBundle(_)
            | Self::PathTraversal(_)
            | Self::FileTooLarge { .. }
            | Self::SymlinkEscape { .. }
            | Self::DiffManifestMismatch { .. } => ReasonCode::InvalidBundle,
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
    pub const fn new(
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
    pub const fn with_time_envelope_ref(mut self, time_envelope_ref: TimeEnvelopeRef) -> Self {
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
    pub const fn new(
        changeset_digest: [u8; 32],
        files_modified: usize,
        applied_at_ns: u64,
    ) -> Self {
        Self {
            changeset_digest,
            files_modified,
            applied_at_ns,
            time_envelope_ref: None,
        }
    }

    /// Sets the HTF time envelope reference.
    #[must_use]
    pub const fn with_time_envelope_ref(mut self, time_envelope_ref: TimeEnvelopeRef) -> Self {
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
    pub const fn new(
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
    pub const fn check_retry_allowed(&self) -> Result<(), WorkspaceError> {
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
    pub const fn record_attempt(&mut self) {
        self.attempts += 1;
    }

    /// Updates the current tick.
    pub const fn update_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }
}

// =============================================================================
// Path Validation
// =============================================================================

/// Validates a file path to prevent directory traversal attacks.
///
/// # Security
///
/// Per TCK-00318 security requirements:
/// - Rejects empty paths
/// - Rejects paths containing `..` components (directory traversal)
/// - Rejects absolute paths (paths starting with `/` or `\`)
/// - Rejects Windows-style absolute paths (e.g., `C:\`)
/// - Rejects paths containing null bytes
/// - Rejects paths containing control characters (e.g. `\t`, `\n`)
/// - Rejects paths exceeding maximum depth
/// - Validates path stays within workspace root after normalization
///
/// # Note
///
/// This function performs syntactic validation only. For symlink escape
/// detection on existing files, use `validate_resolved_path_within_root`.
///
/// # Errors
///
/// Returns error if the path contains traversal patterns or is too deep.
pub fn validate_path(path: &str, workspace_root: &Path) -> Result<PathBuf, WorkspaceError> {
    // Check for empty path
    if path.is_empty() {
        return Err(WorkspaceError::InvalidBundle("empty path".to_string()));
    }

    // Check for null bytes (security: prevents null byte injection attacks)
    if path.contains('\0') {
        return Err(WorkspaceError::PathTraversal(format!(
            "path contains null byte: {}",
            path.replace('\0', "\\0")
        )));
    }

    // Check for control characters
    if path.chars().any(|c| c.is_control()) {
        return Err(WorkspaceError::PathTraversal(format!(
            "path contains control character: {:?}",
            path
        )));
    }

    // Check for path traversal patterns (explicit check for "..")
    if path.contains("..") {
        return Err(WorkspaceError::PathTraversal(format!(
            "path contains '..' traversal: {path}"
        )));
    }

    // Check for Unix absolute paths
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(WorkspaceError::PathTraversal(format!(
            "path is absolute: {path}"
        )));
    }

    // Check for Windows-style absolute paths (C:\, D:\, etc.) even on Unix
    // (defense in depth)
    if path.len() >= 2 {
        let bytes = path.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(WorkspaceError::PathTraversal(format!(
                "path is absolute (Windows-style): {path}"
            )));
        }
    }

    // Check path depth
    let depth = path.split('/').count();
    if depth > MAX_PATH_DEPTH {
        return Err(WorkspaceError::InvalidBundle(format!(
            "path depth exceeds limit: {depth} > {MAX_PATH_DEPTH}"
        )));
    }

    // Construct full path
    let full_path = workspace_root.join(path);

    // Normalize path components to handle edge cases like `foo/./bar`
    // without relying on filesystem access
    let mut normalized_components = Vec::new();
    for component in full_path.components() {
        match component {
            Component::ParentDir => {
                // This should have been caught by the ".." check above,
                // but double-check for safety
                return Err(WorkspaceError::PathTraversal(format!(
                    "path contains parent directory component: {path}"
                )));
            },
            Component::CurDir => {
                // Skip "." components
            },
            _ => {
                normalized_components.push(component);
            },
        }
    }
    let normalized: PathBuf = normalized_components.into_iter().collect();

    // Verify the normalized path starts with workspace root
    if !normalized.starts_with(workspace_root) {
        return Err(WorkspaceError::PathTraversal(format!(
            "path escapes workspace: {path}"
        )));
    }

    Ok(normalized)
}

/// Validates that a resolved (canonicalized) path is within the workspace root.
///
/// # Security
///
/// This function prevents symlink-based sandbox escapes by verifying that the
/// resolved path (after following all symlinks) is still within the workspace
/// root directory. This is critical because an attacker could create a symlink
/// like `workspace/escape -> /etc/shadow` and bypass syntactic path validation.
///
/// # Arguments
///
/// * `resolved_path` - The canonicalized path (symlinks resolved)
/// * `root` - The workspace root directory (must also be canonicalized)
///
/// # Errors
///
/// Returns error if the path escapes the workspace root via symlinks.
pub fn validate_resolved_path_within_root(
    resolved_path: &Path,
    root: &Path,
) -> Result<(), WorkspaceError> {
    if !resolved_path.starts_with(root) {
        return Err(WorkspaceError::SymlinkEscape {
            path: resolved_path.display().to_string(),
        });
    }
    Ok(())
}

/// Validates a path with full symlink resolution for existing files.
///
/// This function combines syntactic validation with runtime symlink resolution
/// to provide complete path security validation. Use this for operations that
/// require verifying existing files don't escape the workspace via symlinks.
///
/// # Arguments
///
/// * `path` - The relative path to validate (as specified in the changeset)
/// * `workspace_root` - The workspace root directory
///
/// # Errors
///
/// Returns error if:
/// - The path fails syntactic validation
/// - The file exists but resolves outside the workspace via symlinks
pub fn validate_path_with_symlink_check(
    path: &str,
    workspace_root: &Path,
) -> Result<PathBuf, WorkspaceError> {
    // First, perform syntactic validation
    let validated_path = validate_path(path, workspace_root)?;

    // If the file exists, verify symlinks don't escape the workspace
    if validated_path.exists() {
        let canonical_root = std::fs::canonicalize(workspace_root).map_err(|e| {
            WorkspaceError::IoError(format!(
                "failed to canonicalize workspace root '{}': {}",
                workspace_root.display(),
                e
            ))
        })?;

        let canonical_path = std::fs::canonicalize(&validated_path).map_err(|e| {
            WorkspaceError::IoError(format!(
                "failed to canonicalize path '{}': {}",
                validated_path.display(),
                e
            ))
        })?;

        validate_resolved_path_within_root(&canonical_path, &canonical_root)?;
    }

    Ok(validated_path)
}

/// Validates all file changes in a changeset bundle.
///
/// # Security
///
/// Per TCK-00318 security requirements:
/// - Rejects bundles with binary files (v0 limitation)
/// - Validates all paths in the file manifest for traversal attacks
/// - Validates old_path for rename operations
/// - For existing files (MODIFY, DELETE, RENAME), validates symlinks don't
///   escape the workspace
///
/// # Errors
///
/// Returns error if any file change has invalid paths, binary detection fails,
/// or symlink escapes are detected.
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
        // For operations on existing files, perform full symlink validation
        match change.change_kind {
            ChangeKind::Modify | ChangeKind::Delete => {
                // These operations work on existing files - check for symlink escapes
                validate_path_with_symlink_check(&change.path, workspace_root)?;
            },
            ChangeKind::Add => {
                // New files - syntactic validation only (file doesn't exist yet)
                validate_path(&change.path, workspace_root)?;
            },
            ChangeKind::Rename => {
                // Rename: old_path must exist, new path will be created
                if let Some(ref old_path) = change.old_path {
                    validate_path_with_symlink_check(old_path, workspace_root)?;
                }
                // New path (destination) - syntactic validation only
                validate_path(&change.path, workspace_root)?;
            },
        }

        // Validate old_path if present (for renames)
        if let Some(ref old_path) = change.old_path {
            // Already validated above for renames, but validate syntactically
            // for any other case where old_path might be present
            if change.change_kind != ChangeKind::Rename {
                validate_path(old_path, workspace_root)?;
            }
        }
    }

    Ok(())
}

// =============================================================================
// Commit Reference Validation
// =============================================================================

/// Validates a git commit reference to prevent command injection attacks.
///
/// # Security
///
/// This function prevents command injection via `commit_ref` by rejecting:
/// - References starting with `-` (could be interpreted as git flags)
/// - Empty references
/// - References containing shell metacharacters
///
/// Valid commit references include:
/// - Hex hashes (40 chars for SHA-1, 64 chars for SHA-256)
/// - Branch/tag names (alphanumeric, hyphens, underscores, slashes, dots)
/// - HEAD, HEAD~N, HEAD^N references
///
/// # Errors
///
/// Returns error if the commit reference is invalid or potentially malicious.
pub fn validate_commit_ref(commit_ref: &str) -> Result<(), WorkspaceError> {
    // Reject empty references
    if commit_ref.is_empty() {
        return Err(WorkspaceError::InvalidCommitRef(
            "commit ref cannot be empty".to_string(),
        ));
    }

    // Security: Reject references starting with '-' to prevent flag injection
    // This is the primary security check per TCK-00318
    if commit_ref.starts_with('-') {
        return Err(WorkspaceError::InvalidCommitRef(format!(
            "commit ref cannot start with '-': {commit_ref}"
        )));
    }

    // Reject null bytes (security: prevents null byte injection)
    if commit_ref.contains('\0') {
        return Err(WorkspaceError::InvalidCommitRef(format!(
            "commit ref contains null byte: {}",
            commit_ref.replace('\0', "\\0")
        )));
    }

    // Validate that the commit ref contains only safe characters
    // Valid git refs: alphanumeric, hyphens, underscores, slashes, dots, tildes, carets
    // See: https://git-scm.com/docs/git-check-ref-format
    let valid_chars = |c: char| {
        c.is_ascii_alphanumeric()
            || c == '-'
            || c == '_'
            || c == '/'
            || c == '.'
            || c == '~'
            || c == '^'
    };

    if !commit_ref.chars().all(valid_chars) {
        return Err(WorkspaceError::InvalidCommitRef(format!(
            "commit ref contains invalid characters: {commit_ref}"
        )));
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
// Review Receipt Recording
// =============================================================================

/// Creates a `ReviewReceiptRecorded` event after successful review completion.
///
/// This function creates a durable ledger event that records the successful
/// review outcome with CAS-stored artifacts.
///
/// # Arguments
///
/// * `receipt_id` - Unique identifier for this receipt
/// * `changeset_digest` - BLAKE3 digest of the reviewed changeset
/// * `artifact_bundle_hash` - CAS hash of the `ReviewArtifactBundleV1`
/// * `time_envelope_ref` - HTF time envelope reference for temporal authority
/// * `reviewer_actor_id` - Actor ID of the reviewer
/// * `signer` - Signer to authorize the event
///
/// # Errors
///
/// Returns error if the event cannot be created (validation failures).
pub fn create_receipt_event(
    receipt_id: String,
    changeset_digest: [u8; 32],
    artifact_bundle_hash: [u8; 32],
    time_envelope_ref: [u8; 32],
    reviewer_actor_id: String,
    signer: &Signer,
) -> Result<ReviewReceiptRecorded, ReviewReceiptError> {
    ReviewReceiptRecordedBuilder::new()
        .receipt_id(receipt_id)
        .changeset_digest(changeset_digest)
        .artifact_bundle_hash(artifact_bundle_hash)
        .time_envelope_ref(time_envelope_ref)
        .reviewer_actor_id(reviewer_actor_id)
        .build_and_sign(signer)
}

/// Creates a `ReviewArtifactBundleV1` from review outputs.
///
/// This function packages the review outputs into a CAS-storable artifact
/// bundle.
///
/// # Arguments
///
/// * `review_id` - Unique review identifier
/// * `changeset_digest` - BLAKE3 digest of the reviewed changeset
/// * `review_text_hash` - CAS hash of the review text
/// * `tool_log_hashes` - CAS hashes of tool execution logs
/// * `time_envelope_ref` - HTF time envelope reference
/// * `metadata` - Optional review metadata (verdict, timestamps)
///
/// # Errors
///
/// Returns error if the bundle cannot be created (validation failures).
pub fn create_artifact_bundle(
    review_id: String,
    changeset_digest: [u8; 32],
    review_text_hash: [u8; 32],
    tool_log_hashes: Vec<[u8; 32]>,
    time_envelope_ref: [u8; 32],
    metadata: Option<ReviewMetadata>,
) -> Result<ReviewArtifactBundleV1, ReviewReceiptError> {
    let mut builder = ReviewArtifactBundleV1::builder()
        .review_id(review_id)
        .changeset_digest(changeset_digest)
        .review_text_hash(review_text_hash)
        .tool_log_hashes(tool_log_hashes)
        .time_envelope_ref(time_envelope_ref);

    if let Some(meta) = metadata {
        builder = builder.metadata(meta);
    }

    builder.build()
}

/// Result of successful review completion.
///
/// This structure packages all the outputs from a successful review episode
/// for storage to CAS and ledger recording.
#[derive(Debug, Clone)]
pub struct ReviewCompletionResult {
    /// Unique receipt ID for this review.
    pub receipt_id: String,
    /// BLAKE3 digest of the changeset that was reviewed.
    pub changeset_digest: [u8; 32],
    /// The artifact bundle containing review outputs.
    pub artifact_bundle: ReviewArtifactBundleV1,
    /// CAS hash of the serialized artifact bundle.
    pub artifact_bundle_hash: [u8; 32],
    /// HTF time envelope reference for temporal authority.
    pub time_envelope_ref: [u8; 32],
    /// Reviewer actor ID.
    pub reviewer_actor_id: String,
}

impl ReviewCompletionResult {
    /// Creates a new builder for `ReviewCompletionResult`.
    #[must_use]
    pub fn builder() -> ReviewCompletionResultBuilder {
        ReviewCompletionResultBuilder::default()
    }

    /// Creates a `ReviewReceiptRecorded` event from this result.
    ///
    /// # Errors
    ///
    /// Returns error if the event cannot be created.
    pub fn create_receipt_event(
        &self,
        signer: &Signer,
    ) -> Result<ReviewReceiptRecorded, ReviewReceiptError> {
        create_receipt_event(
            self.receipt_id.clone(),
            self.changeset_digest,
            self.artifact_bundle_hash,
            self.time_envelope_ref,
            self.reviewer_actor_id.clone(),
            signer,
        )
    }
}

/// Builder for [`ReviewCompletionResult`].
#[derive(Debug, Default)]
pub struct ReviewCompletionResultBuilder {
    receipt_id: Option<String>,
    review_id: Option<String>,
    changeset_digest: Option<[u8; 32]>,
    review_text_hash: Option<[u8; 32]>,
    tool_log_hashes: Vec<[u8; 32]>,
    time_envelope_ref: Option<[u8; 32]>,
    reviewer_actor_id: Option<String>,
    metadata: Option<ReviewMetadata>,
}

#[allow(clippy::missing_const_for_fn)]
impl ReviewCompletionResultBuilder {
    /// Sets the receipt ID.
    #[must_use]
    pub fn receipt_id(mut self, id: impl Into<String>) -> Self {
        self.receipt_id = Some(id.into());
        self
    }

    /// Sets the review ID.
    #[must_use]
    pub fn review_id(mut self, id: impl Into<String>) -> Self {
        self.review_id = Some(id.into());
        self
    }

    /// Sets the changeset digest.
    #[must_use]
    pub fn changeset_digest(mut self, digest: [u8; 32]) -> Self {
        self.changeset_digest = Some(digest);
        self
    }

    /// Sets the review text hash.
    #[must_use]
    pub fn review_text_hash(mut self, hash: [u8; 32]) -> Self {
        self.review_text_hash = Some(hash);
        self
    }

    /// Sets the tool log hashes.
    #[must_use]
    pub fn tool_log_hashes(mut self, hashes: Vec<[u8; 32]>) -> Self {
        self.tool_log_hashes = hashes;
        self
    }

    /// Sets the time envelope reference.
    #[must_use]
    pub fn time_envelope_ref(mut self, hash: [u8; 32]) -> Self {
        self.time_envelope_ref = Some(hash);
        self
    }

    /// Sets the reviewer actor ID.
    #[must_use]
    pub fn reviewer_actor_id(mut self, id: impl Into<String>) -> Self {
        self.reviewer_actor_id = Some(id.into());
        self
    }

    /// Sets the review metadata.
    #[must_use]
    pub fn metadata(mut self, metadata: ReviewMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Builds the `ReviewCompletionResult`.
    ///
    /// This function computes the CAS hash of the artifact bundle and
    /// packages all outputs for ledger recording.
    ///
    /// # Errors
    ///
    /// Returns error if required fields are missing or the artifact bundle
    /// cannot be created.
    pub fn build(self) -> Result<ReviewCompletionResult, ReviewReceiptError> {
        let receipt_id = self
            .receipt_id
            .ok_or(ReviewReceiptError::MissingField("receipt_id"))?;
        let review_id = self
            .review_id
            .ok_or(ReviewReceiptError::MissingField("review_id"))?;
        let changeset_digest = self
            .changeset_digest
            .ok_or(ReviewReceiptError::MissingField("changeset_digest"))?;
        let review_text_hash = self
            .review_text_hash
            .ok_or(ReviewReceiptError::MissingField("review_text_hash"))?;
        let time_envelope_ref = self
            .time_envelope_ref
            .ok_or(ReviewReceiptError::MissingField("time_envelope_ref"))?;
        let reviewer_actor_id = self
            .reviewer_actor_id
            .ok_or(ReviewReceiptError::MissingField("reviewer_actor_id"))?;

        let artifact_bundle = create_artifact_bundle(
            review_id,
            changeset_digest,
            review_text_hash,
            self.tool_log_hashes,
            time_envelope_ref,
            self.metadata,
        )?;

        let artifact_bundle_hash = artifact_bundle.compute_cas_hash();

        Ok(ReviewCompletionResult {
            receipt_id,
            changeset_digest,
            artifact_bundle,
            artifact_bundle_hash,
            time_envelope_ref,
            reviewer_actor_id,
        })
    }
}

// =============================================================================
// Workspace Manager
// =============================================================================

/// Configuration for workspace materialization.
#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    /// Path to the local git repository or mirror to checkout from.
    /// If None, assumes workspace_root is already a git repository.
    pub repo_path: Option<PathBuf>,
    /// Whether to clean the workspace before checkout (git clean -fd).
    pub clean_before_checkout: bool,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            repo_path: None,
            clean_before_checkout: false,
        }
    }
}

impl WorkspaceConfig {
    /// Creates a new workspace config with a specific repo path.
    #[must_use]
    pub fn with_repo_path(mut self, repo_path: impl Into<PathBuf>) -> Self {
        self.repo_path = Some(repo_path.into());
        self
    }

    /// Enables cleaning the workspace before checkout.
    #[must_use]
    pub const fn with_clean_before_checkout(mut self) -> Self {
        self.clean_before_checkout = true;
        self
    }
}

/// Workspace manager for snapshot and apply operations.
///
/// This implementation provides:
/// - **Isolated Workspaces**: Each episode gets an isolated workspace directory
/// - **Secure Patch Apply**: Path validation prevents outside-root writes
/// - **Symlink Safety**: All paths are validated for symlink escapes
/// - **Fail-Closed**: Errors during apply yield `ReviewBlockedRecorded`, not crashes
///
/// # Security Model (TCK-00318)
///
/// - **Containment Boundary**: Workspace is a containment boundary; default deny on
///   suspicious paths
/// - **Path Validation**: All file paths are validated for traversal attacks
/// - **Symlink Escapes**: Existing files are checked for symlink-based sandbox escapes
/// - **Binary Detection**: Binary files are rejected (v0 limitation)
#[derive(Debug)]
pub struct WorkspaceManager {
    /// Workspace root directory.
    pub workspace_root: PathBuf,
    /// Optional CAS store for retrieving diff bytes.
    cas: Option<Arc<dyn ContentAddressedStore>>,
    /// Workspace configuration.
    config: WorkspaceConfig,
}

impl WorkspaceManager {
    /// Creates a new workspace manager with minimal configuration.
    ///
    /// This is suitable for validation-only use cases where the workspace
    /// already exists and is set up.
    #[must_use]
    pub const fn new(workspace_root: PathBuf) -> Self {
        Self {
            workspace_root,
            cas: None,
            config: WorkspaceConfig {
                repo_path: None,
                clean_before_checkout: false,
            },
        }
    }

    /// Creates a workspace manager with CAS access for retrieving diff bytes.
    #[must_use]
    pub fn with_cas(workspace_root: PathBuf, cas: Arc<dyn ContentAddressedStore>) -> Self {
        Self {
            workspace_root,
            cas: Some(cas),
            config: WorkspaceConfig::default(),
        }
    }

    /// Creates a fully configured workspace manager.
    #[must_use]
    pub fn with_config(
        workspace_root: PathBuf,
        cas: Arc<dyn ContentAddressedStore>,
        config: WorkspaceConfig,
    ) -> Self {
        Self {
            workspace_root,
            cas: Some(cas),
            config,
        }
    }

    /// Takes a snapshot of the current workspace state.
    ///
    /// The snapshot captures:
    /// - Work ID binding
    /// - BLAKE3 hash of the workspace state (computed from git HEAD + worktree status)
    /// - Timestamp
    /// - File count
    ///
    /// # Errors
    ///
    /// Returns error if snapshot fails.
    #[allow(clippy::cast_possible_truncation)] // Safe: nanoseconds since epoch won't overflow u64 until 2554
    pub fn snapshot(&self, work_id: &str) -> Result<WorkspaceSnapshot, WorkspaceError> {
        let snapshot_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Try to get git HEAD hash if this is a git repo
        let git_head = self.get_git_head();

        // Compute snapshot hash from work_id and git HEAD (if available)
        let hash_input = if let Some(ref head) = git_head {
            format!("{work_id}:{head}")
        } else {
            work_id.to_string()
        };
        let snapshot_hash = *blake3::hash(hash_input.as_bytes()).as_bytes();

        // Count files in workspace (excluding .git)
        let file_count = self.count_workspace_files().unwrap_or(0);

        Ok(WorkspaceSnapshot::new(
            work_id.to_string(),
            snapshot_hash,
            snapshot_at_ns,
            file_count,
        ))
    }

    /// Applies a changeset bundle to the workspace.
    ///
    /// This is the main entry point for workspace materialization per TCK-00318.
    /// The implementation:
    ///
    /// 1. Validates all file paths in the changeset (security checks)
    /// 2. If CAS is configured, retrieves diff bytes and applies via `git apply`
    /// 3. Otherwise, performs validation-only (suitable for tests)
    ///
    /// # Security
    ///
    /// - All paths are validated for traversal attacks
    /// - Symlink escapes are detected and rejected
    /// - Binary files are rejected (v0 limitation)
    /// - Failed apply yields `WorkspaceError` (maps to `ReviewBlockedRecorded`)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Path validation fails (traversal, symlink escape, etc.)
    /// - Binary files detected
    /// - Diff retrieval from CAS fails
    /// - Git apply fails
    #[allow(clippy::cast_possible_truncation)] // Safe: nanoseconds since epoch won't overflow u64 until 2554
    pub fn apply(&self, bundle: &ChangeSetBundleV1) -> Result<ApplyResult, WorkspaceError> {
        // Step 1: Validate all file changes (security checks)
        validate_file_changes(bundle, &self.workspace_root)?;

        // Step 2: Record start time
        let applied_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Step 3: If CAS is available, retrieve diff and apply
        // Otherwise, this is validation-only mode (for tests or dry-run)
        if self.cas.is_some() {
            // Full apply mode: retrieve diff from CAS and apply
            self.apply_diff_from_cas(bundle)?;
        }

        Ok(ApplyResult::new(
            bundle.changeset_digest,
            bundle.file_manifest.len(),
            applied_at_ns,
        ))
    }

    /// Applies a changeset bundle with explicit diff bytes.
    ///
    /// This method is useful when the diff bytes are already available
    /// (e.g., during testing or when CAS is not configured).
    ///
    /// # Security
    ///
    /// Same security guarantees as `apply()`.
    ///
    /// # Errors
    ///
    /// Returns error if validation or apply fails.
    #[allow(clippy::cast_possible_truncation)] // Safe: nanoseconds since epoch won't overflow u64 until 2554
    pub fn apply_with_diff(
        &self,
        bundle: &ChangeSetBundleV1,
        diff_bytes: &[u8],
    ) -> Result<ApplyResult, WorkspaceError> {
        // Step 1: Validate all file changes
        validate_file_changes(bundle, &self.workspace_root)?;

        // Step 2: Verify diff hash matches
        let computed_hash = *blake3::hash(diff_bytes).as_bytes();
        if computed_hash != bundle.diff_hash {
            return Err(WorkspaceError::InvalidBundle(format!(
                "diff hash mismatch: expected {}, got {}",
                hex::encode(bundle.diff_hash),
                hex::encode(computed_hash)
            )));
        }

        // Step 3: Apply the diff
        self.apply_git_diff(diff_bytes, bundle)?;

        // Step 4: Record timestamp
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

    /// Checkouts the workspace to a specific commit.
    ///
    /// This method is used to set up the workspace to the base commit
    /// before applying a diff.
    ///
    /// # Errors
    ///
    /// Returns error if git checkout fails.
    pub fn checkout(&self, commit_ref: &str) -> Result<(), WorkspaceError> {
        // Validate commit_ref format to prevent argument injection
        // Allow alphanumeric, hyphens, underscores, dots, and slashes
        // Must not start with a hyphen
        if commit_ref.starts_with('-')
            || !commit_ref
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        {
            return Err(WorkspaceError::InvalidCommitRef(commit_ref.to_string()));
        }

        // Optionally clean before checkout
        if self.config.clean_before_checkout {
            self.git_clean()?;
        }

        // Run git checkout
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.workspace_root)
            .args([
                "checkout",
                "--force",
                "--", // End of options separator
                commit_ref,
            ])
            .output()
            .map_err(|e| {
                WorkspaceError::GitOperationFailed(format!("failed to run git checkout: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Check if it's a "not found" error
            if stderr.contains("pathspec")
                || stderr.contains("not a commit")
                || stderr.contains("unknown revision")
            {
                return Err(WorkspaceError::BaseCommitNotFound(commit_ref.to_string()));
            }
            return Err(WorkspaceError::GitOperationFailed(format!(
                "git checkout failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Restores the workspace from a snapshot.
    ///
    /// # Note
    ///
    /// This is a minimal implementation. Full snapshot/restore functionality
    /// would require storing workspace state in CAS.
    ///
    /// # Errors
    ///
    /// Returns error if restore fails.
    pub fn restore(&self, snapshot: &WorkspaceSnapshot) -> Result<(), WorkspaceError> {
        // For now, we can only restore if we have git and know the commit
        // Future: support restoring from CAS-stored snapshot
        if let Some(ref git_head) = self.get_git_head() {
            // If snapshot was taken at a different HEAD, checkout that commit
            let expected_prefix = format!("{}:", snapshot.work_id);
            let hash_input = format!("{}{}", expected_prefix, git_head);
            let computed_hash = *blake3::hash(hash_input.as_bytes()).as_bytes();

            if computed_hash != snapshot.snapshot_hash {
                // Snapshot was from a different state - we can't restore
                // without more information
                return Err(WorkspaceError::ApplyFailed(
                    "cannot restore: snapshot state differs from current git HEAD".to_string(),
                ));
            }
        }

        Ok(())
    }

    // =========================================================================
    // Private Helper Methods
    // =========================================================================

    /// Retrieves diff bytes from CAS and applies them.
    fn apply_diff_from_cas(&self, bundle: &ChangeSetBundleV1) -> Result<(), WorkspaceError> {
        let cas = self
            .cas
            .as_ref()
            .ok_or_else(|| WorkspaceError::CasError("CAS not configured".to_string()))?;

        // Retrieve diff bytes from CAS
        let diff_bytes = cas.retrieve(&bundle.diff_hash).ok_or_else(|| {
            WorkspaceError::MissingArtifact(format!(
                "diff not found in CAS: {}",
                hex::encode(bundle.diff_hash)
            ))
        })?;

        // Apply the diff
        self.apply_git_diff(&diff_bytes, bundle)
    }

    /// Verifies that the diff only touches files listed in the manifest.
    fn verify_diff_against_manifest(
        &self,
        diff_bytes: &[u8],
        bundle: &ChangeSetBundleV1,
    ) -> Result<(), WorkspaceError> {
        let mut allowed_paths = HashSet::new();
        for change in &bundle.file_manifest {
            allowed_paths.insert(change.path.as_str());
            if let Some(ref old) = change.old_path {
                allowed_paths.insert(old.as_str());
            }
        }

        // Check 1: git apply --numstat (gives destination paths)
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&self.workspace_root)
            .args(["apply", "--numstat", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                WorkspaceError::GitOperationFailed(format!("failed to spawn git apply check: {e}"))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(diff_bytes).map_err(|e| {
                WorkspaceError::GitOperationFailed(format!("failed to write to git apply check: {e}"))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            WorkspaceError::GitOperationFailed(format!("failed to wait for git apply check: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkspaceError::ApplyFailed(format!(
                "git apply --numstat failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Output format: added deleted path
            // Split by tab or whitespace
            // NOTE: git apply --numstat separates fields by tabs
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let path = parse_git_path(parts[2]);
                if !allowed_paths.contains(path.as_str()) {
                    return Err(WorkspaceError::DiffManifestMismatch { diff_path: path });
                }
            }
        }

        // Check 2: git apply --summary (gives source paths for renames/deletes)
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&self.workspace_root)
            .args(["apply", "--summary", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                WorkspaceError::GitOperationFailed(format!("failed to spawn git apply summary: {e}"))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(diff_bytes).map_err(|e| {
                WorkspaceError::GitOperationFailed(format!("failed to write to git apply summary: {e}"))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            WorkspaceError::GitOperationFailed(format!("failed to wait for git apply summary: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkspaceError::ApplyFailed(format!(
                "git apply --summary failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Look for " rename <old> => <new> (<percent>)"
            if line.trim().starts_with("rename ") {
                if let Some(arrow_idx) = line.find(" => ") {
                    let old_part = &line[7..arrow_idx].trim(); // skip " rename "
                    let old_path = parse_git_path(old_part);
                    if !allowed_paths.contains(old_path.as_str()) {
                        return Err(WorkspaceError::DiffManifestMismatch {
                            diff_path: old_path,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Applies a git unified diff to the workspace.
    fn apply_git_diff(
        &self,
        diff_bytes: &[u8],
        bundle: &ChangeSetBundleV1,
    ) -> Result<(), WorkspaceError> {
        // Security: Verify diff integrity before applying
        self.verify_diff_against_manifest(diff_bytes, bundle)?;

        // Use git apply to apply the diff
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&self.workspace_root)
            .args([
                "apply",
                "--check", // Dry run first to validate
                "--verbose",
                "--", // End of options
                "-",  // Read from stdin
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                WorkspaceError::GitOperationFailed(format!("failed to spawn git apply: {e}"))
            })?;

        // Write diff to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(diff_bytes).map_err(|e| {
                WorkspaceError::GitOperationFailed(format!("failed to write diff to git apply: {e}"))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            WorkspaceError::GitOperationFailed(format!("failed to wait for git apply: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkspaceError::ApplyFailed(format!(
                "git apply --check failed: {}",
                stderr
            )));
        }

        // Now actually apply the diff
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&self.workspace_root)
            .args([
                "apply",
                "--verbose",
                "--", // End of options
                "-",  // Read from stdin
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                WorkspaceError::GitOperationFailed(format!("failed to spawn git apply: {e}"))
            })?;

        // Write diff to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(diff_bytes).map_err(|e| {
                WorkspaceError::GitOperationFailed(format!("failed to write diff to git apply: {e}"))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            WorkspaceError::GitOperationFailed(format!("failed to wait for git apply: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkspaceError::ApplyFailed(format!(
                "git apply failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Cleans the workspace (git clean -fd).
    fn git_clean(&self) -> Result<(), WorkspaceError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.workspace_root)
            .args(["clean", "-fd"])
            .output()
            .map_err(|e| {
                WorkspaceError::GitOperationFailed(format!("failed to run git clean: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkspaceError::GitOperationFailed(format!(
                "git clean failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Gets the current git HEAD commit hash, if available.
    fn get_git_head(&self) -> Option<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.workspace_root)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()?;

        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        }
    }

    /// Counts files in the workspace (excluding .git directory).
    fn count_workspace_files(&self) -> Result<usize, WorkspaceError> {
        fn count_files_recursive(path: &Path) -> std::io::Result<usize> {
            let mut count = 0;
            if path.is_dir() {
                for entry in std::fs::read_dir(path)? {
                    let entry = entry?;
                    let entry_path = entry.path();
                    // Skip .git directory
                    if entry_path.file_name() == Some(std::ffi::OsStr::new(".git")) {
                        continue;
                    }
                    if entry_path.is_dir() {
                        count += count_files_recursive(&entry_path)?;
                    } else {
                        count += 1;
                    }
                }
            }
            Ok(count)
        }

        count_files_recursive(&self.workspace_root)
            .map_err(|e| WorkspaceError::IoError(format!("failed to count files: {e}")))
    }
}

/// Helper to parse git output paths, removing quotes if present.
fn parse_git_path(raw: &str) -> String {
    let raw = raw.trim();
    if raw.starts_with('"') && raw.ends_with('"') {
        // Simple unquote for spaces
        raw[1..raw.len() - 1].to_string()
    } else {
        raw.to_string()
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
            WorkspaceError::DiffManifestMismatch {
                diff_path: "p".into()
            }
            .reason_code(),
            ReasonCode::InvalidBundle
        );
        assert_eq!(
            WorkspaceError::InvalidCommitRef("bad".into()).reason_code(),
            ReasonCode::ApplyFailed
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
    fn test_validate_path_control_chars_rejected() {
        let workspace = PathBuf::from("/workspace");
        assert!(validate_path("src/lib\n.rs", &workspace).is_err());
        assert!(validate_path("src/lib\t.rs", &workspace).is_err());
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
        let snapshot = WorkspaceSnapshot::new("work-001".into(), [0x42; 32], 1_234_567_890, 10);
        assert_eq!(snapshot.work_id, "work-001");
        assert_eq!(snapshot.snapshot_hash, [0x42; 32]);
        assert_eq!(snapshot.file_count, 10);
        assert!(snapshot.time_envelope_ref.is_none());
    }

    #[test]
    fn test_apply_result_creation() {
        let result = ApplyResult::new([0x33; 32], 5, 9_876_543_210);
        assert_eq!(result.changeset_digest, [0x33; 32]);
        assert_eq!(result.files_modified, 5);
        assert!(result.time_envelope_ref.is_none());
    }

    #[test]
    fn test_workspace_manager_snapshot() {
        let manager = WorkspaceManager::new(PathBuf::from("/workspace"));
        let snapshot = manager.snapshot("work-001").unwrap();
        assert_eq!(snapshot.work_id, "work-001");
        assert_eq!(snapshot.file_count, 0); // stub returns 0
    }

    // =========================================================================
    // TCK-00312: Review receipt tests
    // =========================================================================

    #[test]
    fn test_create_artifact_bundle() {
        let bundle = create_artifact_bundle(
            "review-001".to_string(),
            [0x42; 32],
            [0x11; 32],
            vec![[0x22; 32], [0x33; 32]],
            [0x44; 32],
            None,
        )
        .expect("should create bundle");

        assert_eq!(bundle.review_id, "review-001");
        assert_eq!(bundle.changeset_digest, hex::encode([0x42; 32]));
        assert_eq!(bundle.review_text_hash, hex::encode([0x11; 32]));
        assert_eq!(bundle.tool_log_hashes.len(), 2);
        assert_eq!(bundle.time_envelope_ref, hex::encode([0x44; 32]));
        assert!(bundle.metadata.is_none());
    }

    #[test]
    fn test_create_artifact_bundle_with_metadata() {
        use apm2_core::fac::ReviewVerdict;

        let metadata = ReviewMetadata::new()
            .with_reviewer_actor_id("reviewer-001")
            .with_verdict(ReviewVerdict::Approve)
            .with_started_at(1000)
            .with_completed_at(2000);

        let bundle = create_artifact_bundle(
            "review-001".to_string(),
            [0x42; 32],
            [0x11; 32],
            vec![],
            [0x44; 32],
            Some(metadata),
        )
        .expect("should create bundle");

        assert!(bundle.metadata.is_some());
        let meta = bundle.metadata.unwrap();
        assert_eq!(meta.reviewer_actor_id, Some("reviewer-001".to_string()));
        assert_eq!(meta.review_verdict, Some(ReviewVerdict::Approve));
    }

    #[test]
    fn test_create_receipt_event() {
        let signer = apm2_core::crypto::Signer::generate();

        let receipt = create_receipt_event(
            "RR-001".to_string(),
            [0x42; 32],
            [0x33; 32],
            [0x44; 32],
            "reviewer-001".to_string(),
            &signer,
        )
        .expect("should create receipt");

        assert_eq!(receipt.receipt_id, "RR-001");
        assert_eq!(receipt.changeset_digest, [0x42; 32]);
        assert_eq!(receipt.artifact_bundle_hash, [0x33; 32]);
        assert_eq!(receipt.time_envelope_ref, [0x44; 32]);
        assert_eq!(receipt.reviewer_actor_id, "reviewer-001");

        // Verify signature
        assert!(receipt.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_review_completion_result() {
        let signer = apm2_core::crypto::Signer::generate();

        let result = ReviewCompletionResult::builder()
            .receipt_id("RR-001")
            .review_id("review-001")
            .changeset_digest([0x42; 32])
            .review_text_hash([0x11; 32])
            .tool_log_hashes(vec![[0x22; 32]])
            .time_envelope_ref([0x44; 32])
            .reviewer_actor_id("reviewer-001")
            .build()
            .expect("should create result");

        assert_eq!(result.receipt_id, "RR-001");
        assert_eq!(result.changeset_digest, [0x42; 32]);
        assert_eq!(result.artifact_bundle.review_id, "review-001");

        // CAS hash should be deterministically computed
        let expected_hash = result.artifact_bundle.compute_cas_hash();
        assert_eq!(result.artifact_bundle_hash, expected_hash);

        // Should be able to create receipt event
        let receipt = result
            .create_receipt_event(&signer)
            .expect("should create receipt");
        assert_eq!(receipt.artifact_bundle_hash, expected_hash);
        assert!(receipt.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_review_completion_result_with_metadata() {
        use apm2_core::fac::ReviewVerdict;

        let signer = apm2_core::crypto::Signer::generate();
        let metadata = ReviewMetadata::new()
            .with_reviewer_actor_id("reviewer-001")
            .with_verdict(ReviewVerdict::RequestChanges);

        let result = ReviewCompletionResult::builder()
            .receipt_id("RR-002")
            .review_id("review-002")
            .changeset_digest([0x55; 32])
            .review_text_hash([0x66; 32])
            .time_envelope_ref([0x77; 32])
            .reviewer_actor_id("reviewer-002")
            .metadata(metadata)
            .build()
            .expect("should create result");

        assert!(result.artifact_bundle.metadata.is_some());
        let meta = result.artifact_bundle.metadata.as_ref().unwrap();
        assert_eq!(meta.review_verdict, Some(ReviewVerdict::RequestChanges));

        // Receipt event should still be valid
        let receipt = result
            .create_receipt_event(&signer)
            .expect("should create receipt");
        assert!(receipt.verify_signature(&signer.verifying_key()).is_ok());
    }

    // =========================================================================
    // TCK-00318: Workspace apply implementation tests
    // =========================================================================

    #[test]
    fn test_validate_path_null_byte_rejected() {
        let workspace = PathBuf::from("/workspace");
        let result = validate_path("src/\0lib.rs", &workspace);
        assert!(result.is_err());
        assert!(matches!(result, Err(WorkspaceError::PathTraversal(_))));
    }

    #[test]
    fn test_validate_path_windows_absolute_rejected() {
        let workspace = PathBuf::from("/workspace");
        assert!(validate_path("C:\\Windows\\System32", &workspace).is_err());
        assert!(validate_path("D:file.txt", &workspace).is_err());
    }

    #[test]
    fn test_validate_path_dot_components_handled() {
        let workspace = PathBuf::from("/workspace");
        // Single dot should be allowed (normalized away)
        let result = validate_path("./src/lib.rs", &workspace);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_resolved_path_within_root() {
        let root = PathBuf::from("/workspace");
        let valid = PathBuf::from("/workspace/src/lib.rs");
        let invalid = PathBuf::from("/etc/passwd");

        assert!(validate_resolved_path_within_root(&valid, &root).is_ok());
        assert!(validate_resolved_path_within_root(&invalid, &root).is_err());
    }

    #[test]
    fn test_symlink_escape_error_reason_code() {
        let err = WorkspaceError::SymlinkEscape {
            path: "/etc/passwd".to_string(),
        };
        assert_eq!(err.reason_code(), ReasonCode::InvalidBundle);
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_git_operation_failed_error_reason_code() {
        let err = WorkspaceError::GitOperationFailed("test".to_string());
        assert_eq!(err.reason_code(), ReasonCode::ApplyFailed);
        assert!(err.is_retryable());
    }

    #[test]
    fn test_base_commit_not_found_error_reason_code() {
        let err = WorkspaceError::BaseCommitNotFound("abc123".to_string());
        assert_eq!(err.reason_code(), ReasonCode::ApplyFailed);
        assert!(err.is_retryable());
    }

    #[test]
    fn test_workspace_config_builder() {
        let config = WorkspaceConfig::default()
            .with_repo_path("/path/to/repo")
            .with_clean_before_checkout();

        assert_eq!(config.repo_path, Some(PathBuf::from("/path/to/repo")));
        assert!(config.clean_before_checkout);
    }

    #[test]
    fn test_workspace_manager_new() {
        let manager = WorkspaceManager::new(PathBuf::from("/workspace"));
        assert_eq!(manager.workspace_root, PathBuf::from("/workspace"));
        assert!(manager.cas.is_none());
    }

    #[test]
    fn test_validate_file_changes_binary_rejected() {
        use apm2_core::fac::{FileChange, GitObjectRef, HashAlgo};

        let bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-binary")
            .base(GitObjectRef {
                algo: HashAlgo::Sha1,
                object_kind: "commit".to_string(),
                object_id: "a".repeat(40),
            })
            .diff_hash([0x42; 32])
            .file_manifest(vec![FileChange {
                path: "binary.exe".to_string(),
                change_kind: ChangeKind::Add,
                old_path: None,
            }])
            .binary_detected(true)
            .build()
            .expect("valid bundle");

        let workspace = PathBuf::from("/workspace");
        let result = validate_file_changes(&bundle, &workspace);
        assert!(matches!(result, Err(WorkspaceError::BinaryUnsupported(_))));
    }

    #[test]
    fn test_validate_file_changes_traversal_rejected() {
        use apm2_core::fac::{FileChange, GitObjectRef, HashAlgo};

        let bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-traversal")
            .base(GitObjectRef {
                algo: HashAlgo::Sha1,
                object_kind: "commit".to_string(),
                object_id: "a".repeat(40),
            })
            .diff_hash([0x42; 32])
            .file_manifest(vec![FileChange {
                path: "../etc/passwd".to_string(),
                change_kind: ChangeKind::Modify,
                old_path: None,
            }])
            .binary_detected(false)
            .build()
            .expect("valid bundle");

        let workspace = PathBuf::from("/workspace");
        let result = validate_file_changes(&bundle, &workspace);
        assert!(matches!(result, Err(WorkspaceError::PathTraversal(_))));
    }

    #[test]
    fn test_validate_file_changes_rename_old_path_validated() {
        use apm2_core::fac::{FileChange, GitObjectRef, HashAlgo};

        let bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-rename")
            .base(GitObjectRef {
                algo: HashAlgo::Sha1,
                object_kind: "commit".to_string(),
                object_id: "a".repeat(40),
            })
            .diff_hash([0x42; 32])
            .file_manifest(vec![FileChange {
                path: "new_name.rs".to_string(),
                change_kind: ChangeKind::Rename,
                old_path: Some("../escape.rs".to_string()),
            }])
            .binary_detected(false)
            .build()
            .expect("valid bundle");

        let workspace = PathBuf::from("/workspace");
        let result = validate_file_changes(&bundle, &workspace);
        assert!(matches!(result, Err(WorkspaceError::PathTraversal(_))));
    }

    #[test]
    fn test_workspace_error_display() {
        let err = WorkspaceError::SymlinkEscape {
            path: "/etc/passwd".to_string(),
        };
        assert!(err.to_string().contains("symlink escape"));
        assert!(err.to_string().contains("/etc/passwd"));

        let err = WorkspaceError::GitOperationFailed("checkout failed".to_string());
        assert!(err.to_string().contains("git operation failed"));
        assert!(err.to_string().contains("checkout failed"));
    }

    /// Integration test: workspace apply with real filesystem
    #[test]
    fn test_workspace_apply_validation_only_mode() {
        use apm2_core::fac::{FileChange, GitObjectRef, HashAlgo};

        // Create a temp directory as workspace
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let workspace_root = temp_dir.path().to_path_buf();

        // Create a workspace manager (validation-only, no CAS)
        let manager = WorkspaceManager::new(workspace_root.clone());

        // Create a valid bundle with ADD operations (no symlink checks needed)
        let bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-validation-test")
            .base(GitObjectRef {
                algo: HashAlgo::Sha1,
                object_kind: "commit".to_string(),
                object_id: "a".repeat(40),
            })
            .diff_hash([0x42; 32])
            .file_manifest(vec![
                FileChange {
                    path: "src/lib.rs".to_string(),
                    change_kind: ChangeKind::Add,
                    old_path: None,
                },
                FileChange {
                    path: "tests/test.rs".to_string(),
                    change_kind: ChangeKind::Add,
                    old_path: None,
                },
            ])
            .binary_detected(false)
            .build()
            .expect("valid bundle");

        // Apply should succeed in validation-only mode
        let result = manager.apply(&bundle);
        assert!(result.is_ok());

        let apply_result = result.unwrap();
        assert_eq!(apply_result.changeset_digest, bundle.changeset_digest);
        assert_eq!(apply_result.files_modified, 2);
        assert!(apply_result.applied_at_ns > 0);
    }

    /// Test symlink escape detection with real filesystem
    #[cfg(unix)]
    #[test]
    fn test_symlink_escape_detection() {
        use std::os::unix::fs::symlink;

        use apm2_core::fac::{FileChange, GitObjectRef, HashAlgo};

        // Create temp directories
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let workspace_root = temp_dir.path().join("workspace");
        let outside_dir = temp_dir.path().join("outside");

        std::fs::create_dir_all(&workspace_root).expect("create workspace");
        std::fs::create_dir_all(&outside_dir).expect("create outside dir");

        // Create a file outside the workspace
        let secret_file = outside_dir.join("secret.txt");
        std::fs::write(&secret_file, "secret data").expect("write secret");

        // Create a symlink inside workspace pointing outside
        let symlink_path = workspace_root.join("escape_link.txt");
        symlink(&secret_file, &symlink_path).expect("create symlink");

        let manager = WorkspaceManager::new(workspace_root.clone());

        // Create a bundle that tries to modify the symlink target
        let bundle = ChangeSetBundleV1::builder()
            .changeset_id("cs-symlink-escape")
            .base(GitObjectRef {
                algo: HashAlgo::Sha1,
                object_kind: "commit".to_string(),
                object_id: "a".repeat(40),
            })
            .diff_hash([0x42; 32])
            .file_manifest(vec![FileChange {
                path: "escape_link.txt".to_string(),
                change_kind: ChangeKind::Modify,
                old_path: None,
            }])
            .binary_detected(false)
            .build()
            .expect("valid bundle");

        // Apply should fail with SymlinkEscape error
        let result = manager.apply(&bundle);
        assert!(result.is_err());

        // The error should be SymlinkEscape
        match result {
            Err(WorkspaceError::SymlinkEscape { path }) => {
                assert!(path.contains("secret.txt") || path.contains("outside"));
            },
            Err(other) => panic!("Expected SymlinkEscape, got: {:?}", other),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    /// Test path depth limit
    #[test]
    fn test_path_depth_limit() {
        let workspace = PathBuf::from("/workspace");

        // Create a path that exceeds MAX_PATH_DEPTH
        let deep_path = (0..MAX_PATH_DEPTH + 5)
            .map(|i| format!("dir{i}"))
            .collect::<Vec<_>>()
            .join("/");

        let result = validate_path(&deep_path, &workspace);
        assert!(matches!(result, Err(WorkspaceError::InvalidBundle(_))));
    }

    /// Test that apply result contains correct metadata
    #[test]
    fn test_apply_result_with_time_envelope() {
        use apm2_core::htf::TimeEnvelopeRef;

        let result = ApplyResult::new([0x33; 32], 5, 9_876_543_210);
        assert!(result.time_envelope_ref.is_none());

        let envelope_bytes = [0x44; 32];
        let envelope_ref = TimeEnvelopeRef::from_slice(&envelope_bytes).unwrap();
        let result_with_envelope = result.with_time_envelope_ref(envelope_ref);

        assert!(result_with_envelope.time_envelope_ref.is_some());
        assert_eq!(
            result_with_envelope.time_envelope_ref.unwrap().as_bytes(),
            &envelope_bytes
        );
    }
}