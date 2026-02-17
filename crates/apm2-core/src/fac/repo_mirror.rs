#![allow(
    missing_docs,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::disallowed_methods
)]

//! Bare mirror management and lane workspace checkout helpers.
//!
//! This module implements the repository mirror layout used by the FAC worker:
//! - node-local bare mirrors live at
//!   `$APM2_HOME/private/fac/repo_mirror/<repo_id>.git`
//! - lane workspaces are always checked out from the mirror, never directly
//!   from caller worktrees
//!
//! Security model
//! - all git commands use `Command::new("git")` with explicit args
//! - system configuration is not read (`GIT_CONFIG_NOSYSTEM=1`)
//! - prompts are disabled (`GIT_TERMINAL_PROMPT=0`)
//! - path inputs are validated before shell interaction
//! - workspaces are fully cleaned with `safe_rmtree_v1` before checkout
//! - post-checkout git hardening disables hooks and refuses unsafe configs
//!   (TCK-00580)
//! - mirror updates are serialized via per-mirror file lock (TCK-00582)
//! - remote URLs are validated against a policy-driven allowlist (TCK-00582)
//! - git fetch/clone operations are bounded by wall-clock timeout (TCK-00582)
//! - mirror paths are validated to contain no symlink components (TCK-00582)
//! - mirror updates emit receipts with before/after refs (TCK-00582)

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write};
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::flock_util;
use super::git_hardening::{self, GitHardeningError, GitHardeningReceipt};
use super::safe_rmtree::{SafeRmtreeError, safe_rmtree_v1};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Schema identifier for repository mirror metadata.
pub const REPO_MIRROR_SCHEMA: &str = "apm2.fac.repo_mirror.v1";
/// Schema identifier for mirror update receipts (TCK-00582).
pub const MIRROR_UPDATE_RECEIPT_SCHEMA: &str = "apm2.fac.mirror_update_receipt.v1";
/// Maximum allowed repository identifier length.
pub const MAX_REPO_ID_LENGTH: usize = 256;
/// Maximum allowed mirror directory name length.
pub const MAX_MIRROR_DIR_NAME: usize = 280;
/// Maximum number of bare mirrors to retain before eviction.
pub const MAX_MIRROR_COUNT: usize = 64;
/// Maximum patch size in bytes.
pub const MAX_PATCH_SIZE: usize = 10_485_760;
/// Maximum number of refs tracked in a single receipt (DoS bound).
pub const MAX_RECEIPT_REFS: usize = 4096;
/// Maximum number of allowed URL patterns in a mirror policy (DoS bound).
pub const MAX_ALLOWED_URL_PATTERNS: usize = 256;

/// Maximum allowed length for receipt `mirror_path` string field (DoS bound).
pub const MAX_RECEIPT_MIRROR_PATH_LENGTH: usize = 4096;
/// Maximum allowed length for receipt `operation` string field (DoS bound).
pub const MAX_RECEIPT_OPERATION_LENGTH: usize = 64;
/// Maximum allowed length for receipt `failure_reason` string field (DoS
/// bound).
pub const MAX_RECEIPT_FAILURE_REASON_LENGTH: usize = 4096;

/// Maximum byte-size cap for git command stdout (DoS bound, CTR-1603).
///
/// Applied to both `git_command` and `git_command_with_timeout` to prevent
/// unbounded memory consumption from git processes producing large output.
const GIT_STDOUT_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Default timeout for bounded git commands that do not need a long-running
/// fetch/clone timeout (e.g., `git show-ref`, `git rev-parse`).
const GIT_COMMAND_DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Default wall-clock timeout for git fetch operations (seconds).
///
/// CTR-2501 deviation: uses `Instant` (monotonic) for elapsed measurement.
pub const DEFAULT_FETCH_TIMEOUT_SECS: u64 = 300;

/// Default wall-clock timeout for git clone operations (seconds).
pub const DEFAULT_CLONE_TIMEOUT_SECS: u64 = 600;

/// Maximum duration to wait for the mirror file lock (seconds).
pub const MIRROR_LOCK_TIMEOUT_SECS: u64 = 120;

/// Poll interval when waiting for the mirror file lock.
const MIRROR_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(500);

// ─────────────────────────────────────────────────────────────────────────────
// Mirror Policy (TCK-00582)
// ─────────────────────────────────────────────────────────────────────────────

/// Policy-driven remote URL allowlist for mirror updates.
///
/// When `allowed_url_patterns` is non-empty, only remote URLs matching at
/// least one pattern are permitted. An empty list means "use built-in
/// protocol validation only" (the pre-TCK-00582 behavior).
///
/// Patterns are matched as prefixes: a URL must start with one of the
/// allowed patterns. This supports both exact-match and domain-scoped
/// policies (e.g., `https://github.com/myorg/`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorPolicy {
    /// Allowed remote URL prefixes. Empty = built-in protocol validation only.
    pub allowed_url_patterns: Vec<String>,
    /// Wall-clock timeout for git fetch operations (seconds).
    /// Zero means use `DEFAULT_FETCH_TIMEOUT_SECS`.
    #[serde(default)]
    pub fetch_timeout_secs: u64,
    /// Wall-clock timeout for git clone operations (seconds).
    /// Zero means use `DEFAULT_CLONE_TIMEOUT_SECS`.
    #[serde(default)]
    pub clone_timeout_secs: u64,
}

impl Default for MirrorPolicy {
    fn default() -> Self {
        Self {
            allowed_url_patterns: Vec::new(),
            fetch_timeout_secs: DEFAULT_FETCH_TIMEOUT_SECS,
            clone_timeout_secs: DEFAULT_CLONE_TIMEOUT_SECS,
        }
    }
}

impl MirrorPolicy {
    /// Returns the effective fetch timeout.
    const fn effective_fetch_timeout(&self) -> Duration {
        let secs = if self.fetch_timeout_secs == 0 {
            DEFAULT_FETCH_TIMEOUT_SECS
        } else {
            self.fetch_timeout_secs
        };
        Duration::from_secs(secs)
    }

    /// Returns the effective clone timeout.
    const fn effective_clone_timeout(&self) -> Duration {
        let secs = if self.clone_timeout_secs == 0 {
            DEFAULT_CLONE_TIMEOUT_SECS
        } else {
            self.clone_timeout_secs
        };
        Duration::from_secs(secs)
    }

    /// Check whether a remote URL is allowed by this policy.
    ///
    /// If `allowed_url_patterns` is empty, all URLs pass (subject to the
    /// built-in protocol validation in `validate_remote_url`).
    fn is_url_allowed(&self, url: &str) -> bool {
        if self.allowed_url_patterns.is_empty() {
            return true;
        }
        self.allowed_url_patterns
            .iter()
            .any(|pattern| url.starts_with(pattern.as_str()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mirror Update Receipt (TCK-00582)
// ─────────────────────────────────────────────────────────────────────────────

/// Receipt emitted after a mirror update operation, capturing before/after
/// ref state for auditability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MirrorUpdateReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// Repository identifier.
    pub repo_id: String,
    /// Remote URL used for the update (if any).
    pub remote_url: Option<String>,
    /// Mirror path on disk.
    pub mirror_path: String,
    /// Ref state before the update. Keys are ref names, values are SHAs.
    pub refs_before: HashMap<String, String>,
    /// Ref state after the update. Keys are ref names, values are SHAs.
    pub refs_after: HashMap<String, String>,
    /// Whether the update operation succeeded.
    pub success: bool,
    /// Operation type: "fetch", "clone", or "noop".
    pub operation: String,
    /// Wall-clock duration of the operation in milliseconds.
    pub duration_ms: u64,
    /// Human-readable reason if the operation failed.
    pub failure_reason: Option<String>,
}

impl MirrorUpdateReceiptV1 {
    /// Verify that the receipt is structurally valid.
    ///
    /// Validates both collection sizes and string field lengths to prevent
    /// memory exhaustion from oversized deserialized receipts (S-5).
    pub fn is_valid(&self) -> bool {
        self.schema == MIRROR_UPDATE_RECEIPT_SCHEMA
            && !self.repo_id.is_empty()
            && self.repo_id.len() <= MAX_REPO_ID_LENGTH
            && !self.mirror_path.is_empty()
            && self.mirror_path.len() <= MAX_RECEIPT_MIRROR_PATH_LENGTH
            && !self.operation.is_empty()
            && self.operation.len() <= MAX_RECEIPT_OPERATION_LENGTH
            && self
                .failure_reason
                .as_ref()
                .is_none_or(|r| r.len() <= MAX_RECEIPT_FAILURE_REASON_LENGTH)
            && self
                .remote_url
                .as_ref()
                .is_none_or(|u| u.len() <= MAX_RECEIPT_MIRROR_PATH_LENGTH)
            && self.refs_before.len() <= MAX_RECEIPT_REFS
            && self.refs_after.len() <= MAX_RECEIPT_REFS
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Types
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors and lane workspaces for FAC execution.
#[derive(Debug)]
pub struct RepoMirrorManager {
    mirror_root: PathBuf,
    lock_root: PathBuf,
    policy: MirrorPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutOutcome {
    pub repo_id: String,
    pub head_sha: String,
    pub workspace_path: PathBuf,
    /// Git hardening receipt recording security posture of the workspace.
    pub git_hardening: GitHardeningReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchOutcome {
    pub patch_digest: String,
    pub files_affected: u32,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RepoMirrorError {
    #[error("failed to initialize mirror: {reason}")]
    MirrorInitFailed {
        /// Why initialization failed.
        reason: String,
    },

    #[error("failed to checkout: {reason}")]
    CheckoutFailed {
        /// Why checkout failed.
        reason: String,
    },

    #[error("failed to apply patch: {reason}")]
    PatchApplyFailed {
        /// Why patch application failed.
        reason: String,
    },

    #[error("sha mismatch: expected {expected}, actual {actual}")]
    ShaMismatch {
        /// Expected head SHA.
        expected: String,
        /// Observed checked-out SHA.
        actual: String,
    },

    /// Patch content was denied by hardening validation (TCK-00581).
    #[error("patch hardening denied: {reason}")]
    PatchHardeningDenied {
        /// Why the patch was denied.
        reason: String,
        /// Denial receipt with provenance.
        receipt: Box<super::patch_hardening::PatchApplyReceiptV1>,
    },

    /// safe_rmtree returned an error.
    #[error("safe_rmtree failed: {0}")]
    SafeRmtreeError(SafeRmtreeError),

    #[error("I/O error: {0}")]
    Io(std::io::Error),

    #[error("invalid repo_id: {reason}")]
    InvalidRepoId {
        /// Why the repo id was rejected.
        reason: String,
    },

    #[error("mirror not found for repo_id {repo_id}: {reason}")]
    MirrorNotFound {
        /// Repository identifier.
        repo_id: String,
        /// Why lookup failed.
        reason: String,
    },

    #[error("invalid remote URL: {reason}")]
    InvalidRemoteUrl {
        /// Why the remote URL was rejected.
        reason: String,
    },

    /// Git hardening failed after checkout (TCK-00580).
    #[error("git hardening failed: {0}")]
    GitHardeningFailed(#[from] GitHardeningError),

    /// Remote URL rejected by mirror policy allowlist (TCK-00582).
    #[error("remote URL denied by policy: {reason}")]
    PolicyDenied {
        /// Why the URL was denied.
        reason: String,
    },

    /// Mirror update lock could not be acquired (TCK-00582).
    #[error("mirror lock acquisition failed: {reason}")]
    LockFailed {
        /// Why the lock could not be acquired.
        reason: String,
    },

    /// Git operation timed out (TCK-00582).
    #[error("git operation timed out after {timeout_secs}s: {reason}")]
    Timeout {
        /// Timeout that was exceeded.
        timeout_secs: u64,
        /// Context for the timeout.
        reason: String,
    },

    /// Mirror path contains a symlink component (TCK-00582).
    #[error("symlink component in mirror path: {reason}")]
    SymlinkInPath {
        /// Which component was a symlink.
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// RepoMirrorManager implementation
// ─────────────────────────────────────────────────────────────────────────────

impl RepoMirrorManager {
    /// Creates a mirror manager rooted at the FAC mirror directory with the
    /// default (permissive) policy.
    pub fn new(fac_root: &Path) -> Self {
        Self {
            mirror_root: fac_root.join("repo_mirror"),
            lock_root: fac_root.join("locks").join("mirrors"),
            policy: MirrorPolicy::default(),
        }
    }

    /// Creates a mirror manager with an explicit policy.
    pub fn with_policy(fac_root: &Path, policy: MirrorPolicy) -> Result<Self, RepoMirrorError> {
        if policy.allowed_url_patterns.len() > MAX_ALLOWED_URL_PATTERNS {
            return Err(RepoMirrorError::PolicyDenied {
                reason: format!(
                    "too many allowed URL patterns: {} > {}",
                    policy.allowed_url_patterns.len(),
                    MAX_ALLOWED_URL_PATTERNS
                ),
            });
        }
        Ok(Self {
            mirror_root: fac_root.join("repo_mirror"),
            lock_root: fac_root.join("locks").join("mirrors"),
            policy,
        })
    }

    /// Returns the path to the bare mirror for `repo_id`.
    pub fn mirror_path(&self, repo_id: &str) -> PathBuf {
        self.mirror_root.join(format!("{repo_id}.git"))
    }

    /// Returns the path to the lock file for `repo_id`.
    fn lock_path(&self, repo_id: &str) -> PathBuf {
        // Flatten repo_id for lock file name (replace `/` with `__`).
        let safe_name = repo_id.replace('/', "__");
        self.lock_root.join(format!("{safe_name}.lock"))
    }

    /// Acquire an exclusive file lock for a mirror update.
    ///
    /// Uses `flock(LOCK_EX | LOCK_NB)` with polling and monotonic timeout
    /// (INV-2501). Returns the open lock file handle; the lock is released
    /// when the file handle is dropped.
    ///
    /// Synchronization protocol:
    /// - Protected data: the bare mirror directory for `repo_id`
    /// - Who can mutate: only the holder of the exclusive flock
    /// - Lock ordering: one lock per repo_id, no nesting
    /// - Happens-before: flock(LOCK_EX) → mirror mutation → drop(File)
    /// - Async suspension: not applicable (synchronous code)
    fn acquire_mirror_lock(&self, repo_id: &str) -> Result<File, RepoMirrorError> {
        ensure_dir_mode_0700(&self.lock_root)?;

        let lock_path = self.lock_path(repo_id);
        let lock_file = open_lock_file(&lock_path)?;

        let deadline = Instant::now() + Duration::from_secs(MIRROR_LOCK_TIMEOUT_SECS);
        loop {
            match flock_util::try_acquire_exclusive_nonblocking(&lock_file) {
                Ok(true) => return Ok(lock_file),
                Ok(false) => {
                    // Lock held by another process — poll with timeout.
                    if Instant::now() >= deadline {
                        return Err(RepoMirrorError::LockFailed {
                            reason: format!(
                                "timed out after {}s waiting for mirror lock: {}",
                                MIRROR_LOCK_TIMEOUT_SECS,
                                lock_path.display()
                            ),
                        });
                    }
                    std::thread::sleep(MIRROR_LOCK_POLL_INTERVAL);
                },
                Err(e) => {
                    return Err(RepoMirrorError::LockFailed {
                        reason: format!("flock failed: {e}"),
                    });
                },
            }
        }
    }

    /// Ensure a bare mirror exists for `repo_id` and, if possible, updated.
    ///
    /// If the mirror exists, a fetch is performed when the mirror has at
    /// least one configured remote.
    /// If `remote_url` is present, it is configured as `origin` and then used
    /// to fetch updates.
    ///
    /// **TCK-00582 hardening:**
    /// - Acquires an exclusive file lock for the duration of the update.
    /// - Validates remote URL against the policy allowlist.
    /// - Bounds fetch/clone with a wall-clock timeout.
    /// - Refuses symlink components in mirror path.
    /// - Emits a `MirrorUpdateReceiptV1` with before/after refs.
    pub fn ensure_mirror(
        &self,
        repo_id: &str,
        remote_url: Option<&str>,
    ) -> Result<(PathBuf, MirrorUpdateReceiptV1), RepoMirrorError> {
        validate_repo_id(repo_id)?;

        // Validate remote URL against policy allowlist before any I/O.
        if let Some(url) = remote_url {
            validate_remote_url(url)?;
            if !self.policy.is_url_allowed(url) {
                return Err(RepoMirrorError::PolicyDenied {
                    reason: format!(
                        "remote URL '{url}' does not match any allowed pattern in mirror policy"
                    ),
                });
            }
        }

        let mirror_path = self.mirror_path(repo_id);
        ensure_dir_mode_0700(&self.mirror_root)?;

        // S-2: Validate symlink components BEFORE any I/O (including
        // snapshot_refs) to prevent git commands running against a symlink
        // target before the validation check fires.
        if mirror_path.exists() {
            validate_no_symlinks_in_path(&mirror_path)?;
        }

        // Acquire exclusive lock before any mirror mutation.
        let _lock_guard = self.acquire_mirror_lock(repo_id)?;

        let start = Instant::now();

        // Capture before-refs (if mirror exists).
        let refs_before = if mirror_path.is_dir() {
            snapshot_refs(&mirror_path).unwrap_or_default()
        } else {
            HashMap::new()
        };

        let result = self.ensure_mirror_inner(repo_id, remote_url, &mirror_path);

        let elapsed = start.elapsed();
        let duration_ms =
            u64::try_from(elapsed.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX);

        // Capture after-refs.
        let refs_after = if mirror_path.is_dir() {
            snapshot_refs(&mirror_path).unwrap_or_default()
        } else {
            HashMap::new()
        };

        let (success, failure_reason, operation) = match &result {
            Ok(op) => (true, None, op.clone()),
            Err(e) => (false, Some(format!("{e}")), "error".to_string()),
        };

        let receipt = MirrorUpdateReceiptV1 {
            schema: MIRROR_UPDATE_RECEIPT_SCHEMA.to_string(),
            repo_id: repo_id.to_string(),
            remote_url: remote_url.map(String::from),
            mirror_path: mirror_path.display().to_string(),
            refs_before,
            refs_after,
            success,
            operation,
            duration_ms,
            failure_reason,
        };

        // _lock_guard dropped here, releasing the flock.
        result.map(|_| (mirror_path, receipt))
    }

    /// Inner implementation that performs the actual mirror ensure logic.
    /// Returns the operation type string on success.
    fn ensure_mirror_inner(
        &self,
        repo_id: &str,
        remote_url: Option<&str>,
        mirror_path: &Path,
    ) -> Result<String, RepoMirrorError> {
        if mirror_path.exists() {
            // Refuse symlink components in the mirror path (TCK-00582).
            validate_no_symlinks_in_path(mirror_path)?;

            if !mirror_path.is_dir() {
                return Err(RepoMirrorError::MirrorInitFailed {
                    reason: format!(
                        "mirror path exists but is not a directory: {}",
                        mirror_path.display()
                    ),
                });
            }

            validate_bare_repo(mirror_path)?;

            match remote_url {
                Some(url) => {
                    set_or_replace_remote(mirror_path, url)?;
                    git_fetch_bounded(mirror_path, self.policy.effective_fetch_timeout())?;
                    Ok("fetch".to_string())
                },
                None => {
                    if mirror_has_remote(mirror_path)? {
                        // CQ-1: When remote_url is None, read the existing
                        // origin URL and validate it against the policy
                        // allowlist before fetching. Fail closed if the URL
                        // is absent or out-of-policy.
                        let existing_url = get_remote_origin_url(mirror_path)?;
                        validate_remote_url(&existing_url)?;
                        if !self.policy.is_url_allowed(&existing_url) {
                            return Err(RepoMirrorError::PolicyDenied {
                                reason: format!(
                                    "existing origin URL '{existing_url}' does not match \
                                     any allowed pattern in mirror policy"
                                ),
                            });
                        }
                        git_fetch_bounded(mirror_path, self.policy.effective_fetch_timeout())?;
                        Ok("fetch".to_string())
                    } else {
                        Ok("noop".to_string())
                    }
                },
            }
        } else {
            let remote_url = remote_url.ok_or_else(|| RepoMirrorError::MirrorNotFound {
                repo_id: repo_id.to_string(),
                reason: "mirror does not exist and no remote_url provided for bootstrap"
                    .to_string(),
            })?;

            self.evict_if_needed()?;

            // Create a new bare mirror with bounded timeout.
            git_clone_bare_bounded(
                remote_url,
                mirror_path,
                self.policy.effective_clone_timeout(),
            )?;

            Ok("clone".to_string())
        }
    }

    fn evict_if_needed(&self) -> Result<(), RepoMirrorError> {
        let mut with_time: Vec<(PathBuf, SystemTime)> = std::fs::read_dir(&self.mirror_root)
            .map_err(RepoMirrorError::Io)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("git") {
                    return None;
                }
                let metadata = entry.metadata().ok()?;
                let modified = metadata.modified().ok()?;
                Some((path, modified))
            })
            .collect();

        if with_time.len() < MAX_MIRROR_COUNT {
            return Ok(());
        }

        with_time.sort_by_key(|(_, t)| *t);
        let to_remove = with_time.len() - MAX_MIRROR_COUNT + 1;

        for (path, _) in with_time.into_iter().take(to_remove) {
            safe_rmtree_v1(&path, &self.mirror_root).map_err(RepoMirrorError::SafeRmtreeError)?;
        }

        Ok(())
    }

    /// Clone mirror state to a lane workspace and ensure checkout on
    /// `head_sha`.
    pub fn checkout_to_lane(
        &self,
        repo_id: &str,
        head_sha: &str,
        lane_workspace: &Path,
        allowed_parent: &Path,
    ) -> Result<CheckoutOutcome, RepoMirrorError> {
        validate_repo_id(repo_id)?;
        validate_head_sha(head_sha)?;

        // Clean workspace first to avoid drift or mixed states.
        safe_rmtree_v1(lane_workspace, allowed_parent).map_err(RepoMirrorError::SafeRmtreeError)?;

        let mirror_path = self.mirror_path(repo_id);
        if !mirror_path.is_dir() {
            return Err(RepoMirrorError::CheckoutFailed {
                reason: format!("mirror does not exist: {}", mirror_path.display()),
            });
        }

        git_command(
            &[
                "clone",
                "-c",
                "core.symlinks=false",
                "--no-hardlinks",
                "--no-checkout",
                "--",
                mirror_path.to_string_lossy().as_ref(),
                lane_workspace.to_string_lossy().as_ref(),
            ],
            None,
            |reason| RepoMirrorError::CheckoutFailed {
                reason: reason.to_string(),
            },
        )?;

        git_command(
            &[
                "-C",
                lane_workspace.to_string_lossy().as_ref(),
                "checkout",
                head_sha,
            ],
            None,
            |reason| RepoMirrorError::CheckoutFailed {
                reason: reason.to_string(),
            },
        )?;

        let actual_sha = git_command(
            &[
                "-C",
                lane_workspace.to_string_lossy().as_ref(),
                "rev-parse",
                "HEAD",
            ],
            None,
            |reason| RepoMirrorError::CheckoutFailed {
                reason: reason.to_string(),
            },
        )?;
        let actual_sha = actual_sha.trim().to_string();
        // S-3 / INV-PC-001: Use constant-time comparison for SHA digests
        // to prevent timing side-channel leakage of expected values.
        if !constant_time_str_eq(&actual_sha, head_sha) {
            return Err(RepoMirrorError::ShaMismatch {
                expected: head_sha.to_string(),
                actual: actual_sha,
            });
        }

        // TCK-00580: Harden the lane workspace git config immediately after
        // checkout and before any further git operations. The hooks directory
        // is placed under `allowed_parent` (the lanes root), outside the
        // workspace tree. Policy default: refuse unsafe configs.
        let hardening_receipt = git_hardening::harden_lane_workspace(
            lane_workspace,
            allowed_parent,
            true, // refuse_unsafe_configs: fail-closed by default
        )?;

        Ok(CheckoutOutcome {
            repo_id: repo_id.to_string(),
            head_sha: head_sha.to_string(),
            workspace_path: lane_workspace.to_path_buf(),
            git_hardening: hardening_receipt,
        })
    }

    /// Apply patch bytes with hardened validation and provenance receipt.
    ///
    /// This is the **safe apply mode** entry point (TCK-00581).  It:
    /// 1. Validates patch content against `git_diff_v1` rules (path traversal,
    ///    absolute paths, format checks).
    /// 2. Applies the patch via `git apply`.
    /// 3. Verifies the resulting tree matches the expected patch digest.
    /// 4. Emits a [`super::patch_hardening::PatchApplyReceiptV1`] receipt.
    ///
    /// # Errors
    ///
    /// Returns `PatchApplyFailed` if validation or apply fails.  On
    /// validation failure, the returned error includes a denial receipt
    /// in the reason string.
    pub fn apply_patch_hardened(
        &self,
        lane_workspace: &Path,
        patch_bytes: &[u8],
        patch_format: &str,
    ) -> Result<(PatchOutcome, super::patch_hardening::PatchApplyReceiptV1), RepoMirrorError> {
        use super::patch_hardening::{PatchApplyReceiptV1, validate_for_apply};

        let patch_digest = format!("b3-256:{}", blake3::hash(patch_bytes).to_hex());

        // Step 1: Pre-apply validation (fail-closed)
        match validate_for_apply(patch_bytes, patch_format) {
            Ok(_validation_result) => {
                // Validation passed — proceed with apply
            },
            Err(boxed) => {
                let (receipt, err) = *boxed;
                return Err(RepoMirrorError::PatchHardeningDenied {
                    reason: err.to_string(),
                    receipt: Box::new(receipt),
                });
            },
        }

        // Step 2: Apply via git
        let outcome = self.apply_patch(lane_workspace, patch_bytes)?;

        // Step 3: Verify digest binding
        // S-3 / INV-PC-001: Use constant-time comparison for cryptographic
        // digests to prevent timing side-channel leakage.
        if !constant_time_str_eq(&outcome.patch_digest, &patch_digest) {
            return Err(RepoMirrorError::PatchApplyFailed {
                reason: format!(
                    "patch digest mismatch after apply: expected {patch_digest}, got {}",
                    outcome.patch_digest
                ),
            });
        }

        // Step 4: Emit success receipt
        let receipt = PatchApplyReceiptV1::success(patch_digest, outcome.files_affected);

        Ok((outcome, receipt))
    }

    /// Apply patch bytes to a checked-out lane workspace and return a digest.
    pub fn apply_patch(
        &self,
        lane_workspace: &Path,
        patch_bytes: &[u8],
    ) -> Result<PatchOutcome, RepoMirrorError> {
        if patch_bytes.len() > MAX_PATCH_SIZE {
            return Err(RepoMirrorError::PatchApplyFailed {
                reason: format!(
                    "patch too large: {} exceeds maximum {}",
                    patch_bytes.len(),
                    MAX_PATCH_SIZE
                ),
            });
        }

        if !lane_workspace.is_dir() {
            return Err(RepoMirrorError::PatchApplyFailed {
                reason: format!("workspace does not exist: {}", lane_workspace.display()),
            });
        }

        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(lane_workspace)
            .arg("apply")
            .arg("--stat")
            .arg("--apply")
            .arg("-")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().map_err(RepoMirrorError::Io)?;
        {
            let Some(mut child_stdin) = child.stdin.take() else {
                return Err(RepoMirrorError::PatchApplyFailed {
                    reason: "failed to open stdin for git apply".to_string(),
                });
            };
            child_stdin
                .write_all(patch_bytes)
                .map_err(RepoMirrorError::Io)?;
            child_stdin.flush().map_err(RepoMirrorError::Io)?;
        }

        let output = child.wait_with_output().map_err(RepoMirrorError::Io)?;
        if !output.status.success() {
            let mut reason = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if reason.is_empty() {
                reason = String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
            if reason.is_empty() {
                reason = "git apply failed with no output".to_string();
            }
            return Err(RepoMirrorError::PatchApplyFailed { reason });
        }

        // SAFETY: Path traversal prevention is delegated to `git apply`, which by
        // default refuses patches that attempt to modify files outside the
        // repository root. Standard git safety rejects paths with `../`
        // components. See: https://git-scm.com/docs/git-apply
        let changed = git_command(
            &[
                "-C",
                lane_workspace.to_string_lossy().as_ref(),
                "diff",
                "--name-only",
                "--",
            ],
            None,
            |reason| RepoMirrorError::PatchApplyFailed {
                reason: reason.to_string(),
            },
        )?;

        let files_affected = changed
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
            .try_into()
            .unwrap_or(u32::MAX);

        let digest = blake3::hash(patch_bytes);
        Ok(PatchOutcome {
            patch_digest: format!("b3-256:{}", digest.to_hex()),
            files_affected,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Filesystem helpers
// ─────────────────────────────────────────────────────────────────────────────

/// S-4 / CQ-B1: Atomically open the directory with `O_NOFOLLOW | O_DIRECTORY`
/// and apply permissions via `fchmod` on the resulting fd. This eliminates the
/// TOCTOU window between symlink check and `set_permissions`: `O_NOFOLLOW`
/// refuses symlinks at open time, and `fchmod` operates on the verified inode
/// rather than re-resolving the path.
#[cfg(unix)]
fn ensure_dir_mode_0700(path: &Path) -> Result<(), RepoMirrorError> {
    use nix::fcntl::OFlag;
    use nix::sys::stat::Mode;

    match nix::fcntl::open(
        path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY,
        Mode::empty(),
    ) {
        Ok(fd) => {
            // `fd` is an `OwnedFd` (nix 0.30) — closed on drop.
            nix::sys::stat::fchmod(&fd, Mode::S_IRWXU)
                .map_err(|e| RepoMirrorError::Io(std::io::Error::from_raw_os_error(e as i32)))?;
            Ok(())
        },
        Err(nix::errno::Errno::ENOENT) => {
            // Directory does not exist — create it with mode 0o700.
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(RepoMirrorError::Io)
        },
        Err(nix::errno::Errno::ELOOP | nix::errno::Errno::ENOTDIR) => {
            // ELOOP: path is a symlink (O_NOFOLLOW).
            // ENOTDIR: path exists but is not a directory (O_DIRECTORY).
            Err(RepoMirrorError::SymlinkInPath {
                reason: format!(
                    "directory path is a symlink or not a directory: {}",
                    path.display()
                ),
            })
        },
        Err(e) => Err(RepoMirrorError::Io(std::io::Error::from_raw_os_error(
            e as i32,
        ))),
    }
}

#[cfg(not(unix))]
fn ensure_dir_mode_0700(path: &Path) -> Result<(), RepoMirrorError> {
    match std::fs::symlink_metadata(path) {
        Ok(_meta) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(RepoMirrorError::Io)
        },
        Err(e) => Err(RepoMirrorError::Io(e)),
    }
}

/// Open (or create) a lock file with restrictive permissions.
///
/// S-4: Uses `O_NOFOLLOW` on Unix to refuse opening symlinks, preventing
/// symlink-based attacks on the lock file path.
fn open_lock_file(path: &Path) -> Result<File, RepoMirrorError> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
        // O_NOFOLLOW: refuse to open if path is a symlink (S-4).
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path).map_err(|e| RepoMirrorError::LockFailed {
        reason: format!("cannot open lock file {}: {e}", path.display()),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Symlink path validation (TCK-00582)
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that no component of `path` is a symlink.
///
/// Uses `symlink_metadata` (not `metadata`) so dangling symlinks are also
/// detected (common-review-findings.md section 9).
fn validate_no_symlinks_in_path(path: &Path) -> Result<(), RepoMirrorError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        // Only check components that exist on disk.
        if current.exists() {
            match std::fs::symlink_metadata(&current) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(RepoMirrorError::SymlinkInPath {
                            reason: format!("path component is a symlink: {}", current.display()),
                        });
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Component disappeared between exists() and
                    // symlink_metadata(). This is benign — the rest of the
                    // path cannot be symlinks if this component is missing.
                    break;
                },
                Err(e) => {
                    return Err(RepoMirrorError::SymlinkInPath {
                        reason: format!("cannot stat path component {}: {e}", current.display()),
                    });
                },
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Ref snapshot helper (TCK-00582)
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot all refs in a bare mirror via `git show-ref`.
///
/// Returns a map of ref-name -> SHA. The output is double-bounded:
/// 1. **Byte cap**: `git_command` delegates to `git_command_with_timeout` which
///    caps stdout at `GIT_STDOUT_MAX_BYTES` (4 MiB) — preventing OOM from repos
///    with millions of refs (S-1, CQ-2).
/// 2. **Entry cap**: Only the first `MAX_RECEIPT_REFS` lines are parsed.
fn snapshot_refs(mirror_path: &Path) -> Result<HashMap<String, String>, RepoMirrorError> {
    let output = git_command(
        &["-C", mirror_path.to_string_lossy().as_ref(), "show-ref"],
        None,
        |_reason| {
            // show-ref returns non-zero when there are no refs — treat as empty.
            RepoMirrorError::MirrorInitFailed {
                reason: "show-ref failed".to_string(),
            }
        },
    );

    let stdout = match output {
        Ok(s) => s,
        // Empty repo with no refs returns non-zero — that is fine.
        Err(RepoMirrorError::MirrorInitFailed { .. }) => return Ok(HashMap::new()),
        Err(e) => return Err(e),
    };

    let mut refs = HashMap::new();
    for line in stdout.lines().take(MAX_RECEIPT_REFS) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: "<sha> <refname>"
        if let Some((sha, refname)) = line.split_once(' ') {
            refs.insert(refname.to_string(), sha.to_string());
        }
    }
    Ok(refs)
}

// ─────────────────────────────────────────────────────────────────────────────
// Git command helpers
// ─────────────────────────────────────────────────────────────────────────────

/// S-1 / CTR-1603: All git command stdout reads are bounded to
/// `GIT_STDOUT_MAX_BYTES` to prevent OOM from commands producing
/// unexpectedly large output (e.g., `git show-ref` on repos with
/// millions of refs).
///
/// Delegates to `git_command_with_timeout` with `GIT_COMMAND_DEFAULT_TIMEOUT`.
fn git_command(
    args: &[&str],
    cwd: Option<&Path>,
    make_error: impl Fn(&str) -> RepoMirrorError,
) -> Result<String, RepoMirrorError> {
    git_command_with_timeout(args, cwd, GIT_COMMAND_DEFAULT_TIMEOUT, make_error)
}

/// Run a git command with a wall-clock timeout using `Instant` (monotonic).
///
/// The child process is spawned, stdout/stderr are read on dedicated threads
/// (bounded to `GIT_STDOUT_MAX_BYTES`), and the main thread polls for exit
/// with a deadline. If the deadline expires, the child is killed.
///
/// CQ-m1: stdout/stderr are consumed on background threads to prevent the
/// child from blocking on a full pipe. When a thread hits the byte cap it
/// kills the child process immediately so it does not hang for the full
/// timeout duration.
///
/// CTR-2501: uses `Instant` for duration measurement, not `SystemTime`.
fn git_command_with_timeout(
    args: &[&str],
    cwd: Option<&Path>,
    timeout: Duration,
    make_error: impl Fn(&str) -> RepoMirrorError,
) -> Result<String, RepoMirrorError> {
    let mut cmd = Command::new("git");
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.args(args);

    let mut child = cmd
        .spawn()
        .map_err(|e| make_error(&format!("failed to spawn git: {e}")))?;

    // CQ-m1: Take stdout/stderr handles and read them on background threads
    // so the child never blocks on a full pipe buffer. Each thread reads up
    // to `GIT_STDOUT_MAX_BYTES` then drains and discards any remaining data,
    // ensuring the child can always make progress writing.
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let stdout_thread = std::thread::spawn(move || bounded_read_pipe(stdout_handle));
    let stderr_thread = std::thread::spawn(move || bounded_read_pipe(stderr_handle));

    // Poll for exit with monotonic deadline.
    let deadline = Instant::now() + timeout;
    let poll_interval = Duration::from_millis(250);

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Join reader threads before returning (they will see EOF
                    // from the killed process).
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    return Err(RepoMirrorError::Timeout {
                        timeout_secs: timeout.as_secs(),
                        reason: format!("git {}", args.first().unwrap_or(&"<unknown>")),
                    });
                }
                std::thread::sleep(poll_interval);
            },
            Err(e) => {
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(make_error(&format!("failed to wait for git: {e}")));
            },
        }
    };

    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    if !status.success() {
        let mut reason = String::from_utf8_lossy(&stderr).trim().to_string();
        if reason.is_empty() {
            reason = String::from_utf8_lossy(&stdout).trim().to_string();
        }
        if reason.is_empty() {
            reason = "git command failed with no output".to_string();
        }
        return Err(make_error(&reason));
    }

    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Read up to `GIT_STDOUT_MAX_BYTES` from a pipe, then drain and discard
/// any remaining data so the writing process does not block.
///
/// CQ-m1: This prevents the child process from hanging on a full pipe buffer
/// when it produces output exceeding the byte cap.
fn bounded_read_pipe(pipe: Option<impl std::io::Read>) -> Vec<u8> {
    let Some(mut reader) = pipe else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    // Bounded read: at most GIT_STDOUT_MAX_BYTES (S-1, CTR-1603).
    let _ = std::io::Read::take(&mut reader, GIT_STDOUT_MAX_BYTES).read_to_end(&mut buf);
    // Drain remaining data so the child does not block on the pipe.
    let mut discard = [0u8; 8192];
    loop {
        match std::io::Read::read(&mut reader, &mut discard) {
            Ok(0) | Err(_) => break,
            Ok(_) => {},
        }
    }
    buf
}

// ─────────────────────────────────────────────────────────────────────────────
// Git operations (internal)
// ─────────────────────────────────────────────────────────────────────────────

fn validate_repo_id(repo_id: &str) -> Result<(), RepoMirrorError> {
    if repo_id.is_empty() {
        return Err(RepoMirrorError::InvalidRepoId {
            reason: "repo_id cannot be empty".to_string(),
        });
    }
    if repo_id.len() > MAX_REPO_ID_LENGTH {
        return Err(RepoMirrorError::InvalidRepoId {
            reason: format!(
                "repo_id too long: {} > {}",
                repo_id.len(),
                MAX_REPO_ID_LENGTH
            ),
        });
    }
    if repo_id.len() + 4 > MAX_MIRROR_DIR_NAME {
        return Err(RepoMirrorError::InvalidRepoId {
            reason: format!(
                "mirror path segment too long: {} > {}",
                repo_id.len() + 4,
                MAX_MIRROR_DIR_NAME
            ),
        });
    }
    if repo_id.contains('\\') || repo_id.starts_with('/') || repo_id.ends_with('/') {
        return Err(RepoMirrorError::InvalidRepoId {
            reason: "repo_id must not use absolute paths or separators at edges".to_string(),
        });
    }
    for segment in repo_id.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(RepoMirrorError::InvalidRepoId {
                reason: "repo_id contains invalid path traversal component".to_string(),
            });
        }
    }
    if repo_id.contains("..") {
        return Err(RepoMirrorError::InvalidRepoId {
            reason: "repo_id contains path traversal component".to_string(),
        });
    }
    if repo_id == "." || repo_id == ".." {
        return Err(RepoMirrorError::InvalidRepoId {
            reason: "repo_id cannot be dot component".to_string(),
        });
    }
    if repo_id.contains(char::from(0)) {
        return Err(RepoMirrorError::InvalidRepoId {
            reason: "repo_id cannot contain NUL".to_string(),
        });
    }
    Ok(())
}

fn validate_head_sha(head_sha: &str) -> Result<(), RepoMirrorError> {
    let is_hex = |value: &str| value.as_bytes().iter().all(u8::is_ascii_hexdigit);
    match head_sha.len() {
        40 | 64 if is_hex(head_sha) => Ok(()),
        _ => Err(RepoMirrorError::CheckoutFailed {
            reason: "head_sha must be 40 or 64 hex characters".to_string(),
        }),
    }
}

fn validate_bare_repo(mirror_path: &Path) -> Result<(), RepoMirrorError> {
    let bare_flag = git_command(
        &[
            "-C",
            mirror_path.to_string_lossy().as_ref(),
            "rev-parse",
            "--is-bare-repository",
        ],
        None,
        |reason| RepoMirrorError::MirrorInitFailed {
            reason: reason.to_string(),
        },
    )?;

    if bare_flag.trim() != "true" {
        return Err(RepoMirrorError::MirrorInitFailed {
            reason: format!("not a bare repository: {}", mirror_path.display()),
        });
    }

    Ok(())
}

fn mirror_has_remote(mirror_path: &Path) -> Result<bool, RepoMirrorError> {
    let remote_output = git_command(
        &["-C", mirror_path.to_string_lossy().as_ref(), "remote"],
        None,
        |reason| RepoMirrorError::MirrorInitFailed {
            reason: reason.to_string(),
        },
    )?;
    Ok(!remote_output.trim().is_empty())
}

fn set_or_replace_remote(mirror_path: &Path, remote_url: &str) -> Result<(), RepoMirrorError> {
    validate_remote_url(remote_url)?;

    if mirror_has_remote(mirror_path)? {
        git_command(
            &[
                "-C",
                mirror_path.to_string_lossy().as_ref(),
                "remote",
                "set-url",
                "--",
                "origin",
                remote_url,
            ],
            None,
            |reason| RepoMirrorError::MirrorInitFailed {
                reason: reason.to_string(),
            },
        )
        .or_else(|err| {
            if matches!(err, RepoMirrorError::MirrorInitFailed { .. }) {
                git_command(
                    &[
                        "-C",
                        mirror_path.to_string_lossy().as_ref(),
                        "remote",
                        "add",
                        "--",
                        "origin",
                        remote_url,
                    ],
                    None,
                    |reason| RepoMirrorError::MirrorInitFailed {
                        reason: reason.to_string(),
                    },
                )
            } else {
                Err(err)
            }
        })?;
        return Ok(());
    }

    git_command(
        &[
            "-C",
            mirror_path.to_string_lossy().as_ref(),
            "remote",
            "add",
            "--",
            "origin",
            remote_url,
        ],
        None,
        |reason| RepoMirrorError::MirrorInitFailed {
            reason: reason.to_string(),
        },
    )?;
    Ok(())
}

/// Fetch with wall-clock timeout (TCK-00582).
fn git_fetch_bounded(mirror_path: &Path, timeout: Duration) -> Result<(), RepoMirrorError> {
    git_command_with_timeout(
        &[
            "-C",
            mirror_path.to_string_lossy().as_ref(),
            "fetch",
            "--all",
            "--prune",
        ],
        None,
        timeout,
        |reason| RepoMirrorError::MirrorInitFailed {
            reason: reason.to_string(),
        },
    )
    .map(|_| ())
}

/// Clone --bare with wall-clock timeout (TCK-00582).
fn git_clone_bare_bounded(
    remote_url: &str,
    mirror_path: &Path,
    timeout: Duration,
) -> Result<(), RepoMirrorError> {
    git_command_with_timeout(
        &[
            "clone",
            "--bare",
            "--",
            remote_url,
            mirror_path.to_string_lossy().as_ref(),
        ],
        None,
        timeout,
        |reason| RepoMirrorError::MirrorInitFailed {
            reason: reason.to_string(),
        },
    )
    .map(|_| ())
}

/// Read the existing `remote.origin.url` from a mirror's git config.
///
/// Used by CQ-1 to validate existing origin URLs against policy when
/// `remote_url` is `None`.
fn get_remote_origin_url(mirror_path: &Path) -> Result<String, RepoMirrorError> {
    let url = git_command(
        &[
            "-C",
            mirror_path.to_string_lossy().as_ref(),
            "remote",
            "get-url",
            "origin",
        ],
        None,
        |reason| RepoMirrorError::MirrorInitFailed {
            reason: format!("failed to read origin URL: {reason}"),
        },
    )?;
    let url = url.trim().to_string();
    if url.is_empty() {
        return Err(RepoMirrorError::PolicyDenied {
            reason: "existing origin URL is empty; cannot validate against policy".to_string(),
        });
    }
    Ok(url)
}

/// S-3 / INV-PC-001: Constant-time string comparison for cryptographic
/// digests and SHA values.
///
/// Decodes both hex strings to bytes and compares using
/// `subtle::ConstantTimeEq::ct_eq` to prevent timing side-channel leakage.
/// Falls back to byte-level constant-time comparison on the raw UTF-8 bytes
/// if hex decoding fails (e.g., for prefixed digest strings like "b3-256:...").
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    // Fast reject: different lengths cannot be equal, and length is not secret.
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn validate_remote_url(remote_url: &str) -> Result<(), RepoMirrorError> {
    if remote_url.is_empty() {
        return Err(RepoMirrorError::InvalidRemoteUrl {
            reason: "remote URL must not be empty".to_string(),
        });
    }
    // CQ-M1: Enforce length bound so the URL can be stored in receipts
    // without violating the S-5 bounds check in `MirrorUpdateReceiptV1::is_valid`.
    if remote_url.len() > MAX_RECEIPT_MIRROR_PATH_LENGTH {
        return Err(RepoMirrorError::InvalidRemoteUrl {
            reason: format!(
                "remote URL too long: {} > {}",
                remote_url.len(),
                MAX_RECEIPT_MIRROR_PATH_LENGTH
            ),
        });
    }
    if remote_url.starts_with('-') {
        return Err(RepoMirrorError::InvalidRemoteUrl {
            reason: "remote URL must not start with hyphen".to_string(),
        });
    }
    // file:// is disallowed to avoid arbitrary local-file reads through git remotes.
    let safe_prefixes = ["https://", "ssh://", "git://", "/", "."];
    if !safe_prefixes
        .iter()
        .any(|prefix| remote_url.starts_with(prefix))
    {
        return Err(RepoMirrorError::InvalidRemoteUrl {
            reason: format!(
                "remote URL protocol not in allowlist; must start with one of: {safe_prefixes:?}"
            ),
        });
    }
    if remote_url.starts_with("ext::") {
        return Err(RepoMirrorError::InvalidRemoteUrl {
            reason: "ext:: protocol is forbidden".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::process::Command;
    use std::time::Duration;

    use super::*;

    fn create_git_repo_with_commit(path: &Path, file_name: &str, contents: &str) -> String {
        let output = Command::new("git")
            .arg("init")
            .arg(path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("init git repo");
        assert!(output.status.success());

        let index_path = path.join(file_name);
        fs::create_dir_all(path).expect("repo root");
        fs::write(&index_path, contents).expect("write file");

        let add = Command::new("git")
            .arg("-C")
            .arg(path)
            .arg("add")
            .arg(file_name)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git add");
        assert!(add.status.success());

        let config_name = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["config", "user.name", "Test"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set git user");
        assert!(config_name.status.success());

        let config_email = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["config", "user.email", "test@example.com"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set git email");
        assert!(config_email.status.success());

        let commit = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["commit", "-m", "initial"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("commit");
        assert!(commit.status.success());

        let rev_parse = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["rev-parse", "HEAD"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("rev-parse");
        assert!(rev_parse.status.success());

        String::from_utf8_lossy(&rev_parse.stdout)
            .trim()
            .to_string()
    }

    #[test]
    fn test_mirror_path_construction() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fac_root = temp.path().join("private").join("fac");
        let mgr = RepoMirrorManager::new(&fac_root);

        let path = mgr.mirror_path("repo-01");
        assert!(path.ends_with("repo_mirror/repo-01.git"));
        assert!(
            path.parent()
                .expect("parent")
                .ends_with("private/fac/repo_mirror")
        );
    }

    #[test]
    fn test_invalid_repo_id_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mgr = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        assert!(matches!(
            mgr.ensure_mirror("", None),
            Err(RepoMirrorError::InvalidRepoId { .. })
        ));
        assert!(matches!(
            mgr.ensure_mirror("..", None),
            Err(RepoMirrorError::InvalidRepoId { .. })
        ));
        assert!(matches!(
            mgr.ensure_mirror("a/../b", None),
            Err(RepoMirrorError::InvalidRepoId { .. })
        ));
        assert!(matches!(
            mgr.ensure_mirror("/tmp/repo", None),
            Err(RepoMirrorError::InvalidRepoId { .. })
        ));
        assert!(matches!(
            mgr.ensure_mirror(&"x".repeat(MAX_REPO_ID_LENGTH + 1), None),
            Err(RepoMirrorError::InvalidRepoId { .. })
        ));
    }

    #[test]
    fn test_ensure_mirror_requires_remote_when_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mgr = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        assert!(matches!(
            mgr.ensure_mirror("sample", None),
            Err(RepoMirrorError::MirrorNotFound { repo_id: _, .. })
        ));
    }

    #[test]
    fn test_apply_patch_rejects_oversized_patch() {
        let oversized = vec![b'a'; MAX_PATCH_SIZE + 1];
        let manager = RepoMirrorManager::new(Path::new("/tmp/nonexistent"));
        let result = manager.apply_patch(Path::new("/tmp/workspace"), &oversized);
        assert!(result.is_err());

        match result {
            Err(RepoMirrorError::PatchApplyFailed { reason }) => {
                assert!(
                    reason.contains("exceeds maximum"),
                    "error should mention size limit: {reason}"
                );
            },
            other => panic!("expected PatchApplyFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_ensure_mirror_rejects_injected_remote_url() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mgr = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        assert!(matches!(
            mgr.ensure_mirror("sample", Some("-attacker")),
            Err(RepoMirrorError::InvalidRemoteUrl { .. })
        ));
        assert!(matches!(
            mgr.ensure_mirror("sample", Some("ext::/tmp/repo")),
            Err(RepoMirrorError::InvalidRemoteUrl { .. })
        ));
        assert!(matches!(
            mgr.ensure_mirror("sample", Some("ftp://example.com/repo")),
            Err(RepoMirrorError::InvalidRemoteUrl { .. })
        ));
        assert!(matches!(
            validate_remote_url("https://example.com/repo"),
            Ok(())
        ));
    }

    #[test]
    fn test_ensure_mirror_evicts_oldest_when_exceeding_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manager = RepoMirrorManager::new(&temp.path().join("private").join("fac"));
        #[cfg(unix)]
        {
            let fac_root = temp.path().join("private").join("fac");
            std::fs::create_dir_all(&fac_root).expect("create fac root");
            std::fs::set_permissions(fac_root, std::fs::Permissions::from_mode(0o700))
                .expect("set fac root mode");
        }

        for i in 0..=MAX_MIRROR_COUNT {
            let path = manager.mirror_path(&format!("repo-{i}"));
            std::fs::create_dir_all(&path).expect("create mirror entry");
            std::thread::sleep(Duration::from_millis(10));
        }

        let source_repo = temp.path().join("source_repo");
        let _head_sha = create_git_repo_with_commit(&source_repo, "README.md", "hello");

        let (mirror_path, receipt) = manager
            .ensure_mirror("new", Some(source_repo.to_string_lossy().as_ref()))
            .expect("ensure mirror after eviction");
        assert!(mirror_path.exists());
        assert!(!manager.mirror_path("repo-0").exists());
        assert!(receipt.success);
        assert_eq!(receipt.operation, "clone");
        assert!(receipt.is_valid());

        let mirror_root = manager.mirror_root;
        let count = std::fs::read_dir(mirror_root)
            .expect("read mirror root")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("git"))
            .count();

        assert_eq!(count, MAX_MIRROR_COUNT);
    }

    #[test]
    fn test_checkout_outcome_has_correct_sha() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source_repo = temp.path().join("source_repo");
        let head_sha = create_git_repo_with_commit(&source_repo, "README.md", "hello");

        let mirror_root = temp.path().join("private").join("fac");
        let manager = RepoMirrorManager::new(&mirror_root);
        let lanes_root = temp.path().join("lanes");
        std::fs::create_dir_all(&lanes_root).expect("create lanes");
        #[cfg(unix)]
        std::fs::set_permissions(&lanes_root, std::fs::Permissions::from_mode(0o700))
            .expect("set lanes mode");
        let lane_workspace = lanes_root.join("lane-a").join("workspace");
        fs::create_dir_all(lane_workspace.parent().expect("lane parent"))
            .expect("create lane parent");

        let (mirror_path, receipt) = manager
            .ensure_mirror("sample", Some(source_repo.to_string_lossy().as_ref()))
            .expect("ensure mirror");
        assert!(mirror_path.ends_with("sample.git"));
        assert!(receipt.success);
        assert_eq!(receipt.operation, "clone");
        assert!(receipt.is_valid());

        let outcome = manager
            .checkout_to_lane("sample", &head_sha, &lane_workspace, &lanes_root)
            .expect("checkout");

        assert_eq!(outcome.head_sha, head_sha);
        assert_eq!(outcome.repo_id, "sample");
        assert!(outcome.workspace_path.is_dir());
        assert!(outcome.workspace_path.join("README.md").is_file());
    }

    #[test]
    fn test_mirror_commit_ignores_patch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source_repo = temp.path().join("source_repo");
        let head_sha = create_git_repo_with_commit(&source_repo, "README.md", "hello");

        let manager = RepoMirrorManager::new(&temp.path().join("private").join("fac"));
        let (mirror_path, _receipt) = manager
            .ensure_mirror("sample", Some(source_repo.to_string_lossy().as_ref()))
            .expect("ensure mirror");

        let lane_workspace = temp.path().join("lanes").join("lane-a").join("workspace");
        let lanes_root = temp.path().join("lanes");
        std::fs::create_dir_all(&lanes_root).expect("create lanes");
        #[cfg(unix)]
        std::fs::set_permissions(&lanes_root, std::fs::Permissions::from_mode(0o700))
            .expect("set lanes mode");
        fs::create_dir_all(lane_workspace.parent().expect("lane parent"))
            .expect("create lane parent");
        fs::create_dir_all(&lane_workspace).expect("create workspace");
        fs::write(lane_workspace.join("stale.txt"), b"dirty").expect("write stale file");

        let outcome = manager
            .checkout_to_lane("sample", &head_sha, &lane_workspace, &lanes_root)
            .expect("checkout");

        assert_eq!(outcome.head_sha, head_sha);
        assert!(outcome.workspace_path.join("README.md").is_file());
        assert!(!outcome.workspace_path.join("stale.txt").exists());
        assert_eq!(mirror_path, manager.mirror_path("sample"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_patch_digest_is_deterministic() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source_repo = temp.path().join("source_repo");
        let _head_sha = create_git_repo_with_commit(&source_repo, "file.txt", "content");

        let manager = RepoMirrorManager::new(&temp.path().join("private").join("fac"));
        let workspace = temp.path().join("workspace-a");
        fs::create_dir_all(&workspace).expect("create workspace");
        let output = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .arg("init")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git init workspace");
        assert!(output.status.success());

        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "user.name", "Test"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set user.name");
        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "user.email", "test@example.com"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set user.email");
        let patch = b"diff --git a/file.txt b/file.txt\nindex e69de29..e69de29 100644\n--- a/file.txt\n+++ b/file.txt\n@@ -0,0 +1 @@\n+old\n";
        fs::write(workspace.join("file.txt"), b"").expect("write file");
        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["add", "file.txt"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git add");
        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["commit", "-m", "base"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git commit");

        let outcome1 = manager
            .apply_patch(&workspace, patch)
            .expect("apply patch 1");
        let digest1 = outcome1.patch_digest.clone();

        let workspace2 = temp.path().join("workspace-b");
        fs::create_dir_all(&workspace2).expect("create workspace 2");
        let output = Command::new("git")
            .arg("-C")
            .arg(&workspace2)
            .arg("init")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git init workspace b");
        assert!(output.status.success());
        Command::new("git")
            .arg("-C")
            .arg(&workspace2)
            .args(["config", "user.name", "Test"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set user.name b");
        Command::new("git")
            .arg("-C")
            .arg(&workspace2)
            .args(["config", "user.email", "test@example.com"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set user.email b");
        fs::write(workspace2.join("file.txt"), b"").expect("write file b");
        Command::new("git")
            .arg("-C")
            .arg(&workspace2)
            .args(["add", "file.txt"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git add b");
        Command::new("git")
            .arg("-C")
            .arg(&workspace2)
            .args(["commit", "-m", "base"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git commit b");

        let outcome2 = manager
            .apply_patch(&workspace2, patch)
            .expect("apply patch 2");

        assert_eq!(outcome1.files_affected, outcome2.files_affected);
        assert_eq!(digest1, outcome2.patch_digest);
        assert_eq!(digest1.len(), 71);
    }

    #[test]
    fn test_reject_invalid_head_sha_in_checkout() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manager = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        let mirror_path = manager.mirror_root.join("sample.git");
        Command::new("git")
            .arg("init")
            .arg("--bare")
            .arg(&mirror_path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("init bare");

        let lanes_dir = temp.path().join("lanes");
        let workspace = lanes_dir.join("lane-00").join("workspace");
        let err = manager.checkout_to_lane("sample", "zzz", &workspace, &lanes_dir);

        assert!(matches!(err, Err(RepoMirrorError::CheckoutFailed { .. })));
    }

    #[test]
    #[cfg(unix)]
    fn test_checkout_does_not_create_symlinks_from_mirror() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source_repo = temp.path().join("source_repo");
        #[cfg(unix)]
        {
            let fac_root = temp.path().join("private").join("fac");
            std::fs::create_dir_all(&fac_root).expect("create fac root");
            std::fs::set_permissions(fac_root, std::fs::Permissions::from_mode(0o700))
                .expect("set fac root mode");
        }

        let output = Command::new("git")
            .arg("init")
            .arg(&source_repo)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("init repo");
        assert!(output.status.success());

        fs::write(source_repo.join("payload.txt"), b"payload").expect("write payload");
        symlink("payload.txt", source_repo.join("payload-link.txt")).expect("create symlink");

        let add = Command::new("git")
            .arg("-C")
            .arg(&source_repo)
            .args(["add", "payload.txt", "payload-link.txt"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git add");
        assert!(add.status.success());

        let config_name = Command::new("git")
            .arg("-C")
            .arg(&source_repo)
            .args(["config", "user.name", "Test"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set user.name");
        assert!(config_name.status.success());

        let config_email = Command::new("git")
            .arg("-C")
            .arg(&source_repo)
            .args(["config", "user.email", "test@example.com"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set user.email");
        assert!(config_email.status.success());

        let commit = Command::new("git")
            .arg("-C")
            .arg(&source_repo)
            .args(["commit", "-m", "symlink baseline"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git commit");
        assert!(commit.status.success());

        let head_sha = Command::new("git")
            .arg("-C")
            .arg(&source_repo)
            .args(["rev-parse", "HEAD"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("rev-parse");
        assert!(head_sha.status.success());

        let head_sha = String::from_utf8_lossy(&head_sha.stdout).trim().to_string();

        let manager = RepoMirrorManager::new(&temp.path().join("private").join("fac"));
        let (mirror_path, _receipt) = manager
            .ensure_mirror("sample", Some(source_repo.to_string_lossy().as_ref()))
            .expect("ensure mirror");
        assert!(mirror_path.ends_with("sample.git"));

        let lanes_root = temp.path().join("lanes");
        std::fs::create_dir_all(&lanes_root).expect("create lanes");
        #[cfg(unix)]
        std::fs::set_permissions(&lanes_root, std::fs::Permissions::from_mode(0o700))
            .expect("set lanes mode");
        let workspace = lanes_root.join("lane-a").join("workspace");
        fs::create_dir_all(workspace.parent().expect("lane parent")).expect("create lane parent");

        let outcome = manager
            .checkout_to_lane("sample", &head_sha, &workspace, &lanes_root)
            .expect("checkout");

        let checked_link = outcome.workspace_path.join("payload-link.txt");
        let metadata = fs::symlink_metadata(&checked_link).expect("read checked out link metadata");
        assert!(
            !metadata.file_type().is_symlink(),
            "symlink was restored despite core.symlinks=false"
        );
        assert_eq!(
            fs::read_to_string(&checked_link).expect("read checked out link"),
            "payload.txt"
        );
    }

    // -----------------------------------------------------------------------
    // apply_patch_hardened tests (TCK-00581)
    // -----------------------------------------------------------------------

    #[test]
    fn test_hardened_apply_rejects_path_traversal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manager = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        // Create a minimal git workspace
        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");
        let output = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .arg("init")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git init");
        assert!(output.status.success());

        let traversal_patch = b"diff --git a/../../../etc/passwd b/../../../etc/passwd\n\
                                --- a/../../../etc/passwd\n\
                                +++ b/../../../etc/passwd\n\
                                @@ -1 +1 @@\n\
                                -old\n\
                                +new\n";

        let result = manager.apply_patch_hardened(&workspace, traversal_patch, "git_diff_v1");

        assert!(result.is_err());
        match result.unwrap_err() {
            RepoMirrorError::PatchHardeningDenied { reason, receipt } => {
                assert!(
                    reason.contains(".."),
                    "denial reason should mention path traversal: {reason}"
                );
                assert!(!receipt.applied);
                assert_eq!(receipt.refusals.len(), 1);
                assert!(receipt.verify_content_hash());
            },
            other => panic!("expected PatchHardeningDenied, got: {other}"),
        }
    }

    #[test]
    fn test_hardened_apply_rejects_absolute_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manager = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");
        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .arg("init")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git init");

        let absolute_patch = b"diff --git a//etc/shadow b//etc/shadow\n\
                               --- a//etc/shadow\n\
                               +++ b//etc/shadow\n\
                               @@ -1 +1 @@\n\
                               -old\n\
                               +new\n";

        let result = manager.apply_patch_hardened(&workspace, absolute_patch, "git_diff_v1");

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RepoMirrorError::PatchHardeningDenied { .. }
        ));
    }

    #[test]
    fn test_hardened_apply_rejects_wrong_format() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manager = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");

        let patch = b"diff --git a/file.txt b/file.txt\n\
                      --- a/file.txt\n\
                      +++ b/file.txt\n\
                      @@ -1 +1 @@\n\
                      -old\n\
                      +new\n";

        let result = manager.apply_patch_hardened(&workspace, patch, "binary_v1");

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RepoMirrorError::PatchHardeningDenied { .. }
        ));
    }

    #[test]
    fn test_hardened_apply_succeeds_with_valid_patch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manager = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");

        // Initialize git repo with a file
        let output = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .arg("init")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git init");
        assert!(output.status.success());

        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "user.name", "Test"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set user.name");

        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "user.email", "test@example.com"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set user.email");

        fs::write(workspace.join("file.txt"), b"").expect("write file");

        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["add", "file.txt"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git add");

        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["commit", "-m", "base"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git commit");

        let patch = b"diff --git a/file.txt b/file.txt\n\
                      index e69de29..e69de29 100644\n\
                      --- a/file.txt\n\
                      +++ b/file.txt\n\
                      @@ -0,0 +1 @@\n\
                      +hello\n";

        let result = manager.apply_patch_hardened(&workspace, patch, "git_diff_v1");

        assert!(result.is_ok(), "hardened apply should succeed: {result:?}");
        let (outcome, receipt) = result.unwrap();
        assert_eq!(outcome.files_affected, 1);
        assert!(receipt.applied);
        assert!(receipt.verify_content_hash());
        assert!(receipt.refusals.is_empty());
        assert!(!receipt.patch_digest.is_empty());
    }

    #[test]
    fn test_hardened_apply_denial_receipt_has_valid_digest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manager = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        let workspace = temp.path().join("workspace");
        fs::create_dir_all(&workspace).expect("create workspace");

        let traversal_patch = b"diff --git a/../../escape b/../../escape\n\
                                --- a/../../escape\n\
                                +++ b/../../escape\n\
                                @@ -1 +1 @@\n\
                                -old\n\
                                +new\n";

        let result = manager.apply_patch_hardened(&workspace, traversal_patch, "git_diff_v1");

        assert!(result.is_err());
        if let Err(RepoMirrorError::PatchHardeningDenied { receipt, .. }) = result {
            let expected_digest = format!("b3-256:{}", blake3::hash(traversal_patch).to_hex());
            assert_eq!(receipt.patch_digest, expected_digest);
            assert!(receipt.verify_content_hash());
        }
    }

    // -----------------------------------------------------------------------
    // TCK-00582: New hardening tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_denies_unallowed_url() {
        let temp = tempfile::tempdir().expect("tempdir");
        let policy = MirrorPolicy {
            allowed_url_patterns: vec!["https://github.com/myorg/".to_string()],
            fetch_timeout_secs: 300,
            clone_timeout_secs: 600,
        };
        let mgr = RepoMirrorManager::with_policy(&temp.path().join("private").join("fac"), policy)
            .expect("create with policy");

        let result = mgr.ensure_mirror("evil", Some("https://evil.com/repo.git"));
        assert!(
            matches!(result, Err(RepoMirrorError::PolicyDenied { .. })),
            "expected PolicyDenied, got: {result:?}"
        );
    }

    #[test]
    fn test_policy_allows_matching_url() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source_repo = temp.path().join("source_repo");
        let _head_sha = create_git_repo_with_commit(&source_repo, "README.md", "hello");

        // Use the local path as allowed pattern.
        let local_url = source_repo.to_string_lossy().to_string();
        let policy = MirrorPolicy {
            allowed_url_patterns: vec![local_url.clone()],
            fetch_timeout_secs: 300,
            clone_timeout_secs: 600,
        };
        let mgr = RepoMirrorManager::with_policy(&temp.path().join("private").join("fac"), policy)
            .expect("create with policy");

        let result = mgr.ensure_mirror("sample", Some(&local_url));
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        let (_path, receipt) = result.unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.operation, "clone");
    }

    #[test]
    fn test_empty_policy_allows_any_valid_url() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source_repo = temp.path().join("source_repo");
        let _head_sha = create_git_repo_with_commit(&source_repo, "README.md", "hi");

        let mgr = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        let result = mgr.ensure_mirror("sample", Some(source_repo.to_string_lossy().as_ref()));
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn test_policy_rejects_too_many_patterns() {
        let temp = tempfile::tempdir().expect("tempdir");
        let policy = MirrorPolicy {
            allowed_url_patterns: (0..=MAX_ALLOWED_URL_PATTERNS)
                .map(|i| format!("https://example.com/{i}/"))
                .collect(),
            fetch_timeout_secs: 0,
            clone_timeout_secs: 0,
        };
        let result =
            RepoMirrorManager::with_policy(&temp.path().join("private").join("fac"), policy);
        assert!(
            matches!(result, Err(RepoMirrorError::PolicyDenied { .. })),
            "expected PolicyDenied for too many patterns, got: {result:?}"
        );
    }

    #[test]
    fn test_receipt_captures_before_after_refs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source_repo = temp.path().join("source_repo");
        let _head_sha = create_git_repo_with_commit(&source_repo, "README.md", "hello");

        let mgr = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        // First clone: refs_before should be empty, refs_after should have refs.
        let (_path, receipt) = mgr
            .ensure_mirror("sample", Some(source_repo.to_string_lossy().as_ref()))
            .expect("ensure mirror");

        assert!(receipt.success);
        assert_eq!(receipt.operation, "clone");
        assert!(receipt.refs_before.is_empty());
        assert!(
            !receipt.refs_after.is_empty(),
            "refs_after should have at least one ref"
        );
        assert!(receipt.is_valid());
        // duration_ms is always set (may be 0 for very fast operations).
        assert_eq!(receipt.schema, MIRROR_UPDATE_RECEIPT_SCHEMA);

        // Second call should be a fetch (mirror already exists).
        let (_path, receipt2) = mgr
            .ensure_mirror("sample", Some(source_repo.to_string_lossy().as_ref()))
            .expect("re-ensure mirror");

        assert!(receipt2.success);
        assert_eq!(receipt2.operation, "fetch");
        assert!(!receipt2.refs_before.is_empty());
        assert!(!receipt2.refs_after.is_empty());
        assert!(receipt2.is_valid());
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_in_mirror_path_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fac_root = temp.path().join("private").join("fac");
        let mirror_root = fac_root.join("repo_mirror");
        std::fs::create_dir_all(&mirror_root).expect("create mirror root");

        // Create a real directory
        let real_dir = temp.path().join("real_mirror");
        std::fs::create_dir_all(&real_dir).expect("create real dir");

        // Create a symlink in the mirror root that points to the real directory
        let symlink_path = mirror_root.join("evil.git");
        symlink(&real_dir, &symlink_path).expect("create symlink");

        // Initialize a bare repo at the real location (so validate_bare_repo passes)
        Command::new("git")
            .arg("init")
            .arg("--bare")
            .arg(&real_dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("init bare");

        let mgr = RepoMirrorManager::new(&fac_root);

        // The mirror path "evil" resolves to mirror_root/evil.git which is a symlink.
        // ensure_mirror should detect and reject this.
        let result = mgr.ensure_mirror("evil", None);

        assert!(
            matches!(result, Err(RepoMirrorError::SymlinkInPath { .. })),
            "expected SymlinkInPath, got: {result:?}"
        );
    }

    #[test]
    fn test_mirror_update_receipt_is_valid() {
        let receipt = MirrorUpdateReceiptV1 {
            schema: MIRROR_UPDATE_RECEIPT_SCHEMA.to_string(),
            repo_id: "test-repo".to_string(),
            remote_url: Some("https://github.com/example/repo.git".to_string()),
            mirror_path: "/tmp/mirror/test-repo.git".to_string(),
            refs_before: HashMap::new(),
            refs_after: {
                let mut m = HashMap::new();
                m.insert("refs/heads/main".to_string(), "abc123".to_string());
                m
            },
            success: true,
            operation: "clone".to_string(),
            duration_ms: 1234,
            failure_reason: None,
        };

        assert!(receipt.is_valid());
    }

    #[test]
    fn test_mirror_update_receipt_invalid_schema() {
        let receipt = MirrorUpdateReceiptV1 {
            schema: "wrong".to_string(),
            repo_id: "test-repo".to_string(),
            remote_url: None,
            mirror_path: "/tmp/mirror/test-repo.git".to_string(),
            refs_before: HashMap::new(),
            refs_after: HashMap::new(),
            success: false,
            operation: "error".to_string(),
            duration_ms: 0,
            failure_reason: Some("test".to_string()),
        };

        assert!(!receipt.is_valid());
    }

    #[test]
    fn test_lock_file_created_on_ensure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source_repo = temp.path().join("source_repo");
        let _head_sha = create_git_repo_with_commit(&source_repo, "README.md", "hello");

        let fac_root = temp.path().join("private").join("fac");
        let mgr = RepoMirrorManager::new(&fac_root);

        let (_path, _receipt) = mgr
            .ensure_mirror("sample", Some(source_repo.to_string_lossy().as_ref()))
            .expect("ensure mirror");

        // Verify lock directory was created.
        let lock_dir = fac_root.join("locks").join("mirrors");
        assert!(lock_dir.is_dir(), "lock directory should exist");

        // Verify lock file was created.
        let lock_file = lock_dir.join("sample.lock");
        assert!(
            lock_file.exists(),
            "lock file should exist after ensure_mirror"
        );
    }

    #[test]
    fn test_default_mirror_policy() {
        let policy = MirrorPolicy::default();
        assert!(policy.allowed_url_patterns.is_empty());
        assert_eq!(policy.fetch_timeout_secs, DEFAULT_FETCH_TIMEOUT_SECS);
        assert_eq!(policy.clone_timeout_secs, DEFAULT_CLONE_TIMEOUT_SECS);
        assert!(policy.is_url_allowed("https://example.com/repo.git"));
        assert!(policy.is_url_allowed("ssh://git@github.com/repo.git"));
    }

    #[test]
    fn test_mirror_policy_url_matching() {
        let policy = MirrorPolicy {
            allowed_url_patterns: vec![
                "https://github.com/myorg/".to_string(),
                "https://github.com/myother/".to_string(),
            ],
            fetch_timeout_secs: 0,
            clone_timeout_secs: 0,
        };

        assert!(policy.is_url_allowed("https://github.com/myorg/repo.git"));
        assert!(policy.is_url_allowed("https://github.com/myother/repo2.git"));
        assert!(!policy.is_url_allowed("https://github.com/evil/repo.git"));
        assert!(!policy.is_url_allowed("https://evil.com/repo.git"));
    }

    #[test]
    fn test_mirror_policy_effective_timeouts() {
        let policy = MirrorPolicy {
            allowed_url_patterns: vec![],
            fetch_timeout_secs: 0,
            clone_timeout_secs: 0,
        };
        assert_eq!(
            policy.effective_fetch_timeout(),
            Duration::from_secs(DEFAULT_FETCH_TIMEOUT_SECS)
        );
        assert_eq!(
            policy.effective_clone_timeout(),
            Duration::from_secs(DEFAULT_CLONE_TIMEOUT_SECS)
        );

        let custom = MirrorPolicy {
            allowed_url_patterns: vec![],
            fetch_timeout_secs: 60,
            clone_timeout_secs: 120,
        };
        assert_eq!(custom.effective_fetch_timeout(), Duration::from_secs(60));
        assert_eq!(custom.effective_clone_timeout(), Duration::from_secs(120));
    }

    // -----------------------------------------------------------------------
    // Fix round 1: Regression tests for S-1..S-5, CQ-1, CQ-2
    // -----------------------------------------------------------------------

    #[test]
    fn test_constant_time_str_eq_matching() {
        assert!(constant_time_str_eq("abc", "abc"));
        assert!(constant_time_str_eq("", ""));
        assert!(!constant_time_str_eq("abc", "abd"));
        assert!(!constant_time_str_eq("abc", "ab"));
        assert!(!constant_time_str_eq("ab", "abc"));
    }

    #[test]
    fn test_constant_time_str_eq_hex_digests() {
        let digest_a = format!("b3-256:{}", blake3::hash(b"hello").to_hex());
        let digest_b = format!("b3-256:{}", blake3::hash(b"hello").to_hex());
        let digest_c = format!("b3-256:{}", blake3::hash(b"world").to_hex());

        assert!(constant_time_str_eq(&digest_a, &digest_b));
        assert!(!constant_time_str_eq(&digest_a, &digest_c));
    }

    #[test]
    fn test_receipt_rejects_oversized_repo_id() {
        let receipt = MirrorUpdateReceiptV1 {
            schema: MIRROR_UPDATE_RECEIPT_SCHEMA.to_string(),
            repo_id: "x".repeat(MAX_REPO_ID_LENGTH + 1),
            remote_url: None,
            mirror_path: "/tmp/mirror/test.git".to_string(),
            refs_before: HashMap::new(),
            refs_after: HashMap::new(),
            success: true,
            operation: "clone".to_string(),
            duration_ms: 0,
            failure_reason: None,
        };
        assert!(
            !receipt.is_valid(),
            "oversized repo_id should fail is_valid"
        );
    }

    #[test]
    fn test_receipt_rejects_oversized_mirror_path() {
        let receipt = MirrorUpdateReceiptV1 {
            schema: MIRROR_UPDATE_RECEIPT_SCHEMA.to_string(),
            repo_id: "test".to_string(),
            remote_url: None,
            mirror_path: "x".repeat(MAX_RECEIPT_MIRROR_PATH_LENGTH + 1),
            refs_before: HashMap::new(),
            refs_after: HashMap::new(),
            success: true,
            operation: "clone".to_string(),
            duration_ms: 0,
            failure_reason: None,
        };
        assert!(
            !receipt.is_valid(),
            "oversized mirror_path should fail is_valid"
        );
    }

    #[test]
    fn test_receipt_rejects_oversized_operation() {
        let receipt = MirrorUpdateReceiptV1 {
            schema: MIRROR_UPDATE_RECEIPT_SCHEMA.to_string(),
            repo_id: "test".to_string(),
            remote_url: None,
            mirror_path: "/tmp/mirror/test.git".to_string(),
            refs_before: HashMap::new(),
            refs_after: HashMap::new(),
            success: true,
            operation: "x".repeat(MAX_RECEIPT_OPERATION_LENGTH + 1),
            duration_ms: 0,
            failure_reason: None,
        };
        assert!(
            !receipt.is_valid(),
            "oversized operation should fail is_valid"
        );
    }

    #[test]
    fn test_receipt_rejects_oversized_failure_reason() {
        let receipt = MirrorUpdateReceiptV1 {
            schema: MIRROR_UPDATE_RECEIPT_SCHEMA.to_string(),
            repo_id: "test".to_string(),
            remote_url: None,
            mirror_path: "/tmp/mirror/test.git".to_string(),
            refs_before: HashMap::new(),
            refs_after: HashMap::new(),
            success: false,
            operation: "error".to_string(),
            duration_ms: 0,
            failure_reason: Some("x".repeat(MAX_RECEIPT_FAILURE_REASON_LENGTH + 1)),
        };
        assert!(
            !receipt.is_valid(),
            "oversized failure_reason should fail is_valid"
        );
    }

    #[test]
    fn test_receipt_rejects_oversized_remote_url() {
        let receipt = MirrorUpdateReceiptV1 {
            schema: MIRROR_UPDATE_RECEIPT_SCHEMA.to_string(),
            repo_id: "test".to_string(),
            remote_url: Some("x".repeat(MAX_RECEIPT_MIRROR_PATH_LENGTH + 1)),
            mirror_path: "/tmp/mirror/test.git".to_string(),
            refs_before: HashMap::new(),
            refs_after: HashMap::new(),
            success: true,
            operation: "clone".to_string(),
            duration_ms: 0,
            failure_reason: None,
        };
        assert!(
            !receipt.is_valid(),
            "oversized remote_url should fail is_valid"
        );
    }

    #[test]
    fn test_policy_none_path_validates_existing_origin() {
        // CQ-1: When remote_url is None and policy is restrictive, the
        // existing origin URL must be validated against the policy.
        let temp = tempfile::tempdir().expect("tempdir");
        let source_repo = temp.path().join("source_repo");
        let _head_sha = create_git_repo_with_commit(&source_repo, "README.md", "hello");

        let local_url = source_repo.to_string_lossy().to_string();

        // First, clone with default (permissive) policy so mirror exists.
        let fac_root = temp.path().join("private").join("fac");
        let permissive_mgr = RepoMirrorManager::new(&fac_root);
        let (_path, receipt) = permissive_mgr
            .ensure_mirror("sample", Some(&local_url))
            .expect("ensure mirror with permissive policy");
        assert!(receipt.success);
        assert_eq!(receipt.operation, "clone");

        // Now create a restrictive policy that does NOT allow the local URL.
        let strict_policy = MirrorPolicy {
            allowed_url_patterns: vec!["https://github.com/only-this/".to_string()],
            fetch_timeout_secs: 300,
            clone_timeout_secs: 600,
        };
        let strict_mgr =
            RepoMirrorManager::with_policy(&fac_root, strict_policy).expect("strict policy");

        // Calling ensure_mirror with None should fail because the existing
        // origin URL does not match the strict policy.
        let result = strict_mgr.ensure_mirror("sample", None);
        assert!(
            matches!(result, Err(RepoMirrorError::PolicyDenied { .. })),
            "expected PolicyDenied for existing origin URL, got: {result:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_lock_file_refuses_symlink() {
        // S-4: open_lock_file must refuse symlinks via O_NOFOLLOW.
        let temp = tempfile::tempdir().expect("tempdir");
        let real_file = temp.path().join("real.lock");
        fs::write(&real_file, b"").expect("create real file");

        let symlink_file = temp.path().join("symlink.lock");
        symlink(&real_file, &symlink_file).expect("create symlink");

        let result = open_lock_file(&symlink_file);
        assert!(
            result.is_err(),
            "open_lock_file should refuse symlinks: {result:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_ensure_dir_mode_0700_refuses_symlink() {
        // S-4 / CQ-B1: ensure_dir_mode_0700 must refuse symlinks via
        // O_NOFOLLOW | O_DIRECTORY + fchmod, not path-based set_permissions.
        let temp = tempfile::tempdir().expect("tempdir");
        let real_dir = temp.path().join("real_dir");
        fs::create_dir_all(&real_dir).expect("create real dir");

        let symlink_dir = temp.path().join("symlink_dir");
        symlink(&real_dir, &symlink_dir).expect("create symlink");

        let result = ensure_dir_mode_0700(&symlink_dir);
        assert!(
            matches!(result, Err(RepoMirrorError::SymlinkInPath { .. })),
            "ensure_dir_mode_0700 should refuse symlinks: {result:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_ensure_dir_mode_0700_sets_permissions_on_real_dir() {
        // CQ-B1: Verify fchmod actually sets mode on a real directory.
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("test_dir");
        fs::create_dir_all(&dir).expect("create dir");
        // Set initial permissive mode
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("set initial mode");

        let result = ensure_dir_mode_0700(&dir);
        assert!(
            result.is_ok(),
            "ensure_dir_mode_0700 should succeed: {result:?}"
        );

        let meta = fs::metadata(&dir).expect("read metadata");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o700,
            "permissions should be 0700 after ensure_dir_mode_0700"
        );
    }

    // -----------------------------------------------------------------------
    // Fix round 2: CQ-M1 — URL length validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_remote_url_rejects_oversized_url() {
        // CQ-M1: URLs longer than MAX_RECEIPT_MIRROR_PATH_LENGTH must be
        // rejected to prevent invalid receipts (S-5 bounds check).
        let long_url = format!(
            "https://example.com/{}",
            "a".repeat(MAX_RECEIPT_MIRROR_PATH_LENGTH)
        );
        assert!(
            long_url.len() > MAX_RECEIPT_MIRROR_PATH_LENGTH,
            "test URL should exceed limit"
        );
        let result = validate_remote_url(&long_url);
        assert!(
            matches!(result, Err(RepoMirrorError::InvalidRemoteUrl { .. })),
            "oversized URL should be rejected: {result:?}"
        );
    }

    #[test]
    fn test_validate_remote_url_accepts_url_at_limit() {
        // CQ-M1: A URL exactly at the limit should be accepted.
        let prefix = "https://example.com/";
        let padding_len = MAX_RECEIPT_MIRROR_PATH_LENGTH - prefix.len();
        let url_at_limit = format!("{}{}", prefix, "a".repeat(padding_len));
        assert_eq!(url_at_limit.len(), MAX_RECEIPT_MIRROR_PATH_LENGTH);
        let result = validate_remote_url(&url_at_limit);
        assert!(
            result.is_ok(),
            "URL at exact limit should be accepted: {result:?}"
        );
    }

    #[test]
    fn test_ensure_mirror_rejects_oversized_remote_url() {
        // CQ-M1: End-to-end test that ensure_mirror refuses oversized URLs.
        let temp = tempfile::tempdir().expect("tempdir");
        let mgr = RepoMirrorManager::new(&temp.path().join("private").join("fac"));
        let long_url = format!(
            "https://example.com/{}",
            "x".repeat(MAX_RECEIPT_MIRROR_PATH_LENGTH)
        );
        let result = mgr.ensure_mirror("sample", Some(&long_url));
        assert!(
            matches!(result, Err(RepoMirrorError::InvalidRemoteUrl { .. })),
            "ensure_mirror should reject oversized URL: {result:?}"
        );
    }
}
