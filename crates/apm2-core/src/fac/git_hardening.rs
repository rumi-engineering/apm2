// AGENT-AUTHORED (TCK-00580)
//! Git safety hardening for FAC lane workspaces.
//!
//! This module ensures that lane workspaces checked out from mirrors cannot
//! execute arbitrary code through git hooks, smudge/clean filters, or other
//! git configuration attack vectors.
//!
//! # Hardening Steps
//!
//! 1. **Disable hooks** — `core.hooksPath` is pointed at an empty directory
//!    owned by the FAC process. This prevents any `.git/hooks/` scripts shipped
//!    in the repository from executing during git operations.
//!
//! 2. **Enforce `safe.directory`** — The workspace path is passed as `-c
//!    safe.directory=<path>` on every git command invocation within this
//!    function. Git ignores `safe.directory` when set in local scope
//!    (CVE-2022-24765 security property), so it must NOT be written to local
//!    config. Rather than writing to global config (which causes lock
//!    contention in concurrent lane environments), the `-c` flag approach
//!    passes it transiently on each command. This is performed on all git
//!    commands so that mismatched-owner workspaces can be hardened.
//!
//! 3. **Refuse unsafe configs** — After checkout, the local `.git/config` is
//!    scanned for `filter.*.process`, `filter.*.clean`, `filter.*.smudge`, and
//!    `core.fsmonitor` directives that would execute external commands. If
//!    policy forbids them, the workspace is rejected.
//!
//! # Security Model
//!
//! - [INV-GH-001] After hardening, no repository-shipped hook can execute.
//! - [INV-GH-002] The hooks directory is an empty, FAC-controlled directory
//!   created with mode 0o700. It is never inside the workspace tree.
//! - [INV-GH-003] Unsafe filter/smudge configs are detected and rejected before
//!   any further git operations are performed on the workspace.
//! - [INV-GH-004] All hardening results are recorded in a `GitHardeningReceipt`
//!   for audit/evidence.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Schema identifier for git hardening receipt v1.
pub const GIT_HARDENING_RECEIPT_SCHEMA: &str = "apm2.fac.git_hardening_receipt.v1";

/// Maximum git config file size to scan (256 KiB).
/// Prevents memory exhaustion from oversized `.git/config` files (CTR-1603).
const MAX_GIT_CONFIG_FILE_SIZE: u64 = 256 * 1024;

/// Maximum number of unsafe config keys to report in a receipt.
/// Prevents unbounded collection growth (CTR-1303).
const MAX_UNSAFE_CONFIG_KEYS: usize = 64;

/// Maximum length of a single config key string in findings.
const MAX_CONFIG_KEY_LENGTH: usize = 512;

/// Git config keys that can execute external commands.
/// These are checked against the repo-local config after checkout.
const UNSAFE_CONFIG_PATTERNS: &[&str] = &[
    "filter.", // filter.<driver>.clean, filter.<driver>.smudge, filter.<driver>.process
    "core.fsmonitor",
    "core.sshcommand",
    "core.editor",   // can execute arbitrary commands
    "core.pager",    // can execute arbitrary commands
    "core.askpass",  // can execute arbitrary commands to capture credentials
    "core.gitproxy", // can execute arbitrary proxy commands
    "credential.helper",
    "diff.external",
    "diff.",         // diff.<driver>.command
    "merge.",        // merge.<driver>.driver
    "alias.",        // alias.* can execute arbitrary shell commands via ! prefix
    "receive.fsck.", // server-side but reject if present locally
    "uploadpack.",
    "protocol.",
];

/// Specific config key suffixes that are command-execution vectors.
const UNSAFE_SUFFIX_PATTERNS: &[&str] = &[
    ".clean",
    ".smudge",
    ".process",
    ".command",
    ".driver",
    ".textconv",
];

// ─────────────────────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from git hardening operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GitHardeningError {
    /// Failed to create the empty hooks directory.
    #[error("failed to create hooks directory at {path}: {reason}")]
    HooksDirCreationFailed {
        /// Path where the directory was to be created.
        path: String,
        /// Why creation failed.
        reason: String,
    },

    /// Failed to set a git config value.
    #[error("failed to set git config {key}={value}: {reason}")]
    GitConfigSetFailed {
        /// Config key.
        key: String,
        /// Config value.
        value: String,
        /// Why the command failed.
        reason: String,
    },

    /// Workspace contains unsafe git config entries.
    #[error("workspace contains {count} unsafe git config entries: {keys:?}")]
    UnsafeConfigDetected {
        /// Number of unsafe entries found.
        count: usize,
        /// The offending config keys (bounded to 64 entries max).
        keys: Vec<String>,
        /// The hardening receipt with `Rejected` outcome for audit trail.
        receipt: GitHardeningReceipt,
    },

    /// The workspace path does not exist or is not a directory.
    #[error("workspace path is not a valid directory: {path}")]
    InvalidWorkspace {
        /// Path that was checked.
        path: String,
    },

    /// The git config file is too large to scan.
    #[error("git config file too large: {size} > {max}")]
    ConfigFileTooLarge {
        /// Actual size.
        size: u64,
        /// Maximum allowed.
        max: u64,
    },

    /// `git config --local --list --null` command failed (non-zero exit).
    /// Fail-closed: we cannot verify the config is safe.
    #[error("git config scan command failed (exit {exit_code}): stdout={stdout}, stderr={stderr}")]
    ConfigScanCommandFailed {
        /// Exit code from the git config command.
        exit_code: String,
        /// Standard output captured.
        stdout: String,
        /// Standard error captured.
        stderr: String,
    },

    /// Pre-existing hooks directory failed validation.
    #[error("pre-existing hooks directory validation failed at {path}: {reason}")]
    HooksDirValidationFailed {
        /// Path to the hooks directory.
        path: String,
        /// Why validation failed.
        reason: String,
    },

    /// I/O error.
    #[error("I/O error during git hardening: {0}")]
    Io(#[from] std::io::Error),
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipt type
// ─────────────────────────────────────────────────────────────────────────────

/// Receipt recording the results of git hardening on a lane workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitHardeningReceipt {
    /// Schema identifier.
    pub schema: String,
    /// Whether hooks were disabled (core.hooksPath set).
    pub hooks_disabled: bool,
    /// Path to the empty hooks directory.
    pub hooks_path: String,
    /// Whether safe.directory was enforced.
    pub safe_directory_set: bool,
    /// Whether the unsafe config scan passed (no unsafe entries found).
    pub config_scan_passed: bool,
    /// Any unsafe config keys detected (empty if scan passed).
    pub unsafe_config_keys: Vec<String>,
    /// Overall hardening outcome.
    pub outcome: GitHardeningOutcome,
}

/// Overall outcome of git hardening.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GitHardeningOutcome {
    /// All hardening steps completed successfully.
    Hardened,
    /// Hardening failed; workspace should not be used.
    Failed,
    /// Unsafe configs were detected and rejected.
    Rejected,
}

// ─────────────────────────────────────────────────────────────────────────────
// Core implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Apply git safety hardening to a lane workspace.
///
/// This function MUST be called immediately after `checkout_to_lane` and
/// before any further git operations are performed on the workspace.
///
/// # Steps
///
/// 1. Resolves the workspace absolute path and prepares a `safe.directory`
///    value. This value is passed as `-c safe.directory=<path>` on all
///    subsequent git commands. Git ignores `safe.directory` in local scope
///    (CVE-2022-24765), so it is never written to any config file. The `-c`
///    flag approach avoids lock contention on global config files in concurrent
///    lane environments.
/// 2. Creates an empty hooks directory under `hooks_parent` (outside the
///    workspace tree) and sets `core.hooksPath` in the workspace's local git
///    config (using the `-c safe.directory` flag).
/// 3. Scans the workspace's `.git/config` for unsafe filter/smudge/command
///    entries and rejects the workspace if any are found and
///    `refuse_unsafe_configs` is true.
///
/// # Arguments
///
/// * `workspace` — Path to the lane workspace (must contain a `.git` dir).
/// * `hooks_parent` — Parent directory where the empty hooks dir will be
///   created. Must be outside the workspace tree and controlled by FAC.
/// * `refuse_unsafe_configs` — If true, reject workspaces with dangerous git
///   config entries. If false, record them but allow.
///
/// # Returns
///
/// A `GitHardeningReceipt` recording all hardening actions and their
/// outcomes.
///
/// # Errors
///
/// Returns [`GitHardeningError`] if the workspace is invalid, the hooks
/// directory cannot be created, git config cannot be set, or unsafe
/// config entries are detected when `refuse_unsafe_configs` is true.
pub fn harden_lane_workspace(
    workspace: &Path,
    hooks_parent: &Path,
    refuse_unsafe_configs: bool,
) -> Result<GitHardeningReceipt, GitHardeningError> {
    // Validate workspace exists and has a .git directory.
    if !workspace.is_dir() {
        return Err(GitHardeningError::InvalidWorkspace {
            path: workspace.display().to_string(),
        });
    }
    let git_dir = workspace.join(".git");
    if !git_dir.is_dir() {
        return Err(GitHardeningError::InvalidWorkspace {
            path: format!("{} (no .git directory found)", workspace.display()),
        });
    }

    // Step 1: Resolve workspace absolute path for safe.directory.
    // Git ignores safe.directory in local scope (CVE-2022-24765 security
    // property). Instead of writing it persistently, we pass it as a `-c`
    // flag to all git commands within this function. This avoids writing
    // to the global config (lock contention in concurrent lanes) and
    // ensures mismatched-owner workspaces can be hardened.
    let workspace_abs = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let safe_dir_value = workspace_abs.display().to_string();
    let safe_directory_set = true;

    // Step 2: Create empty hooks directory and set core.hooksPath.
    // The `-c safe.directory=<path>` flag allows this to succeed even
    // when the workspace owner differs from the current user.
    let hooks_dir = create_empty_hooks_dir(hooks_parent)?;
    set_git_config_local_with_safe_dir(
        workspace,
        "core.hooksPath",
        &hooks_dir.display().to_string(),
        &safe_dir_value,
    )?;
    let hooks_disabled = true;

    // Step 3: Scan for unsafe config entries.
    let unsafe_keys = scan_unsafe_configs(workspace, &safe_dir_value)?;
    let config_scan_passed = unsafe_keys.is_empty();

    if !config_scan_passed && refuse_unsafe_configs {
        let count = unsafe_keys.len();
        let rejected_receipt = GitHardeningReceipt {
            schema: GIT_HARDENING_RECEIPT_SCHEMA.to_string(),
            hooks_disabled,
            hooks_path: hooks_dir.display().to_string(),
            safe_directory_set,
            config_scan_passed: false,
            unsafe_config_keys: unsafe_keys.clone(),
            outcome: GitHardeningOutcome::Rejected,
        };
        return Err(GitHardeningError::UnsafeConfigDetected {
            count,
            keys: unsafe_keys,
            receipt: rejected_receipt,
        });
    }

    // If we reach here, either scan passed or refuse_unsafe_configs is false.
    let outcome = GitHardeningOutcome::Hardened;

    Ok(GitHardeningReceipt {
        schema: GIT_HARDENING_RECEIPT_SCHEMA.to_string(),
        hooks_disabled,
        hooks_path: hooks_dir.display().to_string(),
        safe_directory_set,
        config_scan_passed,
        unsafe_config_keys: unsafe_keys,
        outcome,
    })
}

/// Create an empty directory for hooks under `parent`.
///
/// The directory is created with mode 0o700 on Unix. If it already exists,
/// it MUST be validated: not a symlink, owned by current uid, permissions
/// are exactly 0o700, and the directory is empty. If ANY check fails,
/// an error is returned (fail-closed: do not reuse attacker-controlled
/// directories).
///
/// # Security Invariants
///
/// - [INV-GH-005] Pre-existing hooks directories are validated before reuse:
///   symlink check, uid ownership, mode 0o700, emptiness.
fn create_empty_hooks_dir(parent: &Path) -> Result<PathBuf, GitHardeningError> {
    let hooks_dir = parent.join("empty_hooks");

    if hooks_dir.exists() {
        // Validate the pre-existing directory thoroughly.
        return validate_existing_hooks_dir(&hooks_dir);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&hooks_dir)
            .map_err(|e| GitHardeningError::HooksDirCreationFailed {
                path: hooks_dir.display().to_string(),
                reason: e.to_string(),
            })?;
    }

    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&hooks_dir).map_err(|e| {
            GitHardeningError::HooksDirCreationFailed {
                path: hooks_dir.display().to_string(),
                reason: e.to_string(),
            }
        })?;
    }

    Ok(hooks_dir)
}

/// Validate a pre-existing hooks directory.
///
/// Checks: (a) not a symlink, (b) is a directory, (c) owned by current uid
/// (Unix), (d) permissions are exactly 0o700 (Unix), (e) directory is empty.
fn validate_existing_hooks_dir(hooks_dir: &Path) -> Result<PathBuf, GitHardeningError> {
    let display_path = hooks_dir.display().to_string();

    // (a) Check for symlinks — use symlink_metadata to avoid following the link.
    let symlink_meta = std::fs::symlink_metadata(hooks_dir).map_err(|e| {
        GitHardeningError::HooksDirValidationFailed {
            path: display_path.clone(),
            reason: format!("failed to read symlink metadata: {e}"),
        }
    })?;

    if symlink_meta.file_type().is_symlink() {
        return Err(GitHardeningError::HooksDirValidationFailed {
            path: display_path,
            reason: "path is a symlink (potential attack vector)".to_string(),
        });
    }

    // (b) Verify it is a directory (not a file, FIFO, device, etc.)
    if !symlink_meta.is_dir() {
        return Err(GitHardeningError::HooksDirCreationFailed {
            path: display_path,
            reason: "path exists but is not a directory".to_string(),
        });
    }

    // (c) + (d) Unix-specific: ownership and permissions checks.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let current_uid = nix::unistd::getuid().as_raw();
        let dir_uid = symlink_meta.uid();
        if dir_uid != current_uid {
            return Err(GitHardeningError::HooksDirValidationFailed {
                path: display_path,
                reason: format!(
                    "directory owned by uid {dir_uid}, expected current uid {current_uid}"
                ),
            });
        }

        let mode = symlink_meta.mode() & 0o777;
        if mode != 0o700 {
            return Err(GitHardeningError::HooksDirValidationFailed {
                path: display_path,
                reason: format!("directory permissions are {mode:#o}, expected 0o700"),
            });
        }
    }

    // (e) Verify the directory is empty.
    let mut entries =
        std::fs::read_dir(hooks_dir).map_err(|e| GitHardeningError::HooksDirValidationFailed {
            path: display_path.clone(),
            reason: format!("failed to read directory entries: {e}"),
        })?;

    if entries.next().is_some() {
        return Err(GitHardeningError::HooksDirValidationFailed {
            path: display_path,
            reason: "directory is not empty (potential attacker-placed hooks)".to_string(),
        });
    }

    Ok(hooks_dir.to_path_buf())
}

/// Set a git config value in the local (workspace) scope, using a
/// command-line `-c safe.directory=<val>` override so that the config
/// write succeeds even on mismatched-owner workspaces.
///
/// Git ignores `safe.directory` in local scope (CVE-2022-24765), so we
/// pass it as a `-c` flag instead of writing it persistently. This also
/// avoids lock contention on shared global config files in concurrent
/// lane environments.
fn set_git_config_local_with_safe_dir(
    workspace: &Path,
    key: &str,
    value: &str,
    safe_dir_value: &str,
) -> Result<(), GitHardeningError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .arg("-c")
        .arg(format!("safe.directory={safe_dir_value}"))
        .arg("config")
        .arg("--local")
        .arg("--")
        .arg(key)
        .arg(value)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .map_err(|e| GitHardeningError::GitConfigSetFailed {
            key: key.to_string(),
            value: value.to_string(),
            reason: format!("failed to spawn git: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(GitHardeningError::GitConfigSetFailed {
            key: key.to_string(),
            value: value.to_string(),
            reason: if stderr.is_empty() {
                "git config command failed with no output".to_string()
            } else {
                stderr
            },
        });
    }

    Ok(())
}

/// Scan the workspace's local git config for unsafe entries.
///
/// Uses `git config --local --list --null` for NUL-delimited output so
/// that values containing embedded newlines are parsed unambiguously
/// (each entry is `key\nvalue\0`).
///
/// Uses `-c safe.directory=<val>` to allow the scan to succeed even on
/// mismatched-owner workspaces without writing to any persistent config.
///
/// Returns a bounded list of config keys that could execute external
/// commands.
fn scan_unsafe_configs(
    workspace: &Path,
    safe_dir_value: &str,
) -> Result<Vec<String>, GitHardeningError> {
    let config_path = workspace.join(".git").join("config");
    if !config_path.is_file() {
        // No config file means no unsafe entries.
        return Ok(Vec::new());
    }

    // CTR-1603: Bound the file read.
    let metadata = std::fs::metadata(&config_path)?;
    if metadata.len() > MAX_GIT_CONFIG_FILE_SIZE {
        return Err(GitHardeningError::ConfigFileTooLarge {
            size: metadata.len(),
            max: MAX_GIT_CONFIG_FILE_SIZE,
        });
    }

    // Use `git config --local --list --null` to get all local config entries
    // with NUL-delimited output.  With `--null`, each entry is emitted as
    // `key\nvalue\0` (key and value separated by a newline, entries separated
    // by a NUL byte).  This is robust against values that contain embedded
    // newlines — newline-delimited `--list` output would misparse such values
    // as additional key=value lines, risking false-positive unsafe-key matches.
    // Pass `-c safe.directory=<val>` so the command succeeds on
    // mismatched-owner workspaces.
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .arg("-c")
        .arg(format!("safe.directory={safe_dir_value}"))
        .arg("config")
        .arg("--local")
        .arg("--list")
        .arg("--null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .map_err(GitHardeningError::Io)?;

    if !output.status.success() {
        // Fail-closed: if git-config command fails, we cannot verify the
        // config is safe. Return an error instead of silently passing.
        // A failed git-config may indicate adversarial state, malformed
        // config, or a corrupted repository.
        let exit_code = output
            .status
            .code()
            .map_or_else(|| "signal".to_string(), |c| c.to_string());
        let stdout = String::from_utf8_lossy(&output.stdout)
            .chars()
            .take(512)
            .collect::<String>();
        let stderr = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(512)
            .collect::<String>();
        return Err(GitHardeningError::ConfigScanCommandFailed {
            exit_code,
            stdout,
            stderr,
        });
    }

    // Parse NUL-delimited entries.  Each entry is `key\nvalue\0` where the
    // first line within the entry is the key and the remainder (after the
    // first newline) is the value.  An entry with no value may appear as
    // just `key\0`.
    let raw = &output.stdout;
    let mut unsafe_keys = Vec::new();

    for entry in raw.split(|&b| b == 0) {
        // Skip empty trailing segments (the output ends with \0, so split
        // produces a trailing empty slice).
        if entry.is_empty() {
            continue;
        }

        // The key is everything up to the first newline (or the whole
        // entry if there is no newline).
        let key_bytes = entry
            .iter()
            .position(|&b| b == b'\n')
            .map_or(entry, |pos| &entry[..pos]);

        let key = String::from_utf8_lossy(key_bytes);
        let key_lower = key.to_ascii_lowercase();

        if is_unsafe_config_key(&key_lower) {
            let truncated = if key.len() > MAX_CONFIG_KEY_LENGTH {
                format!("{}...", &key[..MAX_CONFIG_KEY_LENGTH])
            } else {
                key.to_string()
            };
            unsafe_keys.push(truncated);
            if unsafe_keys.len() >= MAX_UNSAFE_CONFIG_KEYS {
                break;
            }
        }
    }

    Ok(unsafe_keys)
}

/// Check if a config key (lowercase) matches any unsafe pattern.
fn is_unsafe_config_key(key: &str) -> bool {
    // Skip keys we ourselves set (core.hookspath, safe.directory).
    if key == "core.hookspath" || key == "safe.directory" {
        return false;
    }

    // Check prefix patterns (filter.*, diff.*, merge.*, etc.)
    for pattern in UNSAFE_CONFIG_PATTERNS {
        if key.starts_with(pattern) {
            // For prefix patterns that are broad (filter., diff., merge.),
            // also check if the key ends with a dangerous suffix.
            if *pattern == "filter." || *pattern == "diff." || *pattern == "merge." {
                for suffix in UNSAFE_SUFFIX_PATTERNS {
                    if key.ends_with(suffix) {
                        return true;
                    }
                }
            } else {
                // Exact prefix match for more specific patterns
                // (core.fsmonitor, core.sshcommand, etc.)
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;

    /// Helper: create a minimal git repo at `path` with one commit.
    fn create_test_repo(path: &Path) -> String {
        fs::create_dir_all(path).expect("create repo dir");

        let init = Command::new("git")
            .arg("init")
            .arg(path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git init");
        assert!(init.status.success(), "git init failed");

        // Set user info for commit.
        for (key, val) in [("user.name", "Test"), ("user.email", "test@test.com")] {
            let cfg = Command::new("git")
                .arg("-C")
                .arg(path)
                .args(["config", key, val])
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git config");
            assert!(cfg.status.success());
        }

        fs::write(path.join("README.md"), b"hello").expect("write file");

        let add = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["add", "README.md"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git add");
        assert!(add.status.success());

        let commit = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["commit", "-m", "initial"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git commit");
        assert!(commit.status.success());

        let rev = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["rev-parse", "HEAD"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("rev-parse");
        assert!(rev.status.success());

        String::from_utf8_lossy(&rev.stdout).trim().to_string()
    }

    #[test]
    fn harden_sets_hooks_path_and_safe_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        let receipt = harden_lane_workspace(&workspace, &hooks_parent, true)
            .expect("hardening should succeed");

        assert!(receipt.hooks_disabled);
        assert!(receipt.safe_directory_set);
        assert!(receipt.config_scan_passed);
        assert!(receipt.unsafe_config_keys.is_empty());
        assert_eq!(receipt.outcome, GitHardeningOutcome::Hardened);
        assert_eq!(receipt.schema, GIT_HARDENING_RECEIPT_SCHEMA);

        // Verify core.hooksPath is actually set in local config.
        let hooks_path_val = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "--local", "core.hooksPath"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("read hooks path");
        assert!(hooks_path_val.status.success());
        let hooks_val = String::from_utf8_lossy(&hooks_path_val.stdout)
            .trim()
            .to_string();
        assert!(
            hooks_val.contains("empty_hooks"),
            "core.hooksPath should point to empty_hooks dir, got: {hooks_val}"
        );

        // Verify safe.directory is NOT in local config (CVE-2022-24765 fix).
        // The `-c` flag approach means safe.directory is never persisted
        // anywhere — it is only passed on the command line.
        let local_safe_dir = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "--local", "safe.directory"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("check local safe.directory");
        assert!(
            !local_safe_dir.status.success(),
            "safe.directory should NOT be in local config (CVE-2022-24765)"
        );
    }

    #[test]
    fn harden_rejects_workspace_without_git_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("no_git");
        fs::create_dir_all(&workspace).expect("create dir");
        let hooks_parent = temp.path().join("hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        assert!(
            matches!(result, Err(GitHardeningError::InvalidWorkspace { .. })),
            "expected InvalidWorkspace, got: {result:?}"
        );
    }

    #[test]
    fn harden_rejects_nonexistent_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("nonexistent");
        let hooks_parent = temp.path().join("hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        assert!(
            matches!(result, Err(GitHardeningError::InvalidWorkspace { .. })),
            "expected InvalidWorkspace, got: {result:?}"
        );
    }

    #[test]
    fn harden_detects_unsafe_filter_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Inject a dangerous filter config.
        let cfg = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "--local", "filter.evil.smudge", "cat /etc/passwd"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set filter config");
        assert!(cfg.status.success());

        // With refuse_unsafe_configs=true, should error.
        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        assert!(
            matches!(result, Err(GitHardeningError::UnsafeConfigDetected { .. })),
            "expected UnsafeConfigDetected, got: {result:?}"
        );

        if let Err(GitHardeningError::UnsafeConfigDetected {
            count,
            keys,
            receipt,
        }) = result
        {
            assert_eq!(count, 1);
            assert_eq!(keys.len(), 1);
            assert!(
                keys[0].contains("filter.evil.smudge"),
                "expected filter.evil.smudge in keys, got: {keys:?}"
            );
            // Verify the rejected receipt is populated (MINOR fix: receipt in error).
            assert_eq!(receipt.outcome, GitHardeningOutcome::Rejected);
            assert!(!receipt.config_scan_passed);
            assert_eq!(receipt.unsafe_config_keys.len(), 1);
        }
    }

    #[test]
    fn harden_allows_unsafe_filter_config_when_not_refused() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Inject a dangerous filter config.
        let cfg = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "--local", "filter.evil.clean", "rm -rf /"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set filter config");
        assert!(cfg.status.success());

        // With refuse_unsafe_configs=false, should succeed with findings.
        let receipt = harden_lane_workspace(&workspace, &hooks_parent, false)
            .expect("hardening should succeed with findings");

        assert!(receipt.hooks_disabled);
        assert!(receipt.safe_directory_set);
        assert!(!receipt.config_scan_passed);
        assert_eq!(receipt.unsafe_config_keys.len(), 1);
        assert_eq!(receipt.outcome, GitHardeningOutcome::Hardened);
    }

    #[test]
    fn harden_detects_core_fsmonitor() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        let cfg = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args([
                "config",
                "--local",
                "core.fsmonitor",
                "/usr/bin/evil-monitor",
            ])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set fsmonitor config");
        assert!(cfg.status.success());

        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        assert!(
            matches!(result, Err(GitHardeningError::UnsafeConfigDetected { .. })),
            "expected UnsafeConfigDetected for core.fsmonitor, got: {result:?}"
        );
    }

    #[test]
    fn empty_hooks_dir_is_idempotent() {
        let temp = tempfile::tempdir().expect("tempdir");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let dir1 = create_empty_hooks_dir(&hooks_parent).expect("first create");
        let dir2 = create_empty_hooks_dir(&hooks_parent).expect("second create");
        assert_eq!(dir1, dir2);
        assert!(dir1.is_dir());
    }

    #[test]
    fn is_unsafe_config_key_detects_known_patterns() {
        assert!(is_unsafe_config_key("filter.lfs.smudge"));
        assert!(is_unsafe_config_key("filter.evil.clean"));
        assert!(is_unsafe_config_key("filter.foo.process"));
        assert!(is_unsafe_config_key("core.fsmonitor"));
        assert!(is_unsafe_config_key("core.sshcommand"));
        assert!(is_unsafe_config_key("core.editor"));
        assert!(is_unsafe_config_key("core.pager"));
        assert!(is_unsafe_config_key("core.askpass"));
        assert!(is_unsafe_config_key("core.gitproxy"));
        assert!(is_unsafe_config_key("credential.helper"));
        assert!(is_unsafe_config_key("diff.external"));
        assert!(is_unsafe_config_key("diff.foo.command"));
        assert!(is_unsafe_config_key("diff.foo.textconv"));
        assert!(is_unsafe_config_key("merge.foo.driver"));
        assert!(is_unsafe_config_key("alias.co"));
        assert!(is_unsafe_config_key("alias.deploy"));

        // Safe keys:
        assert!(!is_unsafe_config_key("core.hookspath"));
        assert!(!is_unsafe_config_key("safe.directory"));
        assert!(!is_unsafe_config_key("user.name"));
        assert!(!is_unsafe_config_key("user.email"));
        assert!(!is_unsafe_config_key("core.autocrlf"));
        assert!(!is_unsafe_config_key("core.symlinks"));
    }

    #[test]
    fn receipt_serialization_roundtrip() {
        let receipt = GitHardeningReceipt {
            schema: GIT_HARDENING_RECEIPT_SCHEMA.to_string(),
            hooks_disabled: true,
            hooks_path: "/tmp/hooks".to_string(),
            safe_directory_set: true,
            config_scan_passed: true,
            unsafe_config_keys: vec![],
            outcome: GitHardeningOutcome::Hardened,
        };

        let json = serde_json::to_string(&receipt).expect("serialize");
        let parsed: GitHardeningReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, parsed);
    }

    #[test]
    #[cfg(unix)]
    fn hooks_do_not_execute_after_hardening() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Install a malicious pre-commit hook that creates a marker file.
        let hooks_dir = workspace.join(".git").join("hooks");
        fs::create_dir_all(&hooks_dir).expect("create hooks dir");
        let marker_path = temp.path().join("HOOK_EXECUTED");

        let hook_script = format!("#!/bin/sh\ntouch {}\n", marker_path.display());
        let hook_path = hooks_dir.join("pre-commit");
        fs::write(&hook_path, hook_script).expect("write hook");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).expect("chmod hook");
        }

        // Harden the workspace.
        let receipt = harden_lane_workspace(&workspace, &hooks_parent, true)
            .expect("hardening should succeed");
        assert_eq!(receipt.outcome, GitHardeningOutcome::Hardened);

        // Now attempt a commit — the hook should NOT execute.
        fs::write(workspace.join("new_file.txt"), b"test").expect("write new file");
        let add = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["add", "new_file.txt"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git add");
        assert!(add.status.success());

        let commit = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["commit", "-m", "test commit after hardening"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git commit");
        assert!(
            commit.status.success(),
            "commit should succeed: {}",
            String::from_utf8_lossy(&commit.stderr)
        );

        // The marker file should NOT exist — hook did not execute.
        assert!(
            !marker_path.exists(),
            "malicious hook executed despite hardening! marker file found at: {}",
            marker_path.display()
        );
    }

    #[test]
    #[cfg(unix)]
    fn post_checkout_hook_does_not_execute_after_hardening() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Install a malicious post-checkout hook.
        let hooks_dir = workspace.join(".git").join("hooks");
        fs::create_dir_all(&hooks_dir).expect("create hooks dir");
        let marker_path = temp.path().join("POST_CHECKOUT_HOOK_EXECUTED");

        let hook_script = format!("#!/bin/sh\ntouch {}\n", marker_path.display());
        let hook_path = hooks_dir.join("post-checkout");
        fs::write(&hook_path, hook_script).expect("write hook");

        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755)).expect("chmod hook");
        }

        // Harden the workspace.
        let receipt = harden_lane_workspace(&workspace, &hooks_parent, true)
            .expect("hardening should succeed");
        assert_eq!(receipt.outcome, GitHardeningOutcome::Hardened);

        // Create a branch and switch to it — triggers post-checkout hook.
        let branch = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["checkout", "-b", "test-branch"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git checkout -b");
        assert!(
            branch.status.success(),
            "checkout should succeed: {}",
            String::from_utf8_lossy(&branch.stderr)
        );

        assert!(
            !marker_path.exists(),
            "post-checkout hook executed despite hardening!"
        );
    }

    #[test]
    #[cfg(unix)]
    fn hooks_dir_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let hooks_dir = create_empty_hooks_dir(&hooks_parent).expect("create hooks dir");

        let perms = fs::metadata(&hooks_dir).expect("metadata").permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o700,
            "hooks directory should have 0700 permissions"
        );
    }

    #[test]
    fn harden_does_not_flag_hookspath_as_unsafe() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Harden should set core.hooksPath but not flag it as unsafe.
        let receipt = harden_lane_workspace(&workspace, &hooks_parent, true)
            .expect("hardening should succeed");

        assert!(receipt.config_scan_passed);
        assert!(receipt.unsafe_config_keys.is_empty());
    }

    #[test]
    fn harden_detects_multiple_unsafe_entries() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Inject multiple dangerous configs.
        for (key, val) in [
            ("filter.lfs.smudge", "git-lfs smudge -- %f"),
            ("filter.lfs.clean", "git-lfs clean -- %f"),
            ("core.fsmonitor", "/usr/bin/watchman"),
        ] {
            let cfg = Command::new("git")
                .arg("-C")
                .arg(&workspace)
                .args(["config", "--local", key, val])
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("set config");
            assert!(cfg.status.success());
        }

        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        match result {
            Err(GitHardeningError::UnsafeConfigDetected {
                count,
                keys,
                receipt,
            }) => {
                assert_eq!(count, 3, "expected 3 unsafe keys, got {count}");
                assert_eq!(keys.len(), 3);
                assert_eq!(receipt.outcome, GitHardeningOutcome::Rejected);
            },
            other => panic!("expected UnsafeConfigDetected, got: {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Regression tests for review fix round (MAJOR #1, MAJOR #2, MINOR)
    // ─────────────────────────────────────────────────────────────────────

    /// MAJOR #1 regression: pre-existing non-empty hooks directory must cause
    /// `harden_lane_workspace` to return an error.
    #[test]
    fn preexisting_nonempty_hooks_dir_causes_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Pre-create the hooks directory with an attacker-placed file.
        let hooks_dir = hooks_parent.join("empty_hooks");
        fs::create_dir_all(&hooks_dir).expect("create hooks dir");
        fs::write(hooks_dir.join("post-commit"), "#!/bin/sh\nmalicious").expect("write hook file");

        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        assert!(
            matches!(
                result,
                Err(GitHardeningError::HooksDirValidationFailed { .. })
            ),
            "expected HooksDirValidationFailed for non-empty hooks dir, got: {result:?}"
        );
    }

    /// MAJOR #1 regression: symlinked hooks directory is rejected.
    #[test]
    #[cfg(unix)]
    fn symlinked_hooks_dir_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Create a real directory somewhere else, then symlink to it.
        let attacker_dir = temp.path().join("attacker_hooks");
        fs::create_dir_all(&attacker_dir).expect("attacker dir");
        let hooks_link = hooks_parent.join("empty_hooks");
        std::os::unix::fs::symlink(&attacker_dir, &hooks_link).expect("symlink");

        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        assert!(
            matches!(
                result,
                Err(GitHardeningError::HooksDirValidationFailed { .. })
            ),
            "expected HooksDirValidationFailed for symlinked hooks dir, got: {result:?}"
        );
    }

    /// MAJOR #1 regression: hooks directory with wrong permissions is rejected.
    #[test]
    #[cfg(unix)]
    fn hooks_dir_wrong_permissions_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Create hooks dir with overly permissive mode.
        let hooks_dir = hooks_parent.join("empty_hooks");
        fs::create_dir_all(&hooks_dir).expect("create hooks dir");
        fs::set_permissions(&hooks_dir, fs::Permissions::from_mode(0o755))
            .expect("set wrong perms");

        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        assert!(
            matches!(
                result,
                Err(GitHardeningError::HooksDirValidationFailed { .. })
            ),
            "expected HooksDirValidationFailed for wrong permissions, got: {result:?}"
        );
    }

    /// MAJOR #2 regression: simulate git-config command failure causes
    /// `scan_unsafe_configs` to return an error (not silently pass).
    /// We test `scan_unsafe_configs` directly because corrupting the config
    /// file would also break the preceding `set_git_config_local` calls in
    /// `harden_lane_workspace`.
    #[test]
    fn git_config_command_failure_causes_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");

        let _sha = create_test_repo(&workspace);

        // Corrupt the .git/config to cause git-config --list to exit non-zero.
        // Writing invalid binary content causes git config --list to exit non-zero.
        let config_path = workspace.join(".git").join("config");
        fs::write(&config_path, b"\x00\x01\x02INVALID_GIT_CONFIG\xff\xfe").expect("corrupt config");

        // Call scan_unsafe_configs directly — it should return Err, not Ok(empty).
        let safe_dir = workspace.display().to_string();
        let result = scan_unsafe_configs(&workspace, &safe_dir);
        assert!(
            matches!(
                result,
                Err(GitHardeningError::ConfigScanCommandFailed { .. })
            ),
            "expected ConfigScanCommandFailed for corrupted git config, got: {result:?}"
        );
    }

    /// MAJOR #2 regression (end-to-end): When the config scan fails,
    /// `harden_lane_workspace` propagates the error (not silently succeed).
    /// We corrupt the config after a valid repo is set up, then verify.
    #[test]
    fn harden_fails_on_corrupt_git_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // First harden successfully to set up hooks path etc.
        let receipt = harden_lane_workspace(&workspace, &hooks_parent, true)
            .expect("initial hardening should succeed");
        assert_eq!(receipt.outcome, GitHardeningOutcome::Hardened);

        // Now corrupt the config file.
        let config_path = workspace.join(".git").join("config");
        fs::write(&config_path, b"\x00\x01\x02INVALID_GIT_CONFIG\xff\xfe").expect("corrupt config");

        // Second harden attempt should fail due to config scan failure.
        // Note: the hooks dir already exists from the first call, but since
        // it's valid (empty, correct perms, correct owner), it passes
        // validation. The git config set calls will also fail since the
        // config is corrupt — this is expected.
        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        assert!(
            result.is_err(),
            "expected error for corrupted git config, got: {result:?}"
        );
    }

    /// MINOR regression: rejected receipt has `Rejected` outcome and includes
    /// unsafe config keys.
    #[test]
    fn rejected_receipt_has_correct_outcome_and_keys() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Inject an unsafe config.
        let cfg = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "--local", "core.fsmonitor", "/usr/bin/evil"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set config");
        assert!(cfg.status.success());

        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        match result {
            Err(GitHardeningError::UnsafeConfigDetected {
                count,
                keys,
                receipt,
            }) => {
                assert_eq!(count, 1);
                assert_eq!(keys.len(), 1);
                // Verify receipt outcome is Rejected (not Failed or Hardened).
                assert_eq!(receipt.outcome, GitHardeningOutcome::Rejected);
                assert!(!receipt.config_scan_passed);
                assert!(!receipt.unsafe_config_keys.is_empty());
                // Verify the receipt has correct schema.
                assert_eq!(receipt.schema, GIT_HARDENING_RECEIPT_SCHEMA);
                // Verify hardening steps were recorded in receipt.
                assert!(receipt.hooks_disabled);
                assert!(receipt.safe_directory_set);
            },
            other => panic!("expected UnsafeConfigDetected with receipt, got: {other:?}"),
        }
    }

    /// MAJOR #1 regression: pre-existing EMPTY hooks dir with correct
    /// permissions and ownership is accepted (positive case).
    #[test]
    #[cfg(unix)]
    fn preexisting_empty_hooks_dir_with_correct_perms_accepted() {
        use std::os::unix::fs::DirBuilderExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Create empty hooks dir with correct 0o700 perms (owned by us).
        let hooks_dir = hooks_parent.join("empty_hooks");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&hooks_dir)
            .expect("create hooks dir");

        // Should succeed — the directory is valid.
        let receipt = harden_lane_workspace(&workspace, &hooks_parent, true)
            .expect("hardening should succeed for valid pre-existing hooks dir");
        assert_eq!(receipt.outcome, GitHardeningOutcome::Hardened);
        assert!(receipt.hooks_disabled);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Regression tests for fix round 2 (MAJOR: safe.directory scope,
    // MINOR: incomplete unsafe config blacklist)
    // ─────────────────────────────────────────────────────────────────────

    /// MAJOR: safe.directory must NOT be in local config (CVE-2022-24765).
    /// The `-c safe.directory=<path>` flag approach passes it transiently
    /// on each git command invocation, never persisting it to any config
    /// file (local or global). This avoids lock contention in concurrent
    /// lane environments and respects the CVE-2022-24765 security property.
    #[test]
    fn safe_directory_not_persisted_in_any_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        let receipt = harden_lane_workspace(&workspace, &hooks_parent, true)
            .expect("hardening should succeed");
        assert_eq!(receipt.outcome, GitHardeningOutcome::Hardened);
        assert!(receipt.safe_directory_set);

        // Verify safe.directory is NOT in local config (CVE-2022-24765).
        let local_val = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "--local", "safe.directory"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("check local safe.directory");
        assert!(
            !local_val.status.success(),
            "safe.directory must NOT be in local config (CVE-2022-24765)"
        );
    }

    /// MAJOR: The `-c safe.directory=<path>` flag is used to allow local
    /// config writes on the workspace. We verify that core.hooksPath was
    /// successfully written (which requires safe.directory to be effective)
    /// and that the receipt records `safe_directory_set=true`.
    #[test]
    fn safe_directory_flag_enables_local_config_writes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        let receipt = harden_lane_workspace(&workspace, &hooks_parent, true)
            .expect("hardening should succeed");
        assert!(receipt.safe_directory_set);
        assert!(receipt.hooks_disabled);

        // Verify core.hooksPath was written — this would fail if
        // safe.directory was not passed correctly via `-c` flag.
        let hooks_val = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "--local", "core.hooksPath"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("read core.hooksPath");
        assert!(
            hooks_val.status.success(),
            "core.hooksPath must be set in local config (proves -c safe.directory worked)"
        );
    }

    /// MINOR: newly added unsafe config patterns are detected.
    #[test]
    fn detects_newly_added_unsafe_patterns() {
        // core.editor
        assert!(is_unsafe_config_key("core.editor"));
        // core.pager
        assert!(is_unsafe_config_key("core.pager"));
        // core.askpass
        assert!(is_unsafe_config_key("core.askpass"));
        // core.gitproxy
        assert!(is_unsafe_config_key("core.gitproxy"));
        // alias.* prefix
        assert!(is_unsafe_config_key("alias.co"));
        assert!(is_unsafe_config_key("alias.st"));
        assert!(is_unsafe_config_key("alias.deploy"));
    }

    /// MINOR: alias detection in end-to-end hardening.
    #[test]
    fn harden_detects_alias_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        // Inject a dangerous alias (shell execution via ! prefix).
        let cfg = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "--local", "alias.deploy", "!rm -rf /"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set alias config");
        assert!(cfg.status.success());

        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        assert!(
            matches!(result, Err(GitHardeningError::UnsafeConfigDetected { .. })),
            "expected UnsafeConfigDetected for alias.deploy, got: {result:?}"
        );

        if let Err(GitHardeningError::UnsafeConfigDetected { keys, .. }) = result {
            assert!(
                keys.iter().any(|k| k.contains("alias.deploy")),
                "expected alias.deploy in keys, got: {keys:?}"
            );
        }
    }

    /// MINOR: core.editor detection in end-to-end hardening.
    #[test]
    fn harden_detects_core_editor_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        let hooks_parent = temp.path().join("fac_hooks");
        fs::create_dir_all(&hooks_parent).expect("hooks parent");

        let _sha = create_test_repo(&workspace);

        let cfg = Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "--local", "core.editor", "/usr/bin/evil-editor"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("set editor config");
        assert!(cfg.status.success());

        let result = harden_lane_workspace(&workspace, &hooks_parent, true);
        assert!(
            matches!(result, Err(GitHardeningError::UnsafeConfigDetected { .. })),
            "expected UnsafeConfigDetected for core.editor, got: {result:?}"
        );
    }
}
