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

use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use thiserror::Error;

use super::safe_rmtree::{SafeRmtreeError, safe_rmtree_v1};

/// Schema identifier for repository mirror metadata.
pub const REPO_MIRROR_SCHEMA: &str = "apm2.fac.repo_mirror.v1";
/// Maximum allowed repository identifier length.
pub const MAX_REPO_ID_LENGTH: usize = 256;
/// Maximum allowed mirror directory name length.
pub const MAX_MIRROR_DIR_NAME: usize = 280;
/// Maximum number of bare mirrors to retain before eviction.
pub const MAX_MIRROR_COUNT: usize = 64;
/// Maximum patch size in bytes.
pub const MAX_PATCH_SIZE: usize = 10_485_760;

/// Mirrors and lane workspaces for FAC execution.
pub struct RepoMirrorManager {
    mirror_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutOutcome {
    pub repo_id: String,
    pub head_sha: String,
    pub workspace_path: PathBuf,
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
}

impl RepoMirrorManager {
    /// Creates a mirror manager rooted at the FAC mirror directory.
    pub fn new(fac_root: &Path) -> Self {
        Self {
            mirror_root: fac_root.join("repo_mirror"),
        }
    }

    /// Returns the path to the bare mirror for `repo_id`.
    pub fn mirror_path(&self, repo_id: &str) -> PathBuf {
        self.mirror_root.join(format!("{repo_id}.git"))
    }

    /// Ensure a bare mirror exists for `repo_id` and, if possible, updated.
    ///
    /// If the mirror exists, a fetch is performed when the mirror has at
    /// least one configured remote.
    /// If `remote_url` is present, it is configured as `origin` and then used
    /// to fetch updates.
    pub fn ensure_mirror(
        &self,
        repo_id: &str,
        remote_url: Option<&str>,
    ) -> Result<PathBuf, RepoMirrorError> {
        validate_repo_id(repo_id)?;
        let mirror_path = self.mirror_path(repo_id);
        ensure_dir_mode_0700(&self.mirror_root)?;

        if mirror_path.exists() {
            if !mirror_path.is_dir() {
                return Err(RepoMirrorError::MirrorInitFailed {
                    reason: format!(
                        "mirror path exists but is not a directory: {}",
                        mirror_path.display()
                    ),
                });
            }

            validate_bare_repo(&mirror_path)?;

            match remote_url {
                Some(url) => {
                    validate_remote_url(url)?;
                    set_or_replace_remote(&mirror_path, url)?;
                    git_fetch(&mirror_path)?;
                },
                None => {
                    if mirror_has_remote(&mirror_path)? {
                        git_fetch(&mirror_path)?;
                    }
                },
            }

            return Ok(mirror_path);
        }

        let remote_url = remote_url.ok_or_else(|| RepoMirrorError::MirrorNotFound {
            repo_id: repo_id.to_string(),
            reason: "mirror does not exist and no remote_url provided for bootstrap".to_string(),
        })?;
        validate_remote_url(remote_url)?;

        self.evict_if_needed()?;

        // Create a new bare mirror.
        git_command(
            &[
                "clone",
                "--bare",
                "--",
                remote_url,
                mirror_path.to_string_lossy().as_ref(),
            ],
            None,
            |reason| RepoMirrorError::MirrorInitFailed {
                reason: reason.to_string(),
            },
        )?;

        Ok(mirror_path)
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

        if with_time.len() <= MAX_MIRROR_COUNT {
            return Ok(());
        }

        with_time.sort_by_key(|(_, t)| *t);
        let to_remove = with_time.len() - MAX_MIRROR_COUNT;

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
        if actual_sha != head_sha {
            return Err(RepoMirrorError::ShaMismatch {
                expected: head_sha.to_string(),
                actual: actual_sha,
            });
        }

        Ok(CheckoutOutcome {
            repo_id: repo_id.to_string(),
            head_sha: head_sha.to_string(),
            workspace_path: lane_workspace.to_path_buf(),
        })
    }

    /// Apply patch bytes to a checked-out lane workspace and return a digest.
    pub fn apply_patch(
        &self,
        lane_workspace: &Path,
        patch_bytes: &[u8],
    ) -> Result<PatchOutcome, RepoMirrorError> {
        if patch_bytes.len() > MAX_PATCH_SIZE {
            return Err(RepoMirrorError::PatchApplyFailed {
                reason: format!("patch too large: {}", patch_bytes.len()),
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

#[cfg(unix)]
fn ensure_dir_mode_0700(path: &Path) -> Result<(), RepoMirrorError> {
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(RepoMirrorError::Io)?;
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(RepoMirrorError::Io)
}

#[cfg(not(unix))]
fn ensure_dir_mode_0700(path: &Path) -> Result<(), RepoMirrorError> {
    if path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(path).map_err(RepoMirrorError::Io)
}

fn git_command(
    args: &[&str],
    cwd: Option<&Path>,
    make_error: impl Fn(&str) -> RepoMirrorError,
) -> Result<String, RepoMirrorError> {
    let mut cmd = Command::new("git");
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.args(args);

    let output = cmd
        .output()
        .map_err(|e| make_error(&format!("failed to spawn git: {e}")))?;

    if !output.status.success() {
        let mut reason = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if reason.is_empty() {
            reason = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
        if reason.is_empty() {
            reason = "git command failed with no output".to_string();
        }
        return Err(make_error(&reason));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

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

fn git_fetch(mirror_path: &Path) -> Result<(), RepoMirrorError> {
    git_command(
        &[
            "-C",
            mirror_path.to_string_lossy().as_ref(),
            "fetch",
            "--all",
            "--prune",
        ],
        None,
        |reason| RepoMirrorError::MirrorInitFailed {
            reason: reason.to_string(),
        },
    )
    .map(|_| ())
}

fn validate_remote_url(remote_url: &str) -> Result<(), RepoMirrorError> {
    if remote_url.is_empty() {
        return Err(RepoMirrorError::InvalidRemoteUrl {
            reason: "remote URL must not be empty".to_string(),
        });
    }
    if remote_url.starts_with('-') {
        return Err(RepoMirrorError::InvalidRemoteUrl {
            reason: "remote URL must not start with hyphen".to_string(),
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
    fn test_ensure_mirror_rejects_injected_remote_url() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mgr = RepoMirrorManager::new(&temp.path().join("private").join("fac"));

        assert!(matches!(
            mgr.ensure_mirror("sample", Some("-attacker")),
            Err(RepoMirrorError::InvalidRemoteUrl { .. })
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
        let head_sha = create_git_repo_with_commit(&source_repo, "README.md", "hello");

        let _ = manager
            .ensure_mirror("new", Some(source_repo.to_string_lossy().as_ref()))
            .expect("ensure mirror after eviction");
        assert!(manager.mirror_path("new").exists());
        assert!(!manager.mirror_path("repo-0").exists());

        let mirror_root = manager.mirror_root;
        let count = std::fs::read_dir(mirror_root)
            .expect("read mirror root")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("git"))
            .count();

        assert_eq!(count, MAX_MIRROR_COUNT + 1);
        assert_eq!(head_sha.len(), 40);
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

        let mirror_path = manager
            .ensure_mirror("sample", Some(source_repo.to_string_lossy().as_ref()))
            .expect("ensure mirror");
        assert!(mirror_path.ends_with("sample.git"));

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
        let mirror_path = manager
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
        let mirror_path = manager
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
}
