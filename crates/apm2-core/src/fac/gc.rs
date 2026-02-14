use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fac::GcReceiptV1;
use crate::fac::flock_util::try_acquire_exclusive_nonblocking;
use crate::fac::lane::{LaneManager, LaneState};
use crate::fac::safe_rmtree::{
    MAX_DIR_ENTRIES, SafeRmtreeError, SafeRmtreeOutcome, safe_rmtree_v1,
};

pub const GATE_CACHE_TTL_SECS: u64 = 2_592_000;
pub const QUARANTINE_RETENTION_SECS: u64 = 2_592_000;
const CARGO_HOME_RETENTION_SECS: u64 = 30 * 24 * 3600;
const FAC_CARGO_HOME_DIR: &str = "cargo_home";
const FAC_LEGACY_EVIDENCE_DIR: &str = "evidence";
/// Maximum recursion depth for directory-size estimation.
const MAX_TRAVERSAL_DEPTH: usize = 64;
// Must not exceed safe_rmtree::MAX_DIR_ENTRIES.

#[derive(Debug, Clone)]
pub struct GcPlan {
    pub targets: Vec<GcTarget>,
}

#[derive(Debug, Clone)]
pub struct GcTarget {
    pub path: PathBuf,
    pub allowed_parent: PathBuf,
    pub kind: crate::fac::gc_receipt::GcActionKind,
    pub estimated_bytes: u64,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum GcPlanError {
    Io(String),
    Precondition(String),
}

/// Create a garbage-collection plan from all known FAC artifacts.
///
/// # Errors
///
/// Returns `GcPlanError::Io` when workspace inspection fails.
pub fn plan_gc(fac_root: &Path, lane_manager: &LaneManager) -> Result<GcPlan, GcPlanError> {
    let mut targets = Vec::new();
    let statuses = lane_manager
        .all_lane_statuses()
        .map_err(|error| GcPlanError::Io(error.to_string()))?;

    for status in statuses {
        if status.state != LaneState::Idle {
            continue;
        }
        let lane_dir = lane_manager.lane_dir(&status.lane_id);
        let target_dir = lane_dir.join("target");
        let log_dir = lane_dir.join("logs");

        if target_dir.exists() {
            targets.push(GcTarget {
                path: target_dir.clone(),
                allowed_parent: lane_dir.clone(),
                kind: crate::fac::gc_receipt::GcActionKind::LaneTarget,
                estimated_bytes: estimate_dir_size(&target_dir),
            });
        }
        if log_dir.exists() {
            targets.push(GcTarget {
                path: log_dir.clone(),
                allowed_parent: lane_dir.clone(),
                kind: crate::fac::gc_receipt::GcActionKind::LaneLog,
                estimated_bytes: estimate_dir_size(&log_dir),
            });
        }
    }

    let gate_cache_root = fac_root.join("gate_cache_v2");
    if let Ok(entries) = std::fs::read_dir(&gate_cache_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_stale_by_mtime(&path, GATE_CACHE_TTL_SECS) {
                targets.push(GcTarget {
                    path: path.clone(),
                    allowed_parent: gate_cache_root.clone(),
                    kind: crate::fac::gc_receipt::GcActionKind::GateCache,
                    estimated_bytes: estimate_dir_size(&path),
                });
            }
        }
    }

    let queue_root = infer_queue_root(fac_root);
    let cargo_home_root = fac_root.join(FAC_CARGO_HOME_DIR);
    let legacy_evidence_root = fac_root.join(FAC_LEGACY_EVIDENCE_DIR);

    if cargo_home_root.exists() && is_stale_by_mtime(&cargo_home_root, CARGO_HOME_RETENTION_SECS) {
        targets.push(GcTarget {
            path: cargo_home_root.clone(),
            allowed_parent: fac_root.to_path_buf(),
            kind: crate::fac::gc_receipt::GcActionKind::CargoCache,
            estimated_bytes: estimate_dir_size(&cargo_home_root),
        });
    }

    if legacy_evidence_root.exists() {
        targets.push(GcTarget {
            path: legacy_evidence_root.clone(),
            allowed_parent: fac_root.to_path_buf(),
            kind: crate::fac::gc_receipt::GcActionKind::LaneLog,
            estimated_bytes: estimate_dir_size(&legacy_evidence_root),
        });
    }

    let quarantine_root = queue_root.join("quarantine");
    if let Ok(entries) = std::fs::read_dir(&quarantine_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_stale_by_mtime(&path, QUARANTINE_RETENTION_SECS) {
                targets.push(GcTarget {
                    path: path.clone(),
                    allowed_parent: quarantine_root.clone(),
                    kind: crate::fac::gc_receipt::GcActionKind::QuarantinePrune,
                    estimated_bytes: estimate_dir_size(&path),
                });
            }
        }
    }

    // Legacy directory name — scan for backward compatibility during transition.
    let legacy_quarantine_root = queue_root.join("quarantined");
    if let Ok(entries) = std::fs::read_dir(&legacy_quarantine_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_stale_by_mtime(&path, QUARANTINE_RETENTION_SECS) {
                targets.push(GcTarget {
                    path: path.clone(),
                    allowed_parent: legacy_quarantine_root.clone(),
                    kind: crate::fac::gc_receipt::GcActionKind::QuarantinePrune,
                    estimated_bytes: estimate_dir_size(&path),
                });
            }
        }
    }

    targets.sort_by(|a, b| b.estimated_bytes.cmp(&a.estimated_bytes));
    Ok(GcPlan { targets })
}

/// Execute a garbage-collection plan and produce a best-effort receipt.
///
/// # Errors
///
/// This function records all per-target failures into `errors` and does not
/// abort early.
#[must_use]
pub fn execute_gc(plan: &GcPlan) -> GcReceiptV1 {
    let now = current_wall_clock_secs();

    let mut actions = Vec::new();
    let mut errors = Vec::new();

    for target in &plan.targets {
        let result = if matches!(
            target.kind,
            crate::fac::gc_receipt::GcActionKind::LaneTarget
                | crate::fac::gc_receipt::GcActionKind::LaneLog
        ) {
            let _lock_guard = match try_acquire_lane_lock(&target.path) {
                Ok(Some(lock_guard)) => lock_guard,
                Ok(None) => {
                    errors.push(crate::fac::gc_receipt::GcError {
                        target_path: target.path.display().to_string(),
                        reason: "lane is busy or lock is unavailable".to_string(),
                    });
                    continue;
                },
                Err(error) => {
                    eprintln!(
                        "WARNING: lock check failed for {}: {error}, skipping",
                        target.path.display()
                    );
                    errors.push(crate::fac::gc_receipt::GcError {
                        target_path: target.path.display().to_string(),
                        reason: format!("lock check failed: {error}"),
                    });
                    continue;
                },
            };
            // `_lock_guard` remains alive for the scope of this deletion.
            safe_rmtree_v1(&target.path, &target.allowed_parent)
        } else {
            safe_rmtree_v1(&target.path, &target.allowed_parent)
        };

        match result {
            Ok(outcome) => {
                let (files_deleted, dirs_deleted) = match outcome {
                    SafeRmtreeOutcome::Deleted {
                        files_deleted,
                        dirs_deleted,
                    } => (files_deleted, dirs_deleted),
                    SafeRmtreeOutcome::AlreadyAbsent => (0, 0),
                };
                actions.push(crate::fac::gc_receipt::GcAction {
                    target_path: target.path.display().to_string(),
                    action_kind: target.kind.clone(),
                    bytes_freed: target.estimated_bytes,
                    files_deleted,
                    dirs_deleted,
                });
            },
            Err(error) => {
                errors.push(crate::fac::gc_receipt::GcError {
                    target_path: target.path.display().to_string(),
                    reason: safe_rmtree_error_to_string(error),
                });
            },
        }
    }

    GcReceiptV1 {
        schema: crate::fac::gc_receipt::GC_RECEIPT_SCHEMA.to_string(),
        receipt_id: String::new(),
        timestamp_secs: now,
        before_free_bytes: 0,
        after_free_bytes: 0,
        min_free_threshold: 0,
        actions,
        errors,
        content_hash: String::new(),
    }
}

fn safe_rmtree_error_to_string(error: SafeRmtreeError) -> String {
    match error {
        SafeRmtreeError::OutsideAllowedParent {
            root,
            allowed_parent,
        } => format!(
            "outside_allowed_parent:{}:{}",
            root.display(),
            allowed_parent.display()
        ),
        SafeRmtreeError::Io { context, source } => format!("io:{context}:{source}"),
        SafeRmtreeError::SymlinkDetected { path } => {
            format!("symlink_detected:{}", path.display())
        },
        SafeRmtreeError::CrossesFilesystemBoundary {
            root_dev,
            parent_dev,
        } => format!("crosses_filesystem_boundary:{root_dev}:{parent_dev}"),
        SafeRmtreeError::UnexpectedFileType { path, file_type } => {
            format!("unexpected_file_type:{}:{file_type}", path.display())
        },
        SafeRmtreeError::NotAbsolute { path } => format!("path_not_absolute:{}", path.display()),
        SafeRmtreeError::PermissionDenied { reason } => format!("permission_denied:{reason}"),
        SafeRmtreeError::TocTouRace { reason } => format!("toctou_race:{reason}"),
        SafeRmtreeError::DepthExceeded { path, max } => {
            format!("depth_exceeded:{}:{max}", path.display())
        },
        SafeRmtreeError::TooManyEntries { path, max } => {
            format!("too_many_entries:{}:{max}", path.display())
        },
        SafeRmtreeError::DotSegment { path } => format!("dot_segment:{}", path.display()),
    }
}

// SECURITY JUSTIFICATION (CTR-2501): GC staleness and receipt timestamps use
// wall-clock time because GC is an operational maintenance task, not a
// coordinated consensus operation. GC decisions are local-only and do not
// participate in HTF temporal ordering.
//
// The disallowed_methods lint is narrowly bypassed only for this maintenance
// path.
#[allow(clippy::disallowed_methods)]
fn current_wall_clock_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn estimate_dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = Vec::from([(path.to_path_buf(), 0usize)]);
    let mut entries_count = 0usize;

    while let Some(current) = stack.pop() {
        let (current, depth) = current;
        if depth >= MAX_TRAVERSAL_DEPTH {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            entries_count += 1;
            if entries_count >= MAX_DIR_ENTRIES {
                return total;
            }
            let entry_path = entry.path();
            let Ok(metadata) = entry_path.symlink_metadata() else {
                continue;
            };
            if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            } else if metadata.is_dir() {
                stack.push((entry_path, depth + 1));
            }
        }
    }
    total
}

fn is_stale_by_mtime(path: &Path, ttl_seconds: u64) -> bool {
    if ttl_seconds == 0 {
        return false;
    }
    let Ok(metadata) = path.symlink_metadata() else {
        return false;
    };
    let Ok(mtime) = metadata.modified().and_then(|m| {
        m.duration_since(UNIX_EPOCH)
            .map_err(|_| std::io::ErrorKind::InvalidData.into())
    }) else {
        return false;
    };
    let now = current_wall_clock_secs();
    if now == 0 {
        return false;
    }
    mtime.as_secs().saturating_add(ttl_seconds) <= now
}

fn infer_queue_root(fac_root: &Path) -> PathBuf {
    fac_root.parent().and_then(Path::parent).map_or_else(
        || fac_root.join("queue"),
        |apm2_home| apm2_home.join("queue"),
    )
}

fn try_acquire_lane_lock(path: &Path) -> Result<Option<std::fs::File>, std::io::Error> {
    let lane_root = match path.file_name().and_then(|name| name.to_str()) {
        Some("target" | "logs") => path.parent(),
        _ => None,
    };
    let Some(lane_root) = lane_root else {
        return Ok(None);
    };
    if !lane_root.exists() {
        return Ok(None);
    }
    let fac_root = lane_root.parent().and_then(Path::parent).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "cannot locate FAC root")
    })?;
    let locks_dir = fac_root.join("locks").join("lanes");
    let lane_name = lane_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid lane path")
        })?;
    let lock_path = locks_dir.join(format!("{lane_name}.lock"));
    if !lock_path.exists() {
        return Ok(None);
    }
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    if try_acquire_exclusive_nonblocking(&lock_file)? {
        Ok(Some(lock_file))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::fac::lane::{LaneLeaseV1, LaneManager, LaneState};

    #[test]
    fn test_gc_plan_skips_running_lanes() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("dir setup");

        let lane_id = "lane-00";
        let lane_dir = lane_manager.lane_dir(lane_id);
        let _lane_lock = lane_manager
            .try_lock(lane_id)
            .expect("lock")
            .expect("acquired");
        let lease = LaneLeaseV1::new(
            lane_id,
            "job-001",
            1234,
            LaneState::Running,
            "2026-01-01T00:00:00Z",
            "fp-lane",
            "fp-toolchain",
        )
        .expect("lease");
        lease.persist(&lane_dir).expect("persist lease");

        let plan = plan_gc(&fac_root, &lane_manager).expect("plan");
        assert!(
            !plan
                .targets
                .iter()
                .any(|target| target.path.to_string_lossy().contains(lane_id)),
            "running lanes must be skipped"
        );
    }

    #[test]
    fn test_gc_uses_safe_rmtree() {
        let temp = tempdir().expect("tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(temp.path(), perms).expect("set restrictive permissions");
        }

        let facade = GcTarget {
            path: temp.path().join("x"),
            allowed_parent: temp.path().to_path_buf(),
            kind: crate::fac::gc_receipt::GcActionKind::CargoCache,
            estimated_bytes: 10,
        };
        let plan = GcPlan {
            targets: vec![facade],
        };
        std::fs::create_dir_all(temp.path().join("x")).expect("dir");
        let r = execute_gc(&plan);
        assert!(r.actions.len() == 1 || r.errors.len() == 1);
        assert_eq!(r.errors.len(), 0);
        assert!(!temp.path().join("x").exists());
    }
}
