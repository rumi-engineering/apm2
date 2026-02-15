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
pub const DENIED_RETENTION_SECS: u64 = 604_800;
const DENIED_DIR: &str = "denied";
const QUARANTINE_DIR: &str = "quarantine";
const LEGACY_QUARANTINE_DIR: &str = "quarantined";
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
pub fn plan_gc(
    fac_root: &Path,
    lane_manager: &LaneManager,
    quarantine_ttl_secs: u64,
    denied_ttl_secs: u64,
) -> Result<GcPlan, GcPlanError> {
    let mut targets = Vec::new();
    let effective_quarantine_ttl =
        effective_retention_seconds(quarantine_ttl_secs, QUARANTINE_RETENTION_SECS);
    let effective_denied_ttl = effective_retention_seconds(denied_ttl_secs, DENIED_RETENTION_SECS);

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

    collect_stale_queue_targets(
        &queue_root,
        QUARANTINE_DIR,
        crate::fac::gc_receipt::GcActionKind::QuarantinePrune,
        effective_quarantine_ttl,
        &mut targets,
    );

    // Legacy directory name — scan for backward compatibility during transition.
    collect_stale_queue_targets(
        &queue_root,
        LEGACY_QUARANTINE_DIR,
        crate::fac::gc_receipt::GcActionKind::QuarantinePrune,
        effective_quarantine_ttl,
        &mut targets,
    );

    collect_stale_queue_targets(
        &queue_root,
        DENIED_DIR,
        crate::fac::gc_receipt::GcActionKind::DeniedPrune,
        effective_denied_ttl,
        &mut targets,
    );

    targets.sort_by(|a, b| b.estimated_bytes.cmp(&a.estimated_bytes));
    Ok(GcPlan { targets })
}

/// Create a focused quarantine/denied GC plan with TTL and quota policy.
///
/// # Errors
///
/// Returns `GcPlanError::Io` when entries cannot be scanned.
pub fn plan_quarantine_prune(
    queue_root: &Path,
    quarantine_ttl_secs: u64,
    denied_ttl_secs: u64,
    quarantine_max_bytes: u64,
    now_secs: u64,
) -> Result<GcPlan, GcPlanError> {
    let effective_quarantine_ttl =
        effective_retention_seconds(quarantine_ttl_secs, QUARANTINE_RETENTION_SECS);
    let effective_denied_ttl = effective_retention_seconds(denied_ttl_secs, DENIED_RETENTION_SECS);
    let effective_quarantine_max_bytes = if quarantine_max_bytes == 0 {
        u64::MAX
    } else {
        quarantine_max_bytes
    };

    let mut quarantine_entries = Vec::new();

    let mut candidates: Vec<(QueueEntry, crate::fac::gc_receipt::GcActionKind)> = Vec::new();
    for entry in collect_queue_entries(queue_root, QUARANTINE_DIR) {
        if is_stale_entry(&entry, effective_quarantine_ttl, now_secs) {
            candidates.push((entry, crate::fac::gc_receipt::GcActionKind::QuarantinePrune));
            continue;
        }
        quarantine_entries.push(entry);
    }

    for entry in collect_queue_entries(queue_root, DENIED_DIR) {
        if is_stale_entry(&entry, effective_denied_ttl, now_secs) {
            candidates.push((entry, crate::fac::gc_receipt::GcActionKind::DeniedPrune));
        }
    }

    let mut quarantine_bytes: u64 = quarantine_entries
        .iter()
        .map(|entry| entry.estimated_bytes)
        .sum();

    let needs_dir_size = effective_quarantine_max_bytes != u64::MAX
        && (quarantine_bytes > effective_quarantine_max_bytes
            || quarantine_entries.iter().any(|entry| entry.path.is_dir()));

    if needs_dir_size {
        for entry in &mut quarantine_entries {
            if entry.path.is_dir() {
                entry.estimated_bytes = estimate_dir_size(&entry.path);
            }
        }
        quarantine_bytes = quarantine_entries
            .iter()
            .map(|entry| entry.estimated_bytes)
            .sum();
    }

    if quarantine_bytes > effective_quarantine_max_bytes
        && effective_quarantine_max_bytes != u64::MAX
    {
        quarantine_entries.sort_by(|a, b| compare_entry_age_then_size_desc(a, b, now_secs));
        for entry in &quarantine_entries {
            if quarantine_bytes <= effective_quarantine_max_bytes {
                break;
            }
            candidates.push((
                entry.clone(),
                crate::fac::gc_receipt::GcActionKind::QuarantinePrune,
            ));
            quarantine_bytes = quarantine_bytes.saturating_sub(entry.estimated_bytes);
        }
    }

    candidates.sort_by(|(a, _), (b, _)| compare_entry_age_then_size_desc(a, b, now_secs));

    Ok(GcPlan {
        targets: candidates
            .into_iter()
            .map(|entry| GcTarget {
                path: entry.0.path,
                allowed_parent: entry.0.allowed_parent,
                kind: entry.1,
                estimated_bytes: entry.0.estimated_bytes,
            })
            .collect(),
    })
}

#[derive(Debug, Clone)]
struct QueueEntry {
    path: PathBuf,
    allowed_parent: PathBuf,
    estimated_bytes: u64,
    modified_secs: u64,
}

fn collect_queue_entries(queue_root: &Path, directory: &str) -> Vec<QueueEntry> {
    let allowed_parent = queue_root.join(directory);
    let Ok(entries) = std::fs::read_dir(&allowed_parent) else {
        return Vec::new();
    };

    let mut count = 0usize;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        count += 1;
        if count > MAX_DIR_ENTRIES {
            break;
        }
        let path = entry.path();
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let Ok(duration) = modified.duration_since(UNIX_EPOCH) else {
            continue;
        };
        let estimated_bytes = metadata.len();
        out.push(QueueEntry {
            path,
            allowed_parent: allowed_parent.clone(),
            estimated_bytes,
            modified_secs: duration.as_secs(),
        });
    }
    out
}

fn compare_entry_age_then_size_desc(
    a: &QueueEntry,
    b: &QueueEntry,
    now: u64,
) -> std::cmp::Ordering {
    let a_age = age_secs(now, a.modified_secs);
    let b_age = age_secs(now, b.modified_secs);
    b_age
        .cmp(&a_age)
        .then_with(|| b.estimated_bytes.cmp(&a.estimated_bytes))
        .then_with(|| a.path.cmp(&b.path))
}

fn collect_stale_queue_targets(
    queue_root: &Path,
    directory: &str,
    kind: crate::fac::gc_receipt::GcActionKind,
    ttl_secs: u64,
    targets: &mut Vec<GcTarget>,
) {
    let now = current_wall_clock_secs();
    for entry in collect_queue_entries(queue_root, directory) {
        if !is_stale_entry(&entry, ttl_secs, now) {
            continue;
        }
        targets.push(GcTarget {
            path: entry.path,
            allowed_parent: entry.allowed_parent,
            kind,
            estimated_bytes: entry.estimated_bytes,
        });
    }
}

const fn age_secs(now: u64, modified_secs: u64) -> u64 {
    now.saturating_sub(modified_secs)
}

const fn is_stale_entry(entry: &QueueEntry, ttl_secs: u64, now: u64) -> bool {
    is_stale_by_mtime_seconds(entry.modified_secs, ttl_secs, now)
}

const fn is_stale_by_mtime_seconds(modified_secs: u64, ttl_secs: u64, now: u64) -> bool {
    ttl_secs != 0 && modified_secs.saturating_add(ttl_secs) <= now
}

const fn effective_retention_seconds(value: u64, fallback: u64) -> u64 {
    if value == 0 { fallback } else { value }
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
                    action_kind: target.kind,
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
    let Ok(metadata) = path.symlink_metadata() else {
        return 0;
    };
    if metadata.file_type().is_symlink() {
        return 0;
    }
    if metadata.is_file() {
        return metadata.len();
    }
    if !metadata.is_dir() {
        return 0;
    }

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
            if metadata.file_type().is_symlink() {
                continue;
            }
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
    use std::thread::sleep;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;
    use crate::fac::lane::{LaneLeaseV1, LaneManager, LaneState};

    fn write_file(path: &Path, size: u64) {
        let file = std::fs::File::create(path).expect("create file");
        file.set_len(size).expect("set file size");
    }

    fn file_modified_secs(path: &Path) -> u64 {
        path.symlink_metadata()
            .expect("metadata")
            .modified()
            .expect("modified")
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_secs()
    }

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

        let plan = plan_gc(
            &fac_root,
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
        )
        .expect("plan");
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

    #[test]
    fn test_plan_quarantine_prune_ttl_expiration_prunes_stale_items() {
        let dir = tempdir().expect("tmp");
        let queue_root = dir.path().join("queue");
        let quarantine_dir = queue_root.join(QUARANTINE_DIR);
        let denied_dir = queue_root.join(DENIED_DIR);
        std::fs::create_dir_all(&quarantine_dir).expect("mkdir quarantine");
        std::fs::create_dir_all(&denied_dir).expect("mkdir denied");

        let quarantine_item = quarantine_dir.join("stale-quarantine.json");
        let denied_item = denied_dir.join("stale-denied.json");
        write_file(&quarantine_item, 10);
        write_file(&denied_item, 20);

        let plan = plan_quarantine_prune(
            &queue_root,
            1,
            1,
            10_000,
            current_wall_clock_secs().saturating_add(10),
        )
        .expect("plan");

        assert_eq!(plan.targets.len(), 2);
        assert!(
            plan.targets
                .iter()
                .any(|target| target.path == quarantine_item)
        );
        assert!(plan.targets.iter().any(|target| target.path == denied_item));
        assert!(plan.targets.iter().any(|target| matches!(
            target.kind,
            crate::fac::gc_receipt::GcActionKind::QuarantinePrune
        )));
        assert!(plan.targets.iter().any(|target| matches!(
            target.kind,
            crate::fac::gc_receipt::GcActionKind::DeniedPrune
        )));
    }

    #[test]
    fn test_plan_quarantine_prune_quota_prunes_oldest_items_first() {
        let dir = tempdir().expect("tmp");
        let queue_root = dir.path().join("queue");
        let quarantine_dir = queue_root.join(QUARANTINE_DIR);
        std::fs::create_dir_all(&quarantine_dir).expect("mkdir quarantine");

        let oldest = quarantine_dir.join("oldest.json");
        let middle = quarantine_dir.join("middle.json");
        let newest = quarantine_dir.join("newest.json");

        write_file(&oldest, 20);
        sleep(Duration::from_secs(1));
        write_file(&middle, 20);
        sleep(Duration::from_secs(1));
        write_file(&newest, 1);

        let entries = collect_queue_entries(&queue_root, QUARANTINE_DIR);
        let now_secs = current_wall_clock_secs().saturating_add(10);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.estimated_bytes)
                .sum::<u64>(),
            41
        );
        assert!(
            entries.iter().all(|entry| !is_stale_entry(
                entry,
                effective_retention_seconds(QUARANTINE_RETENTION_SECS, QUARANTINE_RETENTION_SECS),
                now_secs
            )),
            "quota test entries must be within TTL"
        );

        let plan = plan_quarantine_prune(
            &queue_root,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
            15,
            now_secs,
        )
        .expect("plan");

        assert_eq!(plan.targets.len(), 2);
        assert_eq!(plan.targets[0].path, oldest);
        assert_eq!(plan.targets[1].path, middle);
    }

    #[test]
    fn test_plan_quarantine_prune_eviction_order_oldest_then_largest() {
        let dir = tempdir().expect("tmp");
        let queue_root = dir.path().join("queue");
        let quarantine_dir = queue_root.join(QUARANTINE_DIR);
        std::fs::create_dir_all(&quarantine_dir).expect("mkdir quarantine");

        let (large_same_age_entry, small_same_age_entry) = (0..20)
            .find_map(|attempt| {
                let large = quarantine_dir.join(format!("same-age-large-{attempt}.json"));
                let small = quarantine_dir.join(format!("same-age-small-{attempt}.json"));

                write_file(&large, 30);
                write_file(&small, 20);

                if file_modified_secs(&large) == file_modified_secs(&small) {
                    Some((large, small))
                } else {
                    let _ = std::fs::remove_file(&large);
                    let _ = std::fs::remove_file(&small);
                    sleep(Duration::from_secs(1));
                    None
                }
            })
            .expect("same-age entries");

        let older_modified_secs = file_modified_secs(&small_same_age_entry);
        let _newer_entry = (0..20)
            .find_map(|attempt| {
                let candidate = quarantine_dir.join(format!("newer-{attempt}.json"));
                write_file(&candidate, 1);
                if file_modified_secs(&candidate) > older_modified_secs {
                    Some(candidate)
                } else {
                    let _ = std::fs::remove_file(&candidate);
                    sleep(Duration::from_secs(1));
                    None
                }
            })
            .expect("newer entry");

        let entries = collect_queue_entries(&queue_root, QUARANTINE_DIR);
        let now_secs = current_wall_clock_secs().saturating_add(10);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.estimated_bytes)
                .sum::<u64>(),
            51
        );
        assert!(
            entries.iter().all(|entry| !is_stale_entry(
                entry,
                effective_retention_seconds(QUARANTINE_RETENTION_SECS, QUARANTINE_RETENTION_SECS),
                now_secs
            )),
            "eviction ordering test entries must be within TTL"
        );

        let plan = plan_quarantine_prune(
            &queue_root,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
            15,
            now_secs,
        )
        .expect("plan");

        assert_eq!(plan.targets.len(), 2);
        assert_eq!(plan.targets[0].path, large_same_age_entry);
        assert_eq!(plan.targets[1].path, small_same_age_entry);
    }
}
