use std::collections::HashSet;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::fac::GcReceiptV1;
use crate::fac::blob_store::{BLOB_DIR, BlobStore};
use crate::fac::flock_util::try_acquire_exclusive_nonblocking;
use crate::fac::job_spec::parse_b3_256_digest;
use crate::fac::lane::{LaneManager, LaneState, LaneStatusV1};
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
const FAC_RECEIPTS_DIR: &str = "receipts";
const MAX_RECEIPT_SCAN_ENTRIES: usize = 500_000;
const MAX_RECEIPT_SCAN_FILES: usize = 500_000;
const MAX_LIVE_BLOB_HASHES: usize = 500_000;
/// Hard cap on total directory entries visited during receipt scanning
/// (before any filtering). Prevents unbounded traversal of large directory
/// trees that contain many non-JSON or old files.
const MAX_RECEIPT_SCAN_VISITED: usize = 1_000_000;
/// Maximum size for a single receipt file read (1 MiB).
const MAX_RECEIPT_READ_SIZE: u64 = 1_048_576;
pub const BLOB_RETENTION_SECS: u64 = 7 * 86_400;
/// Only receipts within this time window are considered for blob reference
/// tracking. Receipts older than this cannot prevent blob pruning.
const RECEIPT_REFERENCE_HORIZON_SECS: u64 = BLOB_RETENTION_SECS * 2;
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
    let effective_quarantine_ttl =
        effective_retention_seconds(quarantine_ttl_secs, QUARANTINE_RETENTION_SECS);
    let effective_denied_ttl = effective_retention_seconds(denied_ttl_secs, DENIED_RETENTION_SECS);
    let now_secs = current_wall_clock_secs();
    let known_lane_ids = LaneManager::default_lane_ids();

    let statuses = load_lane_statuses(lane_manager, &known_lane_ids)?;
    let mut targets = collect_idle_lane_targets(lane_manager, &statuses, &known_lane_ids);

    let gate_cache_root = fac_root.join("gate_cache_v2");
    if let Ok(entries) = std::fs::read_dir(&gate_cache_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_stale_by_mtime(&path, GATE_CACHE_TTL_SECS, now_secs) {
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

    if cargo_home_root.exists()
        && is_stale_by_mtime(&cargo_home_root, CARGO_HOME_RETENTION_SECS, now_secs)
    {
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
        now_secs,
        &mut targets,
    );

    // Legacy directory name — scan for backward compatibility during transition.
    collect_stale_queue_targets(
        &queue_root,
        LEGACY_QUARANTINE_DIR,
        crate::fac::gc_receipt::GcActionKind::QuarantinePrune,
        effective_quarantine_ttl,
        now_secs,
        &mut targets,
    );

    collect_stale_queue_targets(
        &queue_root,
        DENIED_DIR,
        crate::fac::gc_receipt::GcActionKind::DeniedPrune,
        effective_denied_ttl,
        now_secs,
        &mut targets,
    );

    let (live_blob_hashes, receipt_scan_truncated) =
        collect_recent_receipt_blob_refs(&fac_root.join(FAC_RECEIPTS_DIR));
    let blob_store = BlobStore::new(fac_root);
    if receipt_scan_truncated {
        // Fail closed: incomplete reference scan cannot prove non-reachability.
        // Skip all blob pruning when receipt scan is truncated.
        // Blobs will be collected in a future cycle with fewer receipts.
    } else {
        // Full scan completed — safe to prune unreferenced stale blobs.
        // Blob pruning is based on BLOB_RETENTION_SECS.
        match blob_store.list_all() {
            Ok(all_blobs) => {
                for blob_hash in all_blobs {
                    if live_blob_hashes.contains(&blob_hash) {
                        continue;
                    }
                    if !blob_store.exists(&blob_hash) {
                        continue;
                    }
                    let blob_path = blob_store.blob_path(&blob_hash);
                    if is_stale_by_mtime(&blob_path, BLOB_RETENTION_SECS, now_secs) {
                        targets.push(GcTarget {
                            path: blob_path.clone(),
                            allowed_parent: fac_root.join(BLOB_DIR),
                            kind: crate::fac::gc_receipt::GcActionKind::BlobPrune,
                            estimated_bytes: estimate_dir_size(&blob_path),
                        });
                    }
                }
            },
            Err(error) => {
                return Err(GcPlanError::Io(format!(
                    "failed to list blob store: {error}"
                )));
            },
        }
    }

    targets.sort_by(|a, b| b.estimated_bytes.cmp(&a.estimated_bytes));
    Ok(GcPlan { targets })
}

fn load_lane_statuses(
    lane_manager: &LaneManager,
    lane_ids: &[String],
) -> Result<Vec<LaneStatusV1>, GcPlanError> {
    lane_ids
        .iter()
        .map(|lane_id| {
            lane_manager
                .lane_status(lane_id)
                .map_err(|error| GcPlanError::Io(error.to_string()))
        })
        .collect()
}

fn collect_idle_lane_targets(
    lane_manager: &LaneManager,
    statuses: &[LaneStatusV1],
    known_lane_ids: &[String],
) -> Vec<GcTarget> {
    let mut targets = Vec::with_capacity(statuses.len().saturating_mul(2));
    for status in statuses {
        let is_known_lane = known_lane_ids
            .iter()
            .any(|lane_id| lane_id == &status.lane_id);
        if status.state != LaneState::Idle || !is_known_lane {
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
    targets
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
    now_secs: u64,
    targets: &mut Vec<GcTarget>,
) {
    for entry in collect_queue_entries(queue_root, directory) {
        if !is_stale_entry(&entry, ttl_secs, now_secs) {
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

fn is_stale_by_mtime(path: &Path, ttl_seconds: u64, now_secs: u64) -> bool {
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
    if now_secs == 0 {
        return false;
    }
    mtime.as_secs().saturating_add(ttl_seconds) <= now_secs
}

fn is_recent_receipt(metadata: &std::fs::Metadata, now_secs: u64) -> bool {
    if metadata.file_type().is_symlink() {
        return false;
    }
    if !metadata.is_file() {
        return false;
    }

    let receipt_mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());

    now_secs.saturating_sub(receipt_mtime) <= RECEIPT_REFERENCE_HORIZON_SECS
}

fn collect_recent_receipt_blob_refs(receipts_dir: &Path) -> (HashSet<[u8; 32]>, bool) {
    let mut live_hashes = HashSet::new();
    let mut truncated = false;
    let mut scanned_files = 0usize;
    let mut scanned_receipts = 0usize;
    let mut visited = 0usize;
    let now_secs = current_wall_clock_secs();
    if !receipts_dir.exists() {
        return (live_hashes, truncated);
    }

    let Ok(entries) = std::fs::read_dir(receipts_dir) else {
        return (live_hashes, true);
    };

    for entry_result in entries {
        let Ok(entry) = entry_result else {
            truncated = true;
            continue;
        };
        visited += 1;
        if visited >= MAX_RECEIPT_SCAN_VISITED {
            truncated = true;
            break;
        }
        if scanned_receipts >= MAX_RECEIPT_SCAN_ENTRIES
            || scanned_files >= MAX_RECEIPT_SCAN_FILES
            || live_hashes.len() >= MAX_LIVE_BLOB_HASHES
        {
            truncated = true;
            break;
        }
        let path = entry.path();
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_receipt_digests_recursive(
                &path,
                &mut live_hashes,
                &mut scanned_files,
                &mut scanned_receipts,
                &mut truncated,
                &mut visited,
                now_secs,
                1,
            );
            continue;
        }
        if metadata.is_file() {
            if !is_recent_receipt(&metadata, now_secs) {
                continue;
            }
            scanned_receipts += 1;
            if scanned_receipts > MAX_RECEIPT_SCAN_ENTRIES {
                truncated = true;
                break;
            }
            scanned_files += 1;
            match patch_digest_from_receipt_file(&path) {
                Ok(Some(hash)) => {
                    live_hashes.insert(hash);
                },
                Ok(None) => {},
                Err(()) => {
                    truncated = true;
                },
            }
            if scanned_files >= MAX_RECEIPT_SCAN_FILES {
                truncated = true;
                break;
            }
            if live_hashes.len() >= MAX_LIVE_BLOB_HASHES {
                truncated = true;
                break;
            }
        }
    }
    (live_hashes, truncated)
}

#[allow(clippy::too_many_arguments)]
fn collect_receipt_digests_recursive(
    dir: &Path,
    live_hashes: &mut HashSet<[u8; 32]>,
    scanned_files: &mut usize,
    scanned_receipts: &mut usize,
    truncated: &mut bool,
    visited: &mut usize,
    now_secs: u64,
    depth: usize,
) {
    if *truncated
        || *scanned_receipts >= MAX_RECEIPT_SCAN_ENTRIES
        || *scanned_files >= MAX_RECEIPT_SCAN_FILES
        || live_hashes.len() >= MAX_LIVE_BLOB_HASHES
        || *visited >= MAX_RECEIPT_SCAN_VISITED
    {
        *truncated = true;
        return;
    }
    if depth > 2 {
        *truncated = true;
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        *truncated = true;
        return;
    };
    for entry_result in entries {
        let Ok(entry) = entry_result else {
            *truncated = true;
            continue;
        };
        *visited += 1;
        if *visited >= MAX_RECEIPT_SCAN_VISITED {
            *truncated = true;
            break;
        }
        if *truncated
            || *scanned_receipts >= MAX_RECEIPT_SCAN_ENTRIES
            || *scanned_files >= MAX_RECEIPT_SCAN_FILES
            || live_hashes.len() >= MAX_LIVE_BLOB_HASHES
        {
            *truncated = true;
            break;
        }

        let path = entry.path();
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_receipt_digests_recursive(
                &path,
                live_hashes,
                scanned_files,
                scanned_receipts,
                truncated,
                visited,
                now_secs,
                depth + 1,
            );
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        if !is_recent_receipt(&metadata, now_secs) {
            continue;
        }
        *scanned_receipts += 1;
        if *scanned_receipts > MAX_RECEIPT_SCAN_ENTRIES {
            *truncated = true;
            break;
        }
        *scanned_files += 1;
        match patch_digest_from_receipt_file(&path) {
            Ok(Some(hash)) => {
                live_hashes.insert(hash);
                if live_hashes.len() >= MAX_LIVE_BLOB_HASHES {
                    *truncated = true;
                    break;
                }
                if *scanned_files >= MAX_RECEIPT_SCAN_FILES {
                    *truncated = true;
                    break;
                }
            },
            Ok(None) => {},
            Err(()) => {
                *truncated = true;
                break;
            },
        }
    }
}

fn patch_digest_from_receipt_file(path: &Path) -> Result<Option<[u8; 32]>, ()> {
    use std::io::Read as _;

    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
        return Ok(None);
    }

    // Open with O_NOFOLLOW to prevent symlink attacks
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path).map_err(|_| ())?;

    // Check size from fd metadata (not path-based — no TOCTOU)
    let meta = file.metadata().map_err(|_| ())?;
    if meta.len() > MAX_RECEIPT_READ_SIZE {
        return Err(()); // Oversize receipt
    }

    // Bounded read from fd — meta.len() <= MAX_RECEIPT_READ_SIZE (1 MiB),
    // so the cast to usize is safe on all platforms.
    let capacity = usize::try_from(meta.len()).unwrap_or(0);
    let mut buf = Vec::with_capacity(capacity);
    file.take(MAX_RECEIPT_READ_SIZE + 1)
        .read_to_end(&mut buf)
        .map_err(|_| ())?;
    if buf.len() as u64 > MAX_RECEIPT_READ_SIZE {
        return Err(()); // Read more than expected (race or special file)
    }

    // Parse JSON and extract patch_digest
    let value: Value = serde_json::from_slice(&buf).map_err(|_| ())?;
    let Some(patch_digest) = value.get("patch_digest").and_then(Value::as_str) else {
        return Ok(None);
    };
    // Malformed digest — fail closed (Err), absent key — Ok(None).
    parse_b3_256_digest(patch_digest).map_or(Err(()), |hash| Ok(Some(hash)))
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
    use std::convert::TryFrom;
    use std::thread::sleep;
    use std::time::Duration;

    use filetime::{FileTime, set_file_mtime};
    use tempfile::tempdir;

    use super::*;
    use crate::fac::lane::{LaneManager, LaneState, LaneStatusV1};

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

    fn filetime_from_secs(seconds: u64) -> FileTime {
        FileTime::from_unix_time(i64::try_from(seconds).expect("timestamp fits i64"), 0)
    }

    fn lane_status(lane_id: &str, state: LaneState) -> LaneStatusV1 {
        LaneStatusV1 {
            lane_id: lane_id.to_string(),
            state,
            job_id: None,
            pid: None,
            started_at: None,
            toolchain_fingerprint: None,
            lane_profile_hash: None,
            corrupt_reason: None,
            lock_held: false,
            pid_alive: None,
        }
    }

    #[test]
    fn test_gc_plan_skips_running_lanes() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dir setup");
        let lane_ids = LaneManager::default_lane_ids();
        let running_lane_id = lane_ids.first().cloned().expect("at least one lane");
        let maybe_idle_lane_id = lane_ids.get(1).cloned();
        let mut statuses = vec![lane_status(&running_lane_id, LaneState::Running)];
        if let Some(idle_lane_id) = &maybe_idle_lane_id {
            statuses.push(lane_status(idle_lane_id, LaneState::Idle));
        }
        let targets = collect_idle_lane_targets(&lane_manager, &statuses, &lane_ids);
        let running_lane_dir = lane_manager.lane_dir(&running_lane_id);

        assert!(
            !targets
                .iter()
                .any(|target| target.path.starts_with(&running_lane_dir)),
            "running lanes must be skipped"
        );
        if let Some(idle_lane_id) = maybe_idle_lane_id {
            let idle_lane_dir = lane_manager.lane_dir(&idle_lane_id);
            let idle_targets = targets
                .iter()
                .filter(|target| target.path.starts_with(&idle_lane_dir))
                .count();
            assert!(
                idle_targets >= 2,
                "idle lane should contribute target and logs directories"
            );
        }
    }

    #[test]
    fn test_collect_idle_lane_targets_ignores_unknown_lane_id() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dir setup");
        let known_lane_ids = LaneManager::default_lane_ids();
        let known_lane_id = known_lane_ids.first().cloned().expect("at least one lane");

        let statuses = vec![
            lane_status("../escape", LaneState::Idle),
            lane_status(&known_lane_id, LaneState::Idle),
        ];
        let targets = collect_idle_lane_targets(&lane_manager, &statuses, &known_lane_ids);
        let known_lane_dir = lane_manager.lane_dir(&known_lane_id);

        assert!(
            targets
                .iter()
                .all(|target| target.path.starts_with(&known_lane_dir)),
            "unknown lane IDs must not contribute GC targets"
        );
        assert_eq!(
            targets.len(),
            2,
            "known idle lane should contribute target and logs directories"
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

    #[test]
    fn test_plan_gc_keeps_referenced_blobs() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("directories");

        let blob_store = BlobStore::new(&fac_root);
        let blob_hash = blob_store.store(b"referenced blob").expect("store blob");
        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        std::fs::create_dir_all(&receipts_dir).expect("receipts");
        let blob_digest = format!("b3-256:{}", hex::encode(blob_hash));
        let receipt_path = receipts_dir.join("receipt.json");
        let receipt = format!("{{\"patch_digest\":\"{blob_digest}\"}}");
        std::fs::write(&receipt_path, receipt).expect("write receipt");

        let blob_path = blob_store.blob_path(&blob_hash);
        let stale_secs = BLOB_RETENTION_SECS.saturating_mul(3) + 120;
        let stale_time = filetime_from_secs(current_wall_clock_secs().saturating_sub(stale_secs));
        set_file_mtime(&blob_path, stale_time).expect("set blob mtime");

        let plan = plan_gc(
            &fac_root,
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
        )
        .expect("plan");

        assert!(
            !plan.targets.iter().any(|target| {
                target.path == blob_path
                    && matches!(target.kind, crate::fac::gc_receipt::GcActionKind::BlobPrune)
            }),
            "referenced stale blob must be retained"
        );
    }

    #[test]
    fn test_plan_gc_prunes_unreferenced_stale_blobs() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("directories");

        let blob_store = BlobStore::new(&fac_root);
        let blob_hash = blob_store.store(b"stale blob").expect("store blob");
        let blob_path = blob_store.blob_path(&blob_hash);
        let stale_secs = BLOB_RETENTION_SECS.saturating_mul(3) + 120;
        let stale_time = filetime_from_secs(current_wall_clock_secs().saturating_sub(stale_secs));
        set_file_mtime(&blob_path, stale_time).expect("set blob mtime");

        let plan = plan_gc(
            &fac_root,
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
        )
        .expect("plan");

        assert!(
            plan.targets.iter().any(|target| {
                target.path == blob_path
                    && matches!(target.kind, crate::fac::gc_receipt::GcActionKind::BlobPrune)
            }),
            "unreferenced stale blob should be pruned"
        );
    }

    #[test]
    fn test_plan_gc_keeps_recent_unreferenced_blobs() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("directories");

        let blob_store = BlobStore::new(&fac_root);
        let blob_hash = blob_store.store(b"fresh blob").expect("store blob");
        let blob_path = blob_store.blob_path(&blob_hash);

        let plan = plan_gc(
            &fac_root,
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
        )
        .expect("plan");

        assert!(
            !plan.targets.iter().any(|target| {
                target.path == blob_path
                    && matches!(target.kind, crate::fac::gc_receipt::GcActionKind::BlobPrune)
            }),
            "recent unreferenced blob should not be pruned yet"
        );
    }

    #[test]
    fn test_plan_gc_skips_blob_pruning_when_receipt_scan_truncated() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("directories");

        let blob_store = BlobStore::new(&fac_root);
        let referenced_hash = blob_store
            .store(b"referenced blob beyond scan limit")
            .expect("store referenced");
        let referenced_path = blob_store.blob_path(&referenced_hash);
        let unreferenced_path = {
            let unreferenced_hash = blob_store
                .store(b"unreferenced blob beyond scan limit")
                .expect("store unreferenced");
            blob_store.blob_path(&unreferenced_hash)
        };

        let stale_secs = BLOB_RETENTION_SECS.saturating_mul(3) + 120;
        let stale_time = filetime_from_secs(current_wall_clock_secs().saturating_sub(stale_secs));
        set_file_mtime(&referenced_path, stale_time).expect("set referenced mtime");
        set_file_mtime(&unreferenced_path, stale_time).expect("set unreferenced mtime");

        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        std::fs::create_dir_all(&receipts_dir).expect("receipts");

        // Trigger truncation via an oversize receipt file — the bounded
        // reader in `patch_digest_from_receipt_file` returns `Err(())` for
        // receipts larger than 1 MiB, which sets `truncated = true`.
        let oversize_receipt = receipts_dir.join("oversize.json");
        write_file(&oversize_receipt, 1_048_577); // > 1 MiB

        let referenced_digest = format!("b3-256:{}", hex::encode(referenced_hash));
        let overflow_receipt = receipts_dir.join("overflow-receipt.json");
        std::fs::write(
            &overflow_receipt,
            format!("{{\"patch_digest\":\"{referenced_digest}\"}}"),
        )
        .expect("write overflow receipt");

        let plan = plan_gc(
            &fac_root,
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
        )
        .expect("plan");

        assert!(
            !plan.targets.iter().any(|target| matches!(
                target.kind,
                crate::fac::gc_receipt::GcActionKind::BlobPrune
            )),
            "all blob pruning should be disabled when receipt scan is truncated"
        );
    }

    #[test]
    fn test_plan_gc_prunes_after_old_receipts_age_out() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("directories");

        let blob_store = BlobStore::new(&fac_root);
        let unreferenced_hash = blob_store.store(b"stale blob").expect("store");
        let unreferenced_path = blob_store.blob_path(&unreferenced_hash);
        let stale_secs = BLOB_RETENTION_SECS.saturating_mul(3) + 120;
        let stale_time = filetime_from_secs(current_wall_clock_secs().saturating_sub(stale_secs));
        set_file_mtime(&unreferenced_path, stale_time).expect("set stale blob mtime");

        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        std::fs::create_dir_all(&receipts_dir).expect("receipts");
        let old_receipt_time = filetime_from_secs(
            current_wall_clock_secs()
                .saturating_sub(RECEIPT_REFERENCE_HORIZON_SECS.saturating_add(60)),
        );

        // Create a moderate number of expired receipts — enough to prove
        // that old receipts are skipped without the overhead of creating
        // hundreds of thousands of files.
        for i in 0..100 {
            let receipt_path = receipts_dir.join(format!("expired-{i:05}.json"));
            let hash = blake3::hash(format!("expired receipt {i}").as_bytes());
            let digest = format!("b3-256:{}", hex::encode(hash.as_bytes()));
            std::fs::write(&receipt_path, format!("{{\"patch_digest\":\"{digest}\"}}"))
                .expect("write receipt");
            set_file_mtime(&receipt_path, old_receipt_time).expect("set old receipt mtime");
        }

        let (live_receipt_hashes, truncated) = collect_recent_receipt_blob_refs(&receipts_dir);
        assert_eq!(
            live_receipt_hashes.len(),
            0,
            "old receipts should be ignored"
        );
        assert!(
            !truncated,
            "older receipts beyond horizon should not trigger truncation"
        );

        let plan = plan_gc(
            &fac_root,
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
        )
        .expect("plan");

        assert!(
            plan.targets.iter().any(|target| {
                target.path == unreferenced_path
                    && matches!(target.kind, crate::fac::gc_receipt::GcActionKind::BlobPrune)
            }),
            "old receipts should not prevent pruning stale blob"
        );
    }

    #[test]
    fn test_malformed_patch_digest_triggers_truncated_scan() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("directories");

        // Store a blob and make it stale so it would be pruned normally.
        let blob_store = BlobStore::new(&fac_root);
        let blob_hash = blob_store
            .store(b"blob guarded by malformed receipt")
            .expect("store blob");
        let blob_path = blob_store.blob_path(&blob_hash);
        let stale_secs = BLOB_RETENTION_SECS.saturating_mul(3) + 120;
        let stale_time = filetime_from_secs(current_wall_clock_secs().saturating_sub(stale_secs));
        set_file_mtime(&blob_path, stale_time).expect("set blob mtime");

        // Create a receipt with a malformed patch_digest value.
        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        std::fs::create_dir_all(&receipts_dir).expect("receipts");
        let receipt_path = receipts_dir.join("malformed.json");
        std::fs::write(&receipt_path, r#"{"patch_digest":"not-a-valid-hex"}"#)
            .expect("write malformed receipt");

        let plan = plan_gc(
            &fac_root,
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
        )
        .expect("plan");

        // Malformed digest must cause truncated scan, which disables all blob
        // pruning — fail closed.
        assert!(
            !plan.targets.iter().any(|target| matches!(
                target.kind,
                crate::fac::gc_receipt::GcActionKind::BlobPrune
            )),
            "malformed patch_digest must trigger truncated scan and suppress all BlobPrune targets"
        );
    }
}
