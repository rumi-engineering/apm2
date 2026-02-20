use std::collections::HashSet;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::fac::GcReceiptV1;
use crate::fac::blob_store::{BLOB_DIR, BlobStore};
use crate::fac::cas_reader::CasReader;
use crate::fac::flock_util::try_acquire_exclusive_nonblocking;
use crate::fac::index_compaction::{self, DEFAULT_INDEX_RETENTION_SECS};
use crate::fac::job_spec::parse_b3_256_digest;
use crate::fac::lane::{LaneManager, LaneState, LaneStatusV1};
use crate::fac::receipt_index::ReceiptIndexV1;
use crate::fac::safe_rmtree::{
    MAX_DIR_ENTRIES, MAX_LOG_DIR_ENTRIES, SafeRmtreeError, SafeRmtreeOutcome, safe_rmtree_v1,
    safe_rmtree_v1_with_entry_limit,
};

pub const GATE_CACHE_TTL_SECS: u64 = 2_592_000;
pub const QUARANTINE_RETENTION_SECS: u64 = 2_592_000;
pub const DENIED_RETENTION_SECS: u64 = 604_800;
const DENIED_DIR: &str = "denied";
const QUARANTINE_DIR: &str = "quarantine";
const LEGACY_QUARANTINE_DIR: &str = "quarantined";
const CARGO_HOME_RETENTION_SECS: u64 = 30 * 24 * 3600;
const FAC_CARGO_HOME_DIR: &str = "cargo_home";
/// Retention for managed sccache directory (TCK-00553).
const SCCACHE_RETENTION_SECS: u64 = 30 * 24 * 3600;
const FAC_SCCACHE_DIR: &str = "sccache";
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

/// Default per-job log TTL in seconds (7 days).
///
/// Used when `per_job_log_ttl_secs` is 0 (documented as "use default").
const DEFAULT_PER_JOB_LOG_TTL_SECS: u64 = 7 * 24 * 3600;

/// Configuration for per-lane log retention pruning (TCK-00571).
///
/// Controls which job log directories are eligible for pruning based on
/// TTL, keep-last-N count, and per-lane byte quota.
#[derive(Debug, Clone)]
pub struct LogRetentionConfig {
    /// Maximum total log bytes per lane. Directories exceeding this are pruned
    /// oldest-first. A value of 0 means "no byte quota" (unlimited).
    pub per_lane_log_max_bytes: u64,
    /// Per-job log TTL in seconds. Job log directories older than this are
    /// pruning candidates. A value of 0 means "use default" (7 days),
    /// matching the documented `FacPolicyV1::per_job_log_ttl_days` semantics.
    pub per_job_log_ttl_secs: u64,
    /// Number of most-recent job log directories to keep per lane regardless
    /// of TTL or byte quota. A value of 0 means "no keep-last-N protection".
    pub keep_last_n_jobs_per_lane: u32,
}

impl LogRetentionConfig {
    /// Returns the effective TTL in seconds, mapping 0 to the default (7 days).
    ///
    /// This ensures `per_job_log_ttl_secs == 0` uses the documented default
    /// rather than silently disabling age pruning (CQ-NIT-1 fix).
    pub(crate) const fn effective_ttl_secs(&self) -> u64 {
        if self.per_job_log_ttl_secs == 0 {
            DEFAULT_PER_JOB_LOG_TTL_SECS
        } else {
            self.per_job_log_ttl_secs
        }
    }
}

impl Default for LogRetentionConfig {
    fn default() -> Self {
        Self {
            per_lane_log_max_bytes: 100 * 1024 * 1024, // 100 MiB
            per_job_log_ttl_secs: 7 * 24 * 3600,       // 7 days
            keep_last_n_jobs_per_lane: 5,
        }
    }
}

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
#[allow(clippy::too_many_lines)] // TCK-00546: CAS blob pruning adds additional GC planning logic; extracting sub-functions would obscure the sequential plan construction flow.
pub fn plan_gc(
    fac_root: &Path,
    lane_manager: &LaneManager,
    quarantine_ttl_secs: u64,
    denied_ttl_secs: u64,
) -> Result<GcPlan, GcPlanError> {
    plan_gc_with_log_retention(
        fac_root,
        lane_manager,
        quarantine_ttl_secs,
        denied_ttl_secs,
        &LogRetentionConfig::default(),
    )
}

/// Create a garbage-collection plan with explicit log retention policy.
///
/// This is the extended version of [`plan_gc`] that accepts a
/// [`LogRetentionConfig`] for per-lane log retention pruning (TCK-00571).
///
/// # Errors
///
/// Returns `GcPlanError::Io` when workspace inspection fails.
#[allow(clippy::too_many_lines)]
pub fn plan_gc_with_log_retention(
    fac_root: &Path,
    lane_manager: &LaneManager,
    quarantine_ttl_secs: u64,
    denied_ttl_secs: u64,
    log_retention: &LogRetentionConfig,
) -> Result<GcPlan, GcPlanError> {
    let effective_quarantine_ttl =
        effective_retention_seconds(quarantine_ttl_secs, QUARANTINE_RETENTION_SECS);
    let effective_denied_ttl = effective_retention_seconds(denied_ttl_secs, DENIED_RETENTION_SECS);
    let now_secs = current_wall_clock_secs();
    let known_lane_ids = LaneManager::default_lane_ids();

    let statuses = load_lane_statuses(lane_manager, &known_lane_ids)?;
    let mut targets = collect_idle_lane_targets(lane_manager, &statuses);

    collect_stale_gate_cache_targets(fac_root, now_secs, &mut targets);

    let queue_root = infer_queue_root(fac_root);
    let cargo_home_root = fac_root.join(FAC_CARGO_HOME_DIR);
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

    // TCK-00553: Managed sccache cache directory GC.
    let sccache_root = fac_root.join(FAC_SCCACHE_DIR);
    if sccache_root.exists() && is_stale_by_mtime(&sccache_root, SCCACHE_RETENTION_SECS, now_secs) {
        targets.push(GcTarget {
            path: sccache_root.clone(),
            allowed_parent: fac_root.to_path_buf(),
            kind: crate::fac::gc_receipt::GcActionKind::SccacheCache,
            estimated_bytes: estimate_dir_size(&sccache_root),
        });
    }

    // TCK-00589 review fix: legacy evidence/ and legacy/ directories are NOT
    // GC targets. The evidence/ directory is cleaned up by the migration
    // itself (removed after all files are moved). The legacy/ directory
    // contains read-only migrated evidence that must be retained
    // indefinitely for audit purposes.

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

    let receipt_refs = collect_recent_receipt_blob_refs(&fac_root.join(FAC_RECEIPTS_DIR));
    let blob_store = BlobStore::new(fac_root);
    if receipt_refs.truncated {
        // Fail closed: incomplete reference scan cannot prove non-reachability.
        // Skip all blob and CAS pruning when receipt scan is truncated.
        // Items will be collected in a future cycle with fewer receipts.
    } else {
        // Full scan completed — safe to prune unreferenced stale blobs.
        // Blob pruning is based on BLOB_RETENTION_SECS.
        match blob_store.list_all() {
            Ok(all_blobs) => {
                for blob_hash in all_blobs {
                    if receipt_refs.blob_hashes.contains(&blob_hash) {
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

        // TCK-00546: CAS blob pruning for `apm2_cas` backend digests.
        //
        // The explicit allowlist approach: only CAS objects whose digest
        // appeared in a receipt with `bytes_backend=apm2_cas` are
        // candidates for FAC GC.  This ensures GC never touches CAS
        // data that belongs to other subsystems (evidence, projections).
        //
        // `receipt_refs.cas_hashes` contains the LIVE references from
        // recent receipts.  CAS objects referenced here must NOT be
        // pruned.  CAS objects that were once FAC-referenced but whose
        // receipts have aged out are eligible for pruning.
        //
        // We infer the CAS root from `fac_root`'s parent (`$APM2_HOME/
        // private`) and then check `$APM2_HOME/private/cas`.  If the
        // CAS root cannot be determined or is absent, CAS pruning is
        // skipped (fail-closed — no silent fallback).
        if let Some(cas_root) = infer_cas_root(fac_root) {
            if let Ok(reader) = CasReader::new(&cas_root) {
                // Scan a FAC-specific CAS reference index if it exists.
                // This index is populated by the worker when it retrieves
                // CAS-backed patches, recording their digests for GC
                // tracking.  Only objects listed here are candidates.
                let cas_index_dir = fac_root.join("cas_refs");
                if cas_index_dir.is_dir() {
                    if let Ok(entries) = std::fs::read_dir(&cas_index_dir) {
                        let mut count = 0usize;
                        for entry in entries.flatten() {
                            count += 1;
                            if count > MAX_DIR_ENTRIES {
                                break;
                            }
                            let name = entry.file_name();
                            let Some(name_str) = name.to_str() else {
                                continue;
                            };
                            let Some(hash) = parse_cas_ref_filename(name_str) else {
                                continue;
                            };
                            // MAJOR-1 fix: Use receipt-derived hashes as
                            // the authoritative keep-alive set.  Check BOTH
                            // `cas_hashes` (receipts with bytes_backend=apm2_cas)
                            // AND `blob_hashes` (legacy/unspecified receipts that
                            // may reference the same digest without backend tag).
                            // Fail-closed: if ANY receipt set references this
                            // hash, it MUST NOT be pruned.
                            if receipt_refs.cas_hashes.contains(&hash)
                                || receipt_refs.blob_hashes.contains(&hash)
                            {
                                continue;
                            }
                            // Skip if the ref file itself is recent.
                            let ref_path = entry.path();
                            if !is_stale_by_mtime(&ref_path, BLOB_RETENTION_SECS, now_secs) {
                                continue;
                            }
                            // The CAS object is a stale, unreferenced
                            // FAC artifact — eligible for pruning.
                            let cas_path = reader.hash_to_path(&hash);
                            if reader.exists(&hash) {
                                targets.push(GcTarget {
                                    path: cas_path,
                                    allowed_parent: cas_root.join("objects"),
                                    kind: crate::fac::gc_receipt::GcActionKind::CasBlobPrune,
                                    estimated_bytes: estimate_dir_size(&reader.hash_to_path(&hash)),
                                });
                            }
                            // Clean up the stale ref file itself only when
                            // the hash is not referenced by any receipt set.
                            let _ = std::fs::remove_file(&ref_path);
                        }
                    }
                }
            }
        }
    }

    // TCK-00583: Receipt index compaction as a low-impact GC step.
    // Only schedule compaction if the index exists and has entries that
    // would be pruned. This avoids unnecessary I/O for empty/missing indexes.
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    if let Some(index_size) = estimate_index_compaction_benefit(&receipts_dir, now_secs) {
        let index_path = ReceiptIndexV1::index_path(&receipts_dir);
        targets.push(GcTarget {
            path: index_path,
            allowed_parent: receipts_dir,
            kind: crate::fac::gc_receipt::GcActionKind::IndexCompaction,
            estimated_bytes: index_size,
        });
    }

    // TCK-00571: Per-lane log retention pruning.
    //
    // CQ-MAJOR-1/3 fix: Only scan IDLE lanes for log retention pruning.
    // Active/running lanes must never have their logs pruned.
    //
    // CQ-BLOCKER-1/2 fix: collect_idle_lane_targets no longer emits
    // LaneLog targets, so idle lane logs are always processed through
    // collect_lane_log_retention_targets with full policy enforcement.
    // The lanes_with_full_log_gc set is retained as a defensive guard
    // in case any future code path adds LaneLog targets to the plan.
    let idle_lane_ids: Vec<String> = statuses
        .iter()
        .filter(|s| s.state == LaneState::Idle)
        .map(|s| s.lane_id.clone())
        .collect();

    let lanes_with_full_log_gc: HashSet<String> = targets
        .iter()
        .filter(|t| matches!(t.kind, crate::fac::gc_receipt::GcActionKind::LaneLog))
        .filter_map(|t| {
            // Extract lane_id from path: .../lanes/{lane_id}/logs
            t.path
                .parent()
                .and_then(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
        })
        .collect();

    collect_lane_log_retention_targets(
        lane_manager,
        &idle_lane_ids,
        log_retention,
        now_secs,
        &lanes_with_full_log_gc,
        &mut targets,
    );

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
) -> Vec<GcTarget> {
    let mut targets = Vec::with_capacity(statuses.len());
    for status in statuses {
        if status.state != LaneState::Idle {
            continue;
        }
        let lane_dir = lane_manager.lane_dir(&status.lane_id);
        let target_dir = lane_dir.join("target");

        if target_dir.exists() {
            targets.push(GcTarget {
                path: target_dir.clone(),
                allowed_parent: lane_dir.clone(),
                kind: crate::fac::gc_receipt::GcActionKind::LaneTarget,
                estimated_bytes: estimate_dir_size(&target_dir),
            });
        }
        // CQ-BLOCKER-1/2 fix: Do NOT emit LaneLog targets for idle lanes.
        // Idle lane logs are processed by collect_lane_log_retention_targets
        // which enforces per_lane_log_max_bytes, per_job_log_ttl_days, and
        // keep_last_n_jobs_per_lane. Emitting a blanket LaneLog target here
        // caused plan_gc_with_log_retention to skip retention policy for
        // idle lanes (they were added to lanes_with_full_log_gc, which
        // suppressed collect_lane_log_retention_targets for those lanes).
    }
    targets
}

/// Maximum number of job log subdirectories scanned per lane during
/// retention planning. Prevents unbounded traversal of a lane's `logs/`
/// directory (CTR-1303, INV-RMTREE-009).
const MAX_JOB_LOG_ENTRIES_PER_LANE: usize = 10_000;

/// Collect per-lane log retention pruning targets (TCK-00571).
///
/// For each **idle** lane (caller ensures only idle lane IDs are passed),
/// scans the `logs/` directory for job log subdirectories, then applies
/// three pruning criteria in order:
///
/// 1. **Keep-last-N**: The N most-recent job log directories (by mtime) are
///    always retained.
/// 2. **TTL**: Job log directories older than the effective TTL (0 maps to
///    7-day default) are eligible for pruning.
/// 3. **Byte quota**: If total log bytes still exceed the per-lane cap after
///    TTL pruning, the oldest remaining directories are pruned until the lane
///    is within quota.
///
/// Pruning order is deterministic: entries are sorted by mtime ascending,
/// then by path (lexicographic) for tiebreaking.
///
/// # Fail-Closed Behavior (S-MAJOR-1/2 fix)
///
/// - If `read_dir` on the logs directory fails, the lane is **skipped
///   entirely** (fail-closed: no partial pruning).
/// - If the scan exceeds `MAX_JOB_LOG_ENTRIES_PER_LANE`, the lane is **skipped
///   entirely** rather than proceeding with a partial candidate set that could
///   be starved by decoy directories.
///
/// # Deduplication (CQ-MAJOR-2 fix)
///
/// Lanes whose logs directory is already scheduled for full removal
/// (`LaneLog` target) are excluded via `lanes_with_full_log_gc` to prevent
/// overlapping parent/child targets and double-counting `bytes_freed`.
///
/// # Size Estimation (S-BLOCKER-1 fix)
///
/// Uses lightweight `metadata.len()` from the directory entry stat call
/// (single-level) rather than recursive `estimate_dir_size()` traversal.
/// This reduces the aggregate I/O from O(N * M * depth) to O(N) per lane,
/// preventing the `DoS` from 10,000 job logs with 10,000 files each.
#[allow(clippy::too_many_lines)]
fn collect_lane_log_retention_targets(
    lane_manager: &LaneManager,
    lane_ids: &[String],
    config: &LogRetentionConfig,
    now_secs: u64,
    lanes_with_full_log_gc: &HashSet<String>,
    targets: &mut Vec<GcTarget>,
) {
    // CQ-NIT-1 fix: Apply effective TTL (0 -> 7-day default).
    let effective_ttl = config.effective_ttl_secs();

    for lane_id in lane_ids {
        // CQ-MAJOR-2 fix: Skip lanes whose logs/ is already scheduled for
        // full removal — child targets would be redundant.
        if lanes_with_full_log_gc.contains(lane_id) {
            continue;
        }

        let lane_dir = lane_manager.lane_dir(lane_id);
        let log_dir = lane_dir.join("logs");

        // SECURITY (BLOCKER finding fix): Validate that log_dir is not a
        // symlink before any read_dir/path operations. A symlinked logs/
        // directory would cause all subsequent operations to resolve
        // outside the lane root, enabling arbitrary-file-deletion attacks.
        // Use symlink_metadata (lstat) so symlinks are detected without
        // being followed.
        match std::fs::symlink_metadata(&log_dir) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    // Fail-closed: symlink or non-directory at logs/ path
                    // is never valid. Skip lane entirely so the anomaly
                    // is retried/repaired on the next GC cycle.
                    continue;
                }
            },
            Err(_) => {
                // Path doesn't exist or cannot be stat'd — skip lane.
                continue;
            },
        }

        // S-MAJOR-1/2 fix: Fail-closed on read_dir error — skip lane
        // entirely rather than proceeding with zero candidates.
        let Ok(entries) = std::fs::read_dir(&log_dir) else {
            // Fail-closed: cannot enumerate log directory. Lane is
            // skipped; retention will be retried on the next GC cycle.
            continue;
        };

        // CQ-MAJOR-1/2 fix (overflow atomicity): Collect all targets for
        // this lane into a local vector. Only append to the shared `targets`
        // vector after the full scan completes without overflow. This ensures
        // atomicity: either ALL targets for a lane are included, or NONE.
        let mut lane_targets: Vec<GcTarget> = Vec::new();

        // Collect job log subdirectories with their metadata.
        let mut job_logs: Vec<JobLogEntry> = Vec::new();
        let mut scan_count = 0usize;
        let mut lane_visited_count = 0usize;
        let mut scan_overflow = false;
        for entry in entries.flatten() {
            scan_count += 1;
            if scan_count > MAX_JOB_LOG_ENTRIES_PER_LANE {
                // S-MAJOR-1/2 fix: Fail-closed on overflow — do NOT
                // proceed with a partial candidate set that could be
                // starved by decoy directories with crafted mtime.
                scan_overflow = true;
                break;
            }
            let path = entry.path();
            let Ok(metadata) = path.symlink_metadata() else {
                continue;
            };
            // Fail-closed: symlinks under logs/ are never valid.
            // Emit them as GC targets for unconditional removal so the
            // GC executor will clean them up, preventing symlink-based
            // quota bypass.
            if metadata.file_type().is_symlink() {
                lane_targets.push(GcTarget {
                    path,
                    allowed_parent: log_dir.clone(),
                    kind: crate::fac::gc_receipt::GcActionKind::LaneLogRetention,
                    estimated_bytes: 0,
                });
                continue;
            }
            // Regular files under logs/ are invalid (only job-log
            // subdirectories belong here). Emit them as GC targets so
            // they are removed during GC, preventing stray files from
            // bypassing per-lane log-retention controls.
            if !metadata.is_dir() {
                let file_bytes = metadata.len();
                lane_targets.push(GcTarget {
                    path,
                    allowed_parent: log_dir.clone(),
                    kind: crate::fac::gc_receipt::GcActionKind::LaneLogRetention,
                    estimated_bytes: file_bytes,
                });
                continue;
            }
            let modified_secs = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            // S-BLOCKER-1 fix: Use bounded recursive estimator (DoS protection
            // via lane_visited_count).
            let estimated_bytes =
                estimate_job_log_dir_size_recursive(&path, &mut lane_visited_count);
            job_logs.push(JobLogEntry {
                path,
                modified_secs,
                estimated_bytes,
                pruned: false,
            });
        }

        // S-MAJOR-1/2 fix: If scan overflowed, skip this lane entirely.
        // The lane's log retention will be retried on the next GC cycle
        // after some entries have been organically pruned or manually
        // cleaned. This is fail-closed: we do NOT proceed with a partial
        // set that could be manipulated by decoy flooding.
        //
        // CQ-MAJOR-1/2 fix: Discard ALL lane_targets (including symlink
        // and file targets already collected) when overflow is detected.
        // This ensures atomicity — either all targets for a lane are
        // included or none.
        if scan_overflow {
            continue;
        }

        if job_logs.is_empty() {
            // Atomically commit any non-directory targets (symlinks, stray
            // files) even when there are no job log subdirectories.
            targets.extend(lane_targets);
            continue;
        }

        // Sort by mtime ascending (oldest first), then by path for determinism.
        job_logs.sort_by(|a, b| {
            a.modified_secs
                .cmp(&b.modified_secs)
                .then_with(|| a.path.cmp(&b.path))
        });

        let keep_last_n = config.keep_last_n_jobs_per_lane as usize;
        let total_count = job_logs.len();

        // Mark entries as protected by keep-last-N. The last N entries
        // (most recent by mtime) are protected.
        let protected_start = total_count.saturating_sub(keep_last_n);

        // Phase 1: TTL-based pruning for entries outside the keep-last-N window.
        // CQ-NIT-1 fix: Uses effective_ttl (0 -> default 7 days) so age
        // pruning is always applied when documented default semantics apply.
        for (idx, entry) in job_logs.iter_mut().enumerate() {
            if idx >= protected_start {
                // Protected by keep-last-N — skip TTL pruning.
                break;
            }
            if is_stale_by_mtime_seconds(entry.modified_secs, effective_ttl, now_secs) {
                entry.pruned = true;
            }
        }

        // Phase 2: Byte quota enforcement.
        // Calculate total log bytes and prune oldest entries (outside
        // keep-last-N) until within quota.
        // S-NIT-1 / S-MAJOR-3 fix: Use boolean `pruned` flag on
        // JobLogEntry for O(1) lookup instead of Vec::contains() O(N).
        //
        // SENTINEL GUARD (MAJOR finding fix): If any entry has
        // `estimated_bytes == u64::MAX`, the recursive size estimator
        // hit its scan limit (MAX_LANE_SCAN_ENTRIES) and the returned
        // value is a traversal-failure sentinel, NOT a real byte count.
        // Using it in arithmetic would cause saturating_add to produce
        // u64::MAX for total_bytes, making saturating_sub drop the total
        // below the quota after subtracting pruned entries — effectively
        // disabling byte-quota enforcement. Fail-closed: skip the
        // byte-quota phase entirely when any entry's size is unknown,
        // letting TTL and keep-last-N phases handle retention. The
        // byte-quota will be retried on the next GC cycle.
        let has_size_overflow = job_logs.iter().any(|e| e.estimated_bytes == u64::MAX);
        if config.per_lane_log_max_bytes > 0 && !has_size_overflow {
            let mut total_bytes: u64 = job_logs
                .iter()
                .map(|e| e.estimated_bytes)
                .fold(0u64, u64::saturating_add);

            // Subtract bytes already marked for TTL pruning.
            for entry in &job_logs {
                if entry.pruned {
                    total_bytes = total_bytes.saturating_sub(entry.estimated_bytes);
                }
            }

            if total_bytes > config.per_lane_log_max_bytes {
                // Prune oldest non-protected entries that haven't been
                // TTL-pruned yet.
                for (idx, entry) in job_logs.iter_mut().enumerate() {
                    if total_bytes <= config.per_lane_log_max_bytes {
                        break;
                    }
                    if idx >= protected_start {
                        break; // Cannot prune protected entries.
                    }
                    if entry.pruned {
                        continue; // Already marked by TTL phase.
                    }
                    entry.pruned = true;
                    total_bytes = total_bytes.saturating_sub(entry.estimated_bytes);
                }
            }
        }

        // Emit GC targets for all prune candidates.
        for entry in &job_logs {
            if entry.pruned {
                lane_targets.push(GcTarget {
                    path: entry.path.clone(),
                    allowed_parent: log_dir.clone(),
                    kind: crate::fac::gc_receipt::GcActionKind::LaneLogRetention,
                    estimated_bytes: entry.estimated_bytes,
                });
            }
        }

        // Atomically commit all lane targets to the shared vector.
        targets.extend(lane_targets);
    }
}

/// Maximum total directory entries scanned per lane during log retention
/// size estimation. Prevents unbounded recursion/traversal denial-of-service.
pub const MAX_LANE_SCAN_ENTRIES: usize = 100_000;

pub(super) fn estimate_job_log_dir_size_recursive(path: &Path, visited_count: &mut usize) -> u64 {
    estimate_job_log_dir_size_recursive_inner(path, visited_count, 0)
}

fn estimate_job_log_dir_size_recursive_inner(
    path: &Path,
    visited_count: &mut usize,
    depth: usize,
) -> u64 {
    // CQ-MAJOR-2 fix (round N+1): Depth overflow must return u64::MAX
    // (same fail-closed sentinel as MAX_LANE_SCAN_ENTRIES overflow) so
    // callers treat it as unknown size. Returning 0 would let deeply-
    // nested directories bypass byte-quota pruning by being undercounted.
    if depth >= MAX_TRAVERSAL_DEPTH {
        return u64::MAX;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        *visited_count += 1;
        if *visited_count > MAX_LANE_SCAN_ENTRIES {
            return u64::MAX;
        }

        let Ok(metadata) = entry.path().symlink_metadata() else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }

        if metadata.is_dir() {
            let sub =
                estimate_job_log_dir_size_recursive_inner(&entry.path(), visited_count, depth + 1);
            if sub == u64::MAX {
                return u64::MAX;
            }
            total = total.saturating_add(sub);
        } else {
            total = total.saturating_add(metadata.len());
        }
    }
    total
}

/// Metadata for a single job log subdirectory within a lane's `logs/` dir.
#[derive(Debug, Clone)]
struct JobLogEntry {
    path: PathBuf,
    modified_secs: u64,
    estimated_bytes: u64,
    /// Whether this entry has been marked for pruning (used for O(1) lookup
    /// in Phase 2 byte quota enforcement, fixing S-MAJOR-3/S-NIT-1 O(N^2)
    /// complexity).
    pruned: bool,
}

fn collect_stale_gate_cache_targets(fac_root: &Path, now_secs: u64, targets: &mut Vec<GcTarget>) {
    // Gate cache v2.
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

    // Gate cache v3 (TCK-00541): receipt-indexed cache store.
    // MAJOR fix (round 5): lock files (`.{index_key}.lock`) are excluded from
    // GC targeting. On Unix, unlinking a locked file removes the path without
    // releasing the existing flock — a second writer can recreate the path,
    // acquire flock on a different inode, and bypass mutual exclusion.
    let gate_cache_v3_root = fac_root.join("gate_cache_v3");
    if let Ok(entries) = std::fs::read_dir(&gate_cache_v3_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_v3_lock_file(&path) {
                continue; // Never GC lock files — see MAJOR fix comment above.
            }
            if is_stale_by_mtime(&path, GATE_CACHE_TTL_SECS, now_secs) {
                targets.push(GcTarget {
                    path: path.clone(),
                    allowed_parent: gate_cache_v3_root.clone(),
                    kind: crate::fac::gc_receipt::GcActionKind::GateCacheV3,
                    estimated_bytes: estimate_dir_size(&path),
                });
            }
        }
    }
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
#[allow(clippy::too_many_lines)] // TCK-00583: receipt persistence error handling adds required branching for fail-closed audit evidence.
pub fn execute_gc(plan: &GcPlan) -> GcReceiptV1 {
    let now = current_wall_clock_secs();

    let mut actions = Vec::new();
    let mut errors = Vec::new();

    for target in &plan.targets {
        // TCK-00583: Index compaction is handled separately from file deletion.
        // The compaction step prunes stale entries in-place and persists the
        // compacted index; it does not delete the index file.
        if matches!(
            target.kind,
            crate::fac::gc_receipt::GcActionKind::IndexCompaction
        ) {
            // The target.allowed_parent is the receipts_dir for compaction.
            let receipts_dir = &target.allowed_parent;
            match index_compaction::compact_index(receipts_dir, DEFAULT_INDEX_RETENTION_SECS, now) {
                Ok(compaction_receipt) => {
                    // Receipt persistence failure is a GC error — audit evidence
                    // loss must be explicit (never silently swallowed).
                    match index_compaction::persist_compaction_receipt(
                        receipts_dir,
                        &compaction_receipt,
                    ) {
                        Ok(_) => {
                            actions.push(crate::fac::gc_receipt::GcAction {
                                target_path: target.path.display().to_string(),
                                action_kind: target.kind,
                                bytes_freed: target.estimated_bytes,
                                files_deleted: 0,
                                dirs_deleted: 0,
                            });
                        },
                        Err(persist_err) => {
                            errors.push(crate::fac::gc_receipt::GcError {
                                target_path: target.path.display().to_string(),
                                reason: format!(
                                    "index compaction succeeded but receipt persistence failed: {persist_err}"
                                ),
                            });
                        },
                    }
                },
                Err(error) => {
                    errors.push(crate::fac::gc_receipt::GcError {
                        target_path: target.path.display().to_string(),
                        reason: format!("index compaction failed: {error}"),
                    });
                },
            }
            continue;
        }

        // CQ-MAJOR-1 fix: Require lane lock for LaneLogRetention targets
        // (child targets within a lane's logs/ directory) in addition to
        // LaneTarget and LaneLog. This prevents pruning log directories
        // of a lane that became active between planning and execution.
        let needs_lane_lock = matches!(
            target.kind,
            crate::fac::gc_receipt::GcActionKind::LaneTarget
                | crate::fac::gc_receipt::GcActionKind::LaneLog
                | crate::fac::gc_receipt::GcActionKind::LaneLogRetention
        );
        // Acquire lane lock if needed (LaneTarget, LaneLog, LaneLogRetention).
        // The lock guard must remain alive for the scope of the deletion.
        let _lock_guard: Option<std::fs::File> = if needs_lane_lock {
            // For LaneLogRetention targets, the path is a subdirectory
            // of logs/ (e.g., .../lanes/{lane_id}/logs/{job_id}).
            // try_acquire_lane_lock expects the path to resolve to a
            // lane root by checking if the filename is "target" or "logs".
            // For LaneLogRetention, we pass the parent `logs/` directory
            // to the lock function.
            let lock_path = if matches!(
                target.kind,
                crate::fac::gc_receipt::GcActionKind::LaneLogRetention
            ) {
                &target.allowed_parent
            } else {
                &target.path
            };
            match try_acquire_lane_lock(lock_path) {
                Ok(Some(lock_guard)) => Some(lock_guard),
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
            }
        } else {
            None
        };

        // CQ-MAJOR-1 fix (round N+1): LaneLogRetention targets that are
        // symlinks cannot be removed by `safe_rmtree` (which rejects symlink
        // roots by design). Detect symlinks via `symlink_metadata` and use
        // `std::fs::remove_file` instead — symlinks are files in the
        // directory namespace, so `remove_file` is the correct syscall.
        // Parent-boundary check: verify the target lives under its
        // allowed_parent before deletion.
        if target.kind == crate::fac::gc_receipt::GcActionKind::LaneLogRetention {
            match std::fs::symlink_metadata(&target.path) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    // Parent-boundary check: target must be a child of
                    // allowed_parent. Use canonical comparison on the
                    // target's parent (NOT the symlink target itself).
                    let is_child = target
                        .path
                        .parent()
                        .is_some_and(|p| p.starts_with(&target.allowed_parent));
                    if !is_child {
                        errors.push(crate::fac::gc_receipt::GcError {
                            target_path: target.path.display().to_string(),
                            reason: format!(
                                "symlink target outside allowed parent: {}",
                                target.allowed_parent.display()
                            ),
                        });
                        continue;
                    }
                    match std::fs::remove_file(&target.path) {
                        Ok(()) => {
                            actions.push(crate::fac::gc_receipt::GcAction {
                                target_path: target.path.display().to_string(),
                                action_kind: target.kind,
                                bytes_freed: 0,
                                files_deleted: 1,
                                dirs_deleted: 0,
                            });
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            // Already absent — benign race.
                            actions.push(crate::fac::gc_receipt::GcAction {
                                target_path: target.path.display().to_string(),
                                action_kind: target.kind,
                                bytes_freed: 0,
                                files_deleted: 0,
                                dirs_deleted: 0,
                            });
                        },
                        Err(e) => {
                            errors.push(crate::fac::gc_receipt::GcError {
                                target_path: target.path.display().to_string(),
                                reason: format!("symlink removal failed: {e}"),
                            });
                        },
                    }
                    continue;
                },
                Ok(_) => {
                    // Not a symlink — fall through to normal rmtree path.
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Already absent — report as successful no-op.
                    actions.push(crate::fac::gc_receipt::GcAction {
                        target_path: target.path.display().to_string(),
                        action_kind: target.kind,
                        bytes_freed: 0,
                        files_deleted: 0,
                        dirs_deleted: 0,
                    });
                    continue;
                },
                Err(e) => {
                    errors.push(crate::fac::gc_receipt::GcError {
                        target_path: target.path.display().to_string(),
                        reason: format!("symlink_metadata failed: {e}"),
                    });
                    continue;
                },
            }
        }

        // MAJOR-4 fix: Use elevated entry limit for LaneLogRetention
        // targets. Job log directories may legitimately exceed the default
        // MAX_DIR_ENTRIES (10,000). Without this, oversized log dirs cause
        // permanent TooManyEntries errors during GC.
        let result = if target.kind == crate::fac::gc_receipt::GcActionKind::LaneLogRetention {
            safe_rmtree_v1_with_entry_limit(
                &target.path,
                &target.allowed_parent,
                MAX_LOG_DIR_ENTRIES,
            )
        } else {
            safe_rmtree_v1(&target.path, &target.allowed_parent)
        };

        match result {
            Ok(outcome) => {
                // CQ-MAJOR-2 fix: Report actual bytes_freed as 0 for
                // AlreadyAbsent paths. Previously, estimated_bytes was
                // reported even when nothing was deleted, causing
                // over-reporting when parent/child targets overlap.
                let (files_deleted, dirs_deleted, bytes_freed) = match outcome {
                    SafeRmtreeOutcome::Deleted {
                        files_deleted,
                        dirs_deleted,
                    } => (files_deleted, dirs_deleted, target.estimated_bytes),
                    SafeRmtreeOutcome::AlreadyAbsent => (0, 0, 0),
                };
                actions.push(crate::fac::gc_receipt::GcAction {
                    target_path: target.path.display().to_string(),
                    action_kind: target.kind,
                    bytes_freed,
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

/// Estimate the compaction benefit (bytes of stale index entries) without
/// mutating the index.
///
/// Returns `Some(estimated_bytes_freed)` if the index exists and has stale
/// entries, or `None` if there is nothing to compact.
fn estimate_index_compaction_benefit(receipts_dir: &Path, now_secs: u64) -> Option<u64> {
    let index = ReceiptIndexV1::load_or_rebuild(receipts_dir).ok()?;
    if index.is_empty() {
        return None;
    }

    let cutoff = now_secs.saturating_sub(DEFAULT_INDEX_RETENTION_SECS);
    let stale_count = index
        .header_index
        .values()
        .filter(|h| h.timestamp_secs < cutoff)
        .count();

    if stale_count == 0 {
        return None;
    }

    // Estimate ~200 bytes per entry (JSON overhead).
    let estimated_bytes = (stale_count as u64).saturating_mul(200);
    Some(estimated_bytes)
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

/// Returns `true` if `path` is a v3 gate cache lock file.
///
/// Lock files follow the naming convention `.{index_key}.lock` and live
/// directly under the `gate_cache_v3` root. They MUST NOT be deleted by
/// GC because unlinking a locked file on Unix removes the path without
/// releasing the flock, allowing a second writer to create a new inode
/// and bypass mutual exclusion.
fn is_v3_lock_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.starts_with('.')
        && std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lock"))
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

/// Collected blob reference sets from receipt scanning.
struct ReceiptBlobRefs {
    /// Hashes referenced by `fac_blobs_v1` or unspecified backend receipts.
    blob_hashes: HashSet<[u8; 32]>,
    /// Hashes referenced by `apm2_cas` backend receipts (TCK-00546).
    cas_hashes: HashSet<[u8; 32]>,
    /// Whether the scan was truncated (fail-closed for pruning).
    truncated: bool,
}

fn collect_recent_receipt_blob_refs(receipts_dir: &Path) -> ReceiptBlobRefs {
    let mut refs = ReceiptBlobRefs {
        blob_hashes: HashSet::new(),
        cas_hashes: HashSet::new(),
        truncated: false,
    };
    let mut scanned_files = 0usize;
    let mut scanned_receipts = 0usize;
    let mut visited = 0usize;
    let now_secs = current_wall_clock_secs();
    if !receipts_dir.exists() {
        return refs;
    }

    let Ok(entries) = std::fs::read_dir(receipts_dir) else {
        refs.truncated = true;
        return refs;
    };

    for entry_result in entries {
        let Ok(entry) = entry_result else {
            refs.truncated = true;
            continue;
        };
        visited += 1;
        if visited >= MAX_RECEIPT_SCAN_VISITED {
            refs.truncated = true;
            break;
        }
        let total_hashes = refs.blob_hashes.len().saturating_add(refs.cas_hashes.len());
        if scanned_receipts >= MAX_RECEIPT_SCAN_ENTRIES
            || scanned_files >= MAX_RECEIPT_SCAN_FILES
            || total_hashes >= MAX_LIVE_BLOB_HASHES
        {
            refs.truncated = true;
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
                &mut refs,
                &mut scanned_files,
                &mut scanned_receipts,
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
                refs.truncated = true;
                break;
            }
            scanned_files += 1;
            match patch_digest_from_receipt_file(&path) {
                Ok(Some(info)) => {
                    insert_digest_ref(&mut refs, &info);
                },
                Ok(None) => {},
                Err(()) => {
                    refs.truncated = true;
                },
            }
            let total = refs.blob_hashes.len().saturating_add(refs.cas_hashes.len());
            if scanned_files >= MAX_RECEIPT_SCAN_FILES || total >= MAX_LIVE_BLOB_HASHES {
                refs.truncated = true;
                break;
            }
        }
    }
    refs
}

/// Route a digest into the appropriate reference set based on `bytes_backend`.
fn insert_digest_ref(refs: &mut ReceiptBlobRefs, info: &PatchDigestInfo) {
    match info.bytes_backend.as_deref() {
        Some("apm2_cas") => {
            refs.cas_hashes.insert(info.hash);
        },
        // fac_blobs_v1, unspecified (inline), or any other value -> blob set.
        _ => {
            refs.blob_hashes.insert(info.hash);
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_receipt_digests_recursive(
    dir: &Path,
    refs: &mut ReceiptBlobRefs,
    scanned_files: &mut usize,
    scanned_receipts: &mut usize,
    visited: &mut usize,
    now_secs: u64,
    depth: usize,
) {
    let total_hashes = refs.blob_hashes.len().saturating_add(refs.cas_hashes.len());
    if refs.truncated
        || *scanned_receipts >= MAX_RECEIPT_SCAN_ENTRIES
        || *scanned_files >= MAX_RECEIPT_SCAN_FILES
        || total_hashes >= MAX_LIVE_BLOB_HASHES
        || *visited >= MAX_RECEIPT_SCAN_VISITED
    {
        refs.truncated = true;
        return;
    }
    if depth > 2 {
        refs.truncated = true;
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        refs.truncated = true;
        return;
    };
    for entry_result in entries {
        let Ok(entry) = entry_result else {
            refs.truncated = true;
            continue;
        };
        *visited += 1;
        if *visited >= MAX_RECEIPT_SCAN_VISITED {
            refs.truncated = true;
            break;
        }
        let total = refs.blob_hashes.len().saturating_add(refs.cas_hashes.len());
        if refs.truncated
            || *scanned_receipts >= MAX_RECEIPT_SCAN_ENTRIES
            || *scanned_files >= MAX_RECEIPT_SCAN_FILES
            || total >= MAX_LIVE_BLOB_HASHES
        {
            refs.truncated = true;
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
                refs,
                scanned_files,
                scanned_receipts,
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
            refs.truncated = true;
            break;
        }
        *scanned_files += 1;
        match patch_digest_from_receipt_file(&path) {
            Ok(Some(info)) => {
                insert_digest_ref(refs, &info);
                let total = refs.blob_hashes.len().saturating_add(refs.cas_hashes.len());
                if total >= MAX_LIVE_BLOB_HASHES || *scanned_files >= MAX_RECEIPT_SCAN_FILES {
                    refs.truncated = true;
                    break;
                }
            },
            Ok(None) => {},
            Err(()) => {
                refs.truncated = true;
                break;
            },
        }
    }
}

/// Extracted patch digest information from a receipt file.
struct PatchDigestInfo {
    /// The parsed BLAKE3 hash bytes.
    hash: [u8; 32],
    /// The `bytes_backend` value if present (e.g., `"apm2_cas"`).
    bytes_backend: Option<String>,
}

fn patch_digest_from_receipt_file(path: &Path) -> Result<Option<PatchDigestInfo>, ()> {
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

    // Parse JSON and extract patch_digest + bytes_backend
    let value: Value = serde_json::from_slice(&buf).map_err(|_| ())?;
    let Some(patch_digest) = value.get("patch_digest").and_then(Value::as_str) else {
        return Ok(None);
    };
    let bytes_backend = value
        .get("bytes_backend")
        .and_then(Value::as_str)
        .map(String::from);
    // Malformed digest — fail closed (Err), absent key — Ok(None).
    parse_b3_256_digest(patch_digest).map_or(Err(()), |hash| {
        Ok(Some(PatchDigestInfo {
            hash,
            bytes_backend,
        }))
    })
}

/// Infer the CAS root from the FAC root.
///
/// Layout: `$APM2_HOME/private/fac` -> CAS at `$APM2_HOME/private/cas`.
fn infer_cas_root(fac_root: &Path) -> Option<PathBuf> {
    // fac_root = $APM2_HOME/private/fac
    // CAS root = $APM2_HOME/private/cas (sibling directory)
    let private_dir = fac_root.parent()?;
    let cas_root = private_dir.join("cas");
    if cas_root.is_dir() {
        Some(cas_root)
    } else {
        None
    }
}

/// Parse a CAS reference filename into a hash.
///
/// Ref files are named `{64-hex-chars}.ref` under `fac_root/cas_refs/`.
fn parse_cas_ref_filename(name: &str) -> Option<[u8; 32]> {
    let stem = name.strip_suffix(".ref")?;
    if stem.len() != 64 {
        return None;
    }
    let bytes = hex::decode(stem).ok()?;
    bytes.try_into().ok()
}

/// Record a CAS reference in the FAC GC tracking directory.
///
/// Creates a marker file at `fac_root/cas_refs/{hex}.ref` so that GC can
/// later identify stale CAS-backed patch objects.
///
/// # Errors
///
/// Returns an error if the directory cannot be created or the file cannot
/// be written.
pub fn record_cas_ref(fac_root: &Path, hash: &[u8; 32]) -> Result<(), std::io::Error> {
    let cas_refs_dir = fac_root.join("cas_refs");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(&cas_refs_dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&cas_refs_dir)?;
    }
    let hex = hex::encode(hash);
    let ref_path = cas_refs_dir.join(format!("{hex}.ref"));
    // Touch the file (create or update mtime) using a single file handle
    // to avoid reopening the path (NIT-1: eliminates redundant open).
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&ref_path)?;
    // SECURITY JUSTIFICATION (CTR-2501): CAS ref mtime uses wall-clock time
    // because ref freshness is an operational GC heuristic (not a coordinated
    // consensus operation).  The file creation itself is the authoritative
    // signal; mtime is best-effort recency.
    #[allow(clippy::disallowed_methods)]
    let now = std::time::SystemTime::now();
    let _ = file.set_modified(now);
    Ok(())
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

        // ensure_directories() creates target/ and logs/ for every lane,
        // so collect_idle_lane_targets will find them for idle lanes.
        // Write files so estimated_bytes > 0 (non-trivial GC targets).
        for lane_id in &lane_ids {
            let lane_dir = lane_manager.lane_dir(lane_id);
            std::fs::write(lane_dir.join("target").join("build_artifact"), b"artifact")
                .expect("write target file");
            std::fs::write(lane_dir.join("logs").join("build.log"), b"log data")
                .expect("write log file");
        }

        let mut statuses = vec![lane_status(&running_lane_id, LaneState::Running)];
        if let Some(idle_lane_id) = &maybe_idle_lane_id {
            statuses.push(lane_status(idle_lane_id, LaneState::Idle));
        }
        let targets = collect_idle_lane_targets(&lane_manager, &statuses);
        let running_lane_dir = lane_manager.lane_dir(&running_lane_id);

        assert!(
            !targets
                .iter()
                .any(|target| target.path.starts_with(&running_lane_dir)),
            "running lanes must be skipped"
        );
        if let Some(idle_lane_id) = maybe_idle_lane_id {
            let idle_lane_dir = lane_manager.lane_dir(&idle_lane_id);
            let idle_targets: Vec<_> = targets
                .iter()
                .filter(|target| target.path.starts_with(&idle_lane_dir))
                .collect();
            // CQ-BLOCKER-1/2 fix: collect_idle_lane_targets no longer emits
            // LaneLog targets. Idle lanes contribute only the target/ directory.
            // Logs are processed by collect_lane_log_retention_targets with
            // retention policy enforcement.
            assert_eq!(
                idle_targets.len(),
                1,
                "idle lane must contribute exactly the target directory (logs handled by retention), got {idle_targets:?}"
            );
            assert!(
                idle_targets[0].path.ends_with("target"),
                "idle lane target must be the target/ directory"
            );
        }
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

        let refs = collect_recent_receipt_blob_refs(&receipts_dir);
        assert_eq!(refs.blob_hashes.len(), 0, "old receipts should be ignored");
        assert!(
            !refs.truncated,
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

    // =========================================================================
    // TCK-00541 round-5 MAJOR fix: GC must never target v3 lock files
    // =========================================================================

    #[test]
    fn gc_plan_excludes_v3_lock_files() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("directories");

        // Create a stale v3 cache entry directory AND a stale lock file.
        let v3_root = fac_root.join("gate_cache_v3");
        std::fs::create_dir_all(&v3_root).expect("v3 root");

        let stale_index_dir = v3_root.join("some_index_key_abc123");
        std::fs::create_dir_all(&stale_index_dir).expect("index dir");
        std::fs::write(stale_index_dir.join("gate.json"), b"{}").expect("gate file");

        let lock_file = v3_root.join(".some_index_key_abc123.lock");
        std::fs::write(&lock_file, b"").expect("lock file");

        // Make both stale.
        let stale_secs = GATE_CACHE_TTL_SECS.saturating_mul(2) + 120;
        let stale_time = filetime_from_secs(current_wall_clock_secs().saturating_sub(stale_secs));
        set_file_mtime(&stale_index_dir, stale_time).expect("set dir mtime");
        set_file_mtime(&lock_file, stale_time).expect("set lock mtime");

        let plan = plan_gc(
            &fac_root,
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
        )
        .expect("plan");

        // The stale index directory SHOULD be targeted for GC.
        assert!(
            plan.targets.iter().any(|t| t.path == stale_index_dir
                && matches!(t.kind, crate::fac::gc_receipt::GcActionKind::GateCacheV3)),
            "stale v3 index directory must be targeted for GC"
        );

        // The lock file MUST NOT be targeted for GC.
        assert!(
            !plan.targets.iter().any(|t| t.path == lock_file),
            "v3 lock files must never be targeted for GC — \
             unlinking a locked file breaks flock serialization"
        );
    }

    #[test]
    fn is_v3_lock_file_matches_lock_naming_convention() {
        use std::path::PathBuf;

        // Positive cases: files matching `.{key}.lock`.
        assert!(super::is_v3_lock_file(&PathBuf::from(
            "/tmp/gate_cache_v3/.abc123.lock"
        )));
        assert!(super::is_v3_lock_file(&PathBuf::from(
            "/root/.some_key.lock"
        )));

        // Negative cases: normal directories/files, non-lock dot files.
        assert!(!super::is_v3_lock_file(&PathBuf::from(
            "/tmp/gate_cache_v3/abc123"
        )));
        assert!(!super::is_v3_lock_file(&PathBuf::from(
            "/tmp/gate_cache_v3/abc123.lock"
        ))); // No leading dot.
        assert!(!super::is_v3_lock_file(&PathBuf::from(
            "/tmp/gate_cache_v3/.abc123.json"
        ))); // Wrong extension.
        // Bare `.lock` is treated by Rust's Path as a hidden file with
        // stem "lock" and no extension — so it does NOT match. This is fine:
        // no legitimate v3 index key produces a bare `.lock` filename.
        assert!(!super::is_v3_lock_file(&PathBuf::from(
            "/tmp/gate_cache_v3/.lock"
        )));
    }

    // =========================================================================
    // TCK-00546 MAJOR-1: CAS pruning uses receipt-derived hashes as
    // authoritative keep-alive (fail-closed against legacy receipts)
    // =========================================================================

    /// Helper: write a CAS object in the daemon layout under `cas_root`.
    fn write_cas_object(cas_root: &Path, data: &[u8]) -> [u8; 32] {
        let hash = *blake3::hash(data).as_bytes();
        let hex = hex::encode(hash);
        let (prefix, suffix) = hex.split_at(4);
        let dir = cas_root.join("objects").join(prefix);
        std::fs::create_dir_all(&dir).expect("mkdir CAS prefix");
        let path = dir.join(suffix);
        std::fs::write(&path, data).expect("write CAS object");
        hash
    }

    #[test]
    fn cas_ref_kept_alive_by_legacy_receipt_without_bytes_backend() {
        // MAJOR-1 regression: a CAS ref marker whose hash appears in a
        // legacy receipt (no bytes_backend field -> hash goes into
        // blob_hashes) must NOT be pruned.  Before the fix, only
        // cas_hashes was checked, so legacy receipts did not protect CAS
        // objects.
        let dir = tempdir().expect("tmp");
        // Layout: $dir/private/fac (fac_root), $dir/private/cas (cas_root)
        let private_dir = dir.path().join("private");
        let fac_root = private_dir.join("fac");
        let cas_root = private_dir.join("cas");
        std::fs::create_dir_all(&fac_root).expect("fac_root");
        std::fs::create_dir_all(&cas_root).expect("cas_root");

        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("directories");

        // Create a CAS object.
        let cas_data = b"cas-backed patch data for legacy receipt";
        let cas_hash = write_cas_object(&cas_root, cas_data);
        let cas_hex = hex::encode(cas_hash);

        // Create a cas_refs marker file and make it stale.
        let cas_refs_dir = fac_root.join("cas_refs");
        std::fs::create_dir_all(&cas_refs_dir).expect("cas_refs dir");
        let ref_file = cas_refs_dir.join(format!("{cas_hex}.ref"));
        std::fs::write(&ref_file, b"").expect("write ref file");
        let stale_secs = BLOB_RETENTION_SECS.saturating_mul(3) + 120;
        let stale_time = filetime_from_secs(current_wall_clock_secs().saturating_sub(stale_secs));
        set_file_mtime(&ref_file, stale_time).expect("set ref mtime");

        // Create a receipt that references the SAME hash but WITHOUT
        // bytes_backend — simulating a legacy receipt.  The hash should
        // route to blob_hashes in ReceiptBlobRefs.
        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        std::fs::create_dir_all(&receipts_dir).expect("receipts dir");
        let digest_str = format!("b3-256:{cas_hex}");
        let receipt_json = format!("{{\"patch_digest\":\"{digest_str}\"}}");
        let receipt_path = receipts_dir.join("legacy-receipt.json");
        std::fs::write(&receipt_path, receipt_json).expect("write receipt");

        let plan = plan_gc(
            &fac_root,
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
        )
        .expect("plan");

        // The CAS object MUST NOT be pruned — the legacy receipt keeps it alive.
        assert!(
            !plan
                .targets
                .iter()
                .any(|t| matches!(t.kind, crate::fac::gc_receipt::GcActionKind::CasBlobPrune)),
            "CAS object referenced by legacy receipt (no bytes_backend) must not be pruned"
        );
    }

    #[test]
    fn cas_ref_pruned_when_no_receipt_references_it() {
        // Complement to the above: a stale CAS ref with NO receipt reference
        // anywhere IS eligible for pruning.
        let dir = tempdir().expect("tmp");
        let private_dir = dir.path().join("private");
        let fac_root = private_dir.join("fac");
        let cas_root = private_dir.join("cas");
        std::fs::create_dir_all(&fac_root).expect("fac_root");
        std::fs::create_dir_all(&cas_root).expect("cas_root");

        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("directories");

        let cas_data = b"orphan cas object";
        let cas_hash = write_cas_object(&cas_root, cas_data);
        let cas_hex = hex::encode(cas_hash);

        // Create a stale cas_refs marker.
        let cas_refs_dir = fac_root.join("cas_refs");
        std::fs::create_dir_all(&cas_refs_dir).expect("cas_refs dir");
        let ref_file = cas_refs_dir.join(format!("{cas_hex}.ref"));
        std::fs::write(&ref_file, b"").expect("write ref file");
        let stale_secs = BLOB_RETENTION_SECS.saturating_mul(3) + 120;
        let stale_time = filetime_from_secs(current_wall_clock_secs().saturating_sub(stale_secs));
        set_file_mtime(&ref_file, stale_time).expect("set ref mtime");

        // NO receipt references this hash.
        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        std::fs::create_dir_all(&receipts_dir).expect("receipts dir");

        let plan = plan_gc(
            &fac_root,
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
        )
        .expect("plan");

        assert!(
            plan.targets
                .iter()
                .any(|t| matches!(t.kind, crate::fac::gc_receipt::GcActionKind::CasBlobPrune)),
            "orphan stale CAS ref must be pruned when no receipt references it"
        );
    }

    #[test]
    fn cas_ref_kept_alive_by_apm2_cas_receipt() {
        // A CAS ref whose hash appears in a receipt WITH bytes_backend=apm2_cas
        // (routed to cas_hashes) must also be kept alive.
        let dir = tempdir().expect("tmp");
        let private_dir = dir.path().join("private");
        let fac_root = private_dir.join("fac");
        let cas_root = private_dir.join("cas");
        std::fs::create_dir_all(&fac_root).expect("fac_root");
        std::fs::create_dir_all(&cas_root).expect("cas_root");

        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("directories");

        let cas_data = b"cas-backed patch data with apm2_cas tag";
        let cas_hash = write_cas_object(&cas_root, cas_data);
        let cas_hex = hex::encode(cas_hash);

        let cas_refs_dir = fac_root.join("cas_refs");
        std::fs::create_dir_all(&cas_refs_dir).expect("cas_refs dir");
        let ref_file = cas_refs_dir.join(format!("{cas_hex}.ref"));
        std::fs::write(&ref_file, b"").expect("write ref file");
        let stale_secs = BLOB_RETENTION_SECS.saturating_mul(3) + 120;
        let stale_time = filetime_from_secs(current_wall_clock_secs().saturating_sub(stale_secs));
        set_file_mtime(&ref_file, stale_time).expect("set ref mtime");

        // Receipt WITH bytes_backend=apm2_cas -> hash routes to cas_hashes.
        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        std::fs::create_dir_all(&receipts_dir).expect("receipts dir");
        let digest_str = format!("b3-256:{cas_hex}");
        let receipt_json =
            format!("{{\"patch_digest\":\"{digest_str}\",\"bytes_backend\":\"apm2_cas\"}}");
        let receipt_path = receipts_dir.join("cas-receipt.json");
        std::fs::write(&receipt_path, receipt_json).expect("write receipt");

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
                .any(|t| matches!(t.kind, crate::fac::gc_receipt::GcActionKind::CasBlobPrune)),
            "CAS object referenced by apm2_cas receipt must not be pruned"
        );
    }

    // =========================================================================
    // TCK-00546 NIT-1: record_cas_ref single-handle mtime update
    // =========================================================================

    #[test]
    fn record_cas_ref_creates_marker_and_sets_mtime() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac_root");

        let hash = *blake3::hash(b"test data").as_bytes();
        let before_secs = current_wall_clock_secs();

        super::record_cas_ref(&fac_root, &hash).expect("record_cas_ref");

        let hex = hex::encode(hash);
        let ref_path = fac_root.join("cas_refs").join(format!("{hex}.ref"));
        assert!(ref_path.exists(), "marker file must exist");

        // Verify mtime is recent (within a few seconds of now).
        let mtime_secs = file_modified_secs(&ref_path);
        assert!(
            mtime_secs >= before_secs.saturating_sub(2),
            "marker mtime ({mtime_secs}) must be recent (after {before_secs})"
        );
    }

    #[test]
    fn record_cas_ref_idempotent_updates_mtime() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac_root");

        let hash = *blake3::hash(b"idempotent data").as_bytes();
        super::record_cas_ref(&fac_root, &hash).expect("first record");

        let hex = hex::encode(hash);
        let ref_path = fac_root.join("cas_refs").join(format!("{hex}.ref"));

        // Backdate the marker to simulate staleness.
        let backdated = filetime_from_secs(current_wall_clock_secs().saturating_sub(86400));
        set_file_mtime(&ref_path, backdated).expect("backdate mtime");

        let mtime_before = file_modified_secs(&ref_path);

        // Sleep briefly to ensure time advances.
        sleep(Duration::from_millis(50));

        // Re-record: should update mtime.
        super::record_cas_ref(&fac_root, &hash).expect("second record");

        let mtime_after = file_modified_secs(&ref_path);
        assert!(
            mtime_after > mtime_before,
            "mtime must advance after re-recording (before={mtime_before}, after={mtime_after})"
        );
    }

    // =========================================================================
    // TCK-00571: Per-lane log retention pruning tests
    // =========================================================================

    /// Helper: create a fake job log directory under `logs_dir` with a
    /// specified size and mtime.
    fn create_job_log_dir(logs_dir: &Path, name: &str, size: u64, mtime_secs: u64) -> PathBuf {
        let job_dir = logs_dir.join(name);
        std::fs::create_dir_all(&job_dir).expect("create job log dir");
        let file = job_dir.join("output.log");
        write_file(&file, size);
        set_file_mtime(&job_dir, filetime_from_secs(mtime_secs)).expect("set job dir mtime");
        set_file_mtime(&file, filetime_from_secs(mtime_secs)).expect("set job file mtime");
        job_dir
    }

    #[test]
    fn log_retention_prunes_stale_job_dirs_by_ttl() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();
        let ttl_secs: u64 = 3600; // 1 hour

        // Create a stale job log (older than TTL).
        let stale_dir = create_job_log_dir(
            &logs_dir,
            "job-stale",
            100,
            now.saturating_sub(ttl_secs + 60),
        );

        // Create a fresh job log (within TTL).
        let fresh_dir = create_job_log_dir(&logs_dir, "job-fresh", 100, now);

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 0, // No byte quota.
            per_job_log_ttl_secs: ttl_secs,
            keep_last_n_jobs_per_lane: 0, // No keep-last-N protection.
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // Stale job should be pruned.
        assert!(
            targets.iter().any(|t| t.path == stale_dir
                && matches!(
                    t.kind,
                    crate::fac::gc_receipt::GcActionKind::LaneLogRetention
                )),
            "stale job log directory must be targeted for pruning"
        );

        // Fresh job should NOT be pruned.
        assert!(
            !targets.iter().any(|t| t.path == fresh_dir),
            "fresh job log directory must not be targeted for pruning"
        );
    }

    #[test]
    fn log_retention_respects_keep_last_n() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();
        let ttl_secs: u64 = 60; // Very short TTL to make everything stale.

        // Create 4 job logs, all stale, but keep_last_n=2.
        let _dir_a =
            create_job_log_dir(&logs_dir, "job-a", 100, now.saturating_sub(ttl_secs + 400));
        let _dir_b =
            create_job_log_dir(&logs_dir, "job-b", 100, now.saturating_sub(ttl_secs + 300));
        let dir_c = create_job_log_dir(&logs_dir, "job-c", 100, now.saturating_sub(ttl_secs + 200));
        let dir_d = create_job_log_dir(&logs_dir, "job-d", 100, now.saturating_sub(ttl_secs + 100));

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 0,
            per_job_log_ttl_secs: ttl_secs,
            keep_last_n_jobs_per_lane: 2, // Keep the 2 most recent.
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // The 2 oldest (a, b) should be pruned; the 2 newest (c, d) are protected.
        assert_eq!(
            targets.len(),
            2,
            "exactly 2 stale job log dirs (outside keep-last-2) should be pruned, got {}",
            targets.len()
        );
        assert!(
            !targets.iter().any(|t| t.path == dir_c || t.path == dir_d),
            "protected (keep-last-N) job log dirs must not be pruned"
        );
    }

    #[test]
    fn log_retention_enforces_byte_quota() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();

        // Create 3 job logs totaling 300 bytes, all recent (no TTL pruning).
        let dir_a = create_job_log_dir(&logs_dir, "job-a", 100, now.saturating_sub(30));
        let _dir_b = create_job_log_dir(&logs_dir, "job-b", 100, now.saturating_sub(20));
        let _dir_c = create_job_log_dir(&logs_dir, "job-c", 100, now.saturating_sub(10));

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 250,  // Quota: 250 bytes, total is ~300.
            per_job_log_ttl_secs: 0,      // No TTL pruning.
            keep_last_n_jobs_per_lane: 0, // No keep-last-N protection.
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // The oldest job (a) should be pruned to bring total within 250 bytes.
        assert_eq!(
            targets.len(),
            1,
            "exactly 1 job log dir should be pruned to meet byte quota, got {}",
            targets.len()
        );
        assert_eq!(
            targets[0].path, dir_a,
            "oldest job log directory should be pruned first"
        );
    }

    #[test]
    fn log_retention_byte_quota_respects_keep_last_n() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();

        // Create 3 job logs totaling 300 bytes, with keep_last_n=3.
        // Even though quota is 100 bytes, all 3 must be retained.
        let _dir_a = create_job_log_dir(&logs_dir, "job-a", 100, now.saturating_sub(30));
        let _dir_b = create_job_log_dir(&logs_dir, "job-b", 100, now.saturating_sub(20));
        let _dir_c = create_job_log_dir(&logs_dir, "job-c", 100, now.saturating_sub(10));

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 100, // Very tight quota.
            per_job_log_ttl_secs: 0,
            keep_last_n_jobs_per_lane: 3, // All 3 protected.
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // No pruning because all entries are protected by keep-last-N.
        assert_eq!(
            targets.len(),
            0,
            "no job log dirs should be pruned when all are protected by keep-last-N"
        );
    }

    #[test]
    fn log_retention_targets_top_level_files_and_symlinks() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();

        // Create a regular file (not a directory) in the logs dir.
        let file_path = logs_dir.join("stray-file.log");
        write_file(&file_path, 100);
        set_file_mtime(&file_path, filetime_from_secs(now.saturating_sub(86400)))
            .expect("set file mtime");

        // Create a symlink in the logs dir.
        #[cfg(unix)]
        {
            let symlink_path = logs_dir.join("symlink-job");
            let _ = std::os::unix::fs::symlink("/tmp", &symlink_path);
        }

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 0,
            per_job_log_ttl_secs: 1, // Very short TTL — everything should be stale.
            keep_last_n_jobs_per_lane: 0,
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // Regular files must appear as GC targets (fail-closed: stray
        // files cannot bypass per-lane log-retention controls).
        assert!(
            targets.iter().any(|t| t.path == file_path),
            "regular files in logs dir must be targeted for removal"
        );
        // Verify the file target includes its byte estimate.
        let file_target = targets.iter().find(|t| t.path == file_path).unwrap();
        assert_eq!(
            file_target.estimated_bytes, 100,
            "file target must report accurate byte estimate"
        );

        // Symlinks must appear as GC targets (fail-closed: symlinks in
        // logs/ are never valid and must be removed).
        #[cfg(unix)]
        {
            let symlink_path = logs_dir.join("symlink-job");
            assert!(
                targets.iter().any(|t| t.path == symlink_path),
                "symlinks in logs dir must be targeted for removal"
            );
            // Symlinks report zero bytes (they have no meaningful size).
            let symlink_target = targets.iter().find(|t| t.path == symlink_path).unwrap();
            assert_eq!(
                symlink_target.estimated_bytes, 0,
                "symlink target must report zero bytes"
            );
        }
    }

    #[test]
    fn log_retention_integrated_with_plan_gc() {
        // CQ-BLOCKER-1/2 fix: Verify that plan_gc_with_log_retention applies
        // retention policy (LaneLogRetention) to idle lanes instead of
        // unconditional full removal (LaneLog). The plan should contain
        // LaneLogRetention for the stale job log directory.
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();
        let stale_job = create_job_log_dir(
            &logs_dir,
            "job-stale",
            200,
            now.saturating_sub(86400 * 30), // 30 days old
        );

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 100 * 1024 * 1024,
            per_job_log_ttl_secs: 7 * 86400, // 7 days
            keep_last_n_jobs_per_lane: 0,
        };

        let plan = plan_gc_with_log_retention(
            lane_manager.fac_root(),
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
            &config,
        )
        .expect("plan");

        // CQ-BLOCKER-1/2: Idle lanes must use LaneLogRetention (policy-based
        // pruning), not LaneLog (unconditional full removal).
        let has_retention = plan.targets.iter().any(|t| {
            matches!(
                t.kind,
                crate::fac::gc_receipt::GcActionKind::LaneLogRetention
            )
        });
        assert!(
            has_retention,
            "plan must include LaneLogRetention targets for idle lane (policy-based pruning)"
        );

        // The stale job directory must be individually targeted.
        assert!(
            plan.targets.iter().any(|t| t.path == stale_job),
            "stale job log directory must be targeted for retention-based pruning"
        );

        // LaneLog must NOT appear — idle lanes should not get blanket
        // log directory removal.
        let has_full_log = plan
            .targets
            .iter()
            .any(|t| matches!(t.kind, crate::fac::gc_receipt::GcActionKind::LaneLog));
        assert!(
            !has_full_log,
            "LaneLog must not appear for idle lanes — retention policy must be applied instead"
        );
    }

    #[test]
    fn log_retention_no_pruning_when_all_within_policy() {
        // When all job logs are recent and within byte quota, no pruning
        // should occur.
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();

        // Create 2 recent, small job logs.
        let _dir_a = create_job_log_dir(&logs_dir, "job-a", 50, now.saturating_sub(10));
        let _dir_b = create_job_log_dir(&logs_dir, "job-b", 50, now.saturating_sub(5));

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 1000, // Well within quota.
            per_job_log_ttl_secs: 86400,  // 1 day TTL.
            keep_last_n_jobs_per_lane: 5,
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        assert_eq!(
            targets.len(),
            0,
            "no pruning should occur when all job logs are within policy"
        );
    }

    // =========================================================================
    // Regression tests for review findings
    // =========================================================================

    #[test]
    fn log_retention_skips_lanes_with_full_log_gc_target() {
        // CQ-MAJOR-2 regression: LaneLogRetention targets must be suppressed
        // when the parent LaneLog is already scheduled for full removal.
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();
        let _stale_dir =
            create_job_log_dir(&logs_dir, "job-stale", 200, now.saturating_sub(86400 * 30));

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 0,
            per_job_log_ttl_secs: 3600,
            keep_last_n_jobs_per_lane: 0,
        };

        // Simulate that this lane's LaneLog is already scheduled for GC.
        let lanes_with_full_gc: HashSet<String> = std::iter::once(lane_id.clone()).collect();

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &lanes_with_full_gc,
            &mut targets,
        );

        assert_eq!(
            targets.len(),
            0,
            "LaneLogRetention targets must be suppressed when parent LaneLog \
             is already scheduled for full removal"
        );
    }

    #[test]
    fn log_retention_zero_ttl_uses_default() {
        // CQ-NIT-1 regression: per_job_log_ttl_secs=0 must use the default
        // 7-day TTL, not disable age pruning entirely.
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();
        // Create a job log older than 7 days.
        let stale_dir = create_job_log_dir(
            &logs_dir,
            "job-old",
            100,
            now.saturating_sub(8 * 86400), // 8 days old
        );

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 0,
            per_job_log_ttl_secs: 0, // 0 means "use default" (7 days)
            keep_last_n_jobs_per_lane: 0,
        };

        // Verify effective_ttl_secs maps 0 to 7 days.
        assert_eq!(
            config.effective_ttl_secs(),
            7 * 24 * 3600,
            "effective_ttl_secs must map 0 to default 7-day TTL"
        );

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // The 8-day-old job log should be pruned (older than default 7-day TTL).
        assert!(
            targets.iter().any(|t| t.path == stale_dir),
            "zero TTL must apply default 7-day TTL and prune 8-day-old job log"
        );
    }

    #[test]
    fn execute_gc_reports_zero_bytes_freed_for_already_absent() {
        // CQ-MAJOR-2 regression: bytes_freed must be 0 when the target was
        // AlreadyAbsent (parent already deleted the child).
        let temp = tempdir().expect("tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(temp.path(), perms).expect("set permissions");
        }

        // Create a target that does NOT exist on disk.
        let absent_path = temp.path().join("absent_dir");
        let plan = GcPlan {
            targets: vec![GcTarget {
                path: absent_path,
                allowed_parent: temp.path().to_path_buf(),
                kind: crate::fac::gc_receipt::GcActionKind::CargoCache,
                estimated_bytes: 42,
            }],
        };

        let receipt = execute_gc(&plan);
        assert_eq!(receipt.actions.len(), 1, "should have one action");
        assert_eq!(
            receipt.actions[0].bytes_freed, 0,
            "bytes_freed must be 0 for AlreadyAbsent targets"
        );
    }

    #[test]
    fn log_retention_scan_overflow_skips_lane() {
        // S-MAJOR-1/2 regression: When scan exceeds MAX_JOB_LOG_ENTRIES_PER_LANE,
        // the lane must be skipped entirely (fail-closed) rather than proceeding
        // with a partial candidate set.
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();

        // Create MAX_JOB_LOG_ENTRIES_PER_LANE + 1 directories to trigger overflow.
        for i in 0..=MAX_JOB_LOG_ENTRIES_PER_LANE {
            let name = format!("job-{i:06}");
            let job_dir = logs_dir.join(&name);
            std::fs::create_dir_all(&job_dir).expect("create job dir");
            let file = job_dir.join("output.log");
            write_file(&file, 10);
            // Make them all stale so they would be pruned if scanned.
            set_file_mtime(&job_dir, filetime_from_secs(now.saturating_sub(86400 * 30)))
                .expect("set mtime");
        }

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 0,
            per_job_log_ttl_secs: 3600,
            keep_last_n_jobs_per_lane: 0,
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // The lane must be skipped entirely — no partial pruning.
        assert_eq!(
            targets.len(),
            0,
            "scan overflow must cause lane to be skipped entirely (fail-closed), \
             got {} targets",
            targets.len()
        );
    }

    // =========================================================================
    // CQ-BLOCKER-1/2 regression: keep-last-N enforced for idle lanes through
    // the full plan_gc_with_log_retention path
    // =========================================================================

    #[test]
    fn idle_lane_keep_last_n_enforced_via_plan_gc() {
        // CQ-BLOCKER-1/2 regression: idle lanes with >N jobs in logs must
        // have keep-last-N enforced. Before the fix, collect_idle_lane_targets
        // emitted a blanket LaneLog target for the entire logs/ directory,
        // which caused plan_gc_with_log_retention to skip retention policy
        // for idle lanes.
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();
        let ttl_secs: u64 = 60;

        // Create 5 stale job logs.
        let dir_a = create_job_log_dir(&logs_dir, "job-a", 100, now.saturating_sub(ttl_secs + 500));
        let dir_b = create_job_log_dir(&logs_dir, "job-b", 100, now.saturating_sub(ttl_secs + 400));
        let dir_c = create_job_log_dir(&logs_dir, "job-c", 100, now.saturating_sub(ttl_secs + 300));
        let dir_d = create_job_log_dir(&logs_dir, "job-d", 100, now.saturating_sub(ttl_secs + 200));
        let dir_e = create_job_log_dir(&logs_dir, "job-e", 100, now.saturating_sub(ttl_secs + 100));

        // Keep last 2 — only the 3 oldest should be pruned.
        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 0,
            per_job_log_ttl_secs: ttl_secs,
            keep_last_n_jobs_per_lane: 2,
        };

        let plan = plan_gc_with_log_retention(
            lane_manager.fac_root(),
            &lane_manager,
            QUARANTINE_RETENTION_SECS,
            DENIED_RETENTION_SECS,
            &config,
        )
        .expect("plan");

        // The 3 oldest (a, b, c) should be pruned via LaneLogRetention.
        let retention_targets: Vec<_> = plan
            .targets
            .iter()
            .filter(|t| {
                matches!(
                    t.kind,
                    crate::fac::gc_receipt::GcActionKind::LaneLogRetention
                )
            })
            .collect();
        assert_eq!(
            retention_targets.len(),
            3,
            "exactly 3 stale job log dirs (outside keep-last-2) should be pruned via LaneLogRetention, got {}",
            retention_targets.len()
        );
        assert!(
            retention_targets.iter().any(|t| t.path == dir_a),
            "oldest job (a) must be pruned"
        );
        assert!(
            retention_targets.iter().any(|t| t.path == dir_b),
            "second oldest job (b) must be pruned"
        );
        assert!(
            retention_targets.iter().any(|t| t.path == dir_c),
            "third oldest job (c) must be pruned"
        );

        // The 2 newest (d, e) must NOT be pruned — protected by keep-last-N.
        assert!(
            !plan.targets.iter().any(|t| t.path == dir_d),
            "protected job (d) must not be pruned"
        );
        assert!(
            !plan.targets.iter().any(|t| t.path == dir_e),
            "protected job (e) must not be pruned"
        );

        // No LaneLog target should exist — retention policy is applied instead.
        assert!(
            !plan
                .targets
                .iter()
                .any(|t| matches!(t.kind, crate::fac::gc_receipt::GcActionKind::LaneLog)),
            "LaneLog must not appear for idle lanes — retention policy must be applied"
        );
    }

    // =========================================================================
    // CQ-MAJOR-1/2 regression: overflow discards ALL lane targets atomically
    // =========================================================================

    #[test]
    fn log_retention_overflow_discards_symlink_and_file_targets() {
        // CQ-MAJOR-1/2 regression: When scan_overflow is triggered,
        // previously-appended symlink and regular-file targets for the
        // same lane must also be discarded (atomicity).
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();

        // Create a stray file and a symlink in the logs directory.
        let stray_file = logs_dir.join("stray-file.log");
        write_file(&stray_file, 50);

        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink("/tmp", logs_dir.join("symlink-entry"));
        }

        // Create MAX_JOB_LOG_ENTRIES_PER_LANE + 1 directories to trigger overflow.
        // The stray file and symlink count toward scan_count too, so we need
        // enough total entries to exceed the cap.
        let entries_to_create = MAX_JOB_LOG_ENTRIES_PER_LANE;
        for i in 0..entries_to_create {
            let name = format!("job-{i:06}");
            let job_dir = logs_dir.join(&name);
            std::fs::create_dir_all(&job_dir).expect("create job dir");
            set_file_mtime(&job_dir, filetime_from_secs(now.saturating_sub(86400 * 30)))
                .expect("set mtime");
        }

        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 0,
            per_job_log_ttl_secs: 3600,
            keep_last_n_jobs_per_lane: 0,
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // ALL targets for the overflowed lane must be discarded — including
        // symlink and file targets that were collected before the overflow.
        assert_eq!(
            targets.len(),
            0,
            "overflow must discard ALL lane targets atomically (including symlinks/files), \
             got {} targets",
            targets.len()
        );
    }

    #[test]
    fn test_recursive_estimator_counts_nested_files() {
        let dir = tempdir().expect("tmp");
        let log_dir = dir.path().join("log");
        std::fs::create_dir(&log_dir).expect("mkdir");
        let nested = log_dir.join("nested");
        std::fs::create_dir(&nested).expect("mkdir nested");

        let file = nested.join("large.log");
        write_file(&file, 1024);

        let mut visited = 0;
        let size = estimate_job_log_dir_size_recursive(&log_dir, &mut visited);

        // Metadata for 'nested' dir (usually 4096 on Linux ext4) + file size (1024).
        // Shallow estimator would return only dir metadata (~4096).
        // Recursive should be at least 1024 + dir metadata.
        assert!(
            size >= 1024,
            "recursive estimator must count nested file size"
        );
    }

    #[test]
    fn test_recursive_estimator_enforces_limit() {
        let dir = tempdir().expect("tmp");
        let log_dir = dir.path().join("log");
        std::fs::create_dir(&log_dir).expect("mkdir");

        // Create enough files to trip the limit if we start near it.
        for i in 0..10 {
            write_file(&log_dir.join(format!("{i}")), 10);
        }

        // Initialize visited count close to the limit to simulate a large scan
        // having already happened.
        let mut visited = MAX_LANE_SCAN_ENTRIES.saturating_sub(5);
        let size = estimate_job_log_dir_size_recursive(&log_dir, &mut visited);

        assert_eq!(
            size,
            u64::MAX,
            "must return u64::MAX (fail-closed) when scan limit is exceeded"
        );
    }

    // =========================================================================
    // Regression tests for round-N review findings (PR #759)
    // =========================================================================

    /// BLOCKER regression: `collect_lane_log_retention_targets` MUST skip a
    /// lane whose `logs/` directory is a symlink. If `logs/` is a symlink,
    /// all subsequent `read_dir`/path operations would resolve outside the
    /// lane root, enabling arbitrary-file-deletion attacks via GC targets.
    #[cfg(unix)]
    #[test]
    fn log_retention_skips_lane_with_symlinked_logs_directory() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let lane_dir = lane_manager.lane_dir(lane_id);
        let logs_dir = lane_dir.join("logs");

        // Create a target directory outside the lane with a canary file.
        let target_dir = dir.path().join("attacker-target");
        std::fs::create_dir_all(&target_dir).expect("create target");
        let canary = target_dir.join("canary.txt");
        std::fs::write(&canary, b"must survive").expect("write canary");

        // Replace logs/ with a symlink to the attacker-controlled directory.
        if logs_dir.exists() {
            std::fs::remove_dir_all(&logs_dir).expect("remove real logs");
        }
        std::os::unix::fs::symlink(&target_dir, &logs_dir).expect("create symlink at logs/");

        let now = current_wall_clock_secs();
        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 0,
            per_job_log_ttl_secs: 1, // Very short TTL
            keep_last_n_jobs_per_lane: 0,
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // No targets should be emitted for this lane — the symlinked
        // logs/ directory must be rejected at entry (fail-closed).
        assert_eq!(
            targets.len(),
            0,
            "symlinked logs/ directory must be skipped entirely — \
             no GC targets should be emitted, got {} targets",
            targets.len()
        );

        // Canary file must survive — symlink was not followed.
        assert!(
            canary.exists(),
            "canary file outside lane root must not be affected — \
             symlink following was correctly prevented"
        );
    }

    /// MAJOR regression: when `estimate_job_log_dir_size_recursive` returns
    /// `u64::MAX` (traversal overflow sentinel) for any job log entry, the
    /// byte-quota phase in `collect_lane_log_retention_targets` MUST be
    /// skipped. Using the sentinel in arithmetic would cause `saturating_add`
    /// to produce `u64::MAX` for `total_bytes`, breaking quota enforcement.
    #[test]
    fn log_retention_skips_byte_quota_when_estimator_returns_sentinel() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();

        // Create a small job log (100 bytes, recent).
        let job_a = create_job_log_dir(&logs_dir, "job-a", 100, now.saturating_sub(10));

        // Create a job log with deep nesting that will trigger the
        // MAX_LANE_SCAN_ENTRIES limit in the recursive estimator.
        // We pre-fill the nesting with enough entries to exceed the
        // limit. Use wide nesting: 200 subdirs x 501 files = 100,200.
        let job_b_dir = logs_dir.join("job-b-overflow");
        std::fs::create_dir_all(&job_b_dir).expect("create job-b");
        for dir_idx in 0..200 {
            let subdir = job_b_dir.join(format!("d{dir_idx:04}"));
            std::fs::create_dir_all(&subdir).expect("subdir");
            for file_idx in 0..501 {
                write_file(&subdir.join(format!("f{file_idx:04}")), 10);
            }
        }
        set_file_mtime(&job_b_dir, filetime_from_secs(now.saturating_sub(20)))
            .expect("set job-b mtime");

        // Verify that the estimator actually returns u64::MAX for job-b.
        let mut visited = 0;
        let est = estimate_job_log_dir_size_recursive(&job_b_dir, &mut visited);
        assert_eq!(
            est,
            u64::MAX,
            "precondition: estimator must return u64::MAX for job-b-overflow"
        );

        // Use a very tight byte quota. Without the sentinel guard:
        // - total_bytes would be u64::MAX (saturating_add with sentinel)
        // - After subtracting job-b (u64::MAX), total_bytes would be ~100
        // - 100 < 50 is false, so job-a would be incorrectly pruned
        // OR the arithmetic would be unpredictable.
        // With the sentinel guard: byte-quota phase is skipped entirely.
        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 50, // Tight quota
            per_job_log_ttl_secs: 0,    // No TTL pruning
            keep_last_n_jobs_per_lane: 0,
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // With the sentinel guard, byte-quota is skipped. No TTL pruning
        // (all recent). So no targets should be emitted.
        assert_eq!(
            targets.len(),
            0,
            "byte-quota phase must be skipped when estimator returns u64::MAX \
             sentinel — no targets should be emitted, got {} targets \
             (paths: {:?})",
            targets.len(),
            targets.iter().map(|t| &t.path).collect::<Vec<_>>()
        );

        // Both job dirs must survive — byte quota was not applied.
        assert!(
            job_a.exists(),
            "job-a must survive: byte-quota must be skipped when sentinel detected"
        );
    }

    // =========================================================================
    // Regression tests for round-N+1 review findings (CQ-MAJOR-1, CQ-MAJOR-2)
    // =========================================================================

    /// CQ-MAJOR-1 regression: symlink GC targets emitted by
    /// `collect_lane_log_retention_targets` must be successfully removed by
    /// `execute_gc` using `remove_file`, NOT `safe_rmtree` (which rejects
    /// symlink roots by design with `SymlinkDetected`).
    #[cfg(unix)]
    #[test]
    fn execute_gc_removes_symlink_lane_log_retention_targets() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root.clone()).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        // Create the lane lock file so execute_gc can acquire the lock.
        // ensure_directories() creates locks/lanes/ but not the .lock files.
        let lock_dir = fac_root.join("locks").join("lanes");
        std::fs::create_dir_all(&lock_dir).expect("create lock dir");
        std::fs::write(lock_dir.join(format!("{lane_id}.lock")), b"")
            .expect("create lane lock file");

        // Create a real target outside the lane for the symlink to point to.
        let outside_target = dir.path().join("outside-target");
        std::fs::create_dir_all(&outside_target).expect("create outside target");
        let canary = outside_target.join("canary.txt");
        std::fs::write(&canary, b"must survive").expect("write canary");

        // Create a symlink entry under logs/ (invalid — only directories
        // should exist here).
        let symlink_path = logs_dir.join("evil-symlink-job");
        std::os::unix::fs::symlink(&outside_target, &symlink_path)
            .expect("create symlink under logs/");
        assert!(
            symlink_path
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "precondition: must be a symlink"
        );

        // Construct a GcPlan with the symlink as a LaneLogRetention target
        // (exactly as collect_lane_log_retention_targets would emit).
        let plan = GcPlan {
            targets: vec![GcTarget {
                path: symlink_path.clone(),
                allowed_parent: logs_dir,
                kind: crate::fac::gc_receipt::GcActionKind::LaneLogRetention,
                estimated_bytes: 0,
            }],
        };

        let receipt = execute_gc(&plan);

        // The symlink must have been removed — no errors.
        assert_eq!(
            receipt.errors.len(),
            0,
            "symlink LaneLogRetention target must not produce errors, got: {:?}",
            receipt.errors
        );
        assert_eq!(
            receipt.actions.len(),
            1,
            "exactly one action expected for the symlink target"
        );
        assert!(
            symlink_path.symlink_metadata().is_err(),
            "symlink must have been removed by execute_gc"
        );

        // Canary file must survive — the symlink was removed, not followed.
        assert!(
            canary.exists(),
            "canary file outside lane root must not be affected — \
             only the symlink entry was removed, not its target"
        );
    }

    /// CQ-MAJOR-2 regression: depth overflow in
    /// `estimate_job_log_dir_size_recursive_inner` MUST return `u64::MAX`
    /// (fail-closed sentinel), NOT `0`. Returning `0` would allow deeply-
    /// nested directories to bypass byte-quota pruning by being
    /// undercounted as zero bytes.
    #[test]
    fn depth_overflow_returns_sentinel_not_zero() {
        let dir = tempdir().expect("tmp");
        let root = dir.path().join("deep");

        // Build a directory tree deeper than MAX_TRAVERSAL_DEPTH.
        // Each level has one file to produce a non-zero "real" size if
        // the estimator were not depth-capped.
        let mut current = root.clone();
        for level in 0..=MAX_TRAVERSAL_DEPTH + 2 {
            std::fs::create_dir_all(&current).expect("mkdir deep level");
            write_file(&current.join(format!("file_{level}.dat")), 1024);
            current = current.join(format!("d{level}"));
        }

        let mut visited = 0;
        let size = estimate_job_log_dir_size_recursive(&root, &mut visited);

        // The estimator MUST return u64::MAX because it hits depth >=
        // MAX_TRAVERSAL_DEPTH in the recursive descent. Returning 0
        // would be the old (broken) behavior.
        assert_eq!(
            size,
            u64::MAX,
            "depth overflow must return u64::MAX sentinel (fail-closed), not 0"
        );
    }

    /// CQ-MAJOR-2 regression (end-to-end): a lane log directory whose
    /// recursive size estimation hits the depth limit must not allow
    /// byte-quota bypass. The sentinel value must trigger the fail-closed
    /// path that skips byte-quota enforcement entirely.
    #[test]
    fn deep_tree_cannot_bypass_quota_via_zero_size() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("fac");
        let lane_manager = LaneManager::new(fac_root).expect("manager");
        lane_manager.ensure_directories().expect("dirs");

        let lane_ids = LaneManager::default_lane_ids();
        let lane_id = lane_ids.first().expect("at least one lane");
        let logs_dir = lane_manager.lane_dir(lane_id).join("logs");

        let now = current_wall_clock_secs();

        // Create a "normal" small job log (recent, 100 bytes).
        let _job_a = create_job_log_dir(&logs_dir, "job-normal", 100, now.saturating_sub(10));

        // Create a deep-nested job log that will trigger depth overflow.
        let deep_job = logs_dir.join("job-deep");
        std::fs::create_dir_all(&deep_job).expect("mkdir deep job");
        let mut current = deep_job.clone();
        for level in 0..=MAX_TRAVERSAL_DEPTH + 2 {
            std::fs::create_dir_all(&current).expect("mkdir level");
            write_file(&current.join(format!("data_{level}.bin")), 2048);
            current = current.join(format!("sub{level}"));
        }
        set_file_mtime(&deep_job, filetime_from_secs(now.saturating_sub(20)))
            .expect("set deep job mtime");

        // Verify precondition: estimator returns u64::MAX for the deep job.
        let mut visited = 0;
        let est = estimate_job_log_dir_size_recursive(&deep_job, &mut visited);
        assert_eq!(
            est,
            u64::MAX,
            "precondition: estimator must return u64::MAX for deep job"
        );

        // Use a very tight byte quota. If depth overflow returned 0 (old bug):
        // - deep job counted as 0 bytes
        // - total_bytes = 100 (only job-normal)
        // - 100 > 50 → job-normal pruned (WRONG — deep job is the oversized one)
        // With the fix (u64::MAX sentinel):
        // - has_size_overflow = true → byte-quota phase skipped entirely
        let config = LogRetentionConfig {
            per_lane_log_max_bytes: 50, // Very tight quota
            per_job_log_ttl_secs: 0,    // No TTL pruning (use default 7 days)
            keep_last_n_jobs_per_lane: 0,
        };

        let mut targets = Vec::new();
        collect_lane_log_retention_targets(
            &lane_manager,
            &lane_ids,
            &config,
            now,
            &HashSet::new(),
            &mut targets,
        );

        // With fail-closed sentinel: byte-quota is skipped, no TTL pruning
        // (all recent). No targets should be emitted.
        assert_eq!(
            targets.len(),
            0,
            "deep tree triggering depth-overflow sentinel must not allow \
             byte-quota bypass — no pruning targets expected, got {} \
             (paths: {:?})",
            targets.len(),
            targets.iter().map(|t| &t.path).collect::<Vec<_>>()
        );
    }
}
