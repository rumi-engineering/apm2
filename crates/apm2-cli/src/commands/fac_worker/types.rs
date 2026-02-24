#[allow(clippy::wildcard_imports)]
use super::*;

/// Maximum number of pending entries to scan per cycle (INV-WRK-006).
///
/// Prevents unbounded memory growth from a queue directory with many files.
pub(super) const MAX_PENDING_SCAN_ENTRIES: usize = 4096;

/// Queue subdirectory names.
pub(super) const QUEUE_DIR: &str = "queue";
pub(super) const PENDING_DIR: &str = "pending";
pub(super) const CLAIMED_DIR: &str = "claimed";
pub(super) const COMPLETED_DIR: &str = "completed";
pub(super) const DENIED_DIR: &str = "denied";
pub(super) const QUARANTINE_DIR: &str = "quarantine";
pub(super) const CANCELLED_DIR: &str = "cancelled";
/// Broker requests directory where non-service-user callers submit jobs
/// for promotion by the worker (TCK-00577).
pub(super) const BROKER_REQUESTS_DIR: &str = "broker_requests";
pub(super) const CONSUME_RECEIPTS_DIR: &str = "authority_consumed";

/// Fixed degraded-mode safety nudge interval (seconds).
///
/// This is intentionally not a user-facing CLI knob: steady-state queue pickup
/// is event-driven and this interval is only used as a bounded fallback when
/// watcher delivery is degraded.
pub(super) const DEGRADED_SAFETY_NUDGE_SECS: u64 = 60;

/// Max number of boundary defect classes retained in a trace.
pub(super) const MAX_BOUNDARY_DEFECT_CLASSES: usize = 32;
pub(super) const SCHEDULER_RECOVERY_SCHEMA: &str = "apm2.scheduler_recovery.v1";

/// Lockfile name for the enqueue critical section.
///
/// Shared with `fac_queue_submit::ENQUEUE_LOCKFILE` (same string value).
/// The worker must use the same lockfile as `enqueue_direct` to serialize
/// broker promotions with direct enqueue processes.
///
/// Synchronization protocol:
/// - Protected data: set of files in `queue/pending/` and the snapshot-derived
///   bounds decision.
/// - Who can mutate: only the holder of the exclusive flock.
/// - Lock ordering: single lock, no nesting required.
/// - Happens-before: `lock_exclusive()` → scan pending dir + move → drop
///   lockfile (implicit `flock(LOCK_UN)` on `File::drop`).
/// - Async suspension: not applicable (synchronous path).
pub(super) const ENQUEUE_LOCKFILE: &str = ".enqueue.lock";

/// Lock acquisition method identifier for claimed-file ownership.
pub(super) const CLAIMED_LOCK_ACQUISITION_METHOD_FLOCK_EXCLUSIVE: &str =
    "claimed_file_flock_exclusive_v1";
pub(super) const CLAIMED_LOCK_RELEASE_PHASE_POST_TERMINAL_COMMIT: &str = "post_terminal_commit";

/// Single-owner claimed-file lock guard for CLCK continuity.
///
/// This guard is created only by `claim_pending_job_with_exclusive_lock` and
/// must be threaded through execution until terminal commit completes. The lock
/// is released only when this guard is dropped.
pub(super) struct ClaimedJobLockGuardV1 {
    job_id: String,
    claimed_path: PathBuf,
    lock_acquired_at_epoch_ms: u64,
    lock_acquisition_method: &'static str,
    lock_file: fs::File,
}

impl std::fmt::Debug for ClaimedJobLockGuardV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimedJobLockGuardV1")
            .field("job_id", &self.job_id)
            .field("claimed_path", &self.claimed_path)
            .field("lock_acquired_at_epoch_ms", &self.lock_acquired_at_epoch_ms)
            .field("lock_acquisition_method", &self.lock_acquisition_method)
            .finish_non_exhaustive()
    }
}

impl ClaimedJobLockGuardV1 {
    pub(super) fn from_claimed_lock(
        job_id: String,
        claimed_path: PathBuf,
        lock_file: fs::File,
    ) -> Self {
        Self {
            job_id,
            claimed_path,
            lock_acquired_at_epoch_ms: current_epoch_millis(),
            lock_acquisition_method: CLAIMED_LOCK_ACQUISITION_METHOD_FLOCK_EXCLUSIVE,
            lock_file,
        }
    }

    pub(super) fn job_id(&self) -> &str {
        &self.job_id
    }

    pub(super) fn claimed_path(&self) -> &Path {
        &self.claimed_path
    }

    pub(super) const fn lock_acquired_at_epoch_ms(&self) -> u64 {
        self.lock_acquired_at_epoch_ms
    }

    pub(super) const fn lock_acquisition_method(&self) -> &'static str {
        self.lock_acquisition_method
    }

    pub(super) const fn lock_file(&self) -> &fs::File {
        &self.lock_file
    }
}

fn current_epoch_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// FAC receipt directory under `$APM2_HOME/private/fac`.
pub(super) const FAC_RECEIPTS_DIR: &str = "receipts";
pub(super) const CORRUPT_MARKER_PERSIST_RETRIES: usize = 3;
pub(super) const CORRUPT_MARKER_PERSIST_RETRY_DELAY_MS: u64 = 25;

/// Last-resort fallback boundary ID when node identity cannot be loaded.
///
/// Production deployments use `load_or_default_boundary_id()` which reads
/// the actual boundary from `$APM2_HOME/private/fac/identity/boundary_id`.
/// This constant is only used when `resolve_apm2_home()` fails (no home
/// directory available at all).
pub(super) const FALLBACK_BOUNDARY_ID: &str = "local";

/// Default authority clock for local-mode evaluation windows.
pub(super) const DEFAULT_AUTHORITY_CLOCK: &str = "local";
#[cfg(test)]
pub(super) const DEFAULT_GATES_TIMEOUT_SECONDS: u64 = 600;
#[cfg(test)]
pub(super) const DEFAULT_GATES_MEMORY_MAX: &str = "48G";
#[cfg(test)]
pub(super) const DEFAULT_GATES_PIDS_MAX: u64 = 1536;
#[cfg(test)]
pub(super) const DEFAULT_GATES_CPU_QUOTA: &str = "auto";
pub(super) const UNKNOWN_REPO_SEGMENT: &str = "unknown";
pub(super) const ALLOWED_WORKSPACE_ROOTS_ENV: &str = "APM2_FAC_ALLOWED_WORKSPACE_ROOTS";
pub(super) const GATES_HEARTBEAT_REFRESH_SECS: u64 = 5;
pub(super) const FAC_JOB_UNIT_BASE_PREFIX: &str = "apm2-fac-job-";
pub(super) const FAC_GATES_SYNTHETIC_LANE_ID: &str = "lane-00";
pub(super) const MAX_QUEUED_GATES_UNIT_BASE_LEN: usize = 200;
pub(super) const ORPHAN_LEASE_WARNING_MULTIPLIER: u64 = 2;
pub(super) const MAX_COMPLETED_SCAN_ENTRIES: usize = 4096;
pub(super) const MAX_TERMINAL_JOB_METADATA_FILE_SIZE: usize = MAX_JOB_SPEC_SIZE * 4;
pub(super) const WORKER_WAKE_SIGNAL_BUFFER: usize = 256;
pub(super) const RUNTIME_REPAIR_STATE_SCHEMA: &str = "apm2.fac.runtime_reconcile_machine.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimeRepairState {
    Idle,
    RepairRequested,
    AwaitingScanLock,
    Reconciling,
    Reconciled,
    Blocked,
    Failed,
}

pub(super) const fn runtime_repair_state_label(state: RuntimeRepairState) -> &'static str {
    match state {
        RuntimeRepairState::Idle => "idle",
        RuntimeRepairState::RepairRequested => "repair_requested",
        RuntimeRepairState::AwaitingScanLock => "awaiting_scan_lock",
        RuntimeRepairState::Reconciling => "reconciling",
        RuntimeRepairState::Reconciled => "reconciled",
        RuntimeRepairState::Blocked => "blocked",
        RuntimeRepairState::Failed => "failed",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkerWakeReason {
    Startup,
    PendingQueueChanged,
    ClaimedQueueChanged,
    RepairRequested,
    SafetyNudge,
    WatcherDegraded,
}

#[derive(Debug, Clone)]
pub(super) enum WorkerWakeSignal {
    Wake(WorkerWakeReason),
    WatcherUnavailable { reason: String },
    WatcherOverflow { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum QueueWatcherMode {
    Active,
    Degraded { reason: String },
}

impl QueueWatcherMode {
    pub(super) const fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }

    pub(super) fn transition_to_degraded(&mut self, reason: String) -> bool {
        if self.is_degraded() {
            return false;
        }
        *self = Self::Degraded { reason };
        true
    }

    pub(super) fn reason(&self) -> Option<&str> {
        match self {
            Self::Active => None,
            Self::Degraded { reason } => Some(reason.as_str()),
        }
    }
}

/// Outcome of processing a single job spec file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(super) enum JobOutcome {
    /// Job was quarantined due to malformed spec or digest mismatch.
    Quarantined { reason: String },
    /// Job was denied due to token or admission failure.
    Denied { reason: String },
    /// Job was successfully claimed and executed.
    Completed {
        job_id: String,
        /// Observed runtime cost metrics for post-run cost model calibration.
        observed_cost: Option<apm2_core::economics::cost_model::ObservedJobCost>,
    },
    /// Job was aborted due to unrecoverable internal error.
    /// NOTE: currently unused because cleanup failures no longer change
    /// job outcome (BLOCKER fix for f-685-code_quality-0). Retained for
    /// future use by execution substrate error paths.
    Aborted { reason: String },
    /// Job was skipped (already claimed or missing).
    Skipped {
        reason: String,
        disposition: JobSkipDisposition,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JobSkipDisposition {
    Generic,
    NoLaneAvailable,
    PipelineCommitFailed,
}

impl JobOutcome {
    pub(super) fn skipped(reason: impl Into<String>) -> Self {
        Self::Skipped {
            reason: reason.into(),
            disposition: JobSkipDisposition::Generic,
        }
    }

    pub(super) fn skipped_no_lane(reason: impl Into<String>) -> Self {
        Self::Skipped {
            reason: reason.into(),
            disposition: JobSkipDisposition::NoLaneAvailable,
        }
    }

    pub(super) fn skipped_pipeline_commit(reason: impl Into<String>) -> Self {
        Self::Skipped {
            reason: reason.into(),
            disposition: JobSkipDisposition::PipelineCommitFailed,
        }
    }
}

/// Summary output for JSON mode.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub(super) struct WorkerSummary {
    /// Number of jobs processed.
    pub(super) jobs_processed: usize,
    /// Number of jobs completed (claimed + executed).
    pub(super) jobs_completed: usize,
    /// Number of jobs denied.
    pub(super) jobs_denied: usize,
    /// Number of jobs quarantined.
    pub(super) jobs_quarantined: usize,
    /// Number of jobs skipped.
    pub(super) jobs_skipped: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CanonicalizerTupleCheck {
    Matched,
    Missing,
    Mismatch(CanonicalizerTupleV1),
}

#[derive(Debug)]
pub(super) struct SchedulerRecoveryReceipt {
    /// Scheduler recovery receipt schema.
    pub(super) schema: String,
    /// Recovery reason for reconstructing scheduler state.
    pub(super) reason: String,
    /// Recovery timestamp in epoch seconds.
    pub(super) timestamp_secs: u64,
}

/// A candidate pending job for sorting and processing.
#[derive(Debug)]
pub(super) struct PendingCandidate {
    /// Path to the pending JSON file.
    pub(super) path: PathBuf,
    /// Deserialized job spec (valid parse only, not yet fully validated).
    pub(super) spec: FacJobSpecV1,
    /// Raw bytes from the bounded read.
    pub(super) raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(super) struct GatesJobOptions {
    pub(super) force: bool,
    pub(super) quick: bool,
    pub(super) timeout_seconds: u64,
    pub(super) memory_max: String,
    pub(super) pids_max: u64,
    pub(super) cpu_quota: String,
    pub(super) gate_profile: fac_review_api::GateThroughputProfile,
    pub(super) workspace_root: PathBuf,
}
pub(super) const MAX_BROKER_REQUESTS_PROMOTE: usize = 256;

/// Maximum number of non-candidate (junk) entries to drain per cycle.
///
/// Non-candidate entries in `broker_requests/` (wrong extension, non-regular
/// files, unreadable metadata) are quarantined without counting toward
/// `MAX_BROKER_REQUESTS_PROMOTE`. This cap prevents unbounded quarantine I/O
/// from an attacker flooding the directory with junk. Remaining junk entries
/// are deferred to the next cycle.
pub(super) const MAX_JUNK_DRAIN_PER_CYCLE: usize = 1024;

/// Hard total per-cycle entry budget for broker request scanning.
///
/// Bounds the total number of directory entries iterated per promotion cycle,
/// regardless of whether they are candidates, junk, or skipped entries.
/// This prevents adversarial directory flooding from causing unbounded
/// `readdir` iteration even after both `MAX_BROKER_REQUESTS_PROMOTE` and
/// `MAX_JUNK_DRAIN_PER_CYCLE` are reached (the loop previously kept
/// iterating entries past both caps). After the budget is exhausted, one
/// aggregate warning is emitted and the loop terminates.
///
/// Formula: `MAX_BROKER_REQUESTS_PROMOTE * 4 + MAX_JUNK_DRAIN_PER_CYCLE`
/// — a generous window that accommodates interleaved candidates and junk
/// while still bounding work under adversarial flood.
pub(super) const MAX_BROKER_SCAN_BUDGET: usize =
    MAX_BROKER_REQUESTS_PROMOTE * 4 + MAX_JUNK_DRAIN_PER_CYCLE;

pub(super) const MAX_FAC_RECEIPT_REASON_CHARS: usize = 512;

pub(super) fn truncate_receipt_reason(raw: &str) -> String {
    let len = raw.chars().count();
    if len <= MAX_FAC_RECEIPT_REASON_CHARS {
        return raw.to_string();
    }
    if MAX_FAC_RECEIPT_REASON_CHARS <= 3 {
        return raw.chars().take(MAX_FAC_RECEIPT_REASON_CHARS).collect();
    }
    let mut out = raw
        .chars()
        .take(MAX_FAC_RECEIPT_REASON_CHARS - 3)
        .collect::<String>();
    out.push_str("...");
    out
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ShaDuplicateMatch {
    pub(super) existing_job_id: String,
    pub(super) existing_enqueue_time: String,
    pub(super) matched_by: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CompletedGatesFingerprint {
    pub(super) job_id: String,
    pub(super) enqueue_time: String,
    pub(super) repo_id: String,
    pub(super) head_sha: String,
    /// Canonicalizer tuple digest of the binary that ran this job.
    /// Dedup only matches when the current binary's digest equals this value,
    /// ensuring that a rebuilt binary re-gates the same SHA.
    pub(super) toolchain_digest: String,
}

#[derive(Debug, Clone, Default)]
pub(super) struct CompletedGatesCache {
    pub(super) by_repo_sha: HashMap<(String, String), Vec<CompletedGatesFingerprint>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CompletedGatesFingerprintSpec {
    pub(super) job_id: String,
    pub(super) kind: String,
    pub(super) enqueue_time: String,
    pub(super) source: CompletedGatesFingerprintSource,
}

#[derive(Debug, Deserialize)]
pub(super) struct CompletedGatesFingerprintSource {
    pub(super) repo_id: String,
    pub(super) head_sha: String,
}

impl CompletedGatesFingerprint {
    pub(super) fn from_spec(spec: &FacJobSpecV1, toolchain_digest: &str) -> Option<Self> {
        if !spec.kind.eq_ignore_ascii_case("gates") {
            return None;
        }
        Some(Self {
            job_id: spec.job_id.clone(),
            enqueue_time: spec.enqueue_time.clone(),
            repo_id: spec.source.repo_id.clone(),
            head_sha: spec.source.head_sha.clone(),
            toolchain_digest: toolchain_digest.to_string(),
        })
    }
}

impl CompletedGatesCache {
    pub(super) fn from_fingerprints(fingerprints: Vec<CompletedGatesFingerprint>) -> Self {
        let mut cache = Self::default();
        for fingerprint in fingerprints {
            cache.insert(fingerprint);
        }
        cache
    }

    pub(super) fn insert(&mut self, fingerprint: CompletedGatesFingerprint) {
        let key = (
            normalize_dedupe_key_component(&fingerprint.repo_id),
            normalize_dedupe_key_component(&fingerprint.head_sha),
        );
        self.by_repo_sha.entry(key).or_default().push(fingerprint);
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct LaneResetRecommendation {
    /// Fixed schema identifier for forward-compatible parsing.
    pub(super) schema: &'static str,
    /// The lane that needs operator reset.
    pub(super) lane_id: String,
    /// Human-readable summary for operators (encoded inside the JSON payload,
    /// not emitted as a separate plain-text line — keeps stderr JSON-only).
    pub(super) message: String,
    /// Why the lane is corrupt.
    pub(super) reason: String,
    /// Suggested operator action.
    pub(super) recommended_action: &'static str,
}

/// Schema identifier for [`LaneResetRecommendation`] payloads.
pub(super) const LANE_RESET_RECOMMENDATION_SCHEMA: &str = "apm2.fac.lane_reset_recommendation.v1";

#[derive(Debug)]
pub(super) enum LaneCleanupError {
    CorruptMarkerPersistenceFailed { reason: String },
    CleanupFailed { reason: String },
}

impl std::fmt::Display for LaneCleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CorruptMarkerPersistenceFailed { reason } | Self::CleanupFailed { reason } => {
                write!(f, "{reason}")
            },
        }
    }
}

pub(super) const STOP_REVOKE_BATCH_SIZE: usize = 32;

pub(super) fn serialize_to_json_string<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"serialization_error\"".to_string())
}

pub(super) fn strip_json_string_quotes(value: &str) -> String {
    value.trim_matches('\"').to_string()
}

/// Outputs a worker error message.
pub(super) fn output_worker_error(json_output: bool, message: &str) {
    if json_output {
        emit_worker_event(
            "worker_error",
            serde_json::json!({
                "error": "fac_worker_failed",
                "message": message,
            }),
        );
    } else {
        eprintln!("worker error: {message}");
    }
}

pub(super) fn worker_ts_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub(super) fn emit_worker_jsonl(value: &serde_json::Value) {
    if let Ok(line) = serde_json::to_string(value) {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(line.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
}

pub(super) fn emit_worker_event(event: &str, extra: serde_json::Value) {
    let mut map = serde_json::Map::new();
    map.insert(
        "event".to_string(),
        serde_json::Value::String(event.to_string()),
    );
    map.insert("ts".to_string(), serde_json::Value::String(worker_ts_now()));
    match extra {
        serde_json::Value::Object(extra_map) => {
            for (key, value) in extra_map {
                map.insert(key, value);
            }
        },
        other => {
            map.insert("data".to_string(), other);
        },
    }
    emit_worker_jsonl(&serde_json::Value::Object(map));
}

pub(super) fn emit_worker_summary(summary: &WorkerSummary) {
    let data = serde_json::to_value(summary).unwrap_or_else(|_| serde_json::json!({}));
    emit_worker_event("worker_summary", data);
}

/// Maximum binary file size for startup digest computation (256 MiB).
/// Bounds the read to prevent `DoS` if the binary is unusually large
/// (CTR-1603).
pub(super) const MAX_STARTUP_BINARY_DIGEST_SIZE: u64 = 256 * 1024 * 1024;
