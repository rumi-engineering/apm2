//! Ledger-backed FAC job lifecycle projection and filesystem rehydration.
//!
//! The projection treats `fac.job.*` ledger events as truth and repairs the
//! queue filesystem (`pending/`, `claimed/`, `completed/`, `denied/`) as a
//! witnessed cache.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use apm2_core::fac::job_lifecycle::{
    FAC_JOB_CLAIMED_EVENT_TYPE, FAC_JOB_COMPLETED_EVENT_TYPE, FAC_JOB_ENQUEUED_EVENT_TYPE,
    FAC_JOB_FAILED_EVENT_TYPE, FAC_JOB_RELEASED_EVENT_TYPE, FAC_JOB_STARTED_EVENT_TYPE,
    FacJobLifecycleEventData, FacJobLifecycleEventV1, JobLifecycleError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

use crate::fs_safe;
use crate::protocol::dispatch::{LedgerEventEmitter, SignedLedgerEvent};

/// Projection schema identifier.
pub const JOB_LIFECYCLE_PROJECTION_SCHEMA_ID: &str = "apm2.fac.job_lifecycle_projection.v1";

/// Checkpoint schema identifier.
pub const JOB_LIFECYCLE_CHECKPOINT_SCHEMA_ID: &str = "apm2.fac.job_lifecycle_checkpoint.v1";

/// Witness cache file schema identifier.
pub const JOB_LIFECYCLE_WITNESS_FILE_SCHEMA_ID: &str = "apm2.fac.job_witness_cache.v1";

/// Default event-processing bound per reconciler tick.
pub const DEFAULT_MAX_EVENTS_PER_TICK: usize = 128;

/// Default filesystem mutation bound per reconciler tick.
pub const DEFAULT_MAX_FS_OPS_PER_TICK: usize = 128;

/// Maximum jobs retained in projection state.
pub const MAX_PROJECTED_JOBS: usize = 16_384;

/// Maximum pending reconcile IDs persisted in checkpoint.
pub const MAX_PENDING_RECONCILES: usize = 16_384;

const CHECKPOINT_FILE_NAME: &str = ".job_lifecycle_checkpoint.v1.json";
const MAX_CURSOR_EVENT_ID_LENGTH: usize = 256;
const MAX_QUEUE_JOB_ID_LENGTH: usize = 256;
// At MAX_PROJECTED_JOBS capacity (16,384), checkpoint state can exceed 10 MiB.
// Keep read bound aligned with configured projection/pending limits.
const MAX_CHECKPOINT_FILE_SIZE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TERMINAL_EVICTION_QUEUE_ENTRIES: usize = MAX_PROJECTED_JOBS * 2;

const PENDING_DIR: &str = "pending";
const CLAIMED_DIR: &str = "claimed";
const COMPLETED_DIR: &str = "completed";
const DENIED_DIR: &str = "denied";
const BROKER_REQUESTS_DIR: &str = "broker_requests";
const QUEUE_DIRS: [&str; 4] = [PENDING_DIR, CLAIMED_DIR, COMPLETED_DIR, DENIED_DIR];
const LIFECYCLE_EVENT_TYPES: [&str; 6] = [
    FAC_JOB_ENQUEUED_EVENT_TYPE,
    FAC_JOB_CLAIMED_EVENT_TYPE,
    FAC_JOB_STARTED_EVENT_TYPE,
    FAC_JOB_COMPLETED_EVENT_TYPE,
    FAC_JOB_RELEASED_EVENT_TYPE,
    FAC_JOB_FAILED_EVENT_TYPE,
];

/// Projection/reconciler errors.
#[derive(Debug, Error)]
pub enum JobLifecycleProjectionError {
    /// Filesystem operation failed.
    #[error("job lifecycle filesystem error: {0}")]
    Io(String),
    /// Lifecycle payload decode failed.
    #[error("job lifecycle event decode failed: {0}")]
    Decode(String),
    /// Projection or checkpoint validation failed.
    #[error("job lifecycle validation failed: {0}")]
    Validation(String),
    /// Projection is at capacity with no evictable terminal jobs.
    ///
    /// This is a transient condition — not a permanent defect in the event.
    /// The caller must NOT advance the cursor past this event. Instead, halt
    /// processing for the current tick and retry on a future tick after
    /// terminal jobs complete and free capacity.
    #[error("job lifecycle capacity exhausted: {0}")]
    CapacityExhausted(String),
    /// Serialization error while persisting checkpoint.
    #[error("job lifecycle serialization failed: {0}")]
    Serialization(String),
}

/// Projected queue status derived from ledger lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectedJobStatus {
    /// Job should exist in `pending/`.
    Pending,
    /// Job should exist in `claimed/`.
    Claimed,
    /// Job should exist in `claimed/` as actively running.
    Running,
    /// Job should exist in `completed/`.
    Completed,
    /// Job should exist in `denied/`.
    Failed,
}

impl ProjectedJobStatus {
    const fn desired_dir(self) -> &'static str {
        match self {
            Self::Pending => PENDING_DIR,
            Self::Claimed | Self::Running => CLAIMED_DIR,
            Self::Completed => COMPLETED_DIR,
            Self::Failed => DENIED_DIR,
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

/// Projected lifecycle state for one canonical job ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedJobLifecycleV1 {
    /// Canonical content-addressable job ID.
    pub job_id: String,
    /// Filesystem queue compatibility job ID.
    pub queue_job_id: String,
    /// Work ID associated with this job.
    pub work_id: String,
    /// Current projected status.
    pub status: ProjectedJobStatus,
    /// Most recent applied ledger event ID.
    pub last_event_id: String,
    /// Timestamp of the most recent applied ledger event.
    #[serde(default)]
    pub last_event_timestamp_ns: u64,
    /// Most recent lease ID (for claimed/running/released lineage).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// Most recent reason code for failure/release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

/// Terminal-job eviction queue entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalJobEvictionEntryV1 {
    /// Canonical job identifier.
    pub job_id: String,
    /// Event timestamp bound to this insertion.
    pub last_event_timestamp_ns: u64,
}

/// Full in-memory projection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLifecycleProjectionV1 {
    /// Schema identifier.
    pub schema: String,
    /// Projection records keyed by canonical content-addressable `job_id`.
    pub jobs: BTreeMap<String, ProjectedJobLifecycleV1>,
    /// Insertion-order queue for evictable terminal jobs.
    #[serde(default)]
    pub terminal_job_eviction_order: VecDeque<TerminalJobEvictionEntryV1>,
}

impl Default for JobLifecycleProjectionV1 {
    fn default() -> Self {
        Self {
            schema: JOB_LIFECYCLE_PROJECTION_SCHEMA_ID.to_string(),
            jobs: BTreeMap::new(),
            terminal_job_eviction_order: VecDeque::new(),
        }
    }
}

impl JobLifecycleProjectionV1 {
    fn validate(&self) -> Result<(), JobLifecycleProjectionError> {
        if self.schema != JOB_LIFECYCLE_PROJECTION_SCHEMA_ID {
            return Err(JobLifecycleProjectionError::Validation(format!(
                "projection schema mismatch: expected {JOB_LIFECYCLE_PROJECTION_SCHEMA_ID}, got {}",
                self.schema
            )));
        }
        if self.jobs.len() > MAX_PROJECTED_JOBS {
            return Err(JobLifecycleProjectionError::Validation(format!(
                "projected jobs exceed max bound: {} > {MAX_PROJECTED_JOBS}",
                self.jobs.len()
            )));
        }
        if self.terminal_job_eviction_order.len() > MAX_TERMINAL_EVICTION_QUEUE_ENTRIES {
            return Err(JobLifecycleProjectionError::Validation(format!(
                "terminal eviction queue exceeds max bound: {} > {MAX_TERMINAL_EVICTION_QUEUE_ENTRIES}",
                self.terminal_job_eviction_order.len()
            )));
        }
        Ok(())
    }

    fn ensure_capacity_for_new_job(&mut self) -> Result<(), JobLifecycleProjectionError> {
        while self.jobs.len() >= MAX_PROJECTED_JOBS {
            if !self.evict_oldest_terminal_job() {
                return Err(JobLifecycleProjectionError::CapacityExhausted(format!(
                    "projected jobs at capacity ({MAX_PROJECTED_JOBS}) and no terminal jobs are available for eviction"
                )));
            }
        }
        Ok(())
    }

    fn evict_oldest_terminal_job(&mut self) -> bool {
        self.prune_stale_terminal_head_entries();

        while let Some(entry) = self.terminal_job_eviction_order.pop_front() {
            if !self.is_current_terminal_entry(&entry) {
                continue;
            }
            self.jobs.remove(&entry.job_id);
            self.prune_stale_terminal_head_entries();
            return true;
        }

        false
    }

    fn is_current_terminal_entry(&self, entry: &TerminalJobEvictionEntryV1) -> bool {
        self.jobs.get(&entry.job_id).is_some_and(|record| {
            record.status.is_terminal()
                && record.last_event_timestamp_ns == entry.last_event_timestamp_ns
        })
    }

    fn prune_stale_terminal_head_entries(&mut self) {
        while self
            .terminal_job_eviction_order
            .front()
            .is_some_and(|entry| !self.is_current_terminal_entry(entry))
        {
            self.terminal_job_eviction_order.pop_front();
        }
    }

    fn compact_terminal_eviction_order(&mut self) {
        if self.terminal_job_eviction_order.len() <= MAX_TERMINAL_EVICTION_QUEUE_ENTRIES {
            return;
        }

        // Keep only the newest entry for each terminal job.
        let mut seen = BTreeSet::new();
        let mut compacted_reversed = Vec::new();

        while let Some(entry) = self.terminal_job_eviction_order.pop_back() {
            if !seen.insert(entry.job_id.clone()) {
                continue;
            }
            if !self.is_current_terminal_entry(&entry) {
                continue;
            }
            compacted_reversed.push(entry);
        }

        self.terminal_job_eviction_order = compacted_reversed.into_iter().rev().collect();
        self.prune_stale_terminal_head_entries();
    }

    fn track_terminal_job(&mut self, job_id: &str, last_event_timestamp_ns: u64) {
        self.terminal_job_eviction_order
            .push_back(TerminalJobEvictionEntryV1 {
                job_id: job_id.to_string(),
                last_event_timestamp_ns,
            });
        self.prune_stale_terminal_head_entries();
        self.compact_terminal_eviction_order();
    }

    /// Applies one lifecycle event and returns the touched canonical job ID.
    ///
    /// # Errors
    ///
    /// Returns [`JobLifecycleProjectionError`] if projection bounds are
    /// violated.
    pub fn apply_event(
        &mut self,
        lifecycle_event: &FacJobLifecycleEventV1,
        ledger_event_id: &str,
        ledger_event_timestamp_ns: u64,
    ) -> Result<String, JobLifecycleProjectionError> {
        self.validate()?;

        let (job_id, queue_job_id, work_id) = match &lifecycle_event.event {
            FacJobLifecycleEventData::Enqueued(payload) => (
                payload.identity.job_id.clone(),
                payload.identity.queue_job_id.clone(),
                payload.identity.work_id.clone(),
            ),
            FacJobLifecycleEventData::Claimed(payload) => (
                payload.identity.job_id.clone(),
                payload.identity.queue_job_id.clone(),
                payload.identity.work_id.clone(),
            ),
            FacJobLifecycleEventData::Started(payload) => (
                payload.identity.job_id.clone(),
                payload.identity.queue_job_id.clone(),
                payload.identity.work_id.clone(),
            ),
            FacJobLifecycleEventData::Completed(payload) => (
                payload.identity.job_id.clone(),
                payload.identity.queue_job_id.clone(),
                payload.identity.work_id.clone(),
            ),
            FacJobLifecycleEventData::Released(payload) => (
                payload.identity.job_id.clone(),
                payload.identity.queue_job_id.clone(),
                payload.identity.work_id.clone(),
            ),
            FacJobLifecycleEventData::Failed(payload) => (
                payload.identity.job_id.clone(),
                payload.identity.queue_job_id.clone(),
                payload.identity.work_id.clone(),
            ),
        };

        // f-798-code_quality-1771812851882322-0: Validate queue_job_id at
        // the apply boundary before storing it. Invalid IDs (empty, overlong,
        // or containing unsafe characters) would brick the reconciler when
        // reconcile_projected_job later calls safe_job_file_name. Treat as
        // poison pill: skip and let the caller advance the cursor.
        if let Err(err) = validate_queue_job_id(&queue_job_id) {
            return Err(JobLifecycleProjectionError::Validation(format!(
                "event {ledger_event_id}: invalid queue_job_id: {err}"
            )));
        }

        let existing_status = self.jobs.get(&job_id).map(|record| record.status);
        let mut lease_id: Option<String> = None;
        let mut reason_code: Option<String> = None;

        // Terminal states are authoritative unless another terminal event for
        // the same job supersedes them.
        if existing_status.is_some_and(ProjectedJobStatus::is_terminal) {
            match lifecycle_event.event {
                FacJobLifecycleEventData::Completed(_) | FacJobLifecycleEventData::Failed(_) => {},
                _ => {
                    return Ok(job_id);
                },
            }
        }

        let new_status = match &lifecycle_event.event {
            FacJobLifecycleEventData::Enqueued(_) => ProjectedJobStatus::Pending,
            FacJobLifecycleEventData::Claimed(payload) => {
                let status = ProjectedJobStatus::Claimed;
                lease_id = Some(payload.lease_id.clone());
                status
            },
            FacJobLifecycleEventData::Started(_) => ProjectedJobStatus::Running,
            FacJobLifecycleEventData::Completed(_) => ProjectedJobStatus::Completed,
            FacJobLifecycleEventData::Released(payload) => {
                let status = ProjectedJobStatus::Pending;
                lease_id.clone_from(&payload.previous_lease_id);
                reason_code = Some(payload.reason.clone());
                status
            },
            FacJobLifecycleEventData::Failed(payload) => {
                let status = ProjectedJobStatus::Failed;
                reason_code = Some(payload.reason_class.clone());
                status
            },
        };

        if existing_status.is_none() && self.jobs.len() >= MAX_PROJECTED_JOBS {
            self.ensure_capacity_for_new_job()?;
        }

        let record = ProjectedJobLifecycleV1 {
            job_id: job_id.clone(),
            queue_job_id,
            work_id,
            status: new_status,
            last_event_id: ledger_event_id.to_string(),
            last_event_timestamp_ns: ledger_event_timestamp_ns,
            lease_id,
            reason_code,
        };

        self.jobs.insert(job_id.clone(), record);
        if new_status.is_terminal() {
            self.track_terminal_job(&job_id, ledger_event_timestamp_ns);
        }

        self.validate()?;
        Ok(job_id)
    }
}

/// Persistent checkpoint for bounded reconcile progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLifecycleCheckpointV1 {
    /// Schema identifier.
    pub schema: String,
    /// Last processed event timestamp.
    pub cursor_timestamp_ns: u64,
    /// Last processed event ID at the same timestamp.
    pub cursor_event_id: String,
    /// Projection snapshot.
    pub projection: JobLifecycleProjectionV1,
    /// Remaining job IDs whose filesystem reconciliation is pending.
    pub pending_reconcile_job_ids: Vec<String>,
}

impl Default for JobLifecycleCheckpointV1 {
    fn default() -> Self {
        Self {
            schema: JOB_LIFECYCLE_CHECKPOINT_SCHEMA_ID.to_string(),
            cursor_timestamp_ns: 0,
            cursor_event_id: String::new(),
            projection: JobLifecycleProjectionV1::default(),
            pending_reconcile_job_ids: Vec::new(),
        }
    }
}

impl JobLifecycleCheckpointV1 {
    fn validate(&self) -> Result<(), JobLifecycleProjectionError> {
        if self.schema != JOB_LIFECYCLE_CHECKPOINT_SCHEMA_ID {
            return Err(JobLifecycleProjectionError::Validation(format!(
                "checkpoint schema mismatch: expected {JOB_LIFECYCLE_CHECKPOINT_SCHEMA_ID}, got {}",
                self.schema
            )));
        }
        self.projection.validate()?;
        if self.cursor_event_id.len() > MAX_CURSOR_EVENT_ID_LENGTH {
            return Err(JobLifecycleProjectionError::Validation(format!(
                "cursor_event_id exceeds bound: {} > {MAX_CURSOR_EVENT_ID_LENGTH}",
                self.cursor_event_id.len()
            )));
        }
        if self.pending_reconcile_job_ids.len() > MAX_PENDING_RECONCILES {
            return Err(JobLifecycleProjectionError::Validation(format!(
                "pending reconcile set exceeds bound: {} > {MAX_PENDING_RECONCILES}",
                self.pending_reconcile_job_ids.len()
            )));
        }
        Ok(())
    }
}

/// Fixed reconcile tick budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobLifecycleReconcilerConfig {
    /// Maximum ledger lifecycle events processed per tick.
    pub max_events_per_tick: usize,
    /// Maximum filesystem operations performed per tick.
    pub max_fs_ops_per_tick: usize,
}

impl Default for JobLifecycleReconcilerConfig {
    fn default() -> Self {
        Self {
            max_events_per_tick: DEFAULT_MAX_EVENTS_PER_TICK,
            max_fs_ops_per_tick: DEFAULT_MAX_FS_OPS_PER_TICK,
        }
    }
}

/// Reconciler tick result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobLifecycleReconcileTickV1 {
    /// Number of lifecycle events applied in this tick.
    pub processed_events: usize,
    /// Number of filesystem operations executed in this tick.
    pub applied_fs_ops: usize,
    /// Updated cursor timestamp.
    pub cursor_timestamp_ns: u64,
    /// Updated cursor event ID.
    pub cursor_event_id: String,
    /// Number of jobs deferred to future ticks due to the FS-op budget.
    pub remaining_reconciles: usize,
}

/// Bounded queue lifecycle rehydration reconciler.
pub struct JobLifecycleRehydrationReconciler {
    ledger: Arc<dyn LedgerEventEmitter>,
    queue_root: PathBuf,
    checkpoint_path: PathBuf,
    config: JobLifecycleReconcilerConfig,
}

impl JobLifecycleRehydrationReconciler {
    /// Creates a reconciler with the default checkpoint path under
    /// `queue_root/.job_lifecycle_checkpoint.v1.json`.
    #[must_use]
    pub fn new(
        ledger: Arc<dyn LedgerEventEmitter>,
        queue_root: PathBuf,
        config: JobLifecycleReconcilerConfig,
    ) -> Self {
        let checkpoint_path = queue_root.join(CHECKPOINT_FILE_NAME);
        Self::with_checkpoint_path(ledger, queue_root, checkpoint_path, config)
    }

    /// Creates a reconciler with an explicit checkpoint path.
    #[must_use]
    pub fn with_checkpoint_path(
        ledger: Arc<dyn LedgerEventEmitter>,
        queue_root: PathBuf,
        checkpoint_path: PathBuf,
        config: JobLifecycleReconcilerConfig,
    ) -> Self {
        Self {
            ledger,
            queue_root,
            checkpoint_path,
            config,
        }
    }

    /// Runs one bounded reconcile tick.
    ///
    /// # Errors
    ///
    /// Returns [`JobLifecycleProjectionError`] when projection,
    /// checkpoint persistence, or filesystem operations fail.
    /// Individually undecodable lifecycle events are warned-and-skipped while
    /// still advancing the cursor to prevent poison-pill replay loops.
    pub fn tick(&self) -> Result<JobLifecycleReconcileTickV1, JobLifecycleProjectionError> {
        self.ensure_queue_dirs()?;
        let mut checkpoint = self.load_checkpoint()?;

        let mut dirty_job_ids: BTreeSet<String> = checkpoint
            .pending_reconcile_job_ids
            .drain(..)
            .collect::<BTreeSet<_>>();
        let remaining_pending_capacity = MAX_PENDING_RECONCILES.saturating_sub(dirty_job_ids.len());
        let event_fetch_limit = self
            .config
            .max_events_per_tick
            .min(remaining_pending_capacity);
        let new_events = self.collect_events_since(
            checkpoint.cursor_timestamp_ns,
            &checkpoint.cursor_event_id,
            event_fetch_limit,
        );
        let mut processed_events = 0usize;

        for event in new_events {
            let lifecycle_event = match decode_lifecycle_event(&event) {
                Ok(decoded) => decoded,
                Err(error) => {
                    warn!(
                        event_id = %event.event_id,
                        error = %error,
                        "skipping undecodable fac.job lifecycle event"
                    );
                    checkpoint.cursor_timestamp_ns = event.timestamp_ns;
                    checkpoint.cursor_event_id = event.event_id;
                    continue;
                },
            };
            // f-798-code_quality-1771815588937622-0: Differentiate transient
            // capacity exhaustion from permanent semantic validation failures.
            //
            // CapacityExhausted: The projection is full with no evictable
            //   terminal jobs. This is transient — halt processing for this
            //   tick WITHOUT advancing the cursor. The event will be retried
            //   on a future tick after terminal jobs complete and free capacity.
            //
            // Validation (poison pill): The event is permanently malformed
            //   (e.g. invalid queue_job_id). Skip and advance the cursor to
            //   prevent infinite replay loops.
            let dirty_job_id = match checkpoint.projection.apply_event(
                &lifecycle_event,
                &event.event_id,
                event.timestamp_ns,
            ) {
                Ok(job_id) => job_id,
                Err(JobLifecycleProjectionError::CapacityExhausted(ref msg)) => {
                    warn!(
                        event_id = %event.event_id,
                        error = %msg,
                        "halting tick: projection at capacity with no evictable \
                         terminal jobs; event will be retried on future tick"
                    );
                    // Do NOT advance cursor — the event must be retried.
                    break;
                },
                Err(JobLifecycleProjectionError::Validation(ref msg)) => {
                    warn!(
                        event_id = %event.event_id,
                        error = %msg,
                        "skipping lifecycle event that failed projection validation \
                         (identity poison pill)"
                    );
                    checkpoint.cursor_timestamp_ns = event.timestamp_ns;
                    checkpoint.cursor_event_id = event.event_id;
                    continue;
                },
                Err(other) => return Err(other),
            };
            checkpoint.cursor_timestamp_ns = event.timestamp_ns;
            checkpoint.cursor_event_id = event.event_id;
            processed_events = processed_events.saturating_add(1);
            dirty_job_ids.insert(dirty_job_id);
        }

        if dirty_job_ids.len() > MAX_PENDING_RECONCILES {
            return Err(JobLifecycleProjectionError::Validation(format!(
                "dirty job set exceeds bound: {} > {MAX_PENDING_RECONCILES}",
                dirty_job_ids.len()
            )));
        }

        let mut applied_fs_ops = 0usize;
        let mut remaining_reconcile = Vec::new();
        for job_id in dirty_job_ids {
            if applied_fs_ops >= self.config.max_fs_ops_per_tick {
                remaining_reconcile.push(job_id);
                continue;
            }
            // f-798-code_quality-1771812851882322-0: Treat reconcile-time
            // Validation errors (e.g. safe_job_file_name failure for invalid
            // queue_job_id that was stored before the apply-boundary check
            // existed) as skip-with-cursor-advance defects, not hard failures.
            match self.reconcile_projected_job(&checkpoint.projection, &job_id, &mut applied_fs_ops)
            {
                Ok(true) => {},
                Ok(false) => {
                    remaining_reconcile.push(job_id);
                },
                Err(JobLifecycleProjectionError::Validation(ref msg)) => {
                    warn!(
                        job_id = %job_id,
                        error = %msg,
                        "skipping reconciliation for job with invalid identity \
                         (poison pill in projection state)"
                    );
                },
                Err(other) => return Err(other),
            }
        }

        // f-798-security-1771815813540054-0 / f-798-code_quality-1771815601035651-0:
        // Determine caught-up status by probing for remaining lifecycle events
        // after the current cursor, rather than comparing against the global
        // ledger head (`get_latest_event()`).
        //
        // The previous approach compared cursor position against the latest
        // event across ALL event types (including non-lifecycle events like
        // `work.transitioned`, `evidence.published`).  In production with
        // continuous non-lifecycle events, the lifecycle cursor would never
        // equal the global head — `cursor_caught_up` was always false —
        // `cleanup_unknown_files` never ran — orphaned queue files accumulated
        // unboundedly.
        //
        // The fix uses `get_events_since` with lifecycle type filters and a
        // limit of 1 as a probe.  If no lifecycle events remain after the
        // cursor, the projection is caught up and cleanup can safely fire.
        // This also avoids the fragile lexicographic event_id comparison that
        // broke with legacy EVT-UUID identifiers.
        let remaining_lifecycle_events = self.ledger.get_events_since(
            checkpoint.cursor_timestamp_ns,
            &checkpoint.cursor_event_id,
            &LIFECYCLE_EVENT_TYPES,
            1,
        );
        let cursor_caught_up = remaining_lifecycle_events.is_empty();

        if applied_fs_ops < self.config.max_fs_ops_per_tick && cursor_caught_up {
            self.cleanup_unknown_files(&checkpoint.projection, &mut applied_fs_ops)?;
        }

        checkpoint.pending_reconcile_job_ids = remaining_reconcile;
        checkpoint.validate()?;
        self.save_checkpoint(&checkpoint)?;

        Ok(JobLifecycleReconcileTickV1 {
            processed_events,
            applied_fs_ops,
            cursor_timestamp_ns: checkpoint.cursor_timestamp_ns,
            cursor_event_id: checkpoint.cursor_event_id,
            remaining_reconciles: checkpoint.pending_reconcile_job_ids.len(),
        })
    }

    fn collect_events_since(
        &self,
        cursor_timestamp_ns: u64,
        cursor_event_id: &str,
        max_events: usize,
    ) -> Vec<SignedLedgerEvent> {
        self.ledger.get_events_since(
            cursor_timestamp_ns,
            cursor_event_id,
            &LIFECYCLE_EVENT_TYPES,
            max_events,
        )
    }

    fn ensure_queue_dirs(&self) -> Result<(), JobLifecycleProjectionError> {
        for dir in QUEUE_DIRS {
            let path = self.queue_root.join(dir);
            fs::create_dir_all(&path).map_err(|err| {
                JobLifecycleProjectionError::Io(format!(
                    "create queue dir {}: {err}",
                    path.display()
                ))
            })?;
            #[cfg(unix)]
            {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o711)).map_err(|err| {
                    JobLifecycleProjectionError::Io(format!(
                        "set queue dir mode 0711 {}: {err}",
                        path.display()
                    ))
                })?;
            }
        }

        let broker_requests_path = self.queue_root.join(BROKER_REQUESTS_DIR);
        fs::create_dir_all(&broker_requests_path).map_err(|err| {
            JobLifecycleProjectionError::Io(format!(
                "create queue dir {}: {err}",
                broker_requests_path.display()
            ))
        })?;
        #[cfg(unix)]
        {
            fs::set_permissions(&broker_requests_path, fs::Permissions::from_mode(0o1733))
                .map_err(|err| {
                    JobLifecycleProjectionError::Io(format!(
                        "set queue dir mode 01733 {}: {err}",
                        broker_requests_path.display()
                    ))
                })?;
        }
        Ok(())
    }

    fn reconcile_projected_job(
        &self,
        projection: &JobLifecycleProjectionV1,
        job_id: &str,
        applied_fs_ops: &mut usize,
    ) -> Result<bool, JobLifecycleProjectionError> {
        let Some(projected) = projection.jobs.get(job_id) else {
            return Ok(true);
        };

        let file_name = safe_job_file_name(&projected.queue_job_id)?;
        let desired_dir = projected.status.desired_dir();
        let desired_path = self.queue_root.join(desired_dir).join(&file_name);

        let mut existing_paths = Vec::new();
        for dir in QUEUE_DIRS {
            let candidate = self.queue_root.join(dir).join(&file_name);
            if candidate.exists() {
                existing_paths.push(candidate);
            }
        }

        let has_desired = existing_paths.iter().any(|path| path == &desired_path);
        let mut moved_source_path: Option<PathBuf> = None;
        if !has_desired {
            if *applied_fs_ops >= self.config.max_fs_ops_per_tick {
                return Ok(false);
            }

            if let Some(source) = existing_paths.first() {
                fs::rename(source, &desired_path).map_err(|err| {
                    JobLifecycleProjectionError::Io(format!(
                        "rename {} -> {}: {err}",
                        source.display(),
                        desired_path.display()
                    ))
                })?;
                moved_source_path = Some(source.clone());
            } else {
                write_witness_file(&desired_path, projected)?;
            }
            *applied_fs_ops = applied_fs_ops.saturating_add(1);
        }

        for path in existing_paths {
            if path == desired_path {
                continue;
            }
            if moved_source_path
                .as_ref()
                .is_some_and(|moved| moved == &path)
            {
                continue;
            }
            if *applied_fs_ops >= self.config.max_fs_ops_per_tick {
                return Ok(false);
            }
            fs::remove_file(&path).map_err(|err| {
                JobLifecycleProjectionError::Io(format!("remove {}: {err}", path.display()))
            })?;
            *applied_fs_ops = applied_fs_ops.saturating_add(1);
        }

        Ok(true)
    }

    fn cleanup_unknown_files(
        &self,
        projection: &JobLifecycleProjectionV1,
        applied_fs_ops: &mut usize,
    ) -> Result<(), JobLifecycleProjectionError> {
        let expected_pending_files = projection
            .jobs
            .values()
            .filter(|record| record.status == ProjectedJobStatus::Pending)
            .filter_map(|record| safe_job_file_name(&record.queue_job_id).ok())
            .collect::<BTreeSet<_>>();
        let expected_claimed_files = projection
            .jobs
            .values()
            .filter(|record| {
                matches!(
                    record.status,
                    ProjectedJobStatus::Claimed | ProjectedJobStatus::Running
                )
            })
            .filter_map(|record| safe_job_file_name(&record.queue_job_id).ok())
            .collect::<BTreeSet<_>>();

        if *applied_fs_ops >= self.config.max_fs_ops_per_tick {
            return Ok(());
        }

        // Unknown-file cleanup is intentionally restricted to `pending/` and
        // `claimed/`.
        // Terminal witness files (`completed/`, `denied/`) must be preserved
        // even when in-memory projection entries are evicted.
        self.cleanup_unknown_files_in_dir(PENDING_DIR, &expected_pending_files, applied_fs_ops)?;
        self.cleanup_unknown_files_in_dir(CLAIMED_DIR, &expected_claimed_files, applied_fs_ops)?;
        Ok(())
    }

    fn cleanup_unknown_files_in_dir(
        &self,
        dir_name: &str,
        expected_files: &BTreeSet<String>,
        applied_fs_ops: &mut usize,
    ) -> Result<(), JobLifecycleProjectionError> {
        let dir_path = self.queue_root.join(dir_name);
        let Ok(entries) = fs::read_dir(&dir_path) else {
            return Ok(());
        };
        for entry in entries {
            if *applied_fs_ops >= self.config.max_fs_ops_per_tick {
                return Ok(());
            }
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let file_name = match path.file_name().and_then(|value| value.to_str()) {
                Some(value) => value.to_string(),
                None => continue,
            };
            if expected_files.contains(&file_name) {
                continue;
            }
            fs::remove_file(&path).map_err(|err| {
                JobLifecycleProjectionError::Io(format!(
                    "remove unknown queue file {} in {}: {err}",
                    path.display(),
                    dir_name,
                ))
            })?;
            *applied_fs_ops = applied_fs_ops.saturating_add(1);
        }
        Ok(())
    }

    fn load_checkpoint(&self) -> Result<JobLifecycleCheckpointV1, JobLifecycleProjectionError> {
        if !self.checkpoint_path.exists() {
            return Ok(JobLifecycleCheckpointV1::default());
        }

        let checkpoint: JobLifecycleCheckpointV1 =
            fs_safe::bounded_read_json(&self.checkpoint_path, MAX_CHECKPOINT_FILE_SIZE_BYTES)
                .map_err(|err| match err {
                    fs_safe::FsSafeError::DeserializeFailed(_) => {
                        JobLifecycleProjectionError::Serialization(format!(
                            "deserialize checkpoint {}: {err}",
                            self.checkpoint_path.display()
                        ))
                    },
                    _ => JobLifecycleProjectionError::Io(format!(
                        "read checkpoint {}: {err}",
                        self.checkpoint_path.display()
                    )),
                })?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    fn save_checkpoint(
        &self,
        checkpoint: &JobLifecycleCheckpointV1,
    ) -> Result<(), JobLifecycleProjectionError> {
        fs_safe::atomic_write_json(&self.checkpoint_path, checkpoint).map_err(|err| match err {
            fs_safe::FsSafeError::SerializeFailed(_) => {
                JobLifecycleProjectionError::Serialization(format!(
                    "serialize checkpoint {}: {err}",
                    self.checkpoint_path.display()
                ))
            },
            _ => JobLifecycleProjectionError::Io(format!(
                "write checkpoint {}: {err}",
                self.checkpoint_path.display()
            )),
        })
    }
}

fn decode_lifecycle_event(
    signed_event: &SignedLedgerEvent,
) -> Result<FacJobLifecycleEventV1, JobLifecycleProjectionError> {
    // Session events are persisted as JSON envelope with `payload` hex.
    if let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&signed_event.payload)
        && let Some(payload_hex) = envelope.get("payload").and_then(serde_json::Value::as_str)
    {
        let inner_payload = hex::decode(payload_hex).map_err(|err| {
            JobLifecycleProjectionError::Decode(format!(
                "event {} payload hex decode: {err}",
                signed_event.event_id
            ))
        })?;
        return FacJobLifecycleEventV1::decode_bounded(&inner_payload)
            .map_err(|err| map_lifecycle_decode_error(&err));
    }

    // Test paths may inject raw lifecycle payload bytes directly.
    FacJobLifecycleEventV1::decode_bounded(&signed_event.payload)
        .map_err(|err| map_lifecycle_decode_error(&err))
}

fn map_lifecycle_decode_error(error: &JobLifecycleError) -> JobLifecycleProjectionError {
    JobLifecycleProjectionError::Decode(error.to_string())
}

fn write_witness_file(
    path: &Path,
    projected: &ProjectedJobLifecycleV1,
) -> Result<(), JobLifecycleProjectionError> {
    let witness = serde_json::json!({
        "schema": JOB_LIFECYCLE_WITNESS_FILE_SCHEMA_ID,
        "job_id": projected.job_id,
        "queue_job_id": projected.queue_job_id,
        "work_id": projected.work_id,
        "status": projected.status,
        "last_event_id": projected.last_event_id,
        "last_event_timestamp_ns": projected.last_event_timestamp_ns,
    });
    fs_safe::atomic_write_json(path, &witness).map_err(|err| match err {
        fs_safe::FsSafeError::SerializeFailed(_) => JobLifecycleProjectionError::Serialization(
            format!("serialize witness file {}: {err}", path.display()),
        ),
        _ => {
            JobLifecycleProjectionError::Io(format!("write witness file {}: {err}", path.display()))
        },
    })
}

/// Validates a `queue_job_id` for filesystem safety BEFORE storing it in the
/// projection. This prevents semantically invalid-but-decodable IDs from
/// bricking the reconciler (f-798-code_quality-1771812851882322-0).
fn validate_queue_job_id(queue_job_id: &str) -> Result<(), String> {
    if queue_job_id.is_empty() {
        return Err("queue_job_id is empty".to_string());
    }
    if queue_job_id.len() > MAX_QUEUE_JOB_ID_LENGTH {
        return Err(format!(
            "queue_job_id exceeds bound: {} > {MAX_QUEUE_JOB_ID_LENGTH}",
            queue_job_id.len()
        ));
    }
    if !queue_job_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(format!("unsafe queue_job_id: {queue_job_id:?}"));
    }
    Ok(())
}

fn safe_job_file_name(queue_job_id: &str) -> Result<String, JobLifecycleProjectionError> {
    if queue_job_id.is_empty() {
        return Err(JobLifecycleProjectionError::Validation(
            "queue_job_id is empty".to_string(),
        ));
    }
    if queue_job_id.len() > MAX_QUEUE_JOB_ID_LENGTH {
        return Err(JobLifecycleProjectionError::Validation(format!(
            "queue_job_id exceeds bound: {} > {MAX_QUEUE_JOB_ID_LENGTH}",
            queue_job_id.len()
        )));
    }
    if !queue_job_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(JobLifecycleProjectionError::Validation(format!(
            "unsafe queue_job_id for filesystem path: {queue_job_id:?}"
        )));
    }
    Ok(format!("{queue_job_id}.json"))
}

#[cfg(test)]
mod tests {
    use apm2_core::fac::job_lifecycle::{
        FacJobEnqueuedV1, FacJobFailedV1, FacJobIdentityV1, FacJobLifecycleEventData,
        FacJobLifecycleEventV1, FacJobStartedV1,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::protocol::dispatch::{LedgerEventEmitter, StubLedgerEventEmitter};

    fn now_timestamp_ns() -> u64 {
        1_700_000_000_000_000_000
    }

    fn identity(queue_job_id: &str) -> FacJobIdentityV1 {
        FacJobIdentityV1 {
            job_id: format!("fj1-{queue_job_id}"),
            queue_job_id: queue_job_id.to_string(),
            work_id: "W-42".to_string(),
            changeset_digest: "b3-256:".to_string() + &"a".repeat(64),
            spec_digest: "b3-256:".to_string() + &"b".repeat(64),
            gate_profile: "gates:balanced".to_string(),
            revision: "1".to_string(),
        }
    }

    fn emit_lifecycle(
        emitter: &Arc<dyn LedgerEventEmitter>,
        lifecycle: &FacJobLifecycleEventV1,
        timestamp_ns: u64,
    ) {
        let payload = lifecycle.encode_bounded().expect("encode lifecycle");
        let event_type = match &lifecycle.event {
            FacJobLifecycleEventData::Enqueued(_) => FAC_JOB_ENQUEUED_EVENT_TYPE,
            FacJobLifecycleEventData::Claimed(_) => FAC_JOB_CLAIMED_EVENT_TYPE,
            FacJobLifecycleEventData::Started(_) => FAC_JOB_STARTED_EVENT_TYPE,
            FacJobLifecycleEventData::Completed(_) => FAC_JOB_COMPLETED_EVENT_TYPE,
            FacJobLifecycleEventData::Released(_) => FAC_JOB_RELEASED_EVENT_TYPE,
            FacJobLifecycleEventData::Failed(_) => FAC_JOB_FAILED_EVENT_TYPE,
        };
        emitter
            .emit_session_event(
                "session-job",
                event_type,
                &payload,
                "fac-worker",
                timestamp_ns,
            )
            .expect("emit lifecycle");
    }

    fn make_reconciler(
        queue_root: &Path,
        emitter: Arc<dyn LedgerEventEmitter>,
        config: JobLifecycleReconcilerConfig,
    ) -> JobLifecycleRehydrationReconciler {
        JobLifecycleRehydrationReconciler::new(emitter, queue_root.to_path_buf(), config)
    }

    fn make_queue_root(tmp: &TempDir) -> PathBuf {
        let queue_root = tmp.path().join("queue");
        fs::create_dir_all(&queue_root).expect("create queue root");
        queue_root
    }

    #[test]
    fn crash_after_ledger_before_filesystem_creates_pending_witness() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;

        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:1",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("job-ledger-only"),
                    enqueue_epoch_ns: now_timestamp_ns(),
                }),
            ),
            now_timestamp_ns(),
        );

        let reconciler = make_reconciler(
            &queue_root,
            Arc::clone(&emitter),
            JobLifecycleReconcilerConfig::default(),
        );
        let tick = reconciler.tick().expect("tick");
        assert_eq!(tick.processed_events, 1);
        assert!(
            queue_root
                .join(PENDING_DIR)
                .join("job-ledger-only.json")
                .exists(),
            "ledger-backed enqueue should rehydrate pending witness"
        );
    }

    #[test]
    fn crash_before_ledger_mutation_removes_unknown_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        fs::create_dir_all(queue_root.join(PENDING_DIR)).expect("create pending");
        fs::create_dir_all(queue_root.join(CLAIMED_DIR)).expect("create claimed");
        fs::create_dir_all(queue_root.join(COMPLETED_DIR)).expect("create completed");
        fs::write(queue_root.join(PENDING_DIR).join("orphan.json"), b"{}").expect("seed orphan");
        fs::write(
            queue_root.join(CLAIMED_DIR).join("orphan-claimed.json"),
            b"{}",
        )
        .expect("seed orphan claimed");
        fs::write(queue_root.join(COMPLETED_DIR).join("terminal.json"), b"{}")
            .expect("seed completed");

        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;
        let reconciler = make_reconciler(
            &queue_root,
            Arc::clone(&emitter),
            JobLifecycleReconcilerConfig::default(),
        );

        let tick = reconciler.tick().expect("tick");
        assert_eq!(tick.processed_events, 0);
        assert!(
            !queue_root.join(PENDING_DIR).join("orphan.json").exists(),
            "unknown filesystem state must be removed when ledger has no matching lifecycle event"
        );
        assert!(
            !queue_root
                .join(CLAIMED_DIR)
                .join("orphan-claimed.json")
                .exists(),
            "unknown claimed state must be removed when ledger has no matching lifecycle event"
        );
        assert!(
            queue_root
                .join(COMPLETED_DIR)
                .join("terminal.json")
                .exists(),
            "terminal witness files must not be removed by unknown-file cleanup"
        );
    }

    #[test]
    fn apply_event_evicts_oldest_terminal_job_at_capacity() {
        let mut projection = JobLifecycleProjectionV1::default();
        let base_ts = now_timestamp_ns();
        for index in 0..MAX_PROJECTED_JOBS {
            let queue_job_id = format!("job-terminal-{index}");
            let job_id = format!("fj1-{queue_job_id}");
            let ts = base_ts + index as u64;
            projection.jobs.insert(
                job_id.clone(),
                ProjectedJobLifecycleV1 {
                    job_id: job_id.clone(),
                    queue_job_id,
                    work_id: "W-42".to_string(),
                    status: ProjectedJobStatus::Failed,
                    last_event_id: format!("event-{index}"),
                    last_event_timestamp_ns: ts,
                    lease_id: None,
                    reason_code: Some("test.failure".to_string()),
                },
            );
            projection
                .terminal_job_eviction_order
                .push_back(TerminalJobEvictionEntryV1 {
                    job_id,
                    last_event_timestamp_ns: ts,
                });
        }

        let fresh = FacJobLifecycleEventV1::new(
            "intent:enqueue:fresh",
            None,
            FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                identity: identity("fresh"),
                enqueue_epoch_ns: base_ts + MAX_PROJECTED_JOBS as u64 + 1,
            }),
        );

        let touched_job = projection
            .apply_event(
                &fresh,
                "event-fresh",
                base_ts.saturating_add(MAX_PROJECTED_JOBS as u64 + 1),
            )
            .expect("capacity should be recovered by terminal eviction");
        assert_eq!(touched_job, "fj1-fresh");
        assert_eq!(projection.jobs.len(), MAX_PROJECTED_JOBS);
        assert!(
            !projection.jobs.contains_key("fj1-job-terminal-0"),
            "oldest terminal job must be evicted first"
        );
        assert!(
            projection.jobs.contains_key("fj1-fresh"),
            "new active job must be inserted after eviction"
        );
    }

    #[test]
    fn apply_event_rejects_overflow_when_no_terminal_jobs_exist() {
        let mut projection = JobLifecycleProjectionV1::default();
        let base_ts = now_timestamp_ns();
        for index in 0..MAX_PROJECTED_JOBS {
            let queue_job_id = format!("job-active-{index}");
            let job_id = format!("fj1-{queue_job_id}");
            projection.jobs.insert(
                job_id.clone(),
                ProjectedJobLifecycleV1 {
                    job_id,
                    queue_job_id,
                    work_id: "W-42".to_string(),
                    status: ProjectedJobStatus::Pending,
                    last_event_id: format!("event-{index}"),
                    last_event_timestamp_ns: base_ts + index as u64,
                    lease_id: None,
                    reason_code: None,
                },
            );
        }

        let overflow = FacJobLifecycleEventV1::new(
            "intent:enqueue:overflow",
            None,
            FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                identity: identity("overflow"),
                enqueue_epoch_ns: base_ts + MAX_PROJECTED_JOBS as u64 + 1,
            }),
        );

        let err = projection
            .apply_event(
                &overflow,
                "event-overflow",
                base_ts.saturating_add(MAX_PROJECTED_JOBS as u64 + 1),
            )
            .expect_err("overflow must fail when all slots are active");
        let JobLifecycleProjectionError::CapacityExhausted(message) = err else {
            panic!("expected CapacityExhausted error when capacity is exhausted, got: {err:?}");
        };
        assert!(
            message.contains("no terminal jobs"),
            "error should explain that all slots are active non-terminal jobs"
        );
    }

    #[test]
    fn bounded_tick_advances_cursor_incrementally() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;

        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:job-a",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("job-a"),
                    enqueue_epoch_ns: now_timestamp_ns(),
                }),
            ),
            now_timestamp_ns(),
        );
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:job-b",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("job-b"),
                    enqueue_epoch_ns: now_timestamp_ns() + 1,
                }),
            ),
            now_timestamp_ns() + 1,
        );

        let config = JobLifecycleReconcilerConfig {
            max_events_per_tick: 1,
            max_fs_ops_per_tick: 16,
        };
        let reconciler = make_reconciler(&queue_root, Arc::clone(&emitter), config);

        let first = reconciler.tick().expect("first tick");
        assert_eq!(first.processed_events, 1);
        let second = reconciler.tick().expect("second tick");
        assert_eq!(second.processed_events, 1);

        assert!(queue_root.join(PENDING_DIR).join("job-a.json").exists());
        assert!(queue_root.join(PENDING_DIR).join("job-b.json").exists());
    }

    #[test]
    fn restart_reconciler_heals_divergence_to_ledger_truth() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        fs::create_dir_all(queue_root.join(PENDING_DIR)).expect("create pending");
        fs::write(
            queue_root.join(PENDING_DIR).join("job-diverge.json"),
            br#"{"stale":"pending"}"#,
        )
        .expect("seed stale pending");

        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;

        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:diverge",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("job-diverge"),
                    enqueue_epoch_ns: now_timestamp_ns(),
                }),
            ),
            now_timestamp_ns(),
        );
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:started:diverge",
                None,
                FacJobLifecycleEventData::Started(FacJobStartedV1 {
                    identity: identity("job-diverge"),
                    worker_instance_id: "worker-1".to_string(),
                    start_receipt_id: None,
                }),
            ),
            now_timestamp_ns() + 1,
        );
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:failed:diverge",
                None,
                FacJobLifecycleEventData::Failed(FacJobFailedV1 {
                    identity: identity("job-diverge"),
                    reason_class: "test.failure".to_string(),
                    retryable: false,
                }),
            ),
            now_timestamp_ns() + 2,
        );

        let config = JobLifecycleReconcilerConfig {
            max_events_per_tick: 2,
            max_fs_ops_per_tick: 1,
        };
        let reconciler_a = make_reconciler(&queue_root, Arc::clone(&emitter), config);
        let _ = reconciler_a.tick().expect("first bounded tick");

        let reconciler_b = make_reconciler(&queue_root, Arc::clone(&emitter), config);
        let _ = reconciler_b.tick().expect("second bounded tick");
        let _ = reconciler_b.tick().expect("third bounded tick");

        assert!(
            !queue_root
                .join(PENDING_DIR)
                .join("job-diverge.json")
                .exists(),
            "pending stale file must be removed"
        );
        assert!(
            !queue_root
                .join(CLAIMED_DIR)
                .join("job-diverge.json")
                .exists(),
            "claimed stale file must be removed"
        );
        assert!(
            queue_root
                .join(DENIED_DIR)
                .join("job-diverge.json")
                .exists(),
            "ledger terminal failure must win and place witness in denied/"
        );
    }

    #[test]
    fn reconcile_projected_job_skips_removing_file_already_renamed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        fs::create_dir_all(queue_root.join(PENDING_DIR)).expect("create pending");
        fs::write(queue_root.join(PENDING_DIR).join("job-rename.json"), br"{}")
            .expect("seed stale pending");

        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;

        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:rename",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("job-rename"),
                    enqueue_epoch_ns: now_timestamp_ns(),
                }),
            ),
            now_timestamp_ns(),
        );
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:started:rename",
                None,
                FacJobLifecycleEventData::Started(FacJobStartedV1 {
                    identity: identity("job-rename"),
                    worker_instance_id: "worker-1".to_string(),
                    start_receipt_id: None,
                }),
            ),
            now_timestamp_ns() + 1,
        );

        let reconciler = make_reconciler(
            &queue_root,
            Arc::clone(&emitter),
            JobLifecycleReconcilerConfig {
                max_events_per_tick: 8,
                max_fs_ops_per_tick: 8,
            },
        );

        let tick = reconciler.tick().expect("tick should succeed");
        assert_eq!(tick.processed_events, 2);
        assert!(
            !queue_root
                .join(PENDING_DIR)
                .join("job-rename.json")
                .exists(),
            "source file should have been moved out of pending/"
        );
        assert!(
            queue_root
                .join(CLAIMED_DIR)
                .join("job-rename.json")
                .exists(),
            "renamed witness should exist in claimed/"
        );
    }

    #[test]
    #[cfg(unix)]
    fn tick_hardens_queue_directory_modes() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);

        for dir in QUEUE_DIRS {
            let path = queue_root.join(dir);
            fs::create_dir_all(&path).expect("create queue subdir");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o777))
                .expect("set unsafe subdir mode");
        }
        let broker_requests = queue_root.join(BROKER_REQUESTS_DIR);
        fs::create_dir_all(&broker_requests).expect("create broker_requests");
        fs::set_permissions(&broker_requests, fs::Permissions::from_mode(0o333))
            .expect("set unsafe broker mode");

        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;
        let reconciler = make_reconciler(
            &queue_root,
            Arc::clone(&emitter),
            JobLifecycleReconcilerConfig::default(),
        );
        reconciler.tick().expect("tick");

        for dir in QUEUE_DIRS {
            let mode = fs::metadata(queue_root.join(dir))
                .expect("queue dir metadata")
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(mode, 0o711, "queue dir {dir} must be mode 0711");
        }

        let broker_mode = fs::metadata(&broker_requests)
            .expect("broker dir metadata")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(broker_mode, 0o1733, "broker_requests/ must be mode 01733");
    }

    #[test]
    fn tick_skips_undecodable_event_and_continues_same_tick() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;

        emitter
            .emit_session_event(
                "session-job",
                FAC_JOB_ENQUEUED_EVENT_TYPE,
                b"malformed lifecycle payload",
                "fac-worker",
                now_timestamp_ns(),
            )
            .expect("emit malformed lifecycle payload");

        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:good",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("job-good"),
                    enqueue_epoch_ns: now_timestamp_ns() + 1,
                }),
            ),
            now_timestamp_ns() + 1,
        );

        let reconciler = make_reconciler(
            &queue_root,
            Arc::clone(&emitter),
            JobLifecycleReconcilerConfig {
                max_events_per_tick: 8,
                max_fs_ops_per_tick: 8,
            },
        );

        let first = reconciler.tick().expect("tick should skip malformed event");
        assert_eq!(
            first.processed_events, 1,
            "valid events after poison pill must still be processed in same tick"
        );
        assert!(
            queue_root.join(PENDING_DIR).join("job-good.json").exists(),
            "valid event should still be reconciled"
        );

        let second = reconciler.tick().expect("second tick");
        assert_eq!(
            second.processed_events, 0,
            "malformed event must be cursor-advanced and not replayed"
        );
    }

    #[test]
    fn tick_backpressures_when_pending_reconcile_queue_is_full() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        let checkpoint_path = queue_root.join(CHECKPOINT_FILE_NAME);

        let checkpoint = JobLifecycleCheckpointV1 {
            pending_reconcile_job_ids: (0..MAX_PENDING_RECONCILES)
                .map(|index| format!("pending-{index}"))
                .collect(),
            ..JobLifecycleCheckpointV1::default()
        };
        fs_safe::atomic_write_json(&checkpoint_path, &checkpoint)
            .expect("seed full pending checkpoint");

        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:overflow",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("job-overflow"),
                    enqueue_epoch_ns: now_timestamp_ns(),
                }),
            ),
            now_timestamp_ns(),
        );

        let reconciler = JobLifecycleRehydrationReconciler::with_checkpoint_path(
            Arc::clone(&emitter),
            queue_root.clone(),
            checkpoint_path,
            JobLifecycleReconcilerConfig {
                max_events_per_tick: 64,
                max_fs_ops_per_tick: 0,
            },
        );

        let tick = reconciler
            .tick()
            .expect("full pending queue should backpressure, not fail");
        assert_eq!(
            tick.processed_events, 0,
            "no lifecycle events should be fetched when pending queue is saturated"
        );
        assert_eq!(tick.remaining_reconciles, MAX_PENDING_RECONCILES);
        assert_eq!(tick.cursor_timestamp_ns, 0);
        assert_eq!(tick.cursor_event_id, "");
        assert!(
            !queue_root
                .join(PENDING_DIR)
                .join("job-overflow.json")
                .exists(),
            "new events must remain unread while pending backlog is full"
        );
    }

    #[test]
    fn tick_backpressures_on_capacity_exhaustion_then_recovers() {
        // f-798-code_quality-1771815588937622-0: Verify that when projection
        // is at MAX_PROJECTED_JOBS with no terminal jobs, capacity exhaustion
        // halts the tick WITHOUT advancing the cursor. The event is retried on
        // a future tick after terminal jobs complete and free capacity.
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;
        let base_ts = now_timestamp_ns();

        // Build a checkpoint with MAX_PROJECTED_JOBS active (non-terminal)
        // jobs so there is nothing to evict.
        let mut projection = JobLifecycleProjectionV1::default();
        for index in 0..MAX_PROJECTED_JOBS {
            let queue_job_id = format!("active-{index}");
            let job_id = format!("fj1-{queue_job_id}");
            projection.jobs.insert(
                job_id.clone(),
                ProjectedJobLifecycleV1 {
                    job_id,
                    queue_job_id,
                    work_id: "W-42".to_string(),
                    status: ProjectedJobStatus::Pending,
                    last_event_id: format!("event-{index}"),
                    last_event_timestamp_ns: base_ts + index as u64,
                    lease_id: None,
                    reason_code: None,
                },
            );
        }
        let checkpoint = JobLifecycleCheckpointV1 {
            projection,
            ..JobLifecycleCheckpointV1::default()
        };
        let checkpoint_path = queue_root.join(CHECKPOINT_FILE_NAME);
        fs_safe::atomic_write_json(&checkpoint_path, &checkpoint)
            .expect("seed capacity-full checkpoint");

        // Emit a new job event that will hit capacity with no evictable
        // terminal jobs.
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:overflow-halt",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("overflow-halt"),
                    enqueue_epoch_ns: base_ts + MAX_PROJECTED_JOBS as u64 + 1,
                }),
            ),
            base_ts + MAX_PROJECTED_JOBS as u64 + 1,
        );

        let reconciler = JobLifecycleRehydrationReconciler::with_checkpoint_path(
            Arc::clone(&emitter),
            queue_root,
            checkpoint_path.clone(),
            JobLifecycleReconcilerConfig {
                max_events_per_tick: 16,
                max_fs_ops_per_tick: 16,
            },
        );

        // First tick: capacity exhaustion halts without advancing cursor.
        let tick = reconciler
            .tick()
            .expect("tick must succeed (capacity exhaustion = backpressure, not error)");
        assert_eq!(
            tick.processed_events, 0,
            "no events should be processed when capacity is exhausted"
        );
        assert_eq!(
            tick.cursor_timestamp_ns, 0,
            "cursor must NOT advance past the capacity-exhausted event"
        );

        // Now simulate one of the active jobs completing (terminal) to free
        // a slot. We load the checkpoint, mutate the first job to Failed
        // status and add it to the eviction queue, then save.
        let mut checkpoint: JobLifecycleCheckpointV1 =
            fs_safe::bounded_read_json(&checkpoint_path, MAX_CHECKPOINT_FILE_SIZE_BYTES)
                .expect("reload checkpoint");
        let first_job_id = "fj1-active-0".to_string();
        if let Some(record) = checkpoint.projection.jobs.get_mut(&first_job_id) {
            record.status = ProjectedJobStatus::Failed;
            record.reason_code = Some("test.recovery".to_string());
        }
        checkpoint
            .projection
            .terminal_job_eviction_order
            .push_back(TerminalJobEvictionEntryV1 {
                job_id: first_job_id,
                last_event_timestamp_ns: base_ts,
            });
        fs_safe::atomic_write_json(&checkpoint_path, &checkpoint)
            .expect("save checkpoint with freed slot");

        // Second tick: the capacity-exhausted event is retried and now
        // succeeds because a terminal job can be evicted.
        let second = reconciler
            .tick()
            .expect("second tick must succeed after capacity freed");
        assert_eq!(
            second.processed_events, 1,
            "capacity-exhausted event must be retried and processed on next tick"
        );
        assert!(
            second.cursor_timestamp_ns > base_ts + MAX_PROJECTED_JOBS as u64,
            "cursor must advance past the now-processed event"
        );
        // Verify the job was actually added to the projection.
        let final_checkpoint: JobLifecycleCheckpointV1 =
            fs_safe::bounded_read_json(&checkpoint_path, MAX_CHECKPOINT_FILE_SIZE_BYTES)
                .expect("reload final checkpoint");
        assert!(
            final_checkpoint
                .projection
                .jobs
                .contains_key("fj1-overflow-halt"),
            "the previously-blocked enqueue event must now be in the projection"
        );
    }

    #[test]
    fn tick_skips_invalid_queue_job_id_and_advances_cursor() {
        // f-798-code_quality-1771812851882322-0: Verify that a lifecycle event
        // with an unsafe queue_job_id (e.g. containing "../") is treated as a
        // poison pill: skipped with cursor advance, tick returns Ok.
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;
        let ts = now_timestamp_ns();

        // Construct a lifecycle event with an unsafe queue_job_id.
        let unsafe_identity = FacJobIdentityV1 {
            job_id: "fj1-unsafe-traversal".to_string(),
            queue_job_id: "../etc/passwd".to_string(),
            work_id: "W-42".to_string(),
            changeset_digest: "b3-256:".to_string() + &"a".repeat(64),
            spec_digest: "b3-256:".to_string() + &"b".repeat(64),
            gate_profile: "gates:balanced".to_string(),
            revision: "1".to_string(),
        };
        let unsafe_event = FacJobLifecycleEventV1::new(
            "intent:enqueue:unsafe-traversal",
            None,
            FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                identity: unsafe_identity,
                enqueue_epoch_ns: ts,
            }),
        );
        emit_lifecycle(&emitter, &unsafe_event, ts);

        // Emit a valid event after the unsafe one.
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:valid-after-unsafe",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("valid-after-unsafe"),
                    enqueue_epoch_ns: ts + 1,
                }),
            ),
            ts + 1,
        );

        let reconciler = make_reconciler(
            &queue_root,
            Arc::clone(&emitter),
            JobLifecycleReconcilerConfig {
                max_events_per_tick: 8,
                max_fs_ops_per_tick: 8,
            },
        );

        let tick = reconciler
            .tick()
            .expect("tick must succeed (unsafe queue_job_id treated as poison pill)");
        assert_eq!(
            tick.processed_events, 1,
            "valid event after unsafe queue_job_id poison pill must be processed"
        );
        assert!(
            queue_root
                .join(PENDING_DIR)
                .join("valid-after-unsafe.json")
                .exists(),
            "valid event must be reconciled to pending/"
        );

        // Unsafe event must not be replayed.
        let second = reconciler.tick().expect("second tick");
        assert_eq!(
            second.processed_events, 0,
            "unsafe queue_job_id event must not be replayed"
        );
    }

    #[test]
    fn cleanup_unknown_files_skipped_during_backlog() {
        // f-798-security-1771812591501920-0: Verify that cleanup_unknown_files
        // does NOT delete files in pending/ when the cursor lags behind the
        // ledger head (backlog processing). A file for a job whose event has
        // not yet been projected must survive.
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;
        let base_ts = now_timestamp_ns();

        // Emit two events. We will process only the first event per tick
        // (max_events_per_tick = 1). After the first tick, the cursor will
        // be behind the ledger head.
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:first",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("first"),
                    enqueue_epoch_ns: base_ts,
                }),
            ),
            base_ts,
        );
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:second",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("second"),
                    enqueue_epoch_ns: base_ts + 1,
                }),
            ),
            base_ts + 1,
        );

        // Pre-create a pending file for "second" (e.g. it was enqueued to
        // disk by the submitter before the reconciler caught up).
        fs::create_dir_all(queue_root.join(PENDING_DIR)).expect("create pending");
        fs::write(
            queue_root.join(PENDING_DIR).join("second.json"),
            br#"{"pre-existing":"payload"}"#,
        )
        .expect("seed pre-existing second");

        let reconciler = make_reconciler(
            &queue_root,
            Arc::clone(&emitter),
            JobLifecycleReconcilerConfig {
                max_events_per_tick: 1,
                max_fs_ops_per_tick: 16,
            },
        );

        // First tick: processes only the "first" event. "second" is not yet
        // in projection. Cursor lags behind ledger head.
        let first_tick = reconciler.tick().expect("first tick");
        assert_eq!(first_tick.processed_events, 1);
        assert!(
            queue_root.join(PENDING_DIR).join("second.json").exists(),
            "pre-existing file for not-yet-projected job must NOT be deleted \
             during backlog (cursor behind ledger head)"
        );

        // Second tick: processes the "second" event. Now cursor is caught up.
        let second_tick = reconciler.tick().expect("second tick");
        assert_eq!(second_tick.processed_events, 1);
        assert!(
            queue_root.join(PENDING_DIR).join("second.json").exists(),
            "second job should still exist in pending after being projected"
        );
    }

    #[test]
    fn cleanup_skipped_when_same_timestamp_events_remain_unprocessed() {
        // f-798-security-1771814320321724-0: Verify that the cursor caught-up
        // check requires BOTH timestamp AND event_id to match the latest
        // ledger event.  When multiple events share the same timestamp_ns and
        // the per-tick page limit causes only the first to be processed, the
        // cursor_event_id will be lexicographically earlier than the latest
        // event's ID at that timestamp.  Cleanup must NOT fire in this state.
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;
        let same_ts = now_timestamp_ns();

        // Emit two events at the SAME timestamp.  The StubLedgerEventEmitter
        // assigns event_ids in insertion order, so the second event's ID will
        // sort lexicographically after the first.
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:alpha",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("alpha"),
                    enqueue_epoch_ns: same_ts,
                }),
            ),
            same_ts,
        );
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:beta",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("beta"),
                    enqueue_epoch_ns: same_ts,
                }),
            ),
            same_ts,
        );

        // Pre-create a pending file for "beta" (e.g. the submitter wrote the
        // file before the reconciler processed the event).
        fs::create_dir_all(queue_root.join(PENDING_DIR)).expect("create pending");
        fs::write(
            queue_root.join(PENDING_DIR).join("beta.json"),
            br#"{"pre-existing":"beta-payload"}"#,
        )
        .expect("seed pre-existing beta");

        // Process only ONE event per tick (page boundary simulation).
        let reconciler = make_reconciler(
            &queue_root,
            Arc::clone(&emitter),
            JobLifecycleReconcilerConfig {
                max_events_per_tick: 1,
                max_fs_ops_per_tick: 16,
            },
        );

        // First tick: processes "alpha" only. Cursor timestamp == same_ts
        // but cursor_event_id < latest event_id at same_ts.  Cleanup must
        // NOT fire.
        let first_tick = reconciler.tick().expect("first tick");
        assert_eq!(first_tick.processed_events, 1);
        assert!(
            queue_root.join(PENDING_DIR).join("beta.json").exists(),
            "pre-existing file for not-yet-projected same-timestamp job must \
             NOT be deleted (cursor event_id behind latest at same timestamp)"
        );

        // Second tick: processes "beta". Now cursor is fully caught up.
        let second_tick = reconciler.tick().expect("second tick");
        assert_eq!(second_tick.processed_events, 1);
        assert!(
            queue_root.join(PENDING_DIR).join("beta.json").exists(),
            "beta job should still exist in pending after being projected"
        );
    }

    #[test]
    fn cursor_caught_up_true_with_non_lifecycle_events_ahead() {
        // f-798-security-1771815813540054-0 / f-798-code_quality-1771815601035651-0:
        // Regression test: seed both lifecycle and non-lifecycle events at the
        // same timestamp. Process all lifecycle events. Verify that
        // `cursor_caught_up` evaluates to true (cleanup fires) even while
        // non-lifecycle events are still "ahead" in the global ledger.
        let tmp = tempfile::tempdir().expect("tempdir");
        let queue_root = make_queue_root(&tmp);
        let stub = Arc::new(StubLedgerEventEmitter::new());
        let emitter: Arc<dyn LedgerEventEmitter> = stub;
        let ts = now_timestamp_ns();

        // Emit a lifecycle event.
        emit_lifecycle(
            &emitter,
            &FacJobLifecycleEventV1::new(
                "intent:enqueue:lifecycle-job",
                None,
                FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
                    identity: identity("lifecycle-job"),
                    enqueue_epoch_ns: ts,
                }),
            ),
            ts,
        );

        // Emit a non-lifecycle event AFTER the lifecycle event. This simulates
        // production where `work.transitioned` / `evidence.published` events
        // continuously arrive and push the global ledger head ahead.
        emitter
            .emit_session_event(
                "session-nonlc",
                "work.transitioned",
                b"non-lifecycle-payload",
                "fac-worker",
                ts + 1,
            )
            .expect("emit non-lifecycle event");

        // Seed an orphan file in pending/ that should be cleaned up when the
        // cursor is caught up to the lifecycle stream.
        fs::create_dir_all(queue_root.join(PENDING_DIR)).expect("create pending");
        fs::write(
            queue_root.join(PENDING_DIR).join("orphan-nonlc.json"),
            b"{}",
        )
        .expect("seed orphan file");

        let reconciler = make_reconciler(
            &queue_root,
            Arc::clone(&emitter),
            JobLifecycleReconcilerConfig {
                max_events_per_tick: 16,
                max_fs_ops_per_tick: 16,
            },
        );

        let tick = reconciler.tick().expect("tick");
        assert_eq!(
            tick.processed_events, 1,
            "lifecycle event must be processed"
        );
        assert!(
            queue_root
                .join(PENDING_DIR)
                .join("lifecycle-job.json")
                .exists(),
            "lifecycle job must exist in pending/"
        );
        // The orphan file must be cleaned up because the cursor is caught up
        // to the lifecycle event stream, even though non-lifecycle events
        // exist ahead in the global ledger.
        assert!(
            !queue_root
                .join(PENDING_DIR)
                .join("orphan-nonlc.json")
                .exists(),
            "orphan file must be cleaned up when cursor is caught up to \
             lifecycle stream, regardless of non-lifecycle events ahead"
        );
    }
}
