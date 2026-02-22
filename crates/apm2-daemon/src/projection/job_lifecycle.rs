//! Ledger-backed FAC job lifecycle projection and filesystem rehydration.
//!
//! The projection treats `fac.job.*` ledger events as truth and repairs the
//! queue filesystem (`pending/`, `claimed/`, `completed/`, `denied/`) as a
//! witnessed cache.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use apm2_core::fac::job_lifecycle::{
    FAC_JOB_CLAIMED_EVENT_TYPE, FAC_JOB_COMPLETED_EVENT_TYPE, FAC_JOB_ENQUEUED_EVENT_TYPE,
    FAC_JOB_FAILED_EVENT_TYPE, FAC_JOB_RELEASED_EVENT_TYPE, FAC_JOB_STARTED_EVENT_TYPE,
    FacJobLifecycleEventData, FacJobLifecycleEventV1, JobLifecycleError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

const PENDING_DIR: &str = "pending";
const CLAIMED_DIR: &str = "claimed";
const COMPLETED_DIR: &str = "completed";
const DENIED_DIR: &str = "denied";
const QUEUE_DIRS: [&str; 4] = [PENDING_DIR, CLAIMED_DIR, COMPLETED_DIR, DENIED_DIR];

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
    /// Most recent lease ID (for claimed/running/released lineage).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// Most recent reason code for failure/release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

/// Full in-memory projection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLifecycleProjectionV1 {
    /// Schema identifier.
    pub schema: String,
    /// Projection records keyed by canonical content-addressable `job_id`.
    pub jobs: BTreeMap<String, ProjectedJobLifecycleV1>,
}

impl Default for JobLifecycleProjectionV1 {
    fn default() -> Self {
        Self {
            schema: JOB_LIFECYCLE_PROJECTION_SCHEMA_ID.to_string(),
            jobs: BTreeMap::new(),
        }
    }
}

impl JobLifecycleProjectionV1 {
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
    ) -> Result<String, JobLifecycleProjectionError> {
        if self.schema != JOB_LIFECYCLE_PROJECTION_SCHEMA_ID {
            return Err(JobLifecycleProjectionError::Validation(format!(
                "projection schema mismatch: expected {JOB_LIFECYCLE_PROJECTION_SCHEMA_ID}, got {}",
                self.schema
            )));
        }

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

        let record = ProjectedJobLifecycleV1 {
            job_id: job_id.clone(),
            queue_job_id,
            work_id,
            status: new_status,
            last_event_id: ledger_event_id.to_string(),
            lease_id,
            reason_code,
        };

        self.jobs.insert(job_id.clone(), record);
        if self.jobs.len() > MAX_PROJECTED_JOBS {
            return Err(JobLifecycleProjectionError::Validation(format!(
                "projected jobs exceed max bound: {} > {MAX_PROJECTED_JOBS}",
                self.jobs.len()
            )));
        }

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
    /// Returns [`JobLifecycleProjectionError`] when event decode, projection,
    /// checkpoint persistence, or filesystem operations fail.
    pub fn tick(&self) -> Result<JobLifecycleReconcileTickV1, JobLifecycleProjectionError> {
        self.ensure_queue_dirs()?;
        let mut checkpoint = self.load_checkpoint()?;

        let new_events = self.collect_events_since(
            checkpoint.cursor_timestamp_ns,
            &checkpoint.cursor_event_id,
            self.config.max_events_per_tick,
        );

        let mut dirty_job_ids: BTreeSet<String> = checkpoint
            .pending_reconcile_job_ids
            .drain(..)
            .collect::<BTreeSet<_>>();
        let mut processed_events = 0usize;

        for event in new_events {
            let lifecycle_event = decode_lifecycle_event(&event)?;
            let dirty_job_id = checkpoint
                .projection
                .apply_event(&lifecycle_event, &event.event_id)?;
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
            let fully_reconciled =
                self.reconcile_projected_job(&checkpoint.projection, &job_id, &mut applied_fs_ops)?;
            if !fully_reconciled {
                remaining_reconcile.push(job_id);
            }
        }

        if applied_fs_ops < self.config.max_fs_ops_per_tick {
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
        let mut events = self
            .ledger
            .get_all_events()
            .into_iter()
            .filter(|event| {
                matches!(
                    event.event_type.as_str(),
                    FAC_JOB_ENQUEUED_EVENT_TYPE
                        | FAC_JOB_CLAIMED_EVENT_TYPE
                        | FAC_JOB_STARTED_EVENT_TYPE
                        | FAC_JOB_COMPLETED_EVENT_TYPE
                        | FAC_JOB_RELEASED_EVENT_TYPE
                        | FAC_JOB_FAILED_EVENT_TYPE
                )
            })
            .collect::<Vec<_>>();

        events.sort_by(|left, right| {
            (left.timestamp_ns, &left.event_id).cmp(&(right.timestamp_ns, &right.event_id))
        });

        events
            .into_iter()
            .filter(|event| {
                event.timestamp_ns > cursor_timestamp_ns
                    || (event.timestamp_ns == cursor_timestamp_ns
                        && event.event_id.as_str() > cursor_event_id)
            })
            .take(max_events)
            .collect()
    }

    fn ensure_queue_dirs(&self) -> Result<(), JobLifecycleProjectionError> {
        for dir in QUEUE_DIRS {
            fs::create_dir_all(self.queue_root.join(dir)).map_err(|err| {
                JobLifecycleProjectionError::Io(format!(
                    "create queue dir {}: {err}",
                    self.queue_root.join(dir).display()
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
            } else {
                write_witness_file(&desired_path, projected)?;
            }
            *applied_fs_ops = applied_fs_ops.saturating_add(1);
        }

        for path in existing_paths {
            if path == desired_path {
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
        let expected_files = projection
            .jobs
            .values()
            .filter_map(|record| safe_job_file_name(&record.queue_job_id).ok())
            .collect::<BTreeSet<_>>();

        for dir in QUEUE_DIRS {
            if *applied_fs_ops >= self.config.max_fs_ops_per_tick {
                return Ok(());
            }
            let dir_path = self.queue_root.join(dir);
            let Ok(entries) = fs::read_dir(&dir_path) else {
                continue;
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
                        "remove unknown queue file {}: {err}",
                        path.display()
                    ))
                })?;
                *applied_fs_ops = applied_fs_ops.saturating_add(1);
            }
        }
        Ok(())
    }

    fn load_checkpoint(&self) -> Result<JobLifecycleCheckpointV1, JobLifecycleProjectionError> {
        if !self.checkpoint_path.exists() {
            return Ok(JobLifecycleCheckpointV1::default());
        }

        let bytes = fs::read(&self.checkpoint_path).map_err(|err| {
            JobLifecycleProjectionError::Io(format!(
                "read checkpoint {}: {err}",
                self.checkpoint_path.display()
            ))
        })?;

        let checkpoint: JobLifecycleCheckpointV1 =
            serde_json::from_slice(&bytes).map_err(|err| {
                JobLifecycleProjectionError::Serialization(format!(
                    "deserialize checkpoint {}: {err}",
                    self.checkpoint_path.display()
                ))
            })?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    fn save_checkpoint(
        &self,
        checkpoint: &JobLifecycleCheckpointV1,
    ) -> Result<(), JobLifecycleProjectionError> {
        let bytes = serde_json::to_vec_pretty(checkpoint).map_err(|err| {
            JobLifecycleProjectionError::Serialization(format!(
                "serialize checkpoint {}: {err}",
                self.checkpoint_path.display()
            ))
        })?;
        fs::write(&self.checkpoint_path, bytes).map_err(|err| {
            JobLifecycleProjectionError::Io(format!(
                "write checkpoint {}: {err}",
                self.checkpoint_path.display()
            ))
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
    });
    let bytes = serde_json::to_vec_pretty(&witness).map_err(|err| {
        JobLifecycleProjectionError::Serialization(format!(
            "serialize witness file {}: {err}",
            path.display()
        ))
    })?;
    fs::write(path, bytes).map_err(|err| {
        JobLifecycleProjectionError::Io(format!("write witness file {}: {err}", path.display()))
    })
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
        fs::write(queue_root.join(PENDING_DIR).join("orphan.json"), b"{}").expect("seed orphan");

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
}
