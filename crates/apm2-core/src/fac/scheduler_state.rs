//! Persistent scheduler state schema and I/O for RFC-0029 anti-starvation
//! continuity.
//!
//! This module is intentionally small and defensive:
//! - schema-checked bounded deserialization
//! - bounded content size (1 MiB cap)
//! - atomic persist (temp + rename)
//! - symlink-safe path checks
//! - content-hash verification

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::determinism::canonicalize_json;
use crate::economics::cost_model::CostModelV1;
use crate::economics::queue_admission::QueueLane;

/// Scheduler state schema identifier for on-disk versioning.
pub const SCHEDULER_STATE_SCHEMA: &str = "apm2.scheduler_state.v1";
/// Maximum scheduler state payload size in bytes.
pub const MAX_SCHEDULER_STATE_BYTES: usize = 1_048_576; // 1 MiB

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Canonical scheduler state filename.
const SCHEDULER_STATE_FILE: &str = "state.v1.json";
/// Scheduler subdirectory under FAC root.
const SCHEDULER_STATE_DIR: &str = "scheduler";
/// Domain separator for scheduler state content hashing.
const SCHEDULER_STATE_HASH_DOMAIN: &[u8] = b"apm2.fac.scheduler_state.v1";

/// Persisted scheduler state for RFC-0029 anti-starvation continuity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchedulerStateV1 {
    /// Schema identifier.
    pub schema: String,
    /// Per-lane snapshot of backlog and wait metadata.
    pub lane_snapshots: Vec<LaneSnapshot>,
    /// Last evaluation tick.
    pub last_evaluation_tick: u64,
    /// Epoch seconds of persistence.
    pub persisted_at_secs: u64,
    /// TCK-00532: Per-job-kind cost model for queue admission.
    /// Optional for backward compatibility with pre-TCK-00532 state files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_model: Option<CostModelV1>,
    /// BLAKE3 content hash for integrity.
    pub content_hash: String,
}

/// Snapshot of a single lane's scheduler counters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaneSnapshot {
    /// Lane name (e.g. `stop_revoke`, `control`).
    pub lane: String,
    /// Backlog depth observed at persistence time.
    pub backlog: usize,
    /// Maximum observed waiting ticks.
    pub max_wait_ticks: u64,
}

/// Compute the scheduler content hash using CAC-JSON canonicalization
/// (SP-INV-004).
/// # Errors
/// Returns an error if JSON serialization or canonicalization fails.
pub fn compute_scheduler_state_content_hash(state: &SchedulerStateV1) -> Result<String, String> {
    let mut normalized = state.clone();
    normalized.content_hash = String::new();
    let json_str = serde_json::to_string(&normalized)
        .map_err(|e| format!("cannot serialize scheduler state for hashing: {e}"))?;
    let canonical = canonicalize_json(&json_str)
        .map_err(|e| format!("cannot canonicalize scheduler state for hashing: {e}"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(SCHEDULER_STATE_HASH_DOMAIN);
    hasher.update(canonical.as_bytes());
    Ok(format!("b3-256:{}", hasher.finalize().to_hex()))
}

/// Persist scheduler state atomically.
/// # Errors
/// Returns an error if the state directory cannot be created, serialization
/// fails, or atomic write fails.
pub fn persist_scheduler_state(
    fac_root: &Path,
    state: &SchedulerStateV1,
) -> Result<PathBuf, String> {
    let scheduler_dir = fac_root.join(SCHEDULER_STATE_DIR);
    fs::create_dir_all(&scheduler_dir).map_err(|e| {
        format!(
            "cannot create scheduler state directory {}: {e}",
            scheduler_dir.display()
        )
    })?;

    let target = scheduler_dir.join(SCHEDULER_STATE_FILE);
    let mut state_to_store = state.clone();
    state_to_store.content_hash = compute_scheduler_state_content_hash(state)?;
    let bytes = serde_json::to_vec_pretty(&state_to_store)
        .map_err(|e| format!("cannot serialize scheduler state: {e}"))?;

    atomic_write(&target, &bytes)?;
    Ok(target)
}

/// Load scheduler state if present.
/// # Errors
/// Returns an error if bounds checks, JSON parsing, schema checks, invariants,
/// or hash verification fail.
pub fn load_scheduler_state(fac_root: &Path) -> Result<Option<SchedulerStateV1>, String> {
    let path = fac_root
        .join(SCHEDULER_STATE_DIR)
        .join(SCHEDULER_STATE_FILE);
    if !path.exists() {
        return Ok(None);
    }

    let bytes = bounded_read_file(&path, MAX_SCHEDULER_STATE_BYTES)?;
    let state: SchedulerStateV1 = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to deserialize scheduler state: {e}"))?;

    if state.schema != SCHEDULER_STATE_SCHEMA {
        return Err(format!("unexpected schema: {}", state.schema));
    }

    if state.lane_snapshots.len() > QueueLane::all().len() {
        return Err(format!(
            "unexpected lane snapshot count: {}",
            state.lane_snapshots.len()
        ));
    }

    let mut seen = [false; QueueLane::all().len()];
    for snapshot in &state.lane_snapshots {
        let lane = lane_from_str(&snapshot.lane)
            .ok_or_else(|| format!("unknown lane snapshot name: {}", snapshot.lane))?;
        let lane_idx = lane as usize;
        if seen[lane_idx] {
            return Err(format!("duplicate lane snapshot: {}", snapshot.lane));
        }
        seen[lane_idx] = true;

        if snapshot.backlog > state_max_backlog() {
            return Err(format!(
                "invalid lane backlog {} exceeds max {}",
                snapshot.backlog,
                state_max_backlog()
            ));
        }
    }

    // TCK-00532: Validate cost model if present.
    if let Some(ref cost_model) = state.cost_model {
        cost_model
            .validate()
            .map_err(|e| format!("invalid cost model in scheduler state: {e}"))?;
    }

    let expected = compute_scheduler_state_content_hash(&state)?;
    if state.content_hash != expected {
        return Err("scheduler state content_hash mismatch".to_string());
    }

    Ok(Some(state))
}

pub(crate) const fn state_max_backlog() -> usize {
    crate::economics::queue_admission::MAX_LANE_BACKLOG
}

pub(crate) fn lane_from_str(lane: &str) -> Option<QueueLane> {
    match lane {
        "stop_revoke" => Some(QueueLane::StopRevoke),
        "control" => Some(QueueLane::Control),
        "consume" => Some(QueueLane::Consume),
        "replay" => Some(QueueLane::Replay),
        "projection_replay" => Some(QueueLane::ProjectionReplay),
        "bulk" => Some(QueueLane::Bulk),
        _ => None,
    }
}

fn bounded_read_file(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    ensure_safe_path(path, "bounded_read_file")?;
    let mut file = open_file_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    let max_u64 = u64::try_from(max_size).map_err(|e| e.to_string())?;
    if metadata.len() > max_u64 {
        return Err(format!(
            "scheduler state exceeds max size: {} > {}",
            metadata.len(),
            max_size
        ));
    }

    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|e| format!("scheduler state file size too large: {e}"))?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read scheduler state {}: {e}", path.display()))?;

    if bytes.len() > max_size {
        return Err(format!(
            "scheduler state exceeds max size: {} > {}",
            bytes.len(),
            max_size
        ));
    }

    Ok(bytes)
}

fn atomic_write(target: &Path, data: &[u8]) -> Result<(), String> {
    ensure_safe_path(target, "atomic_write")?;
    let parent = target
        .parent()
        .ok_or_else(|| format!("target path has no parent: {}", target.display()))?;
    if let Err(e) = fs::create_dir_all(parent) {
        return Err(format!(
            "cannot create parent directory {}: {e}",
            parent.display()
        ));
    }

    if target.exists() {
        let target_metadata = fs::symlink_metadata(target)
            .map_err(|e| format!("cannot stat target {}: {e}", target.display()))?;
        if target_metadata.is_dir() {
            return Err(format!("target path is a directory: {}", target.display()));
        }
    }

    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("create temp file in {}: {e}", parent.display()))?;
    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o600);
        if let Err(e) = tmp.as_file().set_permissions(perms) {
            return Err(format!("set temp file permissions: {e}"));
        }
    }

    tmp.write_all(data).map_err(|e| {
        format!(
            "write temporary scheduler state to {}: {e}",
            target.display()
        )
    })?;
    tmp.flush()
        .map_err(|e| format!("flush temporary scheduler state {}: {e}", target.display()))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("sync temporary scheduler state {}: {e}", target.display()))?;

    tmp.persist(target).map_err(|e| {
        format!(
            "rename temporary scheduler state to {}: {}",
            target.display(),
            e.error
        )
    })?;

    Ok(())
}

fn ensure_safe_path(path: &Path, context: &str) -> Result<(), String> {
    for component in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if component.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(component) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "{context}: symlink component in path: {}",
                        component.display()
                    ));
                }
                if component != path && !metadata.is_dir() {
                    return Err(format!(
                        "{context}: non-directory path component: {}",
                        component.display()
                    ));
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {},
            Err(e) => {
                return Err(format!(
                    "{context}: failed to validate path component {}: {e}",
                    component.display()
                ));
            },
        }
    }
    Ok(())
}

fn open_file_no_follow(path: &Path) -> Result<File, String> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW);
        options
            .open(path)
            .map_err(|e| format!("cannot open scheduler state {}: {e}", path.display()))
    }

    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| format!("cannot open scheduler state {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::queue_admission::{
        MAX_CONTROL_WAIT_TICKS, MAX_STOP_REVOKE_WAIT_TICKS, QueueSchedulerState,
    };

    fn temp_state_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn fixture_state() -> SchedulerStateV1 {
        let mut snapshots = Vec::new();
        for lane in QueueLane::all() {
            snapshots.push(LaneSnapshot {
                lane: lane.to_string(),
                backlog: 7,
                max_wait_ticks: match lane {
                    QueueLane::StopRevoke => 11,
                    QueueLane::Control => 22,
                    _ => 0,
                },
            });
        }

        let mut state = SchedulerStateV1 {
            schema: SCHEDULER_STATE_SCHEMA.to_string(),
            lane_snapshots: snapshots,
            last_evaluation_tick: 99,
            persisted_at_secs: 12_345,
            cost_model: None,
            content_hash: String::new(),
        };
        state.content_hash = compute_scheduler_state_content_hash(&state).expect("hash");
        state
    }

    #[test]
    fn round_trip_persist_and_load() {
        let dir = temp_state_root();
        let state = fixture_state();
        let fac_root = dir.path();
        let path = persist_scheduler_state(fac_root, &state).expect("persist");

        let loaded = load_scheduler_state(fac_root).expect("load");
        assert!(loaded.is_some(), "state should be present");
        let loaded = loaded.expect("loaded");
        assert_eq!(loaded.schema, SCHEDULER_STATE_SCHEMA);
        assert_eq!(loaded.last_evaluation_tick, state.last_evaluation_tick);
        assert_eq!(loaded.lane_snapshots.len(), QueueLane::all().len());
        assert_eq!(loaded, state);
        assert!(path.exists(), "state file should exist");
    }

    #[test]
    fn missing_state_returns_none() {
        let dir = temp_state_root();
        let result = load_scheduler_state(dir.path()).expect("load");
        assert!(result.is_none());
    }

    #[test]
    fn corrupt_state_triggers_recovery_error() {
        let dir = temp_state_root();
        let scheduler_dir = dir.path().join("scheduler");
        std::fs::create_dir_all(&scheduler_dir).expect("create scheduler dir");
        let state_path = scheduler_dir.join("state.v1.json");
        let bytes = b"{bad-json";
        std::fs::write(&state_path, bytes).expect("write bad json");

        assert!(load_scheduler_state(dir.path()).is_err());
    }

    #[test]
    fn oversized_state_is_rejected() {
        let dir = temp_state_root();
        let scheduler_dir = dir.path().join("scheduler");
        std::fs::create_dir_all(&scheduler_dir).expect("create scheduler dir");
        let state_path = scheduler_dir.join("state.v1.json");
        let bytes = vec![b'{'; MAX_SCHEDULER_STATE_BYTES + 1];
        std::fs::write(&state_path, &bytes).expect("write oversized");

        let result = load_scheduler_state(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds max size"));
    }

    #[test]
    fn content_hash_is_verified() {
        let dir = temp_state_root();
        let state = fixture_state();
        let fac_root = dir.path();
        persist_scheduler_state(fac_root, &state).expect("persist");
        let state_path = fac_root.join("scheduler").join("state.v1.json");

        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).expect("read")).expect("parse json");
        value["persisted_at_secs"] = serde_json::Value::from(state.persisted_at_secs + 1);
        let bytes = serde_json::to_vec_pretty(&value).expect("serialize");
        std::fs::write(&state_path, bytes).expect("tamper");

        assert!(load_scheduler_state(fac_root).is_err());
    }

    #[test]
    fn schema_validation_rejects_wrong_schema() {
        let dir = temp_state_root();
        let mut state = fixture_state();
        state.schema = "apm2.scheduler_state.bad".to_string();
        state.content_hash = compute_scheduler_state_content_hash(&state).expect("hash");
        let scheduler_dir = dir.path().join("scheduler");
        std::fs::create_dir_all(&scheduler_dir).expect("create dir");
        let state_path = scheduler_dir.join("state.v1.json");
        let bytes = serde_json::to_vec_pretty(&state).expect("serialize");
        std::fs::write(&state_path, bytes).expect("write");

        let result = load_scheduler_state(dir.path());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            format!("unexpected schema: apm2.scheduler_state.bad")
        );
    }

    #[test]
    fn scheduler_state_anti_starvation_wait_ticks_are_restored() {
        let mut snapshots = Vec::new();
        for lane in QueueLane::all() {
            snapshots.push(LaneSnapshot {
                lane: lane.to_string(),
                backlog: 1,
                max_wait_ticks: match lane {
                    QueueLane::StopRevoke => MAX_STOP_REVOKE_WAIT_TICKS,
                    QueueLane::Control => MAX_CONTROL_WAIT_TICKS,
                    _ => 0,
                },
            });
        }

        let state = SchedulerStateV1 {
            schema: SCHEDULER_STATE_SCHEMA.to_string(),
            lane_snapshots: snapshots,
            last_evaluation_tick: 321,
            persisted_at_secs: 12_345,
            cost_model: None,
            content_hash: String::new(),
        };
        let state = SchedulerStateV1 {
            content_hash: compute_scheduler_state_content_hash(&state).expect("hash"),
            ..state
        };

        let restored = QueueSchedulerState::from_persisted(&state);
        let restored_state = restored.to_scheduler_state_v1(state.last_evaluation_tick);
        let stop_revoke = restored_state
            .lane_snapshots
            .iter()
            .find(|snapshot| snapshot.lane == "stop_revoke")
            .expect("stop_revoke");
        let control = restored_state
            .lane_snapshots
            .iter()
            .find(|snapshot| snapshot.lane == "control")
            .expect("control");
        assert_eq!(stop_revoke.max_wait_ticks, MAX_STOP_REVOKE_WAIT_TICKS);
        assert_eq!(control.max_wait_ticks, MAX_CONTROL_WAIT_TICKS);
    }

    #[test]
    fn state_rejects_unknown_lane_names() {
        let mut state = fixture_state();
        state.lane_snapshots.push(LaneSnapshot {
            lane: "unknown".to_string(),
            backlog: 1,
            max_wait_ticks: 10,
        });
        state.content_hash = compute_scheduler_state_content_hash(&state).expect("hash");
        // Persist/load through filesystem to exercise the full reader path.
        let dir = temp_state_root();
        let scheduler_dir = dir.path().join("scheduler");
        std::fs::create_dir_all(&scheduler_dir).expect("create dir");
        let state_path = scheduler_dir.join("state.v1.json");
        let data = serde_json::to_vec_pretty(&state).expect("serialize");
        std::fs::write(&state_path, data).expect("write");
        assert!(load_scheduler_state(dir.path()).is_err());
    }

    #[test]
    fn state_rejects_duplicate_lane_names() {
        let mut state = fixture_state();
        let duplicate = state.lane_snapshots[0].clone();
        state.lane_snapshots.push(duplicate);
        state.content_hash = compute_scheduler_state_content_hash(&state).expect("hash");

        let dir = temp_state_root();
        let scheduler_dir = dir.path().join("scheduler");
        std::fs::create_dir_all(&scheduler_dir).expect("create dir");
        let state_path = scheduler_dir.join("state.v1.json");
        let data = serde_json::to_vec_pretty(&state).expect("serialize");
        std::fs::write(&state_path, data).expect("write");
        assert!(load_scheduler_state(dir.path()).is_err());
    }
}
