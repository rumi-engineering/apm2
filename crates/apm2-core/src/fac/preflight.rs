#![allow(clippy::missing_errors_doc)]

use std::path::Path;

use nix::sys::statvfs::statvfs;

use crate::fac::gc_receipt::{DEFAULT_MIN_FREE_BYTES, persist_gc_receipt};
use crate::fac::lane::LaneManager;
use crate::fac::{GC_RECEIPT_SCHEMA, execute_gc, plan_gc};

pub struct PreflightStatus {
    pub apm2_home_free_bytes: u64,
    pub min_free_threshold: u64,
    pub passed: bool,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum PreflightError {
    Io(String),
    Precondition(String),
}

pub fn check_disk_space(path: &Path) -> Result<u64, String> {
    let stats = statvfs(path).map_err(|error| format!("statvfs failed: {error}"))?;
    let free = stats
        .blocks_available()
        .saturating_mul(stats.fragment_size() as u64);
    Ok(free)
}

pub fn run_preflight(
    fac_root: &Path,
    lane_manager: &LaneManager,
    min_free_bytes: u64,
) -> Result<PreflightStatus, PreflightError> {
    let threshold = if min_free_bytes == 0 {
        DEFAULT_MIN_FREE_BYTES
    } else {
        min_free_bytes
    };

    let apm2_home_status = check_disk_space(fac_root).map_err(PreflightError::Io)?;
    let mut workspace_min = apm2_home_status;

    let statuses = lane_manager
        .all_lane_statuses()
        .map_err(|error| PreflightError::Io(format!("lane status failed: {error}")))?;
    for status in statuses {
        let lane_dir = lane_manager.lane_dir(&status.lane_id);
        let workspace = lane_dir.join("workspace");
        if workspace.exists() {
            if let Ok(space) = check_disk_space(&workspace) {
                workspace_min = workspace_min.min(space);
            }
        }
    }

    if workspace_min >= threshold {
        return Ok(PreflightStatus {
            apm2_home_free_bytes: apm2_home_status,
            min_free_threshold: threshold,
            passed: true,
        });
    }

    let plan = plan_gc(fac_root, lane_manager).map_err(|error| match error {
        super::gc::GcPlanError::Io(message) => PreflightError::Io(message),
        super::gc::GcPlanError::Precondition(message) => PreflightError::Precondition(message),
    })?;
    let mut receipt = execute_gc(&plan);
    let after_preflight = match check_disk_space(fac_root) {
        Ok(value) => value,
        Err(error) => {
            return Err(PreflightError::Io(format!(
                "failed to re-check preflight free space: {error}"
            )));
        },
    };

    receipt.before_free_bytes = apm2_home_status;
    receipt.after_free_bytes = after_preflight;
    receipt.min_free_threshold = threshold;

    let receipts_dir = fac_root.join("receipts");
    receipt.schema = GC_RECEIPT_SCHEMA.to_string();
    let _ = persist_gc_receipt(&receipts_dir, receipt);

    let passed = after_preflight >= threshold;
    if passed {
        Ok(PreflightStatus {
            apm2_home_free_bytes: after_preflight,
            min_free_threshold: threshold,
            passed: true,
        })
    } else {
        Err(PreflightError::Precondition(format!(
            "insufficient disk space after gc: {after_preflight} < {threshold}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::fac::lane::{LaneLeaseV1, LaneManager, LaneState};

    #[test]
    fn test_preflight_passes_with_enough_space() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).unwrap();
        let manager = LaneManager::new(fac_root.clone()).expect("manager");
        manager.ensure_directories().expect("dirs");
        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let lease = LaneLeaseV1::new(
            lane_id,
            "job-001",
            42,
            LaneState::Idle,
            "2026-01-01T00:00:00Z",
            "lane-profile",
            "toolchain",
        )
        .expect("lease");
        lease.persist(&lane_dir).expect("lease persisted");

        let status = run_preflight(&fac_root, &manager, 1).expect("preflight");
        assert!(status.passed);
        assert!(status.apm2_home_free_bytes > 0);
    }

    #[test]
    fn test_preflight_triggers_gc() {
        let dir = tempdir().expect("tmp");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(fac_root.join("receipts")).expect("mkdir");
        let manager = LaneManager::new(fac_root.clone()).expect("manager");
        manager.ensure_directories().expect("dirs");
        let lane_id = "lane-00";
        let lane_dir = manager.lane_dir(lane_id);
        let lease = LaneLeaseV1::new(
            lane_id,
            "job-002",
            42,
            LaneState::Idle,
            "2026-01-01T00:00:00Z",
            "lane-profile",
            "toolchain",
        )
        .expect("lease");
        lease.persist(&lane_dir).expect("lease persisted");

        // Construct an obviously high threshold to force escalation logic path.
        let status = run_preflight(&fac_root, &manager, u64::MAX / 2)
            .err()
            .unwrap();
        assert!(matches!(status, PreflightError::Precondition(_)));
    }
}
