//! Systemd unit detection and FAC work-unit liveness helpers.
//!
//! These helpers support defense-in-depth around detached transient units:
//! - detect the current parent systemd unit from `/proc/self/cgroup`
//! - query whether FAC-associated units for a lane/job are still active
//!
//! Reclaim paths use this to avoid clearing leases solely on dead PID evidence.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use wait_timeout::ChildExt;

/// Marker embedded in lane-corruption reasons for orphaned active systemd work.
pub const ORPHANED_SYSTEMD_UNIT_REASON_CODE: &str = "ORPHANED_SYSTEMD_UNIT";

const MAX_CGROUP_FILE_BYTES: u64 = 8192;
const MAX_SYSTEMD_UNIT_NAME_LENGTH: usize = 255;
const SYSTEMCTL_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Liveness state for FAC-associated systemd units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FacUnitLiveness {
    /// One or more associated units are active/activating.
    Active {
        /// Active unit names reported by systemd.
        active_units: Vec<String>,
    },
    /// No associated units are active.
    Inactive,
    /// Unit liveness could not be determined.
    ///
    /// Reclaim code treats this as fail-closed.
    Unknown {
        /// Diagnostic reason.
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UnitProbeStatus {
    Active,
    Inactive,
    Unavailable,
    Unknown(String),
}

/// Detect the current process's parent systemd unit name.
///
/// Returns `None` when the process is not running under systemd or when the
/// unit component is malformed.
#[must_use]
pub fn detect_systemd_unit_name() -> Option<String> {
    detect_systemd_unit_name_from_proc(Path::new("/proc"))
}

/// Detect the current process's parent systemd unit name using a custom procfs
/// root (test hook).
#[must_use]
pub fn detect_systemd_unit_name_from_proc(proc_root: &Path) -> Option<String> {
    let cgroup_path = read_self_cgroup_path(proc_root)?;
    extract_systemd_unit_from_cgroup_path(&cgroup_path)
}

/// Check whether FAC-associated units for a lease (lane/job) are active.
///
/// Associated units include:
/// - `apm2-fac-job-{lane_id}-{job_id}.service`
/// - any `apm2-fac-job-{lane_id}-{job_id}-*.service`
/// - any `apm2-warm-{lane_id}-{job_prefix}-*.service`
#[must_use]
pub fn check_fac_unit_liveness(lane_id: &str, job_id: &str) -> FacUnitLiveness {
    if !is_safe_unit_fragment(lane_id) {
        return FacUnitLiveness::Unknown {
            reason: format!("unsafe lane id for systemd probe: {lane_id:?}"),
        };
    }
    if !is_safe_unit_fragment(job_id) {
        return FacUnitLiveness::Unknown {
            reason: format!("unsafe job id for systemd probe: {job_id:?}"),
        };
    }

    let exact_job_unit = format!("apm2-fac-job-{lane_id}-{job_id}.service");
    let job_unit_prefix = format!("apm2-fac-job-{lane_id}-{job_id}-");
    let job_prefix = if job_id.len() >= 8 {
        &job_id[..8]
    } else {
        job_id
    };
    let warm_prefix = format!("apm2-warm-{lane_id}-{job_prefix}-");

    let mut active_units: BTreeSet<String> = BTreeSet::new();
    let mut unknown_reasons: Vec<String> = Vec::new();
    let mut successful_probe_count: usize = 0;

    for scope_flag in ["--user", "--system"] {
        match probe_exact_unit(scope_flag, &exact_job_unit) {
            UnitProbeStatus::Active => {
                successful_probe_count = successful_probe_count.saturating_add(1);
                active_units.insert(exact_job_unit.clone());
            },
            UnitProbeStatus::Inactive => {
                successful_probe_count = successful_probe_count.saturating_add(1);
            },
            UnitProbeStatus::Unavailable => {},
            UnitProbeStatus::Unknown(reason) => unknown_reasons.push(reason),
        }

        match probe_pattern_units(scope_flag, &job_unit_prefix) {
            Ok(units) => {
                successful_probe_count = successful_probe_count.saturating_add(1);
                active_units.extend(units);
            },
            Err(
                UnitProbeStatus::Unavailable | UnitProbeStatus::Inactive | UnitProbeStatus::Active,
            ) => {},
            Err(UnitProbeStatus::Unknown(reason)) => unknown_reasons.push(reason),
        }

        match probe_pattern_units(scope_flag, &warm_prefix) {
            Ok(units) => {
                successful_probe_count = successful_probe_count.saturating_add(1);
                active_units.extend(units);
            },
            Err(
                UnitProbeStatus::Unavailable | UnitProbeStatus::Inactive | UnitProbeStatus::Active,
            ) => {},
            Err(UnitProbeStatus::Unknown(reason)) => unknown_reasons.push(reason),
        }
    }

    if !active_units.is_empty() {
        return FacUnitLiveness::Active {
            active_units: active_units.into_iter().collect(),
        };
    }

    if !unknown_reasons.is_empty() {
        return FacUnitLiveness::Unknown {
            reason: unknown_reasons.join("; "),
        };
    }

    if successful_probe_count == 0 {
        return FacUnitLiveness::Unknown {
            reason: "systemd liveness probe unavailable in all scopes".to_string(),
        };
    }

    FacUnitLiveness::Inactive
}

fn probe_exact_unit(scope_flag: &str, unit_name: &str) -> UnitProbeStatus {
    let output =
        match run_systemctl_with_timeout(&[scope_flag, "is-active", "--quiet", "--", unit_name]) {
            Ok(value) => value,
            Err(status) => return status,
        };

    if output.status.success() {
        return UnitProbeStatus::Active;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_scope_unavailable(stderr.as_ref()) {
        return UnitProbeStatus::Unavailable;
    }

    match output.status.code() {
        // Inactive / failed / unknown states from `is-active`.
        Some(3..=5) => UnitProbeStatus::Inactive,
        Some(code) => UnitProbeStatus::Unknown(format!(
            "systemctl {scope_flag} is-active returned {code}: {}",
            stderr.trim()
        )),
        None => UnitProbeStatus::Unknown(format!(
            "systemctl {scope_flag} is-active terminated by signal"
        )),
    }
}

fn probe_pattern_units(
    scope_flag: &str,
    unit_prefix: &str,
) -> Result<Vec<String>, UnitProbeStatus> {
    let pattern = format!("{unit_prefix}*.service");
    let output = run_systemctl_with_timeout(&[
        scope_flag,
        "list-units",
        "--all",
        "--plain",
        "--no-legend",
        "--no-pager",
        "--type=service",
        "--state=active,activating,reloading",
        "--",
        &pattern,
    ])?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_scope_unavailable(stderr.as_ref()) {
            return Err(UnitProbeStatus::Unavailable);
        }
        return Err(UnitProbeStatus::Unknown(format!(
            "systemctl {scope_flag} list-units failed for pattern {pattern}: {}",
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut active_units: BTreeSet<String> = BTreeSet::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // `list-units` columns: UNIT LOAD ACTIVE SUB DESCRIPTION...
        let mut fields = trimmed.split_whitespace();
        let Some(unit) = fields.next() else { continue };
        let _load = fields.next();
        let active = fields.next().unwrap_or_default();

        if !unit.starts_with(unit_prefix) || !unit.ends_with(".service") {
            continue;
        }

        if matches!(active, "active" | "activating" | "reloading") {
            active_units.insert(unit.to_string());
        }
    }

    Ok(active_units.into_iter().collect())
}

fn read_self_cgroup_path(proc_root: &Path) -> Option<String> {
    let cgroup_file = proc_root.join("self").join("cgroup");
    let file = File::open(cgroup_file).ok()?;

    let mut content = String::new();
    file.take(MAX_CGROUP_FILE_BYTES + 1)
        .read_to_string(&mut content)
        .ok()?;

    if u64::try_from(content.len()).ok()? > MAX_CGROUP_FILE_BYTES {
        return None;
    }

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(path) = trimmed.strip_prefix("0::") {
            return Some(path.to_string());
        }
    }

    None
}

fn extract_systemd_unit_from_cgroup_path(cgroup_path: &str) -> Option<String> {
    for component in cgroup_path.split('/').rev() {
        if component.is_empty() {
            continue;
        }
        if !has_supported_unit_suffix(component) {
            continue;
        }
        if !is_valid_systemd_unit_name(component) {
            continue;
        }
        return Some(component.to_string());
    }
    None
}

fn is_valid_systemd_unit_name(unit_name: &str) -> bool {
    if unit_name.is_empty() || unit_name.len() > MAX_SYSTEMD_UNIT_NAME_LENGTH {
        return false;
    }

    let stem = if let Some(value) = unit_name.strip_suffix(".service") {
        value
    } else if let Some(value) = unit_name.strip_suffix(".scope") {
        value
    } else {
        return false;
    };
    if stem.is_empty() {
        return false;
    }
    if !stem.bytes().any(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    if stem.starts_with(['.', '-', '_']) || stem.ends_with(['.', '-', '_']) {
        return false;
    }

    unit_name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
}

fn has_supported_unit_suffix(unit_name: &str) -> bool {
    unit_name
        .rsplit_once('.')
        .is_some_and(|(_, ext)| matches!(ext, "service" | "scope"))
}

fn is_safe_unit_fragment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn run_systemctl_with_timeout(args: &[&str]) -> Result<Output, UnitProbeStatus> {
    let mut child = Command::new("systemctl")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                UnitProbeStatus::Unavailable
            } else {
                UnitProbeStatus::Unknown(format!(
                    "systemctl {} failed to execute: {err}",
                    args.join(" ")
                ))
            }
        })?;

    let status = child.wait_timeout(SYSTEMCTL_PROBE_TIMEOUT).map_err(|err| {
        UnitProbeStatus::Unknown(format!("systemctl {} wait failed: {err}", args.join(" ")))
    })?;
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(UnitProbeStatus::Unknown(format!(
            "systemctl {} timed out after {}s",
            args.join(" "),
            SYSTEMCTL_PROBE_TIMEOUT.as_secs()
        )));
    }

    child.wait_with_output().map_err(|err| {
        UnitProbeStatus::Unknown(format!(
            "systemctl {} output capture failed: {err}",
            args.join(" ")
        ))
    })
}

fn is_scope_unavailable(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("failed to connect to bus")
        || lower.contains("system has not been booted with systemd")
        || lower.contains("access denied")
        || lower.contains("permission denied")
        || lower.contains("connection refused")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn detect_systemd_unit_name_from_system_slice() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let self_dir = tmp.path().join("self");
        fs::create_dir_all(&self_dir).expect("create self dir");
        fs::write(
            self_dir.join("cgroup"),
            "0::/system.slice/apm2-worker.service\n",
        )
        .expect("write cgroup");

        let detected = detect_systemd_unit_name_from_proc(tmp.path());
        assert_eq!(detected.as_deref(), Some("apm2-worker.service"));
    }

    #[test]
    fn detect_systemd_unit_name_from_user_slice() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let self_dir = tmp.path().join("self");
        fs::create_dir_all(&self_dir).expect("create self dir");
        fs::write(
            self_dir.join("cgroup"),
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/apm2-worker@lane_00.service\n",
        )
        .expect("write cgroup");

        let detected = detect_systemd_unit_name_from_proc(tmp.path());
        assert_eq!(detected.as_deref(), Some("apm2-worker@lane_00.service"));
    }

    #[test]
    fn detect_systemd_unit_name_returns_none_without_v2_entry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let self_dir = tmp.path().join("self");
        fs::create_dir_all(&self_dir).expect("create self dir");
        fs::write(self_dir.join("cgroup"), "1:name=systemd:/init.scope\n").expect("write cgroup");

        let detected = detect_systemd_unit_name_from_proc(tmp.path());
        assert!(detected.is_none());
    }

    #[test]
    fn extract_systemd_unit_name_ignores_malformed_components() {
        let path = "/system.slice/apm2-worker.service;rm -rf /.service";
        let detected = extract_systemd_unit_from_cgroup_path(path);
        assert!(detected.is_none());
    }

    #[test]
    fn systemd_unit_name_validation_enforces_charset_and_suffix() {
        assert!(is_valid_systemd_unit_name("apm2-worker.service"));
        assert!(is_valid_systemd_unit_name("user@1000.service"));
        assert!(!is_valid_systemd_unit_name("apm2 worker.service"));
        assert!(!is_valid_systemd_unit_name("../../evil.service"));
        assert!(!is_valid_systemd_unit_name("apm2-worker"));
    }

    #[test]
    fn safe_unit_fragment_allows_dots() {
        assert!(is_safe_unit_fragment("job.123"));
        assert!(!is_safe_unit_fragment("job/123"));
    }
}
