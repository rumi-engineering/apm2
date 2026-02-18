//! Shared FAC queue submission helpers for CLI producers.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use apm2_core::crypto::Signer;
use apm2_core::economics::queue_admission::HtfEvaluationWindow;
use apm2_core::fac::broker::FacBroker;
use apm2_core::fac::broker_health::WorkerHealthPolicy;
use apm2_core::fac::job_spec::{FacJobSpecV1, MAX_JOB_SPEC_SIZE};
use apm2_core::fac::queue_bounds::{QueueBoundsPolicy, check_queue_bounds, scan_pending_queue};
use apm2_core::fac::{
    FacPolicyV1, MAX_POLICY_SIZE, compute_policy_hash, deserialize_policy, parse_policy_hash,
    persist_policy,
};
use apm2_core::github::{parse_github_remote_url, resolve_apm2_home};

use crate::commands::{fac_key_material, fac_secure_io};

/// Queue subdirectory under `$APM2_HOME`.
pub(super) const QUEUE_DIR: &str = "queue";
/// Queue pending subdirectory.
pub(super) const PENDING_DIR: &str = "pending";
/// Default authority clock for local-mode evaluation windows.
pub(super) const DEFAULT_AUTHORITY_CLOCK: &str = "local";

/// Maximum size for broker state file (1 MiB, matching broker constant).
const MAX_BROKER_STATE_FILE_SIZE: usize = 1_048_576;
/// Fallback SHA when git metadata is unavailable.
const UNKNOWN_HEAD_SHA: &str = "0000000000000000000000000000000000000000";
/// Fallback repository segment when path metadata is unavailable.
const UNKNOWN_REPO_SEGMENT: &str = "unknown";
/// Per-process monotonic suffix to prevent same-timestamp collisions.
static JOB_SUFFIX_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub(super) struct RepoSourceInfo {
    pub repo_id: String,
    pub head_sha: String,
    pub workspace_root: PathBuf,
}

/// Resolve the FAC root directory at `$APM2_HOME/private/fac`.
pub(super) fn resolve_fac_root() -> Result<PathBuf, String> {
    let home =
        resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home directory".to_string())?;
    Ok(home.join("private").join("fac"))
}

/// Resolve the FAC queue root directory at `$APM2_HOME/queue`.
pub(super) fn resolve_queue_root() -> Result<PathBuf, String> {
    let home =
        resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home directory".to_string())?;
    Ok(home.join(QUEUE_DIR))
}

/// Resolve the current repository source identity and checked-out HEAD.
///
/// The returned `repo_id` always satisfies FAC job spec constraints.
pub(super) fn resolve_repo_source_info() -> RepoSourceInfo {
    let workspace_root = resolve_workspace_root();
    let head_sha =
        resolve_head_sha(&workspace_root).unwrap_or_else(|| UNKNOWN_HEAD_SHA.to_string());
    let repo_id = resolve_repo_id(&workspace_root);
    RepoSourceInfo {
        repo_id,
        head_sha,
        workspace_root,
    }
}

/// Initialize broker state and open the RFC-0029 admission health gate.
pub(super) fn init_broker(fac_root: &Path, boundary_id: &str) -> Result<FacBroker, String> {
    // Load or generate a persistent signing key (same path as worker).
    let signer = fac_key_material::load_or_generate_persistent_signer(fac_root)?;
    let signer_key_bytes = signer.secret_key_bytes().to_vec();

    // Load or create broker state (matching worker pattern).
    let mk_default_state_broker = || {
        let default_state = apm2_core::fac::broker::BrokerState::default();
        let signer = Signer::from_bytes(&signer_key_bytes).ok()?;
        FacBroker::from_signer_and_state(signer, default_state).ok()
    };

    let mut broker = load_broker_state(fac_root).map_or_else(
        || mk_default_state_broker().unwrap_or_else(FacBroker::new),
        |state| {
            Signer::from_bytes(&signer_key_bytes)
                .ok()
                .and_then(|signer| FacBroker::from_signer_and_state(signer, state).ok())
                .unwrap_or_else(|| mk_default_state_broker().unwrap_or_else(FacBroker::new))
        },
    );

    let mut checker = apm2_core::fac::broker_health::BrokerHealthChecker::new();

    let current_tick = broker.current_tick();
    let tick_end = current_tick.saturating_add(1);
    let eval_window = broker
        .build_evaluation_window(boundary_id, DEFAULT_AUTHORITY_CLOCK, current_tick, tick_end)
        .unwrap_or_else(|_| make_default_eval_window(boundary_id));

    broker.advance_freshness_horizon(tick_end);

    let startup_envelope = broker
        .issue_time_authority_envelope_default_ttl(
            boundary_id,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .ok();

    let _health = broker.check_health(startup_envelope.as_ref(), &eval_window, &[], &mut checker);

    broker
        .evaluate_admission_health_gate(&checker, &eval_window, WorkerHealthPolicy::default())
        .map_err(|err| format!("admission health gate failed: {err}"))?;

    Ok(broker)
}

/// Load or initialize policy and return (`hash_string`, `digest_bytes`,
/// policy).
pub(super) fn load_or_init_policy(
    fac_root: &Path,
) -> Result<(String, [u8; 32], FacPolicyV1), String> {
    let policy_dir = fac_root.join("policy");
    let policy_path = policy_dir.join("fac_policy.v1.json");

    let policy = if policy_path.exists() {
        let bytes = fac_secure_io::read_bounded(&policy_path, MAX_POLICY_SIZE)?;
        deserialize_policy(&bytes).map_err(|err| format!("cannot load fac policy: {err}"))?
    } else {
        let default_policy = FacPolicyV1::default();
        persist_policy(fac_root, &default_policy)
            .map_err(|err| format!("cannot persist default policy: {err}"))?;
        default_policy
    };

    let policy_hash =
        compute_policy_hash(&policy).map_err(|err| format!("cannot compute policy hash: {err}"))?;
    let policy_digest =
        parse_policy_hash(&policy_hash).ok_or_else(|| "invalid policy hash".to_string())?;

    Ok((policy_hash, policy_digest, policy))
}

/// Enqueue a validated job spec into `queue/pending`.
///
/// Enforces queue bounds (TCK-00578) before writing the job spec to disk.
/// If the queue would exceed configured bounds, the enqueue is denied with
/// a structured denial receipt and the job is NOT written.
pub(super) fn enqueue_job(queue_root: &Path, spec: &FacJobSpecV1) -> Result<PathBuf, String> {
    let pending_dir = queue_root.join(PENDING_DIR);
    fs::create_dir_all(&pending_dir).map_err(|err| format!("create pending dir: {err}"))?;

    // Ensure other queue directories exist as well.
    for subdir in &["claimed", "completed", "denied", "cancelled", "quarantine"] {
        let _ = fs::create_dir_all(queue_root.join(subdir));
    }

    let json = serde_json::to_string_pretty(spec).map_err(|err| format!("serialize: {err}"))?;
    if json.len() > MAX_JOB_SPEC_SIZE {
        return Err(format!(
            "serialized spec too large: {} > {}",
            json.len(),
            MAX_JOB_SPEC_SIZE
        ));
    }

    // TCK-00578: Queue bounds check BEFORE writing to disk (INV-QB-002).
    let bounds_policy = QueueBoundsPolicy::default();
    let track_lanes = bounds_policy.per_lane_max_pending_jobs.is_some();
    let snapshot = scan_pending_queue(queue_root, track_lanes)
        .map_err(|err| format!("queue bounds scan failed (enqueue denied fail-closed): {err}"))?;
    let proposed_bytes = json.len() as u64;
    let proposed_lane = Some(spec.queue_lane.as_str());
    check_queue_bounds(&snapshot, &bounds_policy, proposed_bytes, proposed_lane)
        .map_err(|err| format!("queue quota exceeded (enqueue denied): {err}"))?;

    let filename = format!("{}.json", spec.job_id);
    let target = pending_dir.join(filename);

    let temp =
        tempfile::NamedTempFile::new_in(&pending_dir).map_err(|err| format!("temp file: {err}"))?;
    {
        let mut file = temp.as_file();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        file.write_all(json.as_bytes())
            .map_err(|err| format!("write: {err}"))?;
        file.sync_all().map_err(|err| format!("sync: {err}"))?;
    }
    temp.persist(&target)
        .map_err(|err| format!("persist: {}", err.error))?;

    Ok(target)
}

/// Build a deterministic suffix for job and lease identifiers.
pub(super) fn generate_job_suffix() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ts = now.as_secs();
    let subsec_nanos = now.subsec_nanos();
    let pid = std::process::id();
    let counter = JOB_SUFFIX_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{ts}-{subsec_nanos:09}-{pid}-{counter}")
}

/// Current Unix epoch seconds.
pub(super) fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn resolve_workspace_root() -> PathBuf {
    std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout)
                    .ok()
                    .map(|s| PathBuf::from(s.trim()))
            } else {
                None
            }
        })
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn resolve_head_sha(workspace_root: &Path) -> Option<String> {
    std::process::Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}

fn resolve_repo_id(workspace_root: &Path) -> String {
    if let Some(remote_url) = resolve_origin_remote_url(workspace_root) {
        if let Some((owner, repo)) = parse_github_remote_url(&remote_url) {
            return format!("{owner}/{repo}");
        }
    }

    let segment = workspace_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_repo_segment)
        .filter(|segment| !segment.is_empty())
        .unwrap_or_else(|| UNKNOWN_REPO_SEGMENT.to_string());
    format!("local/{segment}")
}

fn resolve_origin_remote_url(workspace_root: &Path) -> Option<String> {
    std::process::Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            } else {
                None
            }
        })
}

fn sanitize_repo_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }

    while out.starts_with('-') || out.starts_with('.') || out.starts_with('_') {
        out.remove(0);
    }
    while out.ends_with('-') || out.ends_with('.') || out.ends_with('_') {
        out.pop();
    }

    if out.is_empty() {
        UNKNOWN_REPO_SEGMENT.to_string()
    } else {
        out
    }
}

fn load_broker_state(fac_root: &Path) -> Option<apm2_core::fac::broker::BrokerState> {
    let state_path = fac_root.join("broker_state.json");
    if !state_path.exists() {
        return None;
    }
    let bytes = fac_secure_io::read_bounded(&state_path, MAX_BROKER_STATE_FILE_SIZE).ok()?;
    FacBroker::deserialize_state(&bytes).ok()
}

fn make_default_eval_window(boundary_id: &str) -> HtfEvaluationWindow {
    HtfEvaluationWindow {
        boundary_id: boundary_id.to_string(),
        authority_clock: DEFAULT_AUTHORITY_CLOCK.to_string(),
        tick_start: 0,
        tick_end: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_job_suffix_is_collision_resistant_per_process() {
        let a = generate_job_suffix();
        let b = generate_job_suffix();
        assert_ne!(a, b, "suffixes must differ across sequential calls");
        assert!(
            a.split('-').count() >= 4,
            "suffix should include timestamp, nanos, pid, and counter"
        );
    }
}
