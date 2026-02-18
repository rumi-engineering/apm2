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
use apm2_core::fac::queue_bounds::{
    QueueBoundsDenialReceipt, QueueBoundsError, QueueBoundsPolicy, check_queue_bounds,
};
use apm2_core::fac::{
    FacPolicyV1, MAX_POLICY_SIZE, compute_policy_hash, deserialize_policy, parse_policy_hash,
    persist_policy,
};
use apm2_core::github::{parse_github_remote_url, resolve_apm2_home};
use fs2::FileExt;

use crate::commands::{fac_key_material, fac_secure_io};

/// Queue subdirectory under `$APM2_HOME`.
pub(super) const QUEUE_DIR: &str = "queue";
/// Queue pending subdirectory.
pub(super) const PENDING_DIR: &str = "pending";
/// Default authority clock for local-mode evaluation windows.
pub(super) const DEFAULT_AUTHORITY_CLOCK: &str = "local";

/// Lockfile name for the enqueue critical section.
///
/// Acquired via `fs2::FileExt::lock_exclusive()` for the full
/// check-queue-bounds + write-job-spec critical section to prevent
/// concurrent `apm2 fac` processes from bypassing queue caps.
///
/// Synchronization protocol:
/// - Protected data: the set of files in `queue/pending/` and the
///   snapshot-derived bounds decision.
/// - Who can mutate: only the holder of the exclusive flock.
/// - Lock ordering: single lock, no nesting required.
/// - Happens-before: `lock_exclusive()` on `ENQUEUE_LOCKFILE` → scan pending
///   dir + write job spec → drop lockfile (implicit `flock(LOCK_UN)` on
///   `File::drop`).
/// - Async suspension: not applicable (synchronous path).
const ENQUEUE_LOCKFILE: &str = ".enqueue.lock";

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

    // MAJOR fix: load persisted token ledger so CLI producer paths have
    // access to the full nonce history for replay detection.
    match super::fac_worker::load_token_ledger_pub(broker.current_tick()) {
        Ok(Some(ledger)) => {
            broker.set_token_ledger(ledger);
        },
        Ok(None) => {
            // First run — no ledger file yet, default empty ledger is fine.
        },
        Err(e) => {
            // Fail-closed: load errors from an existing ledger file are
            // hard security faults (INV-TL-009).
            return Err(format!("token ledger load failed (fail-closed): {e}"));
        },
    }

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
/// Enforces queue bounds (TCK-00578) before writing: the pending queue
/// must not exceed `max_pending_jobs` or `max_pending_bytes` as
/// configured by the provided [`QueueBoundsPolicy`]. Excess enqueue
/// attempts are denied with structured denial receipts persisted to
/// the `denied/` directory and a structured denial event emitted to
/// the trusted audit log under the FAC private directory.
///
/// A process-level lockfile (`queue/.enqueue.lock`) is held for the
/// full check-write critical section to prevent concurrent `apm2 fac`
/// processes from bypassing queue bounds via TOCTOU.
///
/// # Arguments
///
/// * `queue_root` - Path to the queue root directory.
/// * `fac_root` - Path to the FAC private root (`$APM2_HOME/private/fac`), used
///   for trusted denial event logging.
/// * `spec` - The job spec to enqueue.
/// * `queue_bounds_policy` - The queue bounds policy loaded from FAC
///   configuration. Must be pre-validated via `QueueBoundsPolicy::validate()`.
pub(super) fn enqueue_job(
    queue_root: &Path,
    fac_root: &Path,
    spec: &FacJobSpecV1,
    queue_bounds_policy: &QueueBoundsPolicy,
) -> Result<PathBuf, String> {
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

    // TCK-00578: Validate and enforce queue bounds before writing the job spec.
    // Policy is loaded from the persisted FAC configuration by the caller.
    queue_bounds_policy
        .validate()
        .map_err(|err| format!("queue bounds policy validation failed: {err}"))?;

    // Acquire process-level lockfile for the full check-write critical section.
    // This prevents concurrent `apm2 fac` processes from each passing the
    // bounds check against a stale snapshot and then all writing,
    // oversubscribing the cap. The lock is held until after the job spec
    // file is written (dropped at scope exit).
    let lock_file = acquire_enqueue_lock(queue_root)?;

    let proposed_bytes = json.len() as u64;
    if let Err(err) = check_queue_bounds(&pending_dir, proposed_bytes, queue_bounds_policy) {
        // Persist denial receipt for downstream tooling (TCK-00578).
        if let QueueBoundsError::QueueBoundsExceeded {
            ref receipt,
            ref reason,
        } = err
        {
            persist_denial_receipt(queue_root, &spec.job_id, receipt, reason);
            emit_trusted_denial_event(fac_root, &spec.job_id, receipt, reason);
        }
        // Lock is released on drop (implicit flock(LOCK_UN)).
        drop(lock_file);
        return Err(format!(
            "queue bounds check failed (queue/quota_exceeded): {err}"
        ));
    }

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

    // Lock is released on drop (implicit flock(LOCK_UN)) after the job
    // spec file has been persisted.
    drop(lock_file);

    Ok(target)
}

/// Persist a `QueueBoundsDenialReceipt` to the `denied/` directory.
///
/// Best-effort: if persistence fails, the denial is still enforced
/// (the enqueue is rejected), but the receipt is not written. This
/// avoids masking the primary denial error.
fn persist_denial_receipt(
    queue_root: &Path,
    job_id: &str,
    receipt: &QueueBoundsDenialReceipt,
    reason: &str,
) {
    let denied_dir = queue_root.join("denied");
    if fs::create_dir_all(&denied_dir).is_err() {
        return;
    }

    let denial_artifact = serde_json::json!({
        "schema": "apm2.fac.queue_bounds_denial.v1",
        "job_id": job_id,
        "reason": reason,
        "receipt": receipt,
        "denied_at_unix_secs": current_epoch_secs(),
    });

    let filename = format!("denial-{job_id}.json");
    let target = denied_dir.join(&filename);

    // Best-effort atomic write (temp+rename).
    let Ok(temp) = tempfile::NamedTempFile::new_in(&denied_dir) else {
        return;
    };
    let mut file = temp.as_file();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    if file
        .write_all(
            serde_json::to_string_pretty(&denial_artifact)
                .unwrap_or_default()
                .as_bytes(),
        )
        .is_err()
    {
        return;
    }
    let _ = file.sync_all();
    let _ = temp.persist(&target);
}

/// Acquire the process-level enqueue lockfile under `queue_root`.
///
/// Returns the open `File` handle whose lifetime controls the lock.
/// The lock is released when the file handle is dropped (implicit
/// `flock(LOCK_UN)` on `File::drop`).
///
/// # Errors
///
/// Returns `Err` if the lockfile cannot be created or locked.
fn acquire_enqueue_lock(queue_root: &Path) -> Result<fs::File, String> {
    let lock_path = queue_root.join(ENQUEUE_LOCKFILE);
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "cannot open enqueue lockfile {}: {err}",
                lock_path.display()
            )
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = lock_file.set_permissions(fs::Permissions::from_mode(0o600));
    }

    lock_file
        .lock_exclusive()
        .map_err(|err| format!("cannot acquire enqueue lock {}: {err}", lock_path.display()))?;

    Ok(lock_file)
}

/// Emit a structured denial event to the trusted audit log under the
/// FAC private directory.
///
/// The trusted log is stored outside the writable queue directories so
/// that an attacker with filesystem control over `queue/denied/` cannot
/// suppress denial evidence. The denial is still enforced regardless of
/// whether this log write succeeds.
///
/// This is a best-effort audit event: if the log write fails, it is
/// not fatal. The primary denial is enforced by the return value of
/// `enqueue_job`.
fn emit_trusted_denial_event(
    fac_root: &Path,
    job_id: &str,
    receipt: &QueueBoundsDenialReceipt,
    reason: &str,
) {
    let audit_dir = fac_root.join("audit");
    if fs::create_dir_all(&audit_dir).is_err() {
        eprintln!(
            "warning: cannot create FAC audit directory {}: denial event for job {job_id} not logged",
            audit_dir.display()
        );
        return;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&audit_dir, fs::Permissions::from_mode(0o700));
    }

    let event = serde_json::json!({
        "schema": "apm2.fac.queue_bounds_denial_event.v1",
        "job_id": job_id,
        "reason": reason,
        "receipt": receipt,
        "denied_at_unix_secs": current_epoch_secs(),
        "pid": std::process::id(),
    });

    let Ok(event_line) = serde_json::to_string(&event) else {
        eprintln!("warning: cannot serialize denial event for job {job_id}");
        return;
    };

    let log_path = audit_dir.join("denial_events.jsonl");
    let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    else {
        eprintln!(
            "warning: cannot open denial event log {}",
            log_path.display()
        );
        return;
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }

    // Write the event as a single JSONL line.
    if let Err(err) = writeln!(file, "{event_line}") {
        eprintln!(
            "warning: cannot write denial event to {}: {err}",
            log_path.display()
        );
    }
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
