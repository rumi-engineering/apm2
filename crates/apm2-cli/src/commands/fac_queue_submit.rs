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
use apm2_core::fac::service_user_gate::{
    QueueWriteMode, ServiceUserGateError, check_queue_write_permission,
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
/// Broker requests subdirectory for non-service-user submissions (TCK-00577).
///
/// Non-service-user processes write job specs here instead of directly to
/// `pending/`. The FAC worker (running as the service user) picks up
/// requests from this directory and moves them into `pending/` after
/// validation. This directory has mode 01733 (sticky + group/other write)
/// so any local user can submit but cannot read or delete other users'
/// submissions.
pub(super) const BROKER_REQUESTS_DIR: &str = "broker_requests";
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

/// Enqueue a validated job spec into `queue/pending` (service user) or
/// `queue/broker_requests` (broker-mediated fallback for non-service-user).
///
/// # Flow
///
/// 1. **Service user gate (TCK-00577)**: Check whether the current process is
///    the FAC service user. If yes (or if `--unsafe-local-write` is active),
///    write directly to `queue/pending/`.
///
/// 2. **Broker-mediated fallback**: If the service user gate denies (because
///    the caller is not the service user), write to `queue/broker_requests/`
///    instead. The FAC worker (running as the service user) picks up requests
///    from this directory and moves them into `pending/` after validation. This
///    fulfills the TCK-00577 `DoD`: "CLI still works via broker-mediated
///    enqueue."
///
/// 3. **Queue bounds (TCK-00578)**: For direct writes to `pending/`, the
///    pending queue must not exceed `max_pending_jobs` or `max_pending_bytes`
///    as configured by the provided [`QueueBoundsPolicy`].
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
/// * `write_mode` - Controls whether the service user ownership gate is
///   enforced or bypassed (TCK-00577).
pub(super) fn enqueue_job(
    queue_root: &Path,
    fac_root: &Path,
    spec: &FacJobSpecV1,
    queue_bounds_policy: &QueueBoundsPolicy,
    write_mode: QueueWriteMode,
) -> Result<PathBuf, String> {
    // TCK-00577: Gate 1 — service user write permission check.
    // If the gate passes, we do a direct write to pending/. If it denies,
    // we fall back to the broker-mediated requests directory.
    let gate_result = check_queue_write_permission(write_mode);

    match gate_result {
        Ok(()) => {
            // Caller is service user or UnsafeLocalWrite is active —
            // proceed with direct write to pending/.
            enqueue_direct(queue_root, fac_root, spec, queue_bounds_policy)
        },
        Err(ServiceUserGateError::ServiceUserNotResolved { .. })
            if write_mode == QueueWriteMode::ServiceUserOnly =>
        {
            // ServiceUserNotResolved means the configured service user does
            // not exist on this system (fresh deployment, dev environment,
            // or CI). Broker-mediated enqueue is the correct fallback:
            // the caller can write to broker_requests/ (mode 01733) and
            // the worker (once provisioned) will promote into pending/.
            // For local-only workflows without a worker, the inline
            // fallback in run_queued_gates_and_collect handles execution.
            //
            // TCK-00577 round 8: changed from hard error to broker
            // fallback. The previous fail-closed behavior blocked
            // `apm2 fac push` on systems where the service user had not
            // been provisioned, breaking the gate execution path.
            tracing::info!(
                job_id = %spec.job_id,
                "TCK-00577: service user not resolvable, submitting via broker-mediated enqueue"
            );
            enqueue_via_broker_requests(queue_root, spec)
        },
        Err(ServiceUserGateError::NotServiceUser { .. })
            if write_mode == QueueWriteMode::ServiceUserOnly =>
        {
            // NotServiceUser means "I know who you are, you're just not
            // the service user" — broker-mediated enqueue is the correct
            // fallback (TCK-00577 DoD: "CLI still works via broker").
            tracing::info!(
                job_id = %spec.job_id,
                "TCK-00577: non-service-user caller, submitting via broker-mediated enqueue"
            );
            enqueue_via_broker_requests(queue_root, spec)
        },
        Err(err) => {
            // Hard gate errors (invalid service user, env errors, etc.)
            // are not recoverable via broker fallback.
            Err(format!("service user gate denied queue write: {err}"))
        },
    }
}

/// Direct enqueue to `queue/pending/` (privileged path).
///
/// Used when the caller is the service user or `--unsafe-local-write` is
/// active.
fn enqueue_direct(
    queue_root: &Path,
    fac_root: &Path,
    spec: &FacJobSpecV1,
    queue_bounds_policy: &QueueBoundsPolicy,
) -> Result<PathBuf, String> {
    let pending_dir = queue_root.join(PENDING_DIR);
    fs::create_dir_all(&pending_dir).map_err(|err| format!("create pending dir: {err}"))?;

    // TCK-00577 round 8: Harden queue root and pending directory permissions
    // immediately after creation. Mode 0711 allows traversal but prevents
    // world-listing of queue artifacts.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(queue_root, fs::Permissions::from_mode(0o711))
            .map_err(|err| format!("harden queue root mode to 0711: {err}"))?;
        fs::set_permissions(&pending_dir, fs::Permissions::from_mode(0o711))
            .map_err(|err| format!("harden pending dir mode to 0711: {err}"))?;
    }

    // Ensure other queue directories exist as well.
    for subdir in &[
        "claimed",
        "completed",
        "denied",
        "cancelled",
        "quarantine",
        BROKER_REQUESTS_DIR,
    ] {
        let _ = fs::create_dir_all(queue_root.join(subdir));
    }

    // Set broker_requests to mode 01733 (sticky + group/other write-only)
    // so non-service-user callers can submit but not read/delete others.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
        let _ = fs::set_permissions(&broker_dir, fs::Permissions::from_mode(0o1733));
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

/// Broker-mediated enqueue: write job spec to `queue/broker_requests/`
/// for pickup by the service-user worker (TCK-00577).
///
/// This path is used when the caller is NOT the service user but needs to
/// submit a job. The worker process (running as service user) monitors this
/// directory and moves valid requests into `pending/` after validation.
///
/// # Security properties
///
/// - The `broker_requests/` directory has mode 01733 (sticky bit prevents other
///   users from deleting/renaming files they don't own; group/other have
///   write+execute but no read). This allows any local user to create files but
///   prevents enumeration or tampering with other users' requests.
/// - The worker validates each request before promoting to `pending/`, so a
///   malicious submission cannot bypass queue bounds or spec validation.
fn enqueue_via_broker_requests(queue_root: &Path, spec: &FacJobSpecV1) -> Result<PathBuf, String> {
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
    fs::create_dir_all(&broker_dir).map_err(|err| {
        format!(
            "cannot create broker requests directory {}: {err}. \
             The service user may need to initialize this directory first \
             (run `apm2 fac gates` as the service user once).",
            broker_dir.display()
        )
    })?;

    // TCK-00577 round 8: Harden queue root to mode 0711 when created via
    // the broker-mediated path. This prevents world-listing of queue
    // artifacts when the queue root is first created by a non-service-user
    // enqueue submission. Fail-closed: if set_permissions fails, the
    // enqueue is rejected.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(queue_root, fs::Permissions::from_mode(0o711))
            .map_err(|err| format!("harden queue root mode to 0711: {err}"))?;
    }

    // Set broker_requests to mode 01733 if we created it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&broker_dir, fs::Permissions::from_mode(0o1733))
            .map_err(|err| format!("harden broker_requests mode to 01733: {err}"))?;
    }

    let json = serde_json::to_string_pretty(spec).map_err(|err| format!("serialize: {err}"))?;
    if json.len() > MAX_JOB_SPEC_SIZE {
        return Err(format!(
            "serialized spec too large: {} > {}",
            json.len(),
            MAX_JOB_SPEC_SIZE
        ));
    }

    let filename = format!("{}.json", spec.job_id);
    let target = broker_dir.join(&filename);

    let temp = tempfile::NamedTempFile::new_in(&broker_dir).map_err(|err| {
        format!(
            "cannot create temp file in broker requests directory {}: {err}. \
                 Ensure the directory exists with correct permissions (mode 01733).",
            broker_dir.display()
        )
    })?;
    {
        let mut file = temp.as_file();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // TCK-00577 round 6: Mode 0644 (world-readable) so the service-user
            // worker can read files owned by non-service-user callers. The
            // broker_requests/ directory already has sticky bit (01733)
            // preventing callers from deleting each other's files.
            let _ = file.set_permissions(fs::Permissions::from_mode(0o644));
        }
        file.write_all(json.as_bytes())
            .map_err(|err| format!("write: {err}"))?;
        file.sync_all().map_err(|err| format!("sync: {err}"))?;
    }
    temp.persist(&target)
        .map_err(|err| format!("persist broker request: {}", err.error))?;

    tracing::info!(
        job_id = %spec.job_id,
        path = %target.display(),
        "TCK-00577: job spec submitted via broker-mediated enqueue \
         (worker will promote to pending/)"
    );

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

    use apm2_core::fac::job_spec::{Actuation, JobConstraints, JobSource, LaneRequirements};

    /// Build a minimal valid `FacJobSpecV1` for testing enqueue paths.
    fn test_job_spec(job_id: &str) -> FacJobSpecV1 {
        FacJobSpecV1 {
            schema: "apm2.fac.job_spec.v1".to_string(),
            job_id: job_id.to_string(),
            job_spec_digest: "c".repeat(64),
            kind: "gates".to_string(),
            queue_lane: "default".to_string(),
            priority: 50,
            enqueue_time: "2026-01-01T00:00:00Z".to_string(),
            actuation: Actuation {
                lease_id: "test-lease".to_string(),
                request_id: "test-request".to_string(),
                channel_context_token: None,
                decoded_source: None,
            },
            source: JobSource {
                kind: "mirror_commit".to_string(),
                repo_id: "test/repo".to_string(),
                head_sha: "a".repeat(40),
                patch: None,
            },
            lane_requirements: LaneRequirements {
                lane_profile_hash: None,
            },
            constraints: JobConstraints {
                require_nextest: false,
                test_timeout_seconds: None,
                memory_max_bytes: None,
            },
            cancel_target_job_id: None,
        }
    }

    // ── Broker-mediated enqueue (TCK-00577) ──────────────────────────

    #[test]
    fn enqueue_via_broker_requests_writes_to_broker_dir() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path();
        let spec = test_job_spec("test-broker-001");

        let result = enqueue_via_broker_requests(queue_root, &spec);
        assert!(result.is_ok(), "broker enqueue should succeed: {result:?}");

        let path = result.unwrap();
        assert!(path.exists(), "broker request file should exist");
        assert!(
            path.starts_with(queue_root.join(BROKER_REQUESTS_DIR)),
            "file should be in broker_requests/: {path:?}"
        );

        // Verify contents are valid JSON with the right job_id.
        let bytes = std::fs::read(&path).expect("read broker request");
        let parsed: FacJobSpecV1 = serde_json::from_slice(&bytes).expect("parse broker request");
        assert_eq!(parsed.job_id, "test-broker-001");
    }

    #[test]
    fn enqueue_via_broker_requests_rejects_oversize_spec() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path();
        let mut spec = test_job_spec("test-broker-oversize");
        // Make the spec exceed MAX_JOB_SPEC_SIZE by stuffing a large field.
        spec.source.repo_id = "x".repeat(MAX_JOB_SPEC_SIZE + 1);

        let result = enqueue_via_broker_requests(queue_root, &spec);
        assert!(
            result.is_err(),
            "oversize spec should be rejected: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("too large"),
            "error should mention size: {err}"
        );
    }

    // ── enqueue_job fallback (TCK-00577) ─────────────────────────────

    #[cfg(unix)]
    #[test]
    fn enqueue_job_falls_back_to_broker_when_service_user_not_resolved() {
        // This test runs as a normal user on a system where the _apm2-job
        // service user does not exist, so `ServiceUserNotResolved` fires.
        // In ServiceUserOnly mode this falls back to broker-mediated
        // enqueue (TCK-00577 round 8): the service user doesn't exist,
        // so the caller writes to broker_requests/ for worker promotion.
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("create fac root");

        let spec = test_job_spec("test-fallback-001");
        let policy = QueueBoundsPolicy::default();

        let result = enqueue_job(
            &queue_root,
            &fac_root,
            &spec,
            &policy,
            QueueWriteMode::ServiceUserOnly,
        );

        // ServiceUserNotResolved in ServiceUserOnly mode now falls back
        // to broker-mediated enqueue (writes to broker_requests/).
        assert!(
            result.is_ok(),
            "ServiceUserNotResolved should fall back to broker enqueue: {result:?}"
        );

        let path = result.unwrap();
        assert!(
            path.starts_with(queue_root.join(BROKER_REQUESTS_DIR)),
            "file should be in broker_requests/: {path:?}"
        );
    }

    #[test]
    fn enqueue_job_uses_direct_path_with_unsafe_local_write() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("create fac root");

        let spec = test_job_spec("test-direct-001");
        let policy = QueueBoundsPolicy::default();

        let result = enqueue_job(
            &queue_root,
            &fac_root,
            &spec,
            &policy,
            QueueWriteMode::UnsafeLocalWrite,
        );

        assert!(
            result.is_ok(),
            "UnsafeLocalWrite enqueue should succeed: {result:?}"
        );

        let path = result.unwrap();
        assert!(
            path.starts_with(queue_root.join(PENDING_DIR)),
            "UnsafeLocalWrite should write to pending/: {path:?}"
        );
    }

    // ── Permission hardening (TCK-00577 round 8) ─────────────────────

    #[cfg(unix)]
    #[test]
    fn enqueue_direct_hardens_queue_root_and_pending_to_0711() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("create fac root");

        let spec = test_job_spec("test-perms-direct-001");
        let policy = QueueBoundsPolicy::default();

        let result = enqueue_direct(&queue_root, &fac_root, &spec, &policy);
        assert!(result.is_ok(), "direct enqueue should succeed: {result:?}");

        // Queue root should be 0711.
        let qr_mode = std::fs::metadata(&queue_root)
            .expect("queue root metadata")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            qr_mode, 0o711,
            "queue root should be mode 0711, got {qr_mode:04o}"
        );

        // Pending dir should be 0711.
        let pd_mode = std::fs::metadata(queue_root.join(PENDING_DIR))
            .expect("pending dir metadata")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            pd_mode, 0o711,
            "pending dir should be mode 0711, got {pd_mode:04o}"
        );

        // Broker requests should be 01733.
        let br_mode = std::fs::metadata(queue_root.join(BROKER_REQUESTS_DIR))
            .expect("broker_requests metadata")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            br_mode, 0o1733,
            "broker_requests should be mode 01733, got {br_mode:04o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn enqueue_via_broker_requests_hardens_queue_root_to_0711() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");

        let spec = test_job_spec("test-perms-broker-001");

        let result = enqueue_via_broker_requests(&queue_root, &spec);
        assert!(result.is_ok(), "broker enqueue should succeed: {result:?}");

        // Queue root should be 0711.
        let qr_mode = std::fs::metadata(&queue_root)
            .expect("queue root metadata")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            qr_mode, 0o711,
            "queue root should be mode 0711, got {qr_mode:04o}"
        );

        // Broker requests should be 01733.
        let br_mode = std::fs::metadata(queue_root.join(BROKER_REQUESTS_DIR))
            .expect("broker_requests metadata")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            br_mode, 0o1733,
            "broker_requests should be mode 01733, got {br_mode:04o}"
        );
    }
}
