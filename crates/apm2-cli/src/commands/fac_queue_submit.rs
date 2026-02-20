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
    resolve_service_user_identity,
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
        Err(ServiceUserGateError::ServiceUserNotResolved {
            ref service_user,
            ref reason,
        }) if write_mode == QueueWriteMode::ServiceUserOnly => {
            // TCK-00577 round 10 MAJOR fix (security review): ServiceUserNotResolved
            // in ServiceUserOnly mode is a HARD error, not a broker fallback.
            // The service user identity cannot be confirmed, so we must fail-closed.
            //
            // Rationale: ServiceUserNotResolved means "I cannot determine who
            // the service user is" — this is an unresolvable trust question.
            // Allowing broker fallback here would let any local user bypass
            // the service user gate simply by misconfiguring or removing the
            // service user account.
            //
            // For dev environments without a service user, callers MUST use
            // `--unsafe-local-write` explicitly (which returns Ok(()) from
            // check_queue_write_permission before resolution is attempted).
            Err(format!(
                "service user gate denied queue write (fail-closed): \
                 service user '{service_user}' not resolvable ({reason}). \
                 In ServiceUserOnly mode, an unresolvable service user is a hard denial. \
                 Use --unsafe-local-write to bypass in development environments."
            ))
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

    // Track whether we created directories so we only chmod when we own them.
    // A non-service-user caller cannot chmod directories owned by the service
    // user (EPERM), so for pre-existing directories we validate mode instead.
    let queue_root_existed = queue_root.is_dir();
    let broker_dir_existed = broker_dir.is_dir();

    fs::create_dir_all(&broker_dir).map_err(|err| {
        format!(
            "cannot create broker requests directory {}: {err}. \
             The service user may need to initialize this directory first \
             (run `apm2 fac gates` as the service user once).",
            broker_dir.display()
        )
    })?;

    // TCK-00577 round 9 MAJOR fix: Only chmod directories that this process
    // just created. For pre-existing directories (owned by the service user),
    // validate the existing mode is acceptable instead of attempting chmod
    // (which returns EPERM for non-owner callers). This makes the broker
    // fallback work for non-service-user processes.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if queue_root_existed {
            // Pre-existing: validate mode is safe. Accept 0700 (strict) or
            // 0711 (traverse-only). Reject modes with read/write for
            // group/other.
            let meta = fs::metadata(queue_root)
                .map_err(|err| format!("stat queue root {}: {err}", queue_root.display()))?;
            let mode = meta.permissions().mode() & 0o7777;
            // Reject group/other read or write bits (0o066) but allow
            // execute-only (0o011) for traversal.
            if mode & 0o066 != 0 {
                return Err(format!(
                    "queue root {} has unsafe mode {:04o} (expected 0700 or 0711): \
                     the service user should fix permissions",
                    queue_root.display(),
                    mode
                ));
            }
        } else {
            // We created it — set mode 0711 (traversal-only for group/other).
            fs::set_permissions(queue_root, fs::Permissions::from_mode(0o711))
                .map_err(|err| format!("harden queue root mode to 0711: {err}"))?;
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if broker_dir_existed {
            // Pre-existing: validate the directory has acceptable mode.
            // Accept 01733 (sticky + wx for group/other) or 0700 (strict
            // before worker hardens it).
            let meta = fs::metadata(&broker_dir)
                .map_err(|err| format!("stat broker_requests {}: {err}", broker_dir.display()))?;
            let mode = meta.permissions().mode() & 0o7777;
            // The expected modes are 01733 (service user provisioned) or
            // 0700 (strict default). We need write access to create files,
            // but reading/listing is not required. The actual writability
            // is tested by the tempfile creation below (fail-closed).
            //
            // Three checks (fail-closed):
            // 1. Reject group/other read bits (exposes other users' submissions).
            // 2. If group-write OR other-write bit is set, require sticky bit. Without
            //    sticky, any non-owner principal with group or other write access can
            //    unlink/overwrite peer files inside the directory, breaking queue isolation
            //    (CVE-class: CWE-379).
            let has_other_read = mode & 0o044 != 0;
            if has_other_read {
                return Err(format!(
                    "broker_requests {} has unsafe mode {:04o} (group/other read \
                     exposes submissions): the service user should fix permissions",
                    broker_dir.display(),
                    mode
                ));
            }
            // 0o022 = group-write (0o020) | other-write (0o002).
            let writable_by_non_owner = (mode & 0o022) != 0;
            let has_sticky = mode & 0o1000 != 0;
            if writable_by_non_owner && !has_sticky {
                return Err(format!(
                    "broker_requests {} has unsafe mode {:04o} (group/other write \
                     without sticky bit allows non-owner principals to \
                     unlink/replace peer queue entries): the service user \
                     should set mode 01733",
                    broker_dir.display(),
                    mode
                ));
            }
        } else {
            // We created it — set mode 01733 (sticky + write-only for
            // group/other).
            fs::set_permissions(&broker_dir, fs::Permissions::from_mode(0o1733))
                .map_err(|err| format!("harden broker_requests mode to 01733: {err}"))?;
        }
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

    // BLOCKER fix (TCK-00577 round 16): Resolve service user GID so we can
    // set the file's group to the service user, enabling the worker to read
    // broker files in cross-user deployments. If the service user is
    // resolvable, use mode 0640 + fchown(gid). If not resolvable (dev
    // environment without a service user), fall back to mode 0644 with a
    // warning (same-user deployment; world-read is acceptable since the
    // broker_requests/ directory has mode 01733 and cannot be listed by
    // other users, making UUID filenames effectively opaque).
    #[cfg(unix)]
    let service_user_gid: Option<u32> = match resolve_service_user_identity() {
        Ok(identity) => Some(identity.gid),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "TCK-00577: service user not resolvable for group-based broker \
                 file handoff; falling back to mode 0644 (dev/same-user deployment)"
            );
            None
        },
    };

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
            if let Some(gid) = service_user_gid {
                // Cross-user deployment: set group to service user's primary
                // GID and mode 0640 (owner read+write, group read). The
                // service-user worker is in this group and can read the file.
                //
                // fchown(fd, -1, gid): change group only, preserve owner.
                // This works because we own the file (just created it) and
                // either (a) the target gid is our primary/supplementary
                // group, or (b) we have CAP_CHOWN. If fchown fails (e.g.
                // the calling user is not in the service user's group and
                // lacks CAP_CHOWN), fall back to 0644 with a warning.
                use std::os::fd::AsFd;
                match nix::unistd::fchown(file.as_fd(), None, Some(nix::unistd::Gid::from_raw(gid)))
                {
                    Ok(()) => {
                        let _ = file.set_permissions(fs::Permissions::from_mode(0o640));
                        tracing::debug!(
                            gid = gid,
                            mode = "0640",
                            "TCK-00577: broker request file group set to service user GID"
                        );
                    },
                    Err(e) => {
                        // fchown failed (not in group, no CAP_CHOWN). Fall
                        // back to 0644 — the broker_requests/ directory's
                        // mode 01733 prevents enumeration, and UUID filenames
                        // are effectively opaque.
                        tracing::warn!(
                            gid = gid,
                            error = %e,
                            "TCK-00577: fchown to service user GID failed; \
                             falling back to mode 0644 (defense-in-depth: \
                             broker_requests/ mode 01733 prevents enumeration)"
                        );
                        let _ = file.set_permissions(fs::Permissions::from_mode(0o644));
                    },
                }
            } else {
                // Dev/same-user deployment: service user not resolvable.
                // Use mode 0644 — world-readable, but broker_requests/ has
                // mode 01733 (no list permission) so other users cannot
                // discover filenames.
                let _ = file.set_permissions(fs::Permissions::from_mode(0o644));
            }
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
        // Use a subdirectory so queue_root doesn't pre-exist (avoids mode
        // validation against the tempdir's default 0775).
        let queue_root = dir.path().join("queue");
        let spec = test_job_spec("test-broker-001");

        let result = enqueue_via_broker_requests(&queue_root, &spec);
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

    /// TCK-00577 round 16 regression test: Broker request files are created
    /// with mode 0640 (when service user is resolvable and fchown succeeds)
    /// or mode 0644 (fallback when service user not resolvable or fchown
    /// fails). In test environments, the default service user `_apm2-job`
    /// typically does not exist, so the fallback path (0644) is expected.
    ///
    /// The key security invariant: the file MUST NOT have mode 0600 (which
    /// would make it unreadable by the service-user worker in cross-user
    /// deployments — the BLOCKER finding that motivated this fix).
    #[cfg(unix)]
    #[test]
    fn enqueue_via_broker_requests_creates_file_with_cross_user_readable_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let spec = test_job_spec("test-broker-mode-001");

        let result = enqueue_via_broker_requests(&queue_root, &spec);
        assert!(result.is_ok(), "broker enqueue should succeed: {result:?}");

        let path = result.unwrap();
        let mode = std::fs::metadata(&path)
            .expect("broker request file metadata")
            .permissions()
            .mode()
            & 0o7777;

        // Acceptable modes:
        // - 0640: service user resolvable, fchown succeeded (cross-user)
        // - 0644: fallback (dev/same-user deployment, or fchown failed)
        // NOT acceptable: 0600 (would break cross-user readability)
        assert!(
            mode == 0o640 || mode == 0o644,
            "broker request file must have mode 0640 (group-read for service \
             user) or 0644 (dev fallback), got {mode:04o}. Mode 0600 is a \
             BLOCKER — it breaks cross-user broker-mediated enqueue."
        );

        // In test environments, the default service user `_apm2-job` usually
        // does not exist, so we expect mode 0644 (the fallback).
        if mode == 0o644 {
            // Expected in dev/test environments.
        } else {
            // mode == 0640 means the test environment has a service user.
            // Both are acceptable.
        }
    }

    #[test]
    fn enqueue_via_broker_requests_rejects_oversize_spec() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        // Use a subdirectory so queue_root doesn't pre-exist.
        let queue_root = dir.path().join("queue");
        let mut spec = test_job_spec("test-broker-oversize");
        // Make the spec exceed MAX_JOB_SPEC_SIZE by stuffing a large field.
        spec.source.repo_id = "x".repeat(MAX_JOB_SPEC_SIZE + 1);

        let result = enqueue_via_broker_requests(&queue_root, &spec);
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
    fn enqueue_job_hard_denies_when_service_user_not_resolved_in_service_user_only_mode() {
        // TCK-00577 round 10 MAJOR fix: ServiceUserNotResolved in
        // ServiceUserOnly mode is a HARD error (fail-closed). The service
        // user identity cannot be confirmed, so we must not allow any
        // write path (not even broker fallback). Callers in dev
        // environments MUST use --unsafe-local-write explicitly.
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let fac_root = dir.path().join("fac");
        std::fs::create_dir_all(&fac_root).expect("create fac root");

        let spec = test_job_spec("test-hard-deny-001");
        let policy = QueueBoundsPolicy::default();

        let result = enqueue_job(
            &queue_root,
            &fac_root,
            &spec,
            &policy,
            QueueWriteMode::ServiceUserOnly,
        );

        // ServiceUserNotResolved + ServiceUserOnly = hard error.
        assert!(
            result.is_err(),
            "ServiceUserNotResolved in ServiceUserOnly mode must be a hard error: {result:?}"
        );

        let err = result.unwrap_err();
        assert!(
            err.contains("fail-closed") && err.contains("not resolvable"),
            "error should mention fail-closed and not resolvable: {err}"
        );

        // Verify no file was written to broker_requests/ either.
        let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
        assert!(
            !broker_dir.exists()
                || std::fs::read_dir(&broker_dir)
                    .map(|mut d| d.next().is_none())
                    .unwrap_or(true),
            "no files should be written to broker_requests/ on hard denial"
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

    // ── Broker fallback with pre-existing directories (TCK-00577 round 9) ──

    /// TCK-00577 round 9 MAJOR fix: Broker-mediated enqueue must succeed when
    /// queue directories already exist with correct modes. Previously, the
    /// function unconditionally called chmod, which returns EPERM for non-owner
    /// callers. Now it only chmods newly-created dirs and validates existing
    /// ones.
    #[cfg(unix)]
    #[test]
    fn enqueue_via_broker_requests_succeeds_with_preexisting_correct_mode_dirs() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

        // Simulate service-user-provisioned directories with correct modes.
        std::fs::create_dir_all(&broker_dir).expect("create broker dir");
        std::fs::set_permissions(&queue_root, std::fs::Permissions::from_mode(0o711))
            .expect("set queue root mode");
        std::fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o1733))
            .expect("set broker dir mode");

        let spec = test_job_spec("test-preexist-001");
        let result = enqueue_via_broker_requests(&queue_root, &spec);
        assert!(
            result.is_ok(),
            "broker enqueue with pre-existing correct-mode dirs should succeed: {result:?}"
        );

        let path = result.unwrap();
        assert!(path.exists(), "broker request file should exist");
    }

    /// TCK-00577 round 9 MAJOR fix: Broker-mediated enqueue must reject
    /// pre-existing directories with unsafe modes (group/other read).
    #[cfg(unix)]
    #[test]
    fn enqueue_via_broker_requests_rejects_preexisting_unsafe_queue_root() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

        // Create directories with unsafe mode (world-readable queue root).
        std::fs::create_dir_all(&broker_dir).expect("create broker dir");
        std::fs::set_permissions(&queue_root, std::fs::Permissions::from_mode(0o755))
            .expect("set unsafe queue root mode");
        std::fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o1733))
            .expect("set broker dir mode");

        let spec = test_job_spec("test-unsafe-qroot-001");
        let result = enqueue_via_broker_requests(&queue_root, &spec);
        assert!(
            result.is_err(),
            "broker enqueue should reject unsafe queue root mode: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("unsafe mode"),
            "error should mention unsafe mode: {err}"
        );
    }

    /// TCK-00577 round 9 MAJOR fix: Broker-mediated enqueue must reject
    /// pre-existing `broker_requests/` with group/other read bits.
    #[cfg(unix)]
    #[test]
    fn enqueue_via_broker_requests_rejects_preexisting_readable_broker_dir() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

        // Create directories — queue root is safe but broker_requests has
        // read bits (mode 0755 instead of 01733).
        std::fs::create_dir_all(&broker_dir).expect("create broker dir");
        std::fs::set_permissions(&queue_root, std::fs::Permissions::from_mode(0o711))
            .expect("set queue root mode");
        std::fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o755))
            .expect("set unsafe broker dir mode");

        let spec = test_job_spec("test-unsafe-broker-001");
        let result = enqueue_via_broker_requests(&queue_root, &spec);
        assert!(
            result.is_err(),
            "broker enqueue should reject broker_requests with read bits: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("unsafe mode"),
            "error should mention unsafe mode: {err}"
        );
    }

    /// MAJOR fix: `broker_requests` with other-write but NO sticky bit (mode
    /// 0333) allows local users to unlink/replace peer queue entries. Must
    /// reject.
    #[cfg(unix)]
    #[test]
    fn enqueue_via_broker_requests_rejects_world_writable_no_sticky() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

        std::fs::create_dir_all(&broker_dir).expect("create broker dir");
        std::fs::set_permissions(&queue_root, std::fs::Permissions::from_mode(0o711))
            .expect("set queue root mode");
        // Mode 0333: world-writable WITHOUT sticky bit — unsafe.
        std::fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o333))
            .expect("set broker dir mode 0333");

        let spec = test_job_spec("test-no-sticky-001");
        let result = enqueue_via_broker_requests(&queue_root, &spec);
        assert!(
            result.is_err(),
            "broker enqueue should reject world-writable dir without sticky: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("sticky bit"),
            "error should mention sticky bit: {err}"
        );
    }

    /// MAJOR fix: `broker_requests` with other-write AND sticky bit (mode
    /// 01333) is acceptable — sticky prevents cross-user unlink.
    #[cfg(unix)]
    #[test]
    fn enqueue_via_broker_requests_accepts_sticky_world_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

        std::fs::create_dir_all(&broker_dir).expect("create broker dir");
        std::fs::set_permissions(&queue_root, std::fs::Permissions::from_mode(0o711))
            .expect("set queue root mode");
        // Mode 01333: world-writable WITH sticky bit — safe.
        std::fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o1333))
            .expect("set broker dir mode 01333");

        let spec = test_job_spec("test-sticky-001");
        let result = enqueue_via_broker_requests(&queue_root, &spec);
        assert!(
            result.is_ok(),
            "broker enqueue should accept sticky world-writable dir: {result:?}"
        );
    }

    /// Regression: mode 0700 (owner-only) without sticky is acceptable because
    /// other-write is not set.
    #[cfg(unix)]
    #[test]
    fn enqueue_via_broker_requests_accepts_owner_only_no_sticky() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

        std::fs::create_dir_all(&broker_dir).expect("create broker dir");
        std::fs::set_permissions(&queue_root, std::fs::Permissions::from_mode(0o700))
            .expect("set queue root mode");
        // Mode 0700: owner-only, no sticky needed.
        std::fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o700))
            .expect("set broker dir mode 0700");

        let spec = test_job_spec("test-owner-only-001");
        let result = enqueue_via_broker_requests(&queue_root, &spec);
        assert!(
            result.is_ok(),
            "broker enqueue should accept owner-only dir without sticky: {result:?}"
        );
    }

    /// MAJOR fix: `broker_requests` with group-write but NO sticky bit (mode
    /// 0730) allows group members to unlink/replace peer queue entries. Must
    /// reject.
    #[cfg(unix)]
    #[test]
    fn enqueue_via_broker_requests_rejects_group_writable_no_sticky() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

        std::fs::create_dir_all(&broker_dir).expect("create broker dir");
        std::fs::set_permissions(&queue_root, std::fs::Permissions::from_mode(0o711))
            .expect("set queue root mode");
        // Mode 0730: group-writable WITHOUT sticky bit — unsafe.
        std::fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o730))
            .expect("set broker dir mode 0730");

        let spec = test_job_spec("test-grp-no-sticky-001");
        let result = enqueue_via_broker_requests(&queue_root, &spec);
        assert!(
            result.is_err(),
            "broker enqueue should reject group-writable dir without sticky: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("sticky bit"),
            "error should mention sticky bit: {err}"
        );
    }

    /// MAJOR fix: `broker_requests` with group-write AND sticky bit (mode
    /// 01730) is acceptable — sticky prevents cross-user unlink.
    #[cfg(unix)]
    #[test]
    fn enqueue_via_broker_requests_accepts_group_writable_with_sticky() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().expect("create temp dir");
        let queue_root = dir.path().join("queue");
        let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

        std::fs::create_dir_all(&broker_dir).expect("create broker dir");
        std::fs::set_permissions(&queue_root, std::fs::Permissions::from_mode(0o711))
            .expect("set queue root mode");
        // Mode 01730: group-writable WITH sticky bit — safe.
        std::fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o1730))
            .expect("set broker dir mode 01730");

        let spec = test_job_spec("test-grp-sticky-001");
        let result = enqueue_via_broker_requests(&queue_root, &spec);
        assert!(
            result.is_ok(),
            "broker enqueue should accept group-writable dir with sticky: {result:?}"
        );
    }
}
