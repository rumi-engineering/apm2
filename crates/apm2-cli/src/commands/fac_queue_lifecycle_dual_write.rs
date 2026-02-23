//! Temporary dual-write helper for FAC queue lifecycle migration.
//!
//! When enabled by `FacPolicyV1.queue_lifecycle_dual_write_enabled`, queue
//! mutation paths emit `fac.job.*` lifecycle events into the daemon
//! authoritative `SQLite` ledger stream in addition to filesystem mutations.
#![allow(dead_code)] // Staged migration helper: additional emit_* paths wire in follow-up tickets.

#[cfg(not(test))]
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::process::Command;
use std::sync::{Arc, LazyLock, Mutex};

#[cfg(not(test))]
use apm2_core::config::EcosystemConfig;
use apm2_core::fac::job_lifecycle::{
    FAC_JOB_CLAIMED_EVENT_TYPE, FAC_JOB_COMPLETED_EVENT_TYPE, FAC_JOB_ENQUEUED_EVENT_TYPE,
    FAC_JOB_FAILED_EVENT_TYPE, FAC_JOB_RELEASED_EVENT_TYPE, FAC_JOB_STARTED_EVENT_TYPE,
    FacJobClaimedV1, FacJobCompletedV1, FacJobEnqueuedV1, FacJobFailedV1, FacJobIdentityPreimageV1,
    FacJobIdentityV1, FacJobLifecycleEventData, FacJobLifecycleEventV1, FacJobReleasedV1,
    FacJobStartedV1, MAX_JOB_LIFECYCLE_STRING_LENGTH, derive_content_addressable_job_id,
};
use apm2_core::fac::{FacJobSpecV1, MAX_POLICY_SIZE, deserialize_policy};
use apm2_daemon::htf::{ClockConfig, HolonicClock};
use apm2_daemon::ledger::SqliteLedgerEventEmitter;
use apm2_daemon::protocol::dispatch::LedgerEventEmitter;
use rusqlite::Connection;

use super::{fac_key_material, fac_secure_io};

#[cfg(not(test))]
const DEFAULT_CONFIG_FILE: &str = "ecosystem.toml";
#[cfg(test)]
const TEST_QUEUE_LIFECYCLE_LEDGER_DB: &str = "queue_lifecycle_ledger.db";

pub(super) fn queue_lifecycle_dual_write_enabled(fac_root: &Path) -> Result<bool, String> {
    let policy_path = fac_root.join("policy").join("fac_policy.v1.json");
    if !policy_path.exists() {
        return Ok(false);
    }

    let bytes = fac_secure_io::read_bounded(&policy_path, MAX_POLICY_SIZE)?;
    let policy = deserialize_policy(&bytes)
        .map_err(|err| format!("cannot load fac policy for lifecycle dual-write flag: {err}"))?;
    Ok(policy.queue_lifecycle_dual_write_enabled)
}

/// Emits `fac.job.enqueued` for the given spec.
pub(super) fn emit_job_enqueued(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    actor_id: &str,
) -> Result<(), String> {
    let identity = identity_from_spec(spec)?;
    let event = FacJobLifecycleEventV1::new(
        stable_intent_id("enqueue", &spec.job_spec_digest, &spec.kind),
        None,
        FacJobLifecycleEventData::Enqueued(FacJobEnqueuedV1 {
            identity,
            enqueue_epoch_ns: now_timestamp_ns()?,
        }),
    );
    emit_event(fac_root, FAC_JOB_ENQUEUED_EVENT_TYPE, &event, actor_id)
}

/// Emits `fac.job.claimed` for the given spec.
pub(super) fn emit_job_claimed(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    lease_id: &str,
    actor_id: &str,
) -> Result<(), String> {
    let identity = identity_from_spec(spec)?;
    let event = FacJobLifecycleEventV1::new(
        stable_intent_id("claim", &spec.job_spec_digest, lease_id),
        None,
        FacJobLifecycleEventData::Claimed(FacJobClaimedV1 {
            identity,
            lease_id: lease_id.to_string(),
            actor_id: actor_id.to_string(),
            claim_epoch_ns: now_timestamp_ns()?,
        }),
    );
    emit_event(fac_root, FAC_JOB_CLAIMED_EVENT_TYPE, &event, actor_id)
}

/// Emits `fac.job.started` for the given spec.
pub(super) fn emit_job_started(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    worker_instance_id: &str,
    actor_id: &str,
) -> Result<(), String> {
    let identity = identity_from_spec(spec)?;
    let event = FacJobLifecycleEventV1::new(
        stable_intent_id("start", &spec.job_spec_digest, worker_instance_id),
        None,
        FacJobLifecycleEventData::Started(FacJobStartedV1 {
            identity,
            worker_instance_id: worker_instance_id.to_string(),
            start_receipt_id: None,
        }),
    );
    emit_event(fac_root, FAC_JOB_STARTED_EVENT_TYPE, &event, actor_id)
}

/// Emits `fac.job.completed` for the given spec.
pub(super) fn emit_job_completed(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    outcome: &str,
    receipt_id: Option<String>,
    actor_id: &str,
) -> Result<(), String> {
    let identity = identity_from_spec(spec)?;
    let event = FacJobLifecycleEventV1::new(
        stable_intent_id("complete", &spec.job_spec_digest, outcome),
        receipt_id,
        FacJobLifecycleEventData::Completed(FacJobCompletedV1 {
            identity,
            outcome: outcome.to_string(),
            receipt_digests: Vec::new(),
            artifact_digests: Vec::new(),
        }),
    );
    emit_event(fac_root, FAC_JOB_COMPLETED_EVENT_TYPE, &event, actor_id)
}

/// Emits `fac.job.released` for the given spec.
pub(super) fn emit_job_released(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    reason: &str,
    previous_lease_id: Option<String>,
    actor_id: &str,
) -> Result<(), String> {
    let identity = identity_from_spec(spec)?;
    let event = FacJobLifecycleEventV1::new(
        stable_intent_id("release", &spec.job_spec_digest, reason),
        None,
        FacJobLifecycleEventData::Released(FacJobReleasedV1 {
            identity,
            reason: reason.to_string(),
            previous_lease_id,
        }),
    );
    emit_event(fac_root, FAC_JOB_RELEASED_EVENT_TYPE, &event, actor_id)
}

/// Emits `fac.job.failed` for the given spec.
pub(super) fn emit_job_failed(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    reason_class: &str,
    retryable: bool,
    receipt_id: Option<String>,
    actor_id: &str,
) -> Result<(), String> {
    let identity = identity_from_spec(spec)?;
    let event = FacJobLifecycleEventV1::new(
        stable_intent_id("failed", &spec.job_spec_digest, reason_class),
        receipt_id,
        FacJobLifecycleEventData::Failed(FacJobFailedV1 {
            identity,
            reason_class: reason_class.to_string(),
            retryable,
        }),
    );
    emit_event(fac_root, FAC_JOB_FAILED_EVENT_TYPE, &event, actor_id)
}

/// Emits `fac.job.failed` using projection-derived identity fields.
///
/// f-798-code_quality-1771816907239154-0: When `scan_pending_from_projection`
/// quarantines a malformed pending file, the projection still shows the job as
/// `Pending`. Without a terminal lifecycle event, the reconciler recreates the
/// witness stub, the worker re-quarantines it, and the loop repeats forever.
///
/// This function constructs a synthetic `FacJobIdentityV1` from the projection
/// record fields (`job_id`, `queue_job_id`, `work_id`) with sentinel values for
/// fields that are unavailable because the payload could not be deserialized.
pub(super) fn emit_job_failed_by_queue_id(
    fac_root: &Path,
    job_id: &str,
    queue_job_id: &str,
    work_id: &str,
    reason_class: &str,
    retryable: bool,
    actor_id: &str,
) -> Result<(), String> {
    let sentinel = "unavailable:malformed_payload";
    let identity = FacJobIdentityV1 {
        job_id: job_id.to_string(),
        queue_job_id: queue_job_id.to_string(),
        work_id: work_id.to_string(),
        changeset_digest: sentinel.to_string(),
        spec_digest: sentinel.to_string(),
        gate_profile: sentinel.to_string(),
        revision: sentinel.to_string(),
    };
    let event = FacJobLifecycleEventV1::new(
        stable_intent_id("failed", queue_job_id, reason_class),
        None,
        FacJobLifecycleEventData::Failed(FacJobFailedV1 {
            identity,
            reason_class: reason_class.to_string(),
            retryable,
        }),
    );
    emit_event(fac_root, FAC_JOB_FAILED_EVENT_TYPE, &event, actor_id)
}

fn emit_event(
    fac_root: &Path,
    event_type: &str,
    event: &FacJobLifecycleEventV1,
    actor_id: &str,
) -> Result<(), String> {
    let payload = event
        .encode_bounded()
        .map_err(|err| format!("encode lifecycle event: {err}"))?;
    // Temporary migration helper: this path is invoked from short-lived queue
    // mutation commands, so each emit opens and initializes the ledger emitter
    // independently instead of holding a long-lived process-global connection.
    let emitter = open_queue_lifecycle_emitter(fac_root)?;
    emitter
        .emit_session_event(
            queue_job_id(event),
            event_type,
            &payload,
            actor_id,
            now_timestamp_ns()?,
        )
        .map_err(|err| format!("emit lifecycle event `{event_type}`: {err}"))?;
    Ok(())
}

fn open_queue_lifecycle_emitter(fac_root: &Path) -> Result<SqliteLedgerEventEmitter, String> {
    let signer = fac_key_material::load_or_generate_persistent_signer(fac_root)?;
    let secret_key_bytes = signer.secret_key_bytes();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key_bytes);

    let db_path = resolve_authoritative_ledger_db_path(fac_root)?;
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create lifecycle ledger parent directory {}: {err}",
                parent.display()
            )
        })?;
    }
    let conn = Connection::open(&db_path)
        .map_err(|err| format!("open queue lifecycle ledger {}: {err}", db_path.display()))?;
    // f-798-code_quality-1771816912391438-0: Set busy_timeout to prevent
    // SQLITE_BUSY under concurrent queue mutation load (multiple workers
    // claiming jobs). Without this, SQLite immediately returns SQLITE_BUSY
    // instead of waiting for locks, causing dropped dual-write events and
    // projection state divergence.
    conn.busy_timeout(std::time::Duration::from_millis(5000))
        .map_err(|err| {
            format!(
                "set busy_timeout on queue lifecycle ledger {}: {err}",
                db_path.display()
            )
        })?;
    SqliteLedgerEventEmitter::init_schema_with_signing_key(&conn, &signing_key).map_err(|err| {
        format!(
            "init queue lifecycle ledger schema {}: {err}",
            db_path.display()
        )
    })?;

    Ok(SqliteLedgerEventEmitter::new(
        Arc::new(Mutex::new(conn)),
        signing_key,
    ))
}

#[cfg(test)]
fn resolve_authoritative_ledger_db_path(fac_root: &Path) -> Result<PathBuf, String> {
    if !fac_root.exists() {
        return Err(format!(
            "fac_root does not exist for lifecycle test ledger: {}",
            fac_root.display()
        ));
    }
    Ok(fac_root.join(TEST_QUEUE_LIFECYCLE_LEDGER_DB))
}

#[cfg(not(test))]
fn resolve_authoritative_ledger_db_path(_fac_root: &Path) -> Result<PathBuf, String> {
    let config_path = resolve_daemon_config_path(Path::new(DEFAULT_CONFIG_FILE));
    if config_path.exists()
        && let Ok(config) = EcosystemConfig::from_file(&config_path)
        && let Some(ledger_db) = config.daemon.ledger_db
    {
        return Ok(ledger_db);
    }

    let config = EcosystemConfig::from_env();
    config
        .daemon
        .ledger_db
        .ok_or_else(|| "daemon ledger_db is not configured".to_string())
}

#[cfg(not(test))]
fn resolve_daemon_config_path(config_path: &Path) -> PathBuf {
    if config_path != Path::new(DEFAULT_CONFIG_FILE) {
        return config_path.to_path_buf();
    }

    let Some(common_dir) = resolve_git_common_dir() else {
        return config_path.to_path_buf();
    };

    if common_dir.file_name() != Some(OsStr::new(".git")) {
        return config_path.to_path_buf();
    }
    let Some(repo_root) = common_dir.parent() else {
        return config_path.to_path_buf();
    };

    let shared_config = repo_root.join(DEFAULT_CONFIG_FILE);
    if shared_config.exists() {
        shared_config
    } else {
        config_path.to_path_buf()
    }
}

#[cfg(not(test))]
fn resolve_git_common_dir() -> Option<PathBuf> {
    // Security: use absolute path to avoid PATH injection
    // (f-798-security-1771810456437363-0).
    let output = Command::new("/usr/bin/git")
        .args(["rev-parse", "--git-common-dir"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let raw = stdout.trim();
    if raw.is_empty() {
        return None;
    }

    let path = PathBuf::from(raw);
    if path.is_absolute() {
        Some(path)
    } else {
        std::env::current_dir().ok().map(|cwd| cwd.join(path))
    }
}

fn identity_from_spec(spec: &FacJobSpecV1) -> Result<FacJobIdentityV1, String> {
    let gate_profile = spec
        .lane_requirements
        .lane_profile_hash
        .as_ref()
        .map_or_else(|| spec.kind.clone(), |hash| format!("{}:{hash}", spec.kind));
    let changeset_digest = format!(
        "b3-256:{}",
        blake3::hash(spec.source.head_sha.as_bytes()).to_hex()
    );
    let preimage = FacJobIdentityPreimageV1 {
        work_id: spec.source.repo_id.clone(),
        changeset_digest: changeset_digest.clone(),
        gate_profile: gate_profile.clone(),
        revision: spec.job_spec_digest.clone(),
    };
    let job_id = derive_content_addressable_job_id(&preimage)
        .map_err(|err| format!("derive content-addressable job id: {err}"))?;

    Ok(FacJobIdentityV1 {
        job_id,
        queue_job_id: spec.job_id.clone(),
        work_id: preimage.work_id,
        changeset_digest,
        spec_digest: spec.job_spec_digest.clone(),
        gate_profile,
        revision: preimage.revision,
    })
}

fn stable_intent_id(prefix: &str, digest: &str, discriminator: &str) -> String {
    let raw = format!("{prefix}:{digest}:{discriminator}");
    if raw.len() <= MAX_JOB_LIFECYCLE_STRING_LENGTH {
        return raw;
    }
    format!("{prefix}:b3-256:{}", blake3::hash(raw.as_bytes()).to_hex())
}

fn now_timestamp_ns() -> Result<u64, String> {
    static HTF_CLOCK: LazyLock<Result<HolonicClock, String>> = LazyLock::new(|| {
        HolonicClock::new(ClockConfig::default(), None)
            .map_err(|err| format!("initialize HTF clock: {err}"))
    });

    let clock = HTF_CLOCK
        .as_ref()
        .map_err(|err| format!("initialize HTF clock: {err}"))?;
    clock
        .now_hlc()
        .map(|hlc| hlc.wall_ns)
        .map_err(|err| format!("read HTF timestamp: {err}"))
}

fn queue_job_id(event: &FacJobLifecycleEventV1) -> &str {
    match &event.event {
        FacJobLifecycleEventData::Enqueued(payload) => &payload.identity.queue_job_id,
        FacJobLifecycleEventData::Claimed(payload) => &payload.identity.queue_job_id,
        FacJobLifecycleEventData::Started(payload) => &payload.identity.queue_job_id,
        FacJobLifecycleEventData::Completed(payload) => &payload.identity.queue_job_id,
        FacJobLifecycleEventData::Released(payload) => &payload.identity.queue_job_id,
        FacJobLifecycleEventData::Failed(payload) => &payload.identity.queue_job_id,
    }
}
