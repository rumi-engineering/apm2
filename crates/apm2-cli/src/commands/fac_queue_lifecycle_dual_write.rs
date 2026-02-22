//! Temporary dual-write helper for FAC queue lifecycle migration.
//!
//! When enabled by `FacPolicyV1.queue_lifecycle_dual_write_enabled`, queue
//! mutation paths emit `fac.job.*` lifecycle events into a local SQLite-backed
//! ledger stream (`queue_lifecycle_ledger.db`) in addition to filesystem
//! mutations.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apm2_core::fac::FacJobSpecV1;
use apm2_core::fac::job_lifecycle::{
    FAC_JOB_CLAIMED_EVENT_TYPE, FAC_JOB_COMPLETED_EVENT_TYPE, FAC_JOB_ENQUEUED_EVENT_TYPE,
    FAC_JOB_FAILED_EVENT_TYPE, FAC_JOB_RELEASED_EVENT_TYPE, FAC_JOB_STARTED_EVENT_TYPE,
    FacJobClaimedV1, FacJobCompletedV1, FacJobEnqueuedV1, FacJobFailedV1, FacJobIdentityPreimageV1,
    FacJobIdentityV1, FacJobLifecycleEventData, FacJobLifecycleEventV1, FacJobReleasedV1,
    FacJobStartedV1, MAX_JOB_LIFECYCLE_STRING_LENGTH, derive_content_addressable_job_id,
};
use apm2_daemon::ledger::SqliteLedgerEventEmitter;
use apm2_daemon::protocol::dispatch::LedgerEventEmitter;
use rusqlite::Connection;

use super::fac_key_material;

const QUEUE_LIFECYCLE_LEDGER_DB: &str = "queue_lifecycle_ledger.db";

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
            enqueue_epoch_ns: now_timestamp_ns(),
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
            claim_epoch_ns: now_timestamp_ns(),
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

fn emit_event(
    fac_root: &Path,
    event_type: &str,
    event: &FacJobLifecycleEventV1,
    actor_id: &str,
) -> Result<(), String> {
    let payload = event
        .encode_bounded()
        .map_err(|err| format!("encode lifecycle event: {err}"))?;
    let emitter = open_queue_lifecycle_emitter(fac_root)?;
    emitter
        .emit_session_event(
            queue_job_id(event),
            event_type,
            &payload,
            actor_id,
            now_timestamp_ns(),
        )
        .map_err(|err| format!("emit lifecycle event `{event_type}`: {err}"))?;
    Ok(())
}

fn open_queue_lifecycle_emitter(fac_root: &Path) -> Result<SqliteLedgerEventEmitter, String> {
    let signer = fac_key_material::load_or_generate_persistent_signer(fac_root)?;
    let secret_key_bytes = signer.secret_key_bytes();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key_bytes);

    let db_path = fac_root.join(QUEUE_LIFECYCLE_LEDGER_DB);
    let conn = Connection::open(&db_path)
        .map_err(|err| format!("open queue lifecycle ledger {}: {err}", db_path.display()))?;
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

fn now_timestamp_ns() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    elapsed
        .as_secs()
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(elapsed.subsec_nanos()))
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
