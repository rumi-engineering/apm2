#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn resolve_ownership_backend(json_output: bool) -> Result<ExecutionBackend, String> {
    match apm2_core::fac::select_backend() {
        Ok(backend) => Ok(backend),
        Err(ExecutionBackendError::InvalidBackendValue { value }) => {
            let fallback_backend = if probe_user_bus() {
                ExecutionBackend::UserMode
            } else {
                ExecutionBackend::SystemMode
            };
            let warning = format!(
                "invalid {EXECUTION_BACKEND_ENV_VAR}='{value}' for worker ownership checks; \
                 falling back to auto-selected backend '{fallback_backend}'"
            );
            if json_output {
                emit_worker_event(
                    "execution_backend_fallback",
                    serde_json::json!({
                        "env_var": EXECUTION_BACKEND_ENV_VAR,
                        "invalid_value": value,
                        "fallback_backend": fallback_backend.to_string(),
                        "scope": "ownership_checks",
                    }),
                );
            } else {
                eprintln!("worker: WARNING: {warning}");
            }
            Ok(fallback_backend)
        },
        Err(err) => Err(format!(
            "cannot resolve execution backend for ownership checks: {err}"
        )),
    }
}

pub(super) fn load_or_generate_persistent_signer() -> Result<Signer, String> {
    let fac_root = resolve_fac_root()?;
    fac_key_material::load_or_generate_persistent_signer(&fac_root)
}

/// Loads persisted broker state from
/// `$APM2_HOME/private/fac/broker_state.json`.
///
/// Returns None if the file doesn't exist.
pub(super) fn load_broker_state() -> Option<apm2_core::fac::broker::BrokerState> {
    let Ok(fac_root) = resolve_fac_root() else {
        return None;
    };
    let state_path = fac_root.join("broker_state.json");
    if !state_path.exists() {
        return None;
    }
    let bytes = read_bounded(&state_path, 1_048_576).ok()?;
    FacBroker::deserialize_state(&bytes).ok()
}

/// Saves broker state to `$APM2_HOME/private/fac/broker_state.json`.
pub(super) fn save_broker_state(broker: &FacBroker) -> Result<(), String> {
    let fac_root = resolve_fac_root()?;
    let state_path = fac_root.join("broker_state.json");
    let bytes = broker
        .serialize_state()
        .map_err(|e| format!("cannot serialize broker state: {e}"))?;
    fs::write(&state_path, bytes).map_err(|e| format!("cannot write broker state: {e}"))
}

/// TCK-00566: Loads persisted token ledger from
/// `$APM2_HOME/private/fac/broker/token_ledger/state.json`.
///
/// Returns `Ok(None)` if the file doesn't exist (first run).
/// Returns `Err` if the file exists but cannot be read or deserialized
/// (INV-TL-009: fail-closed — load errors from an existing ledger file
/// are hard security faults that refuse to continue).
/// Expired entries are dropped on load.
///
/// If a WAL file exists alongside the snapshot, it is replayed after
/// snapshot load to restore full ledger state.
#[allow(dead_code)] // Called from fac_queue_submit; dead_code false positive in test targets.
pub(super) fn load_token_ledger_pub_impl(
    current_tick: u64,
) -> Result<Option<apm2_core::fac::token_ledger::TokenUseLedger>, String> {
    load_token_ledger(current_tick)
}

pub(super) fn load_token_ledger(
    current_tick: u64,
) -> Result<Option<apm2_core::fac::token_ledger::TokenUseLedger>, String> {
    let fac_root = resolve_fac_root()?;
    let ledger_dir = fac_root.join("broker").join("token_ledger");
    let state_path = ledger_dir.join("state.json");
    if !state_path.exists() {
        // No WAL without a snapshot is valid on first run.
        return Ok(None);
    }
    let bytes = read_bounded(
        &state_path,
        apm2_core::fac::token_ledger::MAX_TOKEN_LEDGER_FILE_SIZE,
    )?;
    let mut ledger =
        apm2_core::fac::token_ledger::TokenUseLedger::deserialize_state(&bytes, current_tick)
            .map_err(|e| format!("token ledger load failed (fail-closed): {e}"))?;

    // Replay WAL if it exists.
    let wal_path = ledger_dir.join("wal.jsonl");
    if wal_path.exists() {
        let wal_bytes = read_bounded(&wal_path, apm2_core::fac::token_ledger::MAX_WAL_FILE_SIZE)?;
        let replayed = ledger
            .replay_wal(&wal_bytes)
            .map_err(|e| format!("token ledger WAL replay failed (fail-closed): {e}"))?;
        if replayed > 0 {
            eprintln!("worker: replayed {replayed} WAL entries for token ledger");
        }
    }

    Ok(Some(ledger))
}

/// TCK-00566: Saves token ledger snapshot to
/// `$APM2_HOME/private/fac/broker/token_ledger/state.json`.
///
/// Uses `write_atomic` (`temp+fsync+dir_fsync+rename`) for crash safety
/// per CTR-2607. After a successful snapshot, the WAL file is truncated
/// and the WAL counter is reset (compaction).
///
/// Errors are propagated to the caller (INV-TL-009: fail-closed).
pub(super) fn save_token_ledger(broker: &mut FacBroker) -> Result<(), String> {
    let fac_root = resolve_fac_root()?;
    let ledger_dir = fac_root.join("broker").join("token_ledger");
    if !ledger_dir.exists() {
        fac_permissions::ensure_dir_with_mode(&ledger_dir)
            .map_err(|e| format!("cannot create token ledger dir: {e}"))?;
    }

    // BLOCKER fix: acquire exclusive flock on compaction.lock to prevent
    // multi-process compaction races. Worker A truncates WAL after snapshot,
    // but Worker B may have appended between snapshot and truncation — B's
    // entry would be lost without this lock.
    let lock_path = ledger_dir.join("compaction.lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false) // Lock file only — never truncate its contents.
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("cannot open compaction lock: {e}"))?;
    // Exclusive lock — blocks until acquired. Flock::lock takes ownership and
    // automatically unlocks on drop.
    let _lock_guard = nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_file, e)| format!("cannot acquire compaction lock: {e}"))?;

    let state_path = ledger_dir.join("state.json");
    let bytes = broker
        .serialize_token_ledger()
        .map_err(|e| format!("cannot serialize token ledger: {e}"))?;
    // CTR-2607: full atomic write protocol (temp+fsync+dir_fsync+rename).
    apm2_core::determinism::write_atomic(&state_path, &bytes)
        .map_err(|e| format!("cannot write token ledger snapshot: {e}"))?;
    // MAJOR fix: Truncate WAL with fsync after successful snapshot (compaction).
    // Uses open+set_len(0)+sync_all instead of fs::write to ensure the
    // truncation is durable before releasing the compaction lock.
    let wal_path = ledger_dir.join("wal.jsonl");
    if wal_path.exists() {
        let wal_file = fs::OpenOptions::new()
            .write(true)
            .open(&wal_path)
            .map_err(|e| format!("cannot open token ledger WAL for truncation: {e}"))?;
        wal_file
            .set_len(0)
            .map_err(|e| format!("cannot truncate token ledger WAL: {e}"))?;
        wal_file
            .sync_all()
            .map_err(|e| format!("cannot fsync token ledger WAL truncation: {e}"))?;
    }
    broker.reset_token_ledger_wal_counter();

    // _lock_guard dropped here — exclusive flock released automatically.
    Ok(())
}

/// TCK-00566: Appends a WAL entry to
/// `$APM2_HOME/private/fac/broker/token_ledger/wal.jsonl`.
///
/// Uses append mode with fsync for crash durability (INV-TL-010).
/// This MUST be called immediately after `validate_and_record_token_nonce`
/// returns Ok and BEFORE job execution begins (BLOCKER fix).
#[allow(dead_code)] // Called from fac_warm and gates; dead_code false positive in test targets.
pub(super) fn append_token_ledger_wal_pub_impl(wal_bytes: &[u8]) -> Result<(), String> {
    append_token_ledger_wal(wal_bytes)
}

pub(super) fn append_token_ledger_wal(wal_bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;

    let fac_root = resolve_fac_root()?;
    let ledger_dir = fac_root.join("broker").join("token_ledger");
    if !ledger_dir.exists() {
        fac_permissions::ensure_dir_with_mode(&ledger_dir)
            .map_err(|e| format!("cannot create token ledger dir: {e}"))?;
    }
    let wal_path = ledger_dir.join("wal.jsonl");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&wal_path)
        .map_err(|e| format!("cannot open token ledger WAL: {e}"))?;
    file.write_all(wal_bytes)
        .map_err(|e| format!("cannot write token ledger WAL: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("cannot fsync token ledger WAL: {e}"))?;
    Ok(())
}

/// Atomically moves a file to a destination directory with collision-safe
/// target names.
///
/// Uses `fs::rename` for atomicity on the same filesystem (INV-WRK-003).
/// If the target file already exists (duplicate job ID from a concurrent
/// worker or replay), the file name is suffixed with a nanosecond timestamp
/// to prevent clobbering (MAJOR-2 fix).
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_scan_receipt(
    fac_root: &Path,
    file_name: &str,
    job_id: &str,
    job_spec_digest: &str,
    outcome: FacJobOutcome,
    denial_reason: DenialReasonCode,
    moved_job_path: Option<&str>,
    reason: &str,
    canonicalizer_tuple_digest: &str,
    // TCK-00538: Optional toolchain fingerprint for receipt provenance.
    toolchain_fingerprint: Option<&str>,
) -> Result<PathBuf, String> {
    let mut builder = FacJobReceiptV1Builder::new(
        format!("wkr-scan-{}-{}", file_name, current_timestamp_epoch_secs()),
        job_id,
        job_spec_digest,
    )
    .outcome(outcome)
    .denial_reason(denial_reason)
    .canonicalizer_tuple_digest(canonicalizer_tuple_digest)
    .reason(reason)
    .timestamp_secs(current_timestamp_epoch_secs());

    if let Some(path) = moved_job_path {
        builder = builder.moved_job_path(path);
    }
    // TCK-00538: Bind toolchain fingerprint to scan receipt.
    if let Some(fp) = toolchain_fingerprint {
        builder = builder.toolchain_fingerprint(fp);
    }

    let receipt = builder
        .try_build()
        .map_err(|e| format!("cannot build scan receipt: {e}"))?;

    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let result = persist_content_addressed_receipt(&receipts_dir, &receipt)?;

    // TCK-00576: Best-effort signed envelope alongside scan receipt.
    if let Ok(signer) = fac_key_material::load_or_generate_persistent_signer(fac_root) {
        let content_hash = apm2_core::fac::compute_job_receipt_content_hash(&receipt);
        let envelope = apm2_core::fac::sign_receipt(&content_hash, &signer, "fac-worker");
        if let Err(e) = apm2_core::fac::persist_signed_envelope(&receipts_dir, &envelope) {
            tracing::warn!(error = %e, "signed scan receipt envelope failed (non-fatal)");
        }
    }

    Ok(result)
}

pub(super) fn load_or_create_policy(
    fac_root: &Path,
) -> Result<(String, [u8; 32], FacPolicyV1), String> {
    let policy_dir = fac_root.join("policy");
    let policy_path = policy_dir.join("fac_policy.v1.json");

    let policy = if policy_path.exists() {
        let bytes = read_bounded(&policy_path, MAX_POLICY_SIZE)?;
        deserialize_policy(&bytes).map_err(|e| format!("cannot load fac policy: {e}"))?
    } else {
        let default_policy = apm2_core::fac::FacPolicyV1::default_policy();
        persist_policy(fac_root, &default_policy)
            .map_err(|e| format!("cannot persist default fac policy: {e}"))?;
        default_policy
    };

    let policy_hash =
        compute_policy_hash(&policy).map_err(|e| format!("cannot compute policy hash: {e}"))?;
    let policy_digest =
        parse_policy_hash(&policy_hash).ok_or_else(|| "invalid policy hash".to_string())?;

    Ok((policy_hash, policy_digest, policy))
}

/// Emit a unified `FacJobReceiptV1` and persist under
/// `$APM2_HOME/private/fac/receipts`.
///
/// MAJOR-2 fix: accepts `bytes_backend` so non-pipeline emission paths
/// carry consistent metadata for GC tracking.
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_job_receipt(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
    rfc0028_channel_boundary: Option<&ChannelBoundaryTrace>,
    eio29_queue_admission: Option<&JobQueueAdmissionTrace>,
    eio29_budget_admission: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: Option<&str>,
    moved_job_path: Option<&str>,
    policy_hash: &str,
    containment: Option<&apm2_core::fac::containment::ContainmentTrace>,
    sandbox_hardening_hash: Option<&str>,
    network_policy_hash: Option<&str>,
    // TCK-00546 MAJOR-2: bytes_backend for GC tracking in non-pipeline paths.
    bytes_backend: Option<&str>,
    // TCK-00538: Optional toolchain fingerprint.
    toolchain_fingerprint: Option<&str>,
) -> Result<PathBuf, String> {
    emit_job_receipt_internal(
        fac_root,
        spec,
        outcome,
        denial_reason,
        reason,
        rfc0028_channel_boundary,
        eio29_queue_admission,
        eio29_budget_admission,
        patch_digest,
        canonicalizer_tuple_digest,
        moved_job_path,
        policy_hash,
        containment,
        None,
        sandbox_hardening_hash,
        network_policy_hash,
        bytes_backend,
        toolchain_fingerprint,
    )
}

/// Emit a unified `FacJobReceiptV1` with observed runtime cost metrics.
///
/// Note: Most callers have been migrated to `commit_claimed_job_via_pipeline`
/// (TCK-00564 BLOCKER-1). This function is retained for future non-pipeline
/// receipt emission paths.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn emit_job_receipt_with_observed_cost(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
    rfc0028_channel_boundary: Option<&ChannelBoundaryTrace>,
    eio29_queue_admission: Option<&JobQueueAdmissionTrace>,
    eio29_budget_admission: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: Option<&str>,
    moved_job_path: Option<&str>,
    policy_hash: &str,
    containment: Option<&apm2_core::fac::containment::ContainmentTrace>,
    observed_cost: apm2_core::economics::cost_model::ObservedJobCost,
    sandbox_hardening_hash: Option<&str>,
    network_policy_hash: Option<&str>,
    // TCK-00546 MAJOR-2: bytes_backend for GC tracking.
    bytes_backend: Option<&str>,
    // TCK-00538: Optional toolchain fingerprint.
    toolchain_fingerprint: Option<&str>,
) -> Result<PathBuf, String> {
    emit_job_receipt_internal(
        fac_root,
        spec,
        outcome,
        denial_reason,
        reason,
        rfc0028_channel_boundary,
        eio29_queue_admission,
        eio29_budget_admission,
        patch_digest,
        canonicalizer_tuple_digest,
        moved_job_path,
        policy_hash,
        containment,
        Some(observed_cost),
        sandbox_hardening_hash,
        network_policy_hash,
        bytes_backend,
        toolchain_fingerprint,
    )
}

/// Build a `FacJobReceiptV1` from the given parameters without persisting.
///
/// This is the shared receipt construction logic used by both the direct
/// persist path and the `ReceiptWritePipeline` commit path (TCK-00564).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_job_receipt(
    spec: &FacJobSpecV1,
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
    rfc0028_channel_boundary: Option<&ChannelBoundaryTrace>,
    eio29_queue_admission: Option<&JobQueueAdmissionTrace>,
    eio29_budget_admission: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: Option<&str>,
    moved_job_path: Option<&str>,
    policy_hash: &str,
    containment: Option<&apm2_core::fac::containment::ContainmentTrace>,
    observed_cost: Option<apm2_core::economics::cost_model::ObservedJobCost>,
    sandbox_hardening_hash: Option<&str>,
    network_policy_hash: Option<&str>,
    // TCK-00587: Optional stop/revoke admission trace for receipt binding.
    stop_revoke_admission: Option<&apm2_core::economics::queue_admission::StopRevokeAdmissionTrace>,
    // TCK-00546: Optional patch bytes backend identifier for GC tracking.
    bytes_backend: Option<&str>,
    // TCK-00538: Optional toolchain fingerprint.
    toolchain_fingerprint: Option<&str>,
) -> Result<FacJobReceiptV1, String> {
    let mut builder = FacJobReceiptV1Builder::new(
        format!("wkr-{}-{}", spec.job_id, current_timestamp_epoch_secs()),
        &spec.job_id,
        &spec.job_spec_digest,
    )
    .policy_hash(policy_hash)
    .outcome(outcome)
    .reason(reason)
    .timestamp_secs(current_timestamp_epoch_secs());

    if let Some(denial_reason) = denial_reason {
        builder = builder.denial_reason(denial_reason);
    }

    if let Some(boundary_trace) = rfc0028_channel_boundary {
        builder = builder.rfc0028_channel_boundary(boundary_trace.clone());
    }
    if let Some(queue_admission_trace) = eio29_queue_admission {
        builder = builder.eio29_queue_admission(queue_admission_trace.clone());
    }
    if let Some(budget_admission_trace) = eio29_budget_admission {
        builder = builder.eio29_budget_admission(budget_admission_trace.clone());
    }
    if let Some(patch_digest) = patch_digest {
        builder = builder.patch_digest(patch_digest);
    }
    if let Some(canonicalizer_tuple_digest) = canonicalizer_tuple_digest {
        builder = builder.canonicalizer_tuple_digest(canonicalizer_tuple_digest);
    }
    if let Some(path) = moved_job_path {
        builder = builder.moved_job_path(path);
    }
    if let Some(fp) = toolchain_fingerprint {
        builder = builder.toolchain_fingerprint(fp);
    }
    if let Some(trace) = containment {
        builder = builder.containment(trace.clone());
        // TCK-00572: Collect cgroup usage stats from the containment cgroup path.
        // Best-effort: if stats cannot be read, observed_usage is None.
        if !trace.cgroup_path.is_empty() {
            let usage = apm2_core::fac::cgroup_stats::collect_cgroup_usage(&trace.cgroup_path);
            if !usage.is_empty() {
                builder = builder.observed_usage(usage);
            }
        }
    }
    if let Some(cost) = observed_cost {
        builder = builder.observed_cost(cost);
    }
    // TCK-00573: Bind sandbox hardening hash to receipt for audit.
    if let Some(hash) = sandbox_hardening_hash {
        builder = builder.sandbox_hardening_hash(hash);
    }
    // TCK-00574: Bind network policy hash to receipt for audit.
    if let Some(hash) = network_policy_hash {
        builder = builder.network_policy_hash(hash);
    }
    // TCK-00587: Bind stop/revoke admission trace to receipt for audit.
    if let Some(trace) = stop_revoke_admission {
        builder = builder.stop_revoke_admission(trace.clone());
    }
    // TCK-00546: Bind bytes_backend to receipt for GC tracking.
    if let Some(backend) = bytes_backend {
        builder = builder.bytes_backend(backend);
    }

    builder
        .try_build()
        .map_err(|e| format!("cannot build job receipt: {e}"))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_job_receipt_internal(
    fac_root: &Path,
    spec: &FacJobSpecV1,
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
    rfc0028_channel_boundary: Option<&ChannelBoundaryTrace>,
    eio29_queue_admission: Option<&JobQueueAdmissionTrace>,
    eio29_budget_admission: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: Option<&str>,
    moved_job_path: Option<&str>,
    policy_hash: &str,
    containment: Option<&apm2_core::fac::containment::ContainmentTrace>,
    observed_cost: Option<apm2_core::economics::cost_model::ObservedJobCost>,
    sandbox_hardening_hash: Option<&str>,
    network_policy_hash: Option<&str>,
    // TCK-00546 MAJOR-2: bytes_backend threaded through for GC tracking.
    bytes_backend: Option<&str>,
    // TCK-00538: Optional toolchain fingerprint.
    toolchain_fingerprint: Option<&str>,
) -> Result<PathBuf, String> {
    let receipt = build_job_receipt(
        spec,
        outcome,
        denial_reason,
        reason,
        rfc0028_channel_boundary,
        eio29_queue_admission,
        eio29_budget_admission,
        patch_digest,
        canonicalizer_tuple_digest,
        moved_job_path,
        policy_hash,
        containment,
        observed_cost,
        sandbox_hardening_hash,
        network_policy_hash,
        None,                  // stop_revoke_admission
        bytes_backend,         // TCK-00546: bytes_backend
        toolchain_fingerprint, // TCK-00538: toolchain fingerprint
    )?;
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let result = persist_content_addressed_receipt(&receipts_dir, &receipt)?;

    // TCK-00576: Best-effort signed envelope alongside receipt.
    if let Ok(signer) = fac_key_material::load_or_generate_persistent_signer(fac_root) {
        let content_hash = apm2_core::fac::compute_job_receipt_content_hash(&receipt);
        let envelope = apm2_core::fac::sign_receipt(&content_hash, &signer, "fac-worker");
        if let Err(e) = apm2_core::fac::persist_signed_envelope(&receipts_dir, &envelope) {
            tracing::warn!(error = %e, "signed envelope persistence failed (non-fatal)");
        }
    }

    if outcome == FacJobOutcome::Denied
        && let Some(path) = moved_job_path
    {
        annotate_denied_job_from_moved_path(fac_root, path, denial_reason, reason);
    }

    Ok(result)
}

/// Commit a claimed job through the `ReceiptWritePipeline`: persist receipt,
/// update index, move job atomically (TCK-00564 BLOCKER-1).
///
/// Returns the terminal path of the moved job file, or a structured
/// [`ReceiptPipelineError`] that preserves error specificity (including
/// [`ReceiptPipelineError::TornState`]) for callers to decide recovery
/// strategy.
#[allow(clippy::too_many_arguments)]
pub(super) fn commit_claimed_job_via_pipeline(
    fac_root: &Path,
    queue_root: &Path,
    spec: &FacJobSpecV1,
    claimed_path: &Path,
    claimed_file_name: &str,
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
    rfc0028_channel_boundary: Option<&ChannelBoundaryTrace>,
    eio29_queue_admission: Option<&JobQueueAdmissionTrace>,
    eio29_budget_admission: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: Option<&str>,
    policy_hash: &str,
    containment: Option<&apm2_core::fac::containment::ContainmentTrace>,
    observed_cost: Option<apm2_core::economics::cost_model::ObservedJobCost>,
    sandbox_hardening_hash: Option<&str>,
    network_policy_hash: Option<&str>,
    // TCK-00587: Optional stop/revoke admission trace for receipt binding.
    stop_revoke_admission: Option<&apm2_core::economics::queue_admission::StopRevokeAdmissionTrace>,
    // TCK-00546: Optional patch bytes backend identifier for GC tracking.
    bytes_backend: Option<&str>,
    // TCK-00538: Optional toolchain fingerprint for receipt binding.
    toolchain_fingerprint: Option<&str>,
) -> Result<PathBuf, ReceiptPipelineError> {
    let terminal_state = outcome_to_terminal_state(outcome).ok_or_else(|| {
        ReceiptPipelineError::ReceiptPersistFailed(format!(
            "non-terminal outcome {outcome:?} cannot be committed"
        ))
    })?;

    let receipt = build_job_receipt(
        spec,
        outcome,
        denial_reason,
        reason,
        rfc0028_channel_boundary,
        eio29_queue_admission,
        eio29_budget_admission,
        patch_digest,
        canonicalizer_tuple_digest,
        None, // moved_job_path: not known before move
        policy_hash,
        containment,
        observed_cost,
        sandbox_hardening_hash,
        network_policy_hash,
        stop_revoke_admission,
        bytes_backend,
        toolchain_fingerprint,
    )
    .map_err(ReceiptPipelineError::ReceiptPersistFailed)?;

    let pipeline =
        ReceiptWritePipeline::new(fac_root.join(FAC_RECEIPTS_DIR), queue_root.to_path_buf());

    // TCK-00576: Attempt signed commit using the persistent broker key.
    // If the signing key is available, persist a signed receipt envelope
    // alongside the receipt. If key loading fails, fall back to unsigned
    // commit (the receipt is still valid but will be treated as unsigned
    // for cache-reuse decisions, which is fail-closed).
    let result = match fac_key_material::load_or_generate_persistent_signer(fac_root) {
        Ok(signer) => pipeline.commit_signed(
            &receipt,
            claimed_path,
            claimed_file_name,
            terminal_state,
            &signer,
            "fac-worker",
        )?,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "cannot load signing key for receipt signing (falling back to unsigned)"
            );
            pipeline.commit(&receipt, claimed_path, claimed_file_name, terminal_state)?
        },
    };

    if outcome == FacJobOutcome::Denied
        && let Err(err) = annotate_denied_job_file(&result.job_terminal_path, denial_reason, reason)
    {
        eprintln!(
            "worker: WARNING: failed to update denied job metadata for {}: {err}",
            result.job_terminal_path.display()
        );
    }

    // TCK-00669 fix (f-798-code_quality-1771810793166416-0): Dual-write
    // lifecycle emission is best-effort / advisory.  The filesystem pipeline
    // commit above is authoritative — a lifecycle emit failure must never
    // abort the terminal commit.  Warn-and-continue on any error.
    match fac_queue_lifecycle_dual_write::queue_lifecycle_dual_write_enabled(fac_root) {
        Ok(true) => {
            let claimed_parent = claimed_path
                .parent()
                .and_then(Path::file_name)
                .and_then(|value| value.to_str());
            if claimed_parent == Some(CLAIMED_DIR) {
                if let Err(err) = fac_queue_lifecycle_dual_write::emit_job_started(
                    fac_root,
                    spec,
                    "fac.worker",
                    "fac.worker",
                ) {
                    tracing::warn!(
                        error = %err,
                        "dual-write lifecycle started event failed (non-fatal)"
                    );
                }
            }

            if outcome == FacJobOutcome::Completed {
                if let Err(err) = fac_queue_lifecycle_dual_write::emit_job_completed(
                    fac_root,
                    spec,
                    "completed",
                    None,
                    "fac.worker",
                ) {
                    tracing::warn!(
                        error = %err,
                        "dual-write lifecycle completed event failed (non-fatal)"
                    );
                }
            } else {
                let reason_class = lifecycle_failed_reason_class(outcome, denial_reason);
                if let Err(err) = fac_queue_lifecycle_dual_write::emit_job_failed(
                    fac_root,
                    spec,
                    &reason_class,
                    false,
                    None,
                    "fac.worker",
                ) {
                    tracing::warn!(
                        error = %err,
                        "dual-write lifecycle failed event failed (non-fatal)"
                    );
                }
            }
        },
        Ok(false) => { /* dual-write disabled — nothing to emit */ },
        Err(err) => {
            tracing::warn!(
                error = %err,
                "resolve lifecycle dual-write flag failed (non-fatal)"
            );
        },
    }

    Ok(result.job_terminal_path)
}

fn lifecycle_failed_reason_class(
    outcome: FacJobOutcome,
    denial_reason: Option<DenialReasonCode>,
) -> String {
    if let Some(code) = denial_reason {
        return strip_json_string_quotes(&serialize_to_json_string(&code));
    }
    strip_json_string_quotes(&serialize_to_json_string(&outcome))
}

/// Handle a pipeline commit failure for a denial/failure path.
///
/// When `commit_claimed_job_via_pipeline` fails, the job has no terminal
/// receipt and no terminal queue transition. This function:
/// 1. Logs the commit error prominently via `eprintln!`.
/// 2. Leaves the job in `claimed/` for reconcile to repair.
/// 3. Returns `JobOutcome::Skipped` so the caller does NOT report a terminal
///    outcome that was never durably persisted.
///
/// The job is intentionally left in `claimed/` rather than moved to `pending/`.
/// If the receipt was persisted before the commit failed (torn state),
/// reconcile will detect the receipt and route the job to the correct terminal
/// directory based on the receipt outcome (completed, denied, etc.) via
/// `recover_torn_state`. If the receipt was not persisted, the orphan policy
/// applies. Moving to `pending/` would cause the outcome-blind duplicate
/// detection in `process_job` to route all receipted jobs to `completed/`,
/// masking denied outcomes (TCK-00564 MAJOR-1 fix round 4).
pub(super) fn handle_pipeline_commit_failure(
    commit_err: &ReceiptPipelineError,
    context: &str,
    _claimed_path: &Path,
    _queue_root: &Path,
    _claimed_file_name: &str,
) -> JobOutcome {
    eprintln!("worker: pipeline commit failed for {context}: {commit_err}");
    // Job stays in claimed/ — reconcile will repair torn states or the orphan
    // policy will handle unreceipted failures.
    JobOutcome::skipped_pipeline_commit(format!(
        "pipeline commit failed for {context}: {commit_err}"
    ))
}

/// Compute observed job cost from wall-clock elapsed time.
///
/// CPU time and I/O bytes are reported as 0 (best-effort: these metrics
/// require cgroup accounting which is not yet wired into the worker).
pub(super) fn observed_cost_from_elapsed(
    elapsed: std::time::Duration,
) -> apm2_core::economics::cost_model::ObservedJobCost {
    apm2_core::economics::cost_model::ObservedJobCost {
        duration_ms: u64::try_from(elapsed.as_millis().min(u128::from(u64::MAX)))
            .unwrap_or(u64::MAX),
        cpu_time_ms: 0,
        bytes_written: 0,
    }
}

pub(super) fn compute_job_spec_digest_preview(bytes: &[u8]) -> String {
    let hash = blake3::hash(bytes);
    format!("b3-256:{}", hash.to_hex())
}

pub(super) fn build_channel_boundary_trace_with_binding(
    defects: &[ChannelBoundaryDefect],
    binding: Option<&apm2_core::channel::TokenBindingV1>,
) -> ChannelBoundaryTrace {
    let mut defect_classes = Vec::new();
    for defect in defects.iter().take(MAX_BOUNDARY_DEFECT_CLASSES) {
        defect_classes.push(strip_json_string_quotes(&serialize_to_json_string(
            &defect.violation_class,
        )));
    }

    let defect_count = u32::try_from(defects.len()).unwrap_or(u32::MAX);

    let (policy_hash, tuple_digest, boundary_id, issued_at_tick, expiry_tick) =
        binding.map_or((None, None, None, None, None), |b| {
            (
                Some(hex::encode(b.fac_policy_hash)),
                Some(hex::encode(b.canonicalizer_tuple_digest)),
                Some(b.boundary_id.clone()),
                Some(b.issued_at_tick),
                Some(b.expiry_tick),
            )
        });

    ChannelBoundaryTrace {
        passed: defects.is_empty(),
        defect_count,
        defect_classes,
        token_fac_policy_hash: policy_hash,
        token_canonicalizer_tuple_digest: tuple_digest,
        token_boundary_id: boundary_id,
        token_issued_at_tick: issued_at_tick,
        token_expiry_tick: expiry_tick,
    }
}

pub(super) fn fac_budget_admission_trace(
    trace: &EconomicsBudgetAdmissionTrace,
) -> FacBudgetAdmissionTrace {
    let verdict = match trace.verdict {
        BudgetAdmissionVerdict::Allow => "allow",
        BudgetAdmissionVerdict::Freeze => "freeze",
        BudgetAdmissionVerdict::Escalate => "escalate",
        _ => "deny",
    };

    FacBudgetAdmissionTrace {
        verdict: verdict.to_string(),
        reason: trace.deny_reason.clone(),
    }
}

pub(super) fn build_queue_admission_trace(
    decision: &QueueAdmissionDecision,
) -> JobQueueAdmissionTrace {
    let lane = decision.trace.lane.as_ref().map_or_else(
        || "unknown".to_string(),
        |v| strip_json_string_quotes(&serialize_to_json_string(v)),
    );

    JobQueueAdmissionTrace {
        verdict: strip_json_string_quotes(&serialize_to_json_string(&decision.trace.verdict)),
        queue_lane: lane,
        defect_reason: decision.trace.defect.as_ref().map(|d| d.reason.clone()),
        cost_estimate_ticks: decision.trace.cost_estimate_ticks,
    }
}

/// Persists a `GateReceipt` alongside the completed job.
pub(super) fn write_gate_receipt(queue_root: &Path, file_name: &str, receipt: &GateReceipt) {
    let receipts_dir = queue_root.join("receipts");
    let _ = fs::create_dir_all(&receipts_dir);

    let receipt_name = format!("{}-gate.receipt.json", file_name.trim_end_matches(".json"),);
    let receipt_path = receipts_dir.join(receipt_name);

    if let Ok(bytes) = serde_json::to_vec_pretty(receipt) {
        let _ = fs::write(&receipt_path, bytes);
    }
}

/// Returns the current epoch seconds as a u64.
///
/// Named `current_timestamp_epoch_secs` to accurately reflect that this
/// returns epoch seconds, not an ISO 8601 string (MINOR-1 fix).
pub(super) fn current_timestamp_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Creates a default evaluation window for local-only queue admission.
pub(super) fn make_default_eval_window(boundary_id: &str) -> HtfEvaluationWindow {
    HtfEvaluationWindow {
        boundary_id: boundary_id.to_string(),
        authority_clock: DEFAULT_AUTHORITY_CLOCK.to_string(),
        tick_start: 0,
        tick_end: 1,
    }
}

/// Computes a BLAKE3 evidence hash for receipt binding.
pub(super) fn compute_evidence_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2.fac_worker.evidence.v1");
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Persists a stuck scan lock receipt under `$APM2_HOME/private/fac/receipts/`.
///
/// Best-effort: errors are logged but not propagated (stuck detection is
/// observability, not correctness).
///
/// Atomic write protocol (CTR-1502): writes to a temp file via
/// `NamedTempFile::new_in()` then `persist()` to rename into place.
/// Directory created with mode 0700 (CTR-2611).
pub(super) fn persist_scan_lock_stuck_receipt(
    fac_root: &Path,
    receipt_json: &str,
) -> Result<(), String> {
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);

    // Create receipts directory with restricted permissions (CTR-2611).
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&receipts_dir)
            .map_err(|e| format!("create receipts dir: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(&receipts_dir).map_err(|e| format!("create receipts dir: {e}"))?;
    }

    let filename = format!(
        "scan_lock_stuck_{}.json",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
    );

    // Atomic write: temp file + persist (rename) to prevent partial reads
    // (CTR-1502). NamedTempFile provides unpredictable name + O_EXCL.
    let mut tmp = tempfile::NamedTempFile::new_in(&receipts_dir)
        .map_err(|e| format!("create stuck receipt temp file: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = tmp.as_file().set_permissions(perms);
    }

    tmp.write_all(receipt_json.as_bytes())
        .map_err(|e| format!("write stuck receipt: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("sync stuck receipt: {e}"))?;

    let receipt_path = receipts_dir.join(&filename);
    tmp.persist(&receipt_path)
        .map_err(|e| format!("rename stuck receipt: {e}"))?;

    Ok(())
}
