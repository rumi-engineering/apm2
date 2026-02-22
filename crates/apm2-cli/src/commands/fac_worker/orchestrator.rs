#[allow(clippy::wildcard_imports)]
use super::*;

/// Explicit orchestration state machine for worker job processing.
///
/// States: `Idle` -> `Claimed` -> `LaneAcquired`
///         -> `LeasePersisted` -> `Executing`
///         -> `Committing` -> `Completed`
///
/// Invariants:
/// - A job may be in claimed IFF state >= `Claimed` and < `Completed`.
/// - A lane may have a lease IFF state >= `LeasePersisted` and < `Completed`.
/// - Receipt is the source of truth for terminal outcome; reconcile can repair
///   torn state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum OrchestratorState {
    Idle,
    Claimed { job_id: String },
    LaneAcquired { job_id: String, lane_id: String },
    LeasePersisted { job_id: String, lane_id: String },
    Executing { job_id: String, lane_id: String },
    Committing { job_id: String, lane_id: String },
    Completed { job_id: String, outcome: String },
}

/// Outcome from a single step of the orchestrator.
#[derive(Debug, Clone)]
pub(super) enum StepOutcome {
    /// Orchestrator advanced to the next state; call `step()` again.
    Advanced,
    /// Job processing complete with this final outcome.
    Done(super::types::JobOutcome),
    /// Job was skipped (duplicate, invalid filename, etc.)
    Skipped(String),
}

pub(super) struct WorkerOrchestrator {
    state: OrchestratorState,
    terminal_outcome: Option<JobOutcome>,
}

impl WorkerOrchestrator {
    pub(super) const fn new() -> Self {
        Self {
            state: OrchestratorState::Idle,
            terminal_outcome: None,
        }
    }

    pub(super) const fn state(&self) -> &OrchestratorState {
        &self.state
    }

    pub(super) fn transition(&mut self, next: OrchestratorState) {
        self.state = next;
        if !matches!(self.state, OrchestratorState::Completed { .. }) {
            self.terminal_outcome = None;
        }
    }

    pub(super) fn complete_with_outcome(&mut self, job_id: String, outcome: JobOutcome) {
        self.state = OrchestratorState::Completed {
            job_id,
            outcome: job_outcome_label(&outcome).to_string(),
        };
        self.terminal_outcome = Some(outcome);
    }

    #[cfg(test)]
    pub(super) const fn is_terminal(&self) -> bool {
        matches!(self.state, OrchestratorState::Completed { .. })
    }

    pub(super) fn step(&self) -> StepOutcome {
        if let Some(outcome) = self.terminal_outcome.clone() {
            return StepOutcome::Done(outcome);
        }
        match &self.state {
            OrchestratorState::Completed { job_id, outcome } => match outcome.as_str() {
                "completed" => StepOutcome::Done(JobOutcome::Completed {
                    job_id: job_id.clone(),
                    observed_cost: None,
                }),
                "denied" => StepOutcome::Done(JobOutcome::Denied {
                    reason: "denied".to_string(),
                }),
                "quarantined" => StepOutcome::Done(JobOutcome::Quarantined {
                    reason: "quarantined".to_string(),
                }),
                _ => StepOutcome::Skipped(outcome.clone()),
            },
            _ => StepOutcome::Advanced,
        }
    }
}

const fn job_outcome_label(outcome: &JobOutcome) -> &'static str {
    match outcome {
        JobOutcome::Quarantined { .. } => "quarantined",
        JobOutcome::Denied { .. } => "denied",
        JobOutcome::Completed { .. } => "completed",
        JobOutcome::Aborted { .. } => "aborted",
        JobOutcome::Skipped { .. } => "skipped",
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn process_job(
    candidate: &PendingCandidate,
    queue_root: &Path,
    fac_root: &Path,
    completed_gates_cache: &mut Option<CompletedGatesCache>,
    verifying_key: &apm2_core::crypto::VerifyingKey,
    scheduler: &QueueSchedulerState,
    lane: QueueLane,
    broker: &mut FacBroker,
    signer: &Signer,
    policy_hash: &str,
    policy_digest: &[u8; 32],
    policy: &FacPolicyV1,
    job_spec_policy: &apm2_core::fac::JobSpecValidationPolicy,
    budget_cas: &MemoryCas,
    _candidates_count: usize,
    print_unit: bool,
    canonicalizer_tuple_digest: &str,
    boundary_id: &str,
    heartbeat_cycle_count: u64,
    heartbeat_jobs_completed: u64,
    heartbeat_jobs_denied: u64,
    heartbeat_jobs_quarantined: u64,
    cost_model: &apm2_core::economics::CostModelV1,
    // TCK-00538: Toolchain fingerprint computed once at worker startup.
    toolchain_fingerprint: Option<&str>,
) -> JobOutcome {
    let job_wall_start = Instant::now();

    let path = &candidate.path;
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_string(),
        None => {
            return JobOutcome::skipped("invalid filename");
        },
    };

    // Step 0: Index-first duplicate detection (TCK-00560).
    //
    // Check the receipt index to see if a receipt already exists for this
    // job_id. This avoids redundant processing of already-completed jobs
    // and replaces full directory scans with an O(1) index lookup.
    //
    // When a duplicate is detected, the pending file is moved to the correct
    // terminal directory based on the receipt outcome (completed, denied,
    // cancelled, quarantine). This is outcome-aware to prevent denied jobs
    // from being routed to completed/ (TCK-00564 MAJOR-1 fix round 4).
    let spec = &candidate.spec;
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    if let Some(existing_receipt) =
        apm2_core::fac::find_receipt_for_job(&receipts_dir, &spec.job_id)
    {
        // BLOCKER-1 fix (round 7): Handle non-terminal outcomes explicitly.
        // If the receipt outcome is non-terminal (e.g., CancellationRequested),
        // do NOT move the job — skip it and log a warning. Only terminal
        // outcomes produce a valid target directory.
        let Some(terminal_state) =
            apm2_core::fac::outcome_to_terminal_state(existing_receipt.outcome)
        else {
            eprintln!(
                "worker: duplicate job {} has non-terminal receipt outcome {:?}, \
                 skipping move (job stays in pending/ for reconciliation)",
                spec.job_id, existing_receipt.outcome,
            );
            return JobOutcome::skipped(format!(
                "receipt already exists for job {} with non-terminal outcome {:?}, \
                 skipped (no terminal directory for this outcome)",
                spec.job_id, existing_receipt.outcome,
            ));
        };
        let terminal_dir = queue_root.join(terminal_state.dir_name());
        // BLOCKER-2 fix (round 7): Use hardened move_job_to_terminal instead
        // of move_to_dir_safe. move_job_to_terminal includes symlink checks,
        // ownership verification, and restrictive directory creation mode.
        let moved_terminal_path = match move_job_to_terminal(path, &terminal_dir, &file_name) {
            Ok(path) => path,
            Err(move_err) => {
                eprintln!(
                    "worker: duplicate job {} detected but move to terminal failed: {move_err}",
                    spec.job_id,
                );
                return JobOutcome::skipped(format!(
                    "receipt already exists for job {} but move to terminal failed: {move_err}",
                    spec.job_id,
                ));
            },
        };

        annotate_denied_job_metadata_from_receipt(&moved_terminal_path, &existing_receipt);
        return JobOutcome::skipped(format!(
            "receipt already exists for job {} (index lookup, outcome={:?})",
            spec.job_id, existing_receipt.outcome,
        ));
    }

    // NIT-2: Compute sandbox hardening hash once at the top of process_job
    // instead of re-computing it in every denial path.
    let sbx_hash = policy.sandbox_hardening.content_hash_hex();

    // TCK-00574 MAJOR-2 fix: Resolve the network policy hash immediately
    // using spec.kind (always available since spec is parsed before
    // process_job is called). This ensures ALL receipt commits — including
    // early post-parse denial paths — use the correct resolved hash for the
    // job kind, not the default-deny hash. The operator policy override is
    // threaded through to preserve FacPolicyV1.network_policy configuration.
    let resolved_net_hash =
        apm2_core::fac::resolve_network_policy(&spec.kind, policy.network_policy.as_ref())
            .content_hash_hex();

    // TCK-00622 S8: SHA-level gates dedupe.
    //
    // For `gates` jobs, deny duplicate submissions when a completed receipt
    // already exists for the same `(repo_id, head_sha)` AND the same
    // toolchain (canonicalizer_tuple_digest). Including the toolchain digest
    // ensures that a rebuilt binary re-gates the same SHA, while identical
    // binaries still benefit from dedup.
    if let Some(dupe) = find_completed_gates_duplicate(
        queue_root,
        fac_root,
        spec,
        completed_gates_cache,
        canonicalizer_tuple_digest,
    ) {
        let reason = format!(
            "already completed: repo={} sha={} kind={} existing_job_id={} matched_by={} existing_enqueue_time={}",
            spec.source.repo_id,
            spec.source.head_sha,
            spec.kind,
            dupe.existing_job_id,
            dupe.matched_by,
            dupe.existing_enqueue_time
        );
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::AlreadyCompleted),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!(
                "worker: WARNING: receipt emission failed for dedup-denied job: {receipt_err}"
            );
        }
        return JobOutcome::Denied { reason };
    }

    // Step 1+2: Use the bounded bytes already loaded by scan_pending.
    //
    // The file was already validated by `scan_pending`; this avoids duplicate I/O.
    let _ = &candidate.raw_bytes;
    // Validate structure + digest + request_id binding.
    // stop_revoke jobs use control-lane validation which now enforces the
    // RFC-0028 token at the core validation layer, consistent with the
    // worker's dual-layer authorization (token + queue directory ownership).
    let is_stop_revoke = spec.kind == "stop_revoke";
    let validation_result = if is_stop_revoke {
        validate_job_spec_control_lane_with_policy(spec, job_spec_policy)
    } else {
        validate_job_spec_with_policy(spec, job_spec_policy)
    };
    if let Err(e) = validation_result {
        let is_digest_error = matches!(
            e,
            JobSpecError::DigestMismatch { .. } | JobSpecError::RequestIdMismatch { .. }
        );
        if is_digest_error {
            let reason = format!("digest validation failed: {e}");
            // BLOCKER-3 fix (round 7): Use ReceiptWritePipeline for atomic
            // commit even for pre-claim paths. The pipeline persists the
            // receipt, updates the index, and moves the job to the terminal
            // directory using the hardened move_job_to_terminal.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                path,
                &file_name,
                FacJobOutcome::Quarantined,
                Some(DenialReasonCode::DigestMismatch),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!(
                    "worker: WARNING: pipeline commit failed for quarantined job: {commit_err}"
                );
                // Job stays in pending/ for reconciliation.
                return JobOutcome::skipped_pipeline_commit(format!(
                    "pipeline commit failed for quarantined job (digest mismatch): {commit_err}"
                ));
            }
            return JobOutcome::Quarantined { reason };
        }
        // Other validation errors (missing token, schema, etc.) -> deny.
        let reason = format!("validation failed: {e}");
        let reason_code = match e {
            JobSpecError::MissingToken { .. } => DenialReasonCode::MissingChannelToken,
            JobSpecError::InvalidDigest { .. } => DenialReasonCode::MalformedSpec,
            // TCK-00579: Policy-specific variants map to PolicyViolation
            // for distinct audit signal and automated triage.
            JobSpecError::DisallowedRepoId { .. }
            | JobSpecError::DisallowedBytesBackend { .. }
            | JobSpecError::FilesystemPathRejected { .. }
            | JobSpecError::InvalidControlLaneRepoId { .. } => DenialReasonCode::PolicyViolation,
            _ => DenialReasonCode::ValidationFailed,
        };
        // BLOCKER-3 fix (round 7): Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            path,
            &file_name,
            FacJobOutcome::Denied,
            Some(reason_code),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: pipeline commit failed for denied job: {commit_err}");
            // Job stays in pending/ for reconciliation.
            return JobOutcome::skipped_pipeline_commit(format!(
                "pipeline commit failed for denied job (validation failed): {commit_err}"
            ));
        }
        return JobOutcome::Denied { reason };
    }

    // TCK-00587: Control-lane stop_revoke with RFC-0028 token enforcement.
    //
    // Control-lane stop_revoke jobs enforce a dual-layer authorization:
    // 1. RFC-0028 token validation (signing key proof)
    // 2. Queue directory ownership validation (filesystem privilege proof)
    //
    // The cancel command issues a self-signed token using the persistent FAC
    // signing key. The worker validates this token here, ensuring only entities
    // with access to the signing key can issue valid cancellation tokens.
    if is_stop_revoke {
        // Step CL-1: Validate RFC-0028 token (fail-closed).
        // The token MUST be present and valid. Missing or invalid tokens
        // deny the job immediately — no queue-write-only authorization.
        let token = match &spec.actuation.channel_context_token {
            Some(t) if !t.is_empty() => t.as_str(),
            _ => {
                let reason = "stop_revoke missing RFC-0028 token (no unauth cancel)".to_string();
                let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                    .map(|p| {
                        p.strip_prefix(queue_root)
                            .unwrap_or(&p)
                            .to_string_lossy()
                            .to_string()
                    })
                    .ok();
                if let Err(receipt_err) = emit_job_receipt(
                    fac_root,
                    spec,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::MissingChannelToken),
                    &reason,
                    None,
                    None,
                    None,
                    None,
                    Some(canonicalizer_tuple_digest),
                    moved_path.as_deref(),
                    policy_hash,
                    None,
                    Some(&sbx_hash),
                    Some(&resolved_net_hash),
                    None, // bytes_backend
                    toolchain_fingerprint,
                ) {
                    eprintln!(
                        "worker: WARNING: receipt emission failed for denied stop_revoke: {receipt_err}"
                    );
                }
                return JobOutcome::Denied { reason };
            },
        };

        let current_time_secs = current_timestamp_epoch_secs();
        // Decode and verify the token signature+fields without binding
        // checks (control-lane tokens do not carry policy/canonicalizer
        // bindings — those are broker-issued concerns).
        let boundary_check = match apm2_core::channel::enforcement::decode_channel_context_token(
            token,
            verifying_key,
            &spec.actuation.lease_id,
            current_time_secs,
            &spec.actuation.request_id,
        ) {
            Ok(check) => check,
            Err(e) => {
                let reason = format!("stop_revoke token validation failed: {e}");
                let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                    .map(|p| {
                        p.strip_prefix(queue_root)
                            .unwrap_or(&p)
                            .to_string_lossy()
                            .to_string()
                    })
                    .ok();
                if let Err(receipt_err) = emit_job_receipt(
                    fac_root,
                    spec,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::TokenDecodeFailed),
                    &reason,
                    None,
                    None,
                    None,
                    None,
                    Some(canonicalizer_tuple_digest),
                    moved_path.as_deref(),
                    policy_hash,
                    None,
                    Some(&sbx_hash),
                    Some(&resolved_net_hash),
                    None, // bytes_backend
                    toolchain_fingerprint,
                ) {
                    eprintln!(
                        "worker: WARNING: receipt emission failed for denied stop_revoke: {receipt_err}"
                    );
                }
                return JobOutcome::Denied { reason };
            },
        };

        // Build boundary trace from real token validation results.
        let boundary_trace = ChannelBoundaryTrace {
            passed: true,
            defect_count: 0,
            defect_classes: Vec::new(),
            // Control-lane tokens do not carry policy/canonicalizer bindings;
            // populate from token_binding if present, otherwise None.
            token_fac_policy_hash: boundary_check
                .token_binding
                .as_ref()
                .map(|b| hex::encode(b.fac_policy_hash)),
            token_canonicalizer_tuple_digest: boundary_check
                .token_binding
                .as_ref()
                .map(|b| hex::encode(b.canonicalizer_tuple_digest)),
            token_boundary_id: boundary_check
                .token_binding
                .as_ref()
                .map(|b| b.boundary_id.clone()),
            token_issued_at_tick: boundary_check
                .token_binding
                .as_ref()
                .map(|b| b.issued_at_tick),
            token_expiry_tick: boundary_check.token_binding.as_ref().map(|b| b.expiry_tick),
        };
        let queue_trace = JobQueueAdmissionTrace {
            verdict: "allow".to_string(),
            queue_lane: "stop_revoke".to_string(),
            defect_reason: None,
            cost_estimate_ticks: None,
        };
        let budget_trace: Option<FacBudgetAdmissionTrace> = None;

        // Step CL-2: Verify local-origin authority via strict owner+mode
        // validation on the queue directory tree. The queue root and all
        // critical subdirectories must be owned by the current uid with
        // mode <= 0700 (no group/world access).
        {
            #[cfg(unix)]
            let current_uid = nix::unistd::geteuid().as_raw();
            #[cfg(not(unix))]
            let current_uid = 0u32;

            // Validate queue_root and all state subdirectories.
            let dirs_to_check: &[&Path] = &[
                queue_root,
                &queue_root.join(PENDING_DIR),
                &queue_root.join(CLAIMED_DIR),
                &queue_root.join(COMPLETED_DIR),
                &queue_root.join(DENIED_DIR),
                &queue_root.join(CANCELLED_DIR),
            ];
            let mut perm_err: Option<String> = None;
            for dir in dirs_to_check {
                if !dir.exists() {
                    continue;
                }
                if let Err(e) = fac_permissions::validate_directory(dir, current_uid) {
                    perm_err = Some(format!(
                        "stop_revoke local-origin authority denied: \
                         unsafe queue directory {}: {e}",
                        dir.display()
                    ));
                    break;
                }
            }
            if let Some(reason) = perm_err {
                let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                    .map(|p| {
                        p.strip_prefix(queue_root)
                            .unwrap_or(&p)
                            .to_string_lossy()
                            .to_string()
                    })
                    .ok();
                if let Err(receipt_err) = emit_job_receipt(
                    fac_root,
                    spec,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::UnsafeQueuePermissions),
                    &reason,
                    Some(&boundary_trace),
                    Some(&queue_trace),
                    budget_trace.as_ref(),
                    None,
                    Some(canonicalizer_tuple_digest),
                    moved_path.as_deref(),
                    policy_hash,
                    None,
                    Some(&sbx_hash),
                    Some(&resolved_net_hash),
                    None, // bytes_backend
                    toolchain_fingerprint,
                ) {
                    eprintln!(
                        "worker: WARNING: receipt emission failed for denied stop_revoke: {receipt_err}"
                    );
                }
                return JobOutcome::Denied { reason };
            }
        }

        // PCAC lifecycle: check if authority was already consumed.
        if is_authority_consumed(queue_root, &spec.job_id) {
            let reason = format!("authority already consumed for job {}", spec.job_id);
            let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                .map(|p| {
                    p.strip_prefix(queue_root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string()
                })
                .ok();
            if let Err(receipt_err) = emit_job_receipt(
                fac_root,
                spec,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::AuthorityAlreadyConsumed),
                &reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                budget_trace.as_ref(),
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!(
                    "worker: WARNING: receipt emission failed for denied stop_revoke: {receipt_err}"
                );
            }
            return JobOutcome::Denied { reason };
        }

        // Atomic claim via rename.
        let claimed_dir = queue_root.join(CLAIMED_DIR);
        let claimed_path = match move_to_dir_safe(path, &claimed_dir, &file_name) {
            Ok(p) => p,
            Err(e) => {
                return JobOutcome::skipped(format!("atomic claim failed: {e}"));
            },
        };
        let claimed_file_name = claimed_path
            .file_name()
            .map_or_else(|| file_name.clone(), |n| n.to_string_lossy().to_string());

        // PCAC consume.
        if let Err(e) = consume_authority(queue_root, &spec.job_id, &spec.job_spec_digest) {
            let reason = format!("PCAC consume failed: {e}");
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                &claimed_path,
                &claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::PcacConsumeFailed),
                &reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                budget_trace.as_ref(),
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied job (PCAC consume failed)",
                    &claimed_path,
                    queue_root,
                    &claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        }

        // TCK-00587: Construct stop/revoke admission trace from real
        // runtime state. Each field is derived from actual admission
        // predicates and queue state — no hardcoded constants.
        let sr_policy =
            apm2_core::economics::queue_admission::StopRevokeAdmissionPolicy::default_policy();
        let lane_state = scheduler.lane(QueueLane::StopRevoke);
        let total_items = scheduler.total_items();
        // reservation_used: true only when total queue was already at or over
        // capacity before this job was admitted (i.e., the lane reservation was
        // actually needed). Uses `>` because `total_items` includes the
        // currently admitted job.
        let reservation_used =
            total_items > apm2_core::economics::queue_admission::MAX_TOTAL_QUEUE_ITEMS;
        // Control-lane jobs bypass RFC-0029 temporal predicates entirely.
        // TP-001/002/003 are not evaluated — record None to indicate
        // "not evaluated" (distinct from Some(false) = "evaluated and failed").
        let tp001_emergency_carveout_activated = false;
        let tp002_passed: Option<bool> = None;
        let tp003_passed: Option<bool> = None;
        // tick_floor_active: true when stop_revoke items have been waiting
        // longer than the policy max_wait_ticks threshold.
        let tick_floor_active = lane_state.max_wait_ticks >= sr_policy.max_wait_ticks;
        // worker_first_pass: stop_revoke jobs have priority 0 (highest) in
        // the sorted candidate list, so they are always processed before
        // other lanes.  This is true by construction of the scan ordering.
        let worker_first_pass = sr_policy.worker_priority_first_pass;

        let sr_admission_trace = apm2_core::economics::queue_admission::StopRevokeAdmissionTrace {
            verdict: "allow".to_string(),
            reservation_used,
            tp001_emergency_carveout_activated,
            tp002_passed,
            tp003_passed,
            lane_backlog_at_admission: lane_state.backlog,
            total_queue_items_at_admission: total_items,
            tick_floor_active,
            worker_first_pass,
            policy_snapshot: sr_policy,
        };

        // Control-lane stop_revoke jobs skip lane acquisition and go
        // directly to handle_stop_revoke.
        return handle_stop_revoke(
            spec,
            &claimed_path,
            &claimed_file_name,
            queue_root,
            fac_root,
            &boundary_trace,
            &queue_trace,
            budget_trace.as_ref(),
            canonicalizer_tuple_digest,
            policy_hash,
            &sbx_hash,
            &resolved_net_hash,
            job_wall_start,
            Some(&sr_admission_trace),
            toolchain_fingerprint,
        );
    }

    // Step 2.5: Enforce admitted policy binding (INV-PADOPT-004, TCK-00561).
    // Workers MUST fail-closed when the actuation token's policy binding
    // does not match the admitted digest. This prevents policy drift where
    // tokens issued under an old policy continue to authorize actuation
    // after a new policy has been adopted.
    if !apm2_core::fac::is_policy_hash_admitted(fac_root, policy_hash) {
        let reason = format!(
            "policy hash not admitted (INV-PADOPT-004): worker policy_hash={policy_hash} is not \
             the currently admitted digest"
        );
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            path,
            &file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::PolicyAdmissionDenied),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!(
                "worker: WARNING: pipeline commit failed for policy-admission-denied job: {commit_err}"
            );
            return JobOutcome::skipped_pipeline_commit(format!(
                "pipeline commit failed for policy-admission-denied job: {commit_err}"
            ));
        }
        return JobOutcome::Denied { reason };
    }

    // Step 2.6: Enforce admitted economics profile binding (INV-EADOPT-004,
    // TCK-00584). Workers MUST fail-closed when the policy's economics
    // profile hash does not match the broker-admitted economics profile
    // digest. This prevents economics drift where profiles from an old
    // policy continue to authorize budget decisions after a new economics
    // profile has been adopted.
    //
    // Error handling is fail-closed by error variant:
    // - NoAdmittedRoot + policy has non-zero economics_profile_hash: DENY the job.
    //   The policy requires economics enforcement but there is no admitted root to
    //   verify against. An attacker could delete the root file to bypass admission
    //   — this arm prevents that (INV-EADOPT-004).
    // - NoAdmittedRoot + policy has zero economics_profile_hash: skip check
    //   (backwards compatibility for installations that have not adopted an
    //   economics profile and whose policies don't require one).
    // - Any other error (Io, Serialization, FileTooLarge, SchemaMismatch,
    //   UnsupportedSchemaVersion, etc.): DENY the job. Treating I/O/corruption
    //   errors as "no root" would let an attacker bypass admission by tampering
    //   with or removing the admitted-economics root file.
    {
        let profile_hash_str = format!("b3-256:{}", hex::encode(policy.economics_profile_hash));
        let fac_root_for_econ = fac_root;
        let econ_load_result =
            apm2_core::fac::economics_adoption::load_admitted_economics_profile_root(
                fac_root_for_econ,
            );
        let econ_denial_reason: Option<String> = match econ_load_result {
            Ok(root) => {
                // Root loaded successfully: constant-time compare hashes.
                let admitted_bytes = root.admitted_profile_hash.as_bytes();
                let check_bytes = profile_hash_str.as_bytes();
                let matches = admitted_bytes.len() == check_bytes.len()
                    && bool::from(admitted_bytes.ct_eq(check_bytes));
                if matches {
                    None // admitted -- proceed
                } else {
                    Some(format!(
                        "economics profile hash not admitted (INV-EADOPT-004): \
                         policy economics_profile_hash={profile_hash_str} is not \
                         the currently admitted digest"
                    ))
                }
            },
            Err(apm2_core::fac::EconomicsAdoptionError::NoAdmittedRoot { .. }) => {
                // No admitted root exists. Fail-closed decision based on
                // whether the policy requires economics enforcement:
                // - If the policy's economics_profile_hash is all zeros, no economics binding
                //   is required, so the check is skipped (backwards compatibility for
                //   installations that have not adopted an economics profile).
                // - If the policy's economics_profile_hash is non-zero, it specifies a concrete
                //   economics binding. Without an admitted root, we cannot verify that binding,
                //   so the job MUST be denied. This prevents bypass via root file deletion
                //   (INV-EADOPT-004).
                if policy.economics_profile_hash == [0u8; 32] {
                    None
                } else {
                    Some(format!(
                        "economics admission denied (INV-EADOPT-004, fail-closed): \
                         policy requires economics binding (economics_profile_hash={profile_hash_str}) \
                         but no admitted economics root exists on this broker"
                    ))
                }
            },
            Err(load_err) => {
                // Any other error (I/O, corruption, schema mismatch,
                // oversized file, etc.) is fail-closed: deny the job
                // to prevent admission bypass via root tampering.
                Some(format!(
                    "economics admission denied (INV-EADOPT-004, fail-closed): \
                     cannot load admitted economics root: {load_err}"
                ))
            },
        };
        if let Some(reason) = econ_denial_reason {
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                path,
                &file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::EconomicsAdmissionDenied),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!(
                    "worker: WARNING: pipeline commit failed for \
                     economics-admission-denied job: {commit_err}"
                );
                return JobOutcome::skipped_pipeline_commit(format!(
                    "pipeline commit failed for \
                     economics-admission-denied job: {commit_err}"
                ));
            }
            return JobOutcome::Denied { reason };
        }
    }

    // Step 3: Validate RFC-0028 token (non-control-lane jobs only).
    let token = match &spec.actuation.channel_context_token {
        Some(t) if !t.is_empty() => t.as_str(),
        _ => {
            let reason = "missing channel_context_token".to_string();
            let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                .map(|p| {
                    p.strip_prefix(queue_root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string()
                })
                .ok();
            // (sbx_hash computed once at top of process_job)
            if let Err(receipt_err) = emit_job_receipt(
                fac_root,
                spec,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::MissingChannelToken),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
            }
            return JobOutcome::Denied { reason };
        },
    };

    // Use monotonic wall-clock seconds for token temporal validation.
    let current_time_secs = current_timestamp_epoch_secs();

    // TCK-00565: Build expected token binding for fail-closed validation.
    // Parse the canonicalizer tuple digest from the b3-256 hex string to raw bytes.
    // Fail-closed: if the digest cannot be parsed, deny the job immediately —
    // never fall through with None (which would skip token binding validation).
    let Some(ct_digest_bytes) = parse_b3_256_digest(canonicalizer_tuple_digest) else {
        let reason = format!(
            "invalid canonicalizer tuple digest: cannot parse b3-256 hex: {canonicalizer_tuple_digest}"
        );
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::InvalidCanonicalizerDigest),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    };
    // TCK-00567: Derive expected intent from job kind for intent-binding
    // verification.  The worker denies if the token intent does not match
    // the job kind (fail-closed).  Unknown job kinds produce None from
    // job_kind_to_intent — treat as hard denial to prevent fail-open bypass.
    let Some(expected_intent) = apm2_core::fac::job_spec::job_kind_to_intent(&spec.kind) else {
        let reason = format!("unknown job kind for intent binding: {}", spec.kind);
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::UnknownJobKindIntent),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    };
    let expected_intent_str = Some(expected_intent.as_str());
    let expected_binding = ExpectedTokenBinding {
        fac_policy_hash: policy_digest,
        canonicalizer_tuple_digest: &ct_digest_bytes,
        boundary_id,
        current_tick: broker.current_tick(),
        expected_intent: expected_intent_str,
    };

    let boundary_check = match decode_channel_context_token_with_binding(
        token,
        verifying_key,
        &spec.actuation.lease_id,
        current_time_secs,
        &spec.actuation.request_id,
        Some(&expected_binding),
    ) {
        Ok(check) => check,
        Err(e) => {
            let reason = format!("token decode failed: {e}");
            let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                .map(|p| {
                    p.strip_prefix(queue_root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string()
                })
                .ok();
            // (sbx_hash computed once at top of process_job)
            if let Err(receipt_err) = emit_job_receipt(
                fac_root,
                spec,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::TokenDecodeFailed),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
            }
            return JobOutcome::Denied { reason };
        },
    };

    let admitted_policy_root_digest = if let Some(binding) =
        boundary_check.boundary_flow_policy_binding.as_ref()
    {
        if !bool::from(
            binding
                .policy_digest
                .ct_eq(&binding.admitted_policy_root_digest),
        ) {
            let reason = "policy digest mismatch within channel boundary binding".to_string();
            let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                .map(|p| {
                    p.strip_prefix(queue_root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string()
                })
                .ok();
            // (sbx_hash computed once at top of process_job)
            if let Err(receipt_err) = emit_job_receipt(
                fac_root,
                spec,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ChannelBoundaryViolation),
                &reason,
                None,
                None,
                None,
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
            }

            return JobOutcome::Denied { reason };
        }

        binding.admitted_policy_root_digest
    } else {
        let reason = "missing boundary-flow policy binding".to_string();
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ChannelBoundaryViolation),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    };

    if !broker.is_policy_digest_admitted(&admitted_policy_root_digest)
        || !bool::from(admitted_policy_root_digest.ct_eq(policy_digest))
    {
        let reason = "policy digest mismatch with admitted fac policy".to_string();
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ChannelBoundaryViolation),
            &reason,
            None,
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    // Validate boundary check defects.
    let defects = validate_channel_boundary(&boundary_check);
    // TCK-00565: Include decoded token binding in the boundary trace for receipt
    // audit.
    let boundary_trace =
        build_channel_boundary_trace_with_binding(&defects, boundary_check.token_binding.as_ref());
    if !defects.is_empty() {
        let reason = format!(
            "channel boundary violations: {}",
            defects
                .iter()
                .map(|d| strip_json_string_quotes(&serialize_to_json_string(&d.violation_class)))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ChannelBoundaryViolation),
            &reason,
            Some(&boundary_trace),
            None,
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    // TCK-00566: Token replay protection — validate nonce and record use.
    //
    // After the token is decoded and boundary defects are checked, extract
    // the nonce from the token binding and validate it against the broker's
    // token-use ledger. If the nonce is already consumed or revoked, deny
    // the job (fail-closed). If the nonce is fresh, record it so any
    // subsequent replay is detected.
    //
    // BLOCKER fix: the WAL entry MUST be persisted to disk (with fsync)
    // BEFORE job execution begins. This ensures the "consumed" state is
    // durable even if the process crashes during job execution.
    if let Some(binding) = boundary_check.token_binding.as_ref() {
        if let Some(ref nonce) = binding.nonce {
            match broker.validate_and_record_token_nonce(nonce, &spec.actuation.request_id) {
                Ok(wal_bytes) => {
                    // INV-TL-009/INV-TL-010: Persist WAL entry BEFORE job
                    // execution. If persistence fails, deny the job
                    // (fail-closed: we cannot guarantee replay protection
                    // without durable state).
                    if let Err(wal_err) = append_token_ledger_wal(&wal_bytes) {
                        let reason = format!(
                            "FATAL: token ledger WAL persist failed (fail-closed): {wal_err}"
                        );
                        eprintln!("worker: {reason}");
                        let moved_path =
                            move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                                .map(|p| {
                                    p.strip_prefix(queue_root)
                                        .unwrap_or(&p)
                                        .to_string_lossy()
                                        .to_string()
                                })
                                .ok();
                        if let Err(receipt_err) = emit_job_receipt(
                            fac_root,
                            spec,
                            FacJobOutcome::Denied,
                            Some(DenialReasonCode::TokenReplayDetected),
                            &reason,
                            Some(&boundary_trace),
                            None,
                            None,
                            None,
                            Some(canonicalizer_tuple_digest),
                            moved_path.as_deref(),
                            policy_hash,
                            None,
                            Some(&sbx_hash),
                            Some(&resolved_net_hash),
                            None, // bytes_backend
                            toolchain_fingerprint,
                        ) {
                            eprintln!(
                                "worker: WARNING: receipt emission failed for denied job: {receipt_err}"
                            );
                        }
                        return JobOutcome::Denied { reason };
                    }
                },
                Err(ledger_err) => {
                    let denial_code = match &ledger_err {
                        apm2_core::fac::token_ledger::TokenLedgerError::TokenRevoked { .. } => {
                            DenialReasonCode::TokenRevoked
                        },
                        _ => DenialReasonCode::TokenReplayDetected,
                    };
                    let reason =
                        format!("token nonce replay/revocation check failed: {ledger_err}");
                    let moved_path =
                        move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                            .map(|p| {
                                p.strip_prefix(queue_root)
                                    .unwrap_or(&p)
                                    .to_string_lossy()
                                    .to_string()
                            })
                            .ok();
                    if let Err(receipt_err) = emit_job_receipt(
                        fac_root,
                        spec,
                        FacJobOutcome::Denied,
                        Some(denial_code),
                        &reason,
                        Some(&boundary_trace),
                        None,
                        None,
                        None,
                        Some(canonicalizer_tuple_digest),
                        moved_path.as_deref(),
                        policy_hash,
                        None,
                        Some(&sbx_hash),
                        Some(&resolved_net_hash),
                        None, // bytes_backend
                        toolchain_fingerprint,
                    ) {
                        eprintln!(
                            "worker: WARNING: receipt emission failed for denied job: {receipt_err}"
                        );
                    }
                    return JobOutcome::Denied { reason };
                },
            }
        }
        // If nonce is None (pre-TCK-00566 token), skip nonce validation.
        // This is backwards-compatible: old tokens without nonces are
        // admitted based on other checks alone.
    }

    // Step 4: Evaluate RFC-0029 queue admission.
    //
    if !broker.is_admission_health_gate_passed() {
        let reason = "broker admission health gate not passed (INV-BH-003)".to_string();
        let admission_trace = JobQueueAdmissionTrace {
            verdict: "deny".to_string(),
            queue_lane: spec.queue_lane.clone(),
            defect_reason: Some("admission health gate not passed".to_string()),
            cost_estimate_ticks: None,
        };
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::AdmissionHealthGateFailed),
            &reason,
            Some(&boundary_trace),
            Some(&admission_trace),
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    let verifier = BrokerSignatureVerifier::new(*verifying_key);

    // Build a proper admission request with broker-issued authority artifacts
    // (BLOCKER-1 fix). The broker provides:
    // - TP-EIO29-001: time authority envelope (signed)
    // - TP-EIO29-002: freshness horizon + revocation frontier
    // - TP-EIO29-003: convergence horizon + convergence receipts
    let current_tick = broker.current_tick();
    let tick_end = current_tick.saturating_add(1);

    // Advance the freshness horizon so TP-EIO29-002 check passes:
    // eval_window.tick_end must be <= freshness_horizon.tick_end.
    // Without this, the default horizon (tick_end=1) is exceeded by any
    // eval_window with tick_end >= 2, causing fail-closed denial.
    broker.advance_freshness_horizon(tick_end);

    let eval_window = broker
        .build_evaluation_window(boundary_id, DEFAULT_AUTHORITY_CLOCK, current_tick, tick_end)
        .unwrap_or_else(|_| make_default_eval_window(boundary_id));

    let envelope = broker
        .issue_time_authority_envelope_default_ttl(
            boundary_id,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .ok();

    let freshness = Some(broker.freshness_horizon());
    let revocation = Some(broker.revocation_frontier());
    let convergence = Some(broker.convergence_horizon());
    let convergence_receipts = broker.convergence_receipts().to_vec();

    let admission_request = QueueAdmissionRequest {
        lane,
        envelope,
        eval_window,
        freshness_horizon: freshness,
        revocation_frontier: revocation,
        convergence_horizon: convergence,
        convergence_receipts,
        required_authority_sets: Vec::new(),
        cost: cost_model.queue_cost(&spec.kind),
        current_tick,
    };

    let decision = evaluate_queue_admission(&admission_request, scheduler, Some(&verifier));
    let queue_trace = build_queue_admission_trace(&decision);
    if decision.verdict != QueueAdmissionVerdict::Allow {
        let reason = decision.defect().map_or_else(
            || "admission denied (no defect detail)".to_string(),
            |defect| format!("admission denied: {}", defect.reason),
        );
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::QueueAdmissionDenied),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            None,
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    let (budget_tier, budget_intent_class) = job_kind_to_budget_key(&spec.kind);
    let budget_trace = {
        let budget_evaluator =
            BudgetAdmissionEvaluator::new(budget_cas, policy.economics_profile_hash);
        // Pre-execution budget admission: observed_usage reflects declared constraints
        // from the job spec, not runtime telemetry. Tokens and tool calls have no
        // pre-execution estimate. Post-execution enforcement is a separate concern.
        let observed_usage = ObservedUsage {
            tokens_used: 0,
            tool_calls_used: 0,
            time_ms_used: spec
                .constraints
                .test_timeout_seconds
                .map_or(0, |s| s.saturating_mul(1000)),
            io_bytes_used: candidate.raw_bytes.len() as u64,
        };
        let budget_decision =
            budget_evaluator.evaluate(budget_tier, budget_intent_class, &observed_usage);
        let trace = fac_budget_admission_trace(&budget_decision.trace);
        if budget_decision.verdict != BudgetAdmissionVerdict::Allow {
            let reason = budget_decision
                .deny_reason
                .as_deref()
                .unwrap_or("budget admission denied (no detail)");
            let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
                .map(|p| {
                    p.strip_prefix(queue_root)
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .to_string()
                })
                .ok();
            // (sbx_hash computed once at top of process_job)
            if let Err(receipt_err) = emit_job_receipt(
                fac_root,
                spec,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::BudgetAdmissionDenied),
                reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                Some(&trace),
                None,
                Some(canonicalizer_tuple_digest),
                moved_path.as_deref(),
                policy_hash,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!(
                    "worker: WARNING: receipt emission failed for budget-denied job: {receipt_err}"
                );
            }
            return JobOutcome::Denied {
                reason: reason.to_string(),
            };
        }
        Some(trace)
    };

    // PCAC lifecycle: check if authority was already consumed (replay protection).
    if is_authority_consumed(queue_root, &spec.job_id) {
        let reason = format!("authority already consumed for job {}", spec.job_id);
        let moved_path = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name)
            .map(|p| {
                p.strip_prefix(queue_root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string()
            })
            .ok();
        // (sbx_hash computed once at top of process_job)
        if let Err(receipt_err) = emit_job_receipt(
            fac_root,
            spec,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::AuthorityAlreadyConsumed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            moved_path.as_deref(),
            policy_hash,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            eprintln!("worker: WARNING: receipt emission failed for denied job: {receipt_err}");
        }
        return JobOutcome::Denied { reason };
    }

    // Step 5: Atomic claim + exclusive claimed lock.
    //
    // Keep this lock file alive for the entire remainder of process_job so
    // runtime reconcile's flock probe cannot reclaim actively executing jobs.
    let claimed_dir = queue_root.join(CLAIMED_DIR);
    let (claimed_path, _claimed_lock_file) =
        match claim_pending_job_with_exclusive_lock(path, &claimed_dir, &file_name) {
            Ok(result) => result,
            Err(e) => {
                // Another worker may have claimed first, or the entry failed lock
                // invariants; skip this candidate and continue.
                return JobOutcome::skipped(e);
            },
        };

    let claimed_file_name = claimed_path
        .file_name()
        .map_or_else(|| file_name.clone(), |n| n.to_string_lossy().to_string());

    // PCAC lifecycle: durable consume after atomic claim; if this fails the claimed
    // job is committed to denied/ via pipeline.
    if let Err(e) = consume_authority(queue_root, &spec.job_id, &spec.job_spec_digest) {
        let reason = format!("PCAC consume failed: {e}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::PcacConsumeFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (PCAC consume failed)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // Gates jobs are executed through the FAC gate runner directly. They are
    // already admission-checked (RFC-0028/0029) and consumed at this point.
    // Avoid acquiring a second worker lane here: `fac gates` already uses its
    // own lane lock/containment strategy for heavy phases.
    if spec.kind == "gates" {
        // TCK-00574 MAJOR-2: Use the resolved net hash computed at the top
        // of process_job (same resolve_network_policy call, now deduplicated).
        let gates_outcome = execute_queued_gates_job(
            spec,
            &claimed_path,
            &claimed_file_name,
            queue_root,
            fac_root,
            &boundary_trace,
            &queue_trace,
            budget_trace.as_ref(),
            canonicalizer_tuple_digest,
            policy_hash,
            &sbx_hash,
            &resolved_net_hash,
            heartbeat_cycle_count,
            heartbeat_jobs_completed,
            heartbeat_jobs_denied,
            heartbeat_jobs_quarantined,
            toolchain_fingerprint,
        );
        return gates_outcome;
    }

    // Step 6: Acquire lane lease (INV-WRK-008, BLOCKER-3 fix).
    //
    // Try to acquire a lane lock. If no lane is available, move the job
    // back to pending for retry in a future cycle.
    let lane_mgr = match LaneManager::new(fac_root.to_path_buf()) {
        Ok(mgr) => mgr,
        Err(e) => {
            if let Err(move_err) = move_to_dir_safe(
                &claimed_path,
                &queue_root.join(PENDING_DIR),
                &claimed_file_name,
            ) {
                eprintln!("worker: WARNING: failed to return claimed job to pending: {move_err}");
            }
            return JobOutcome::skipped(format!("lane manager init failed: {e}"));
        },
    };

    // Best-effort directory setup (ignore errors if already exists).
    let _ = lane_mgr.ensure_directories();

    let lane_ids = LaneManager::default_lane_ids();
    let Some((_lane_guard, acquired_lane_id)) = acquire_worker_lane(&lane_mgr, &lane_ids) else {
        // No lane available -> move back to pending for retry.
        if let Err(move_err) = move_to_dir_safe(
            &claimed_path,
            &queue_root.join(PENDING_DIR),
            &claimed_file_name,
        ) {
            eprintln!("worker: WARNING: failed to return claimed job to pending: {move_err}");
        }
        return JobOutcome::skipped_no_lane("no lane available, returning to pending");
    };

    if let Err(error) = run_preflight(
        fac_root,
        &lane_mgr,
        u64::from(policy.quarantine_ttl_days).saturating_mul(86400),
        u64::from(policy.denied_ttl_days).saturating_mul(86400),
    ) {
        let reason = format!("preflight failed: {error:?}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::InsufficientDiskSpace),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (preflight failed)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // Step 7: Compute authoritative Systemd properties for the acquired lane.
    // This is the single source of truth for CPU/memory/PIDs/IO/timeouts and
    // is shared between user-mode and system-mode execution backends.
    let lane_dir = lane_mgr.lane_dir(&acquired_lane_id);
    let lane_profile = match LaneProfileV1::load(&lane_dir) {
        Ok(profile) => profile,
        Err(e) => {
            let reason = format!("lane profile load failed for {acquired_lane_id}: {e}");
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                &claimed_path,
                &claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                budget_trace.as_ref(),
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied warm job (lane profile load)",
                    &claimed_path,
                    queue_root,
                    &claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };

    // Resolve network policy for this job kind (TCK-00574).
    // The hash was already computed at the top of process_job (resolved_net_hash).
    // We still need the full NetworkPolicy struct here for SystemdUnitProperties.
    let job_network_policy =
        apm2_core::fac::resolve_network_policy(&spec.kind, policy.network_policy.as_ref());
    let lane_systemd_properties = SystemdUnitProperties::from_lane_profile_with_hardening(
        &lane_profile,
        Some(&spec.constraints),
        policy.sandbox_hardening.clone(),
        job_network_policy,
    );
    if print_unit {
        eprintln!(
            "worker: computed systemd properties for job {}",
            spec.job_id
        );
        eprintln!("{}", lane_systemd_properties.to_unit_directives());
        eprintln!("worker: D-Bus properties for job {}", spec.job_id);
        eprintln!("{:?}", lane_systemd_properties.to_dbus_properties());
    }

    // Step 6b: Persist a RUNNING lease for this lane/job (INV-LANE-CLEANUP-001).
    //
    // The lane cleanup state machine in `run_lane_cleanup` requires a RUNNING
    // lease to be present. Without it, cleanup fails its precondition and
    // marks the lane CORRUPT, which deterministically exhausts lane capacity.
    //
    // Synchronization: this lease is bound to the current PID and the flock-
    // guarded lane lock held by `_lane_guard`. Only this process can write to
    // the lane directory while the lock is held.
    let lane_profile_hash = lane_profile
        .compute_hash()
        .unwrap_or_else(|_| "b3-256:unknown".to_string());

    // TCK-00538: Use toolchain fingerprint from worker startup for lane lease.
    // Worker startup is fail-closed (refuses to start without fingerprint), so
    // this should always be Some. The unwrap_or is defensive only.
    let toolchain_fp_for_lease = toolchain_fingerprint.unwrap_or("b3-256:unknown");
    let lane_lease = match build_running_lane_lease(
        &acquired_lane_id,
        &spec.job_id,
        std::process::id(),
        &lane_profile_hash,
        toolchain_fp_for_lease,
    ) {
        Ok(lease) => lease,
        Err(e) => {
            let reason = format!("failed to create lane lease: {e}");
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                &claimed_path,
                &claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(&boundary_trace),
                Some(&queue_trace),
                budget_trace.as_ref(),
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(&sbx_hash),
                Some(&resolved_net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied warm job (lane lease creation)",
                    &claimed_path,
                    queue_root,
                    &claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };
    if let Err(e) = lane_lease.persist(&lane_dir) {
        let reason = format!("failed to persist lane lease: {e}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (lane lease persist)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // Step 7: Execute job under containment.
    //
    // For the default-mode MVP, execution validates that the job is structurally
    // sound and the lane is held. Full FESv1 execution (subprocess spawning,
    // cgroup containment) is deferred to a future ticket. The lane guard ensures
    // exclusive access during this phase.
    //
    // We verify that the claimed file is still present and intact before
    // marking as completed.
    //
    // INVARIANT: A RUNNING lease is now persisted for `acquired_lane_id`.
    // Every early return from this point MUST remove the lease via
    // `LaneLeaseV1::remove(&lane_dir)` to prevent stale lease accumulation.
    if !claimed_path.exists() {
        let _ = LaneLeaseV1::remove(&lane_dir);
        return JobOutcome::skipped("claimed file disappeared during execution");
    }

    // Handle stop_revoke jobs: kill the target unit and cancel the target job.
    if spec.kind == "stop_revoke" {
        let _ = LaneLeaseV1::remove(&lane_dir);
        let stop_revoke_outcome = handle_stop_revoke(
            spec,
            &claimed_path,
            &claimed_file_name,
            queue_root,
            fac_root,
            &boundary_trace,
            &queue_trace,
            budget_trace.as_ref(),
            canonicalizer_tuple_digest,
            policy_hash,
            &sbx_hash,
            &resolved_net_hash,
            job_wall_start,
            None, // Non-control-lane stop_revoke: standard admission path
            toolchain_fingerprint,
        );
        return stop_revoke_outcome;
    }

    let mut patch_digest: Option<String> = None;
    // TCK-00546: Track which bytes_backend was used for receipt binding.
    let mut resolved_bytes_backend: Option<String> = None;
    // process_job executes one job at a time in a single worker lane, so
    // blocking mirror I/O is intentionally accepted in this default-mode
    // execution path. The entire job execution remains sequential behind the
    // lane lease and remains fail-closed on error.
    let mirror_manager = RepoMirrorManager::new(fac_root);
    if let Err(e) = mirror_manager
        .ensure_mirror(&spec.source.repo_id, None)
        .map(|(_path, _receipt)| ())
    {
        let reason = format!("mirror ensure failed: {e}");
        let _ = LaneLeaseV1::remove(&lane_dir);
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (mirror ensure)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    let lanes_root = fac_root.join("lanes");
    let lane_workspace = lane_mgr.lane_dir(&acquired_lane_id).join("workspace");
    if let Err(e) = mirror_manager.checkout_to_lane(
        &spec.source.repo_id,
        &spec.source.head_sha,
        &lane_workspace,
        &lanes_root,
    ) {
        let reason = format!("lane workspace checkout failed: {e}");
        // SEC-CTRL-LANE-CLEANUP-002: Checkout failure may leave the workspace
        // in a partially modified state. Run lane cleanup to restore isolation
        // before denying the job. On cleanup failure, the lane is marked CORRUPT.
        if let Err(cleanup_err) = execute_lane_cleanup(
            fac_root,
            &lane_mgr,
            &acquired_lane_id,
            &lane_workspace,
            &log_retention_from_policy(policy),
        ) {
            eprintln!(
                "worker: WARNING: lane cleanup during checkout-failure denial failed for {acquired_lane_id}: {cleanup_err}"
            );
            // Lane is already marked CORRUPT by execute_lane_cleanup on
            // failure.
        }
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (checkout failure)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // SEC-CTRL-LANE-CLEANUP-002: Cleanup-aware denial helper for post-checkout
    // paths.
    //
    // After workspace modification (checkout, patch application), a denial MUST
    // run `execute_lane_cleanup` to restore the workspace to a clean state.
    // Without this, the next job on the lane inherits a modified workspace,
    // violating lane isolation invariants (cross-job contamination).
    //
    // The cleanup transitions the lease to Cleanup, runs git reset + clean +
    // temp prune + log quota, then removes the lease on success. On cleanup
    // failure, the lane is marked CORRUPT via `execute_lane_cleanup`'s
    // existing corruption handling, preventing future job execution on a
    // dirty lane.
    let deny_with_reason_and_lease_cleanup = |reason: &str| -> JobOutcome {
        // Run full lane cleanup to restore workspace isolation.
        // This is the same cleanup path used after successful job completion.
        if let Err(cleanup_err) = execute_lane_cleanup(
            fac_root,
            &lane_mgr,
            &acquired_lane_id,
            &lane_workspace,
            &log_retention_from_policy(policy),
        ) {
            eprintln!(
                "worker: WARNING: lane cleanup during denial failed for {acquired_lane_id}: {cleanup_err}"
            );
            // Lane is already marked CORRUPT by execute_lane_cleanup on
            // failure. The denial receipt is still emitted below so
            // the job has a terminal receipt.
        }
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (post-checkout denial)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        JobOutcome::Denied {
            reason: reason.to_string(),
        }
    };

    if spec.source.kind == "patch_injection" {
        let patch_missing_error = "patch_injection requires a patch descriptor object";

        let Some(patch_value) = &spec.source.patch else {
            return deny_with_reason_and_lease_cleanup(patch_missing_error);
        };
        let Some(patch_obj) = patch_value.as_object() else {
            return deny_with_reason_and_lease_cleanup(patch_missing_error);
        };

        // TCK-00546: Branch on `bytes_backend` to resolve patch bytes.
        let bytes_backend = patch_obj.get("bytes_backend").and_then(|v| v.as_str());
        // MINOR-1 fix: Capture resolved_bytes_backend immediately at
        // deserialization time so both success and failure receipts carry
        // consistent metadata.  Previously this was deferred until after
        // the patch was successfully applied, leaving failure receipts
        // without bytes_backend.
        resolved_bytes_backend = bytes_backend.map(String::from);

        let patch_bytes: Vec<u8> = match bytes_backend {
            // ---- apm2_cas backend: retrieve from daemon CAS ----
            Some("apm2_cas") => {
                let Some(digest_str) = patch_obj.get("digest").and_then(|v| v.as_str()) else {
                    return deny_with_reason_and_lease_cleanup(
                        "apm2_cas backend requires a 'digest' field in patch descriptor",
                    );
                };
                let Some(hash_bytes) = apm2_core::fac::job_spec::parse_b3_256_digest(digest_str)
                else {
                    return deny_with_reason_and_lease_cleanup(&format!(
                        "invalid digest format for apm2_cas backend: {digest_str}"
                    ));
                };
                // Resolve CAS root: $APM2_HOME/private/cas (sibling of fac_root).
                let cas_root = fac_root.parent().map(|private| private.join("cas"));
                let Some(cas_root) = cas_root else {
                    return deny_with_reason_and_lease_cleanup(
                        "cannot resolve CAS root from FAC root (fail-closed)",
                    );
                };
                let reader = match apm2_core::fac::cas_reader::CasReader::new(&cas_root) {
                    Ok(r) => r,
                    Err(e) => {
                        return deny_with_reason_and_lease_cleanup(&format!(
                            "apm2_cas backend unavailable: {e} (fail-closed)"
                        ));
                    },
                };
                match reader.retrieve(&hash_bytes) {
                    Ok(bytes) => {
                        // Record the CAS reference for GC tracking.
                        if let Err(e) = apm2_core::fac::record_cas_ref(fac_root, &hash_bytes) {
                            eprintln!("worker: WARNING: failed to record CAS ref for GC: {e}");
                        }
                        bytes
                    },
                    Err(e) => {
                        return deny_with_reason_and_lease_cleanup(&format!(
                            "failed to retrieve patch from CAS: {e} (fail-closed)"
                        ));
                    },
                }
            },

            // ---- fac_blobs_v1 backend: retrieve from blob store ----
            Some("fac_blobs_v1") => {
                let Some(digest_str) = patch_obj.get("digest").and_then(|v| v.as_str()) else {
                    return deny_with_reason_and_lease_cleanup(
                        "fac_blobs_v1 backend requires a 'digest' field in patch descriptor",
                    );
                };
                let Some(hash_bytes) = apm2_core::fac::job_spec::parse_b3_256_digest(digest_str)
                else {
                    return deny_with_reason_and_lease_cleanup(&format!(
                        "invalid digest format for fac_blobs_v1 backend: {digest_str}"
                    ));
                };
                let blob_store = BlobStore::new(fac_root);
                match blob_store.retrieve(&hash_bytes) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return deny_with_reason_and_lease_cleanup(&format!(
                            "failed to retrieve patch from blob store: {e}"
                        ));
                    },
                }
            },

            // ---- Inline bytes (no backend or unknown with bytes) ----
            _ => {
                let Some(bytes_b64) = patch_obj.get("bytes").and_then(|value| value.as_str())
                else {
                    // Fail-closed: unknown backend without inline bytes.
                    let backend_desc = bytes_backend.unwrap_or("(none)");
                    return deny_with_reason_and_lease_cleanup(&format!(
                        "patch_injection: no inline bytes and unknown/missing bytes_backend={backend_desc} (fail-closed)"
                    ));
                };
                let decoded = match STANDARD.decode(bytes_b64) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        return deny_with_reason_and_lease_cleanup(&format!(
                            "invalid base64 in patch.bytes: {err}"
                        ));
                    },
                };
                // Verify digest if provided.
                if let Some(expected_digest) = patch_obj.get("digest").and_then(|v| v.as_str()) {
                    let actual_digest = format!("b3-256:{}", blake3::hash(&decoded).to_hex());
                    let expected_bytes = expected_digest.as_bytes();
                    let actual_bytes = actual_digest.as_bytes();
                    if expected_bytes.len() != actual_bytes.len()
                        || !bool::from(expected_bytes.ct_eq(actual_bytes))
                    {
                        return deny_with_reason_and_lease_cleanup(&format!(
                            "patch digest mismatch: expected {expected_digest}, got {actual_digest}"
                        ));
                    }
                }
                decoded
            },
        };

        // Store patch bytes in blob store for local caching regardless of
        // backend source.
        let blob_store = BlobStore::new(fac_root);
        if let Err(error) = blob_store.store(&patch_bytes) {
            return deny_with_reason_and_lease_cleanup(&format!(
                "failed to store patch in blob store: {error}"
            ));
        }

        let patch_outcome = match mirror_manager.apply_patch_hardened(
            &lane_workspace,
            &patch_bytes,
            PATCH_FORMAT_GIT_DIFF_V1,
        ) {
            Ok((outcome, _receipt)) => outcome,
            Err(apm2_core::fac::RepoMirrorError::PatchHardeningDenied { reason, receipt }) => {
                // TCK-00581: Map PatchHardeningDenied to explicit denial
                // with receipt metadata in the reason string for audit.
                let receipt_hash = receipt.content_hash_hex();
                let denial_reason =
                    format!("patch hardening denied: {reason} [receipt_hash={receipt_hash}]");

                // Persist the denial receipt as a standalone file for
                // provenance evidence alongside the job receipt.
                let patch_receipt_json = serde_json::json!({
                    "schema_id": receipt.schema_id,
                    "schema_version": receipt.schema_version,
                    "patch_digest": receipt.patch_digest,
                    "applied_files_count": receipt.applied_files_count,
                    "applied": receipt.applied,
                    "refusals": receipt.refusals.iter().map(|r| {
                        serde_json::json!({
                            "path": r.path,
                            "reason": r.reason,
                        })
                    }).collect::<Vec<_>>(),
                    "content_hash": receipt_hash,
                });
                let patch_receipts_dir = fac_root.join("patch_receipts");
                if let Err(e) = std::fs::create_dir_all(&patch_receipts_dir) {
                    eprintln!("worker: WARNING: failed to create patch_receipts dir: {e}");
                } else if let Ok(body) = serde_json::to_vec_pretty(&patch_receipt_json) {
                    let receipt_file = patch_receipts_dir.join(format!("{receipt_hash}.json"));
                    if let Err(e) = std::fs::write(&receipt_file, &body) {
                        eprintln!("worker: WARNING: failed to persist patch denial receipt: {e}");
                    }
                }

                // Run lane cleanup and commit denial via pipeline.
                if let Err(cleanup_err) = execute_lane_cleanup(
                    fac_root,
                    &lane_mgr,
                    &acquired_lane_id,
                    &lane_workspace,
                    &log_retention_from_policy(policy),
                ) {
                    eprintln!(
                        "worker: WARNING: lane cleanup during patch hardening denial failed for {acquired_lane_id}: {cleanup_err}"
                    );
                }
                if let Err(commit_err) = commit_claimed_job_via_pipeline(
                    fac_root,
                    queue_root,
                    spec,
                    &claimed_path,
                    &claimed_file_name,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::PatchHardeningDenied),
                    &denial_reason,
                    Some(&boundary_trace),
                    Some(&queue_trace),
                    budget_trace.as_ref(),
                    None,
                    Some(canonicalizer_tuple_digest),
                    policy_hash,
                    None,
                    None,
                    Some(&sbx_hash),
                    Some(&resolved_net_hash),
                    None, // stop_revoke_admission
                    None, // bytes_backend
                    toolchain_fingerprint,
                ) {
                    return handle_pipeline_commit_failure(
                        &commit_err,
                        "denied warm job (patch hardening denied)",
                        &claimed_path,
                        queue_root,
                        &claimed_file_name,
                    );
                }
                return JobOutcome::Denied {
                    reason: denial_reason,
                };
            },
            Err(err) => {
                return deny_with_reason_and_lease_cleanup(&format!("patch apply failed: {err}"));
            },
        };
        patch_digest = Some(patch_outcome.patch_digest);
        // (resolved_bytes_backend already captured at deserialization time
        // above)
    } else if spec.source.kind != "mirror_commit" {
        let reason = format!("unsupported source kind: {}", spec.source.kind);
        // SEC-CTRL-LANE-CLEANUP-002: This denial path is post-checkout, so the
        // workspace may have been modified by a prior checkout. Run lane cleanup
        // to restore workspace isolation before denying the job.
        if let Err(cleanup_err) = execute_lane_cleanup(
            fac_root,
            &lane_mgr,
            &acquired_lane_id,
            &lane_workspace,
            &log_retention_from_policy(policy),
        ) {
            eprintln!(
                "worker: WARNING: lane cleanup during source-kind denial failed for {acquired_lane_id}: {cleanup_err}"
            );
            // Lane is already marked CORRUPT by execute_lane_cleanup on
            // failure.
        }
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            &claimed_path,
            &claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(&boundary_trace),
            Some(&queue_trace),
            budget_trace.as_ref(),
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(&sbx_hash),
            Some(&resolved_net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (unsupported source kind)",
                &claimed_path,
                queue_root,
                &claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // Step 8: Containment verification (TCK-00548 BLOCKER-1).
    //
    // Verify that the worker's process tree is contained within the
    // expected cgroup hierarchy. This uses the current process PID as
    // the reference because the default-mode worker validates the job
    // spec in-process (no subprocess spawning yet).
    //
    // TCK-00553: sccache activation is now policy-gated. When
    // `policy.sccache_enabled` is true, sccache is active (the env
    // injection happens in `build_job_environment`). When disabled,
    // we still check ambient RUSTC_WRAPPER for legacy detection.
    let sccache_active = policy.sccache_enabled
        || std::env::var("RUSTC_WRAPPER")
            .ok()
            .is_some_and(|v| v.contains("sccache"));

    // TCK-00554: Build sccache env for server lifecycle management.
    // Defined before the containment match so it's accessible for both
    // the server containment protocol and the stop call at unit end.
    //
    // fix-round-4 MAJOR: Use lane-scoped SCCACHE_DIR to prevent server
    // lifecycle collisions across concurrent lanes. Each lane gets its own
    // sccache directory (and therefore its own Unix domain socket), so
    // --stop-server in one lane cannot terminate another lane's server.
    let sccache_server_env: Vec<(String, String)> = if policy.sccache_enabled {
        let apm2_home = resolve_apm2_home().unwrap_or_else(|| {
            fac_root
                .parent()
                .and_then(|p| p.parent())
                .unwrap_or_else(|| Path::new("/"))
                .to_path_buf()
        });
        let sccache_dir = policy
            .resolve_sccache_dir(&apm2_home)
            .join(&acquired_lane_id);
        vec![(
            "SCCACHE_DIR".to_string(),
            sccache_dir.to_string_lossy().to_string(),
        )]
    } else {
        vec![]
    };

    let containment_trace = match apm2_core::fac::containment::verify_containment(
        std::process::id(),
        sccache_active,
    ) {
        Ok(verdict) => {
            eprintln!(
                "worker: containment check: contained={} processes_checked={} mismatches={}",
                verdict.contained,
                verdict.processes_checked,
                verdict.mismatches.len(),
            );
            if !verdict.contained {
                return deny_with_reason_and_lease_cleanup(&format!(
                    "containment verification failed: contained=false processes_checked={} mismatches={}",
                    verdict.processes_checked,
                    verdict.mismatches.len()
                ));
            }
            // TCK-00553: Probe sccache version when policy enables it.
            let sccache_version = if policy.sccache_enabled {
                apm2_core::fac::containment::probe_sccache_version()
            } else {
                None
            };

            // TCK-00554: Execute sccache server containment protocol.
            //
            // When the policy enables sccache, verify that the sccache
            // server is inside the unit cgroup. If a pre-existing server
            // is outside the cgroup, refuse to use it and start a new one.
            // If server containment cannot be verified, auto-disable sccache.
            let server_containment = if policy.sccache_enabled {
                let sc = apm2_core::fac::containment::execute_sccache_server_containment_protocol(
                    std::process::id(),
                    &verdict.reference_cgroup,
                    &sccache_server_env,
                );
                eprintln!(
                    "worker: sccache server containment: protocol_executed={} \
                     server_started={} server_cgroup_verified={} auto_disabled={}",
                    sc.protocol_executed,
                    sc.server_started,
                    sc.server_cgroup_verified,
                    sc.auto_disabled,
                );
                if sc.auto_disabled {
                    eprintln!(
                        "worker: WARNING: sccache auto-disabled by server containment: {}",
                        sc.reason.as_deref().unwrap_or("unknown"),
                    );
                }
                Some(sc)
            } else {
                None
            };

            if let Some(ref sc) = server_containment {
                Some(
                    apm2_core::fac::containment::ContainmentTrace::from_verdict_with_server_containment(
                        &verdict,
                        policy.sccache_enabled,
                        sccache_version,
                        sc.clone(),
                    ),
                )
            } else {
                Some(
                    apm2_core::fac::containment::ContainmentTrace::from_verdict_with_sccache(
                        &verdict,
                        policy.sccache_enabled,
                        sccache_version,
                    ),
                )
            }
        },
        Err(err) => {
            eprintln!("worker: ERROR: containment check failed: {err}");
            return deny_with_reason_and_lease_cleanup(&format!(
                "containment verification failed: {err}"
            ));
        },
    };

    // Step 8b: Handle warm jobs (TCK-00525).
    //
    // Warm jobs execute warm phases (fetch/build/nextest/clippy/doc) using the
    // lane workspace and lane-managed CARGO_HOME/CARGO_TARGET_DIR. The warm
    // receipt is persisted to the FAC receipts directory alongside the job receipt.
    if spec.kind == "warm" {
        // TCK-00554 BLOCKER-1 fix: Derive effective sccache enablement from
        // server containment protocol result. If the containment protocol
        // auto-disabled sccache, the warm execution environment MUST NOT
        // inject RUSTC_WRAPPER/SCCACHE_* — even though `policy.sccache_enabled`
        // is true. This prevents build paths from using an untrusted server
        // that was refused by containment verification.
        let effective_sccache_enabled = policy.sccache_enabled
            && containment_trace
                .as_ref()
                .is_some_and(|ct| !ct.sccache_auto_disabled);
        let warm_outcome = execute_warm_job(
            spec,
            &claimed_path,
            &claimed_file_name,
            queue_root,
            fac_root,
            signer,
            &lane_workspace,
            &lane_dir,
            &acquired_lane_id,
            &lane_profile_hash,
            &boundary_trace,
            &queue_trace,
            budget_trace.as_ref(),
            patch_digest.as_deref(),
            canonicalizer_tuple_digest,
            policy_hash,
            containment_trace.as_ref(),
            &lane_mgr,
            &candidate.raw_bytes,
            policy,
            &lane_systemd_properties,
            &sbx_hash,
            &resolved_net_hash,
            heartbeat_cycle_count,
            heartbeat_jobs_completed,
            heartbeat_jobs_denied,
            heartbeat_jobs_quarantined,
            job_wall_start,
            toolchain_fingerprint,
            effective_sccache_enabled,
        );

        // TCK-00554: Stop sccache server at unit end (INV-CONTAIN-011).
        // MINOR-1 fix: Gate shutdown on ownership — only stop the server if
        // this unit started one or verified a pre-existing in-cgroup server.
        // This prevents one lane from terminating a shared sccache server
        // that another concurrent lane is using.
        if owns_sccache_server(containment_trace.as_ref()) && !sccache_server_env.is_empty() {
            let stopped = apm2_core::fac::stop_sccache_server(&sccache_server_env);
            eprintln!("worker: sccache server stop (warm unit end): stopped={stopped}");
        }
        return warm_outcome;
    }

    // Step 9: Write authoritative GateReceipt and move to completed.
    //
    // BLOCKER FIX (f-685-code_quality-0): Job completion is now recorded
    // BEFORE lane cleanup. This ensures that infrastructure failures in
    // the cleanup phase cannot negate a successful job execution. The job
    // outcome is decoupled from lane lifecycle management.
    let evidence_hash = compute_evidence_hash(&candidate.raw_bytes);
    let changeset_digest = compute_evidence_hash(spec.source.head_sha.as_bytes());
    let receipt_id = format!("wkr-{}-{}", spec.job_id, current_timestamp_epoch_secs());
    let gate_receipt =
        GateReceiptBuilder::new(&receipt_id, "fac-worker-exec", &spec.actuation.lease_id)
            .changeset_digest(changeset_digest)
            .executor_actor_id("fac-worker")
            .receipt_version(1)
            .payload_kind("validation-only")
            .payload_schema_version(1)
            .payload_hash(evidence_hash)
            .evidence_bundle_hash(evidence_hash)
            .job_spec_digest(&spec.job_spec_digest)
            .sandbox_hardening_hash(&sbx_hash)
            .network_policy_hash(&resolved_net_hash)
            .passed(false)
            .build_and_sign(signer);

    let observed_cost = observed_cost_from_elapsed(job_wall_start.elapsed());

    // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
    // This ensures receipt persistence, index update, and job move happen
    // in a crash-safe order via a single ReceiptWritePipeline::commit() call.
    // Persist the gate receipt alongside the completed job (before atomic commit).
    write_gate_receipt(queue_root, &claimed_file_name, &gate_receipt);

    // TCK-00538: Include toolchain fingerprint in the completed job receipt.
    if let Err(commit_err) = commit_claimed_job_via_pipeline(
        fac_root,
        queue_root,
        spec,
        &claimed_path,
        &claimed_file_name,
        FacJobOutcome::Completed,
        None,
        "completed",
        Some(&boundary_trace),
        Some(&queue_trace),
        budget_trace.as_ref(),
        patch_digest.as_deref(),
        Some(canonicalizer_tuple_digest),
        policy_hash,
        containment_trace.as_ref(),
        Some(observed_cost),
        Some(&sbx_hash),
        Some(&resolved_net_hash),
        None,                              // stop_revoke_admission
        resolved_bytes_backend.as_deref(), // TCK-00546: bytes_backend
        toolchain_fingerprint,
    ) {
        eprintln!("worker: pipeline commit failed, cannot complete job: {commit_err}");
        let _ = LaneLeaseV1::remove(&lane_dir);
        if let Err(move_err) = move_to_dir_safe(
            &claimed_path,
            &queue_root.join(PENDING_DIR),
            &claimed_file_name,
        ) {
            eprintln!("worker: WARNING: failed to return claimed job to pending: {move_err}");
        }
        // TCK-00554 MINOR-1 fix: Stop sccache server on early-return path.
        // The containment protocol may have started a server; failing to stop
        // it here would leak a daemon beyond the unit lifecycle, violating
        // INV-CONTAIN-011.
        // Gate on ownership: only stop the server this unit started/verified.
        if owns_sccache_server(containment_trace.as_ref()) && !sccache_server_env.is_empty() {
            let stopped = apm2_core::fac::stop_sccache_server(&sccache_server_env);
            eprintln!("worker: sccache server stop (pipeline commit failure): stopped={stopped}");
        }
        return JobOutcome::skipped_pipeline_commit(format!(
            "pipeline commit failed: {commit_err}"
        ));
    }

    // Step 10: Post-completion lane cleanup.
    //
    // Lane cleanup runs AFTER the job is officially completed (Step 9).
    // Cleanup failures are logged and result in lane corruption markers,
    // but they do NOT change the already-recorded job outcome. This
    // decouples infrastructure lifecycle from job execution integrity.
    if let Err(cleanup_err) = execute_lane_cleanup(
        fac_root,
        &lane_mgr,
        &acquired_lane_id,
        &lane_workspace,
        &log_retention_from_policy(policy),
    ) {
        eprintln!(
            "worker: WARNING: post-completion lane cleanup failed for {acquired_lane_id}: {cleanup_err}"
        );
        // Lane is already marked corrupt by execute_lane_cleanup on failure.
        // The job outcome remains Completed — infrastructure failures do not
        // retroactively negate successful execution.
    }

    // TCK-00554: Stop sccache server at unit end (INV-CONTAIN-011).
    // MINOR-1 fix: Gate shutdown on ownership — only stop the server if
    // this unit started one or verified a pre-existing in-cgroup server.
    // This prevents one lane from terminating a shared sccache server
    // that another concurrent lane is using.
    if owns_sccache_server(containment_trace.as_ref()) && !sccache_server_env.is_empty() {
        let stopped = apm2_core::fac::stop_sccache_server(&sccache_server_env);
        eprintln!("worker: sccache server stop (unit end): stopped={stopped}");
    }

    // Lane guard is dropped here (RAII), releasing the lane lock.
    let _ = acquired_lane_id;

    JobOutcome::Completed {
        job_id: spec.job_id.clone(),
        observed_cost: Some(observed_cost),
    }
}
