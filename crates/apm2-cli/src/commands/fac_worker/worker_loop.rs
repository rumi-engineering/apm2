#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) struct RuntimeRepairCoordinator {
    pub(super) state: RuntimeRepairState,
    pub(super) repair_requested: bool,
    pub(super) in_progress: bool,
    config: RuntimeQueueReconcileConfig,
}

impl RuntimeRepairCoordinator {
    pub(super) const fn new(config: RuntimeQueueReconcileConfig) -> Self {
        Self {
            state: RuntimeRepairState::Idle,
            repair_requested: false,
            in_progress: false,
            config,
        }
    }

    const fn transition_to(&mut self, next: RuntimeRepairState) {
        self.state = next;
    }

    pub(super) fn request(
        &mut self,
        wake_tx: &SyncSender<WorkerWakeSignal>,
        json_output: bool,
        trigger: &str,
    ) {
        let was_requested = self.repair_requested;
        self.repair_requested = true;
        if !self.in_progress {
            self.transition_to(RuntimeRepairState::RepairRequested);
        }
        if json_output {
            emit_worker_event(
                "runtime_repair_requested",
                serde_json::json!({
                    "schema": RUNTIME_REPAIR_STATE_SCHEMA,
                    "trigger": trigger,
                    "coalesced": was_requested,
                    "state": runtime_repair_state_label(self.state),
                }),
            );
        }
        if !was_requested {
            try_send_worker_signal(
                wake_tx,
                WorkerWakeSignal::Wake(WorkerWakeReason::RepairRequested),
            );
        }
    }

    pub(super) const fn mark_scan_lock_awaiting(&mut self) {
        if self.repair_requested && !self.in_progress {
            self.transition_to(RuntimeRepairState::AwaitingScanLock);
        }
    }

    pub(super) fn attempt(
        &mut self,
        fac_root: &Path,
        queue_root: &Path,
        scan_lock_held: bool,
    ) -> Option<apm2_core::fac::RuntimeQueueReconcileOutcome> {
        if !self.repair_requested {
            return None;
        }
        if !scan_lock_held {
            self.mark_scan_lock_awaiting();
            return None;
        }
        if self.in_progress {
            return None;
        }

        self.in_progress = true;
        self.transition_to(RuntimeRepairState::Reconciling);
        let outcome = reconcile_claimed_runtime(fac_root, queue_root, self.config);
        self.in_progress = false;
        self.repair_requested = !matches!(
            outcome.status,
            RuntimeQueueReconcileStatus::Applied
                | RuntimeQueueReconcileStatus::Skipped
                | RuntimeQueueReconcileStatus::Blocked
        );

        match outcome.status {
            RuntimeQueueReconcileStatus::Applied | RuntimeQueueReconcileStatus::Skipped => {
                self.transition_to(RuntimeRepairState::Reconciled);
            },
            RuntimeQueueReconcileStatus::Blocked => {
                self.transition_to(RuntimeRepairState::Blocked);
            },
            RuntimeQueueReconcileStatus::Failed => {
                self.transition_to(RuntimeRepairState::Failed);
            },
        }

        Some(outcome)
    }

    pub(super) const fn settle_idle(&mut self) {
        if matches!(
            self.state,
            RuntimeRepairState::Reconciled
                | RuntimeRepairState::Blocked
                | RuntimeRepairState::Failed
        ) && !self.repair_requested
        {
            self.transition_to(RuntimeRepairState::Idle);
        }
    }
}

pub(super) fn try_send_worker_signal(
    wake_tx: &SyncSender<WorkerWakeSignal>,
    signal: WorkerWakeSignal,
) {
    match wake_tx.try_send(signal) {
        Ok(()) | Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {},
    }
}

pub(super) fn send_critical_worker_signal(
    wake_tx: &SyncSender<WorkerWakeSignal>,
    signal: WorkerWakeSignal,
) {
    match wake_tx.try_send(signal) {
        Ok(()) | Err(TrySendError::Disconnected(_)) => {},
        Err(TrySendError::Full(signal)) => {
            let wake_tx = wake_tx.clone();
            let _ = std::thread::Builder::new()
                .name("apm2-worker-critical-wake".to_string())
                .spawn(move || {
                    let _ = wake_tx.send(signal);
                });
        },
    }
}

pub(super) fn wait_for_worker_signal(
    wake_rx: &Receiver<WorkerWakeSignal>,
    watcher_mode: &QueueWatcherMode,
    safety_nudge_secs: u64,
) -> WorkerWakeSignal {
    let bounded_backoff_secs = safety_nudge_secs.max(1);
    let bounded_backoff = Duration::from_secs(bounded_backoff_secs);

    let disconnected_backoff = || {
        // Prevent tight-loop CPU spin if the wake channel disconnects while
        // runtime remains active. We degrade to bounded safety cadence.
        std::thread::sleep(bounded_backoff);
        WorkerWakeSignal::WatcherUnavailable {
            reason: format!(
                "worker wake channel disconnected; applying bounded \
                 {bounded_backoff_secs}s safety backoff"
            ),
        }
    };

    if watcher_mode.is_degraded() {
        match wake_rx.recv_timeout(bounded_backoff) {
            Ok(signal) => signal,
            Err(RecvTimeoutError::Timeout) => WorkerWakeSignal::Wake(WorkerWakeReason::SafetyNudge),
            Err(RecvTimeoutError::Disconnected) => disconnected_backoff(),
        }
    } else {
        wake_rx.recv().unwrap_or_else(|_| disconnected_backoff())
    }
}

pub(super) fn request_runtime_repair_for_wake(
    repair_coordinator: &mut RuntimeRepairCoordinator,
    wake_tx: &SyncSender<WorkerWakeSignal>,
    watcher_mode: &QueueWatcherMode,
    wake_reason: WorkerWakeReason,
    json_output: bool,
) {
    match wake_reason {
        WorkerWakeReason::ClaimedQueueChanged => {
            repair_coordinator.request(wake_tx, json_output, "queue_claimed_fs_changed");
        },
        WorkerWakeReason::WatcherDegraded if watcher_mode.is_degraded() => {
            repair_coordinator.request(wake_tx, json_output, "queue_watcher_degraded");
        },
        WorkerWakeReason::SafetyNudge if watcher_mode.is_degraded() => {
            repair_coordinator.request(wake_tx, json_output, "degraded_safety_nudge");
        },
        _ => {},
    }
}

pub(super) fn emit_watcher_degraded_diagnostic(
    json_output: bool,
    reason: &str,
    safety_nudge_secs: u64,
) {
    if json_output {
        emit_worker_event(
            "queue_watcher_degraded",
            serde_json::json!({
                "reason": reason,
                "safety_nudge_secs": safety_nudge_secs,
            }),
        );
    } else {
        eprintln!(
            "worker: queue watcher degraded ({reason}); entering bounded safety-nudge mode \
             (interval={safety_nudge_secs}s). remediation: run `apm2 fac doctor --fix` if stuck claimed persists"
        );
    }
}

pub(super) fn emit_runtime_reconcile_outcome(
    json_output: bool,
    outcome: &apm2_core::fac::RuntimeQueueReconcileOutcome,
) {
    let status = match outcome.status {
        RuntimeQueueReconcileStatus::Applied => "applied",
        RuntimeQueueReconcileStatus::Skipped => "skipped",
        RuntimeQueueReconcileStatus::Blocked => "blocked",
        RuntimeQueueReconcileStatus::Failed => "failed",
    };
    if json_output {
        emit_worker_event(
            "runtime_claimed_reconcile",
            serde_json::json!({
                "schema": outcome.schema,
                "status": status,
                "lanes_inspected": outcome.lanes_inspected,
                "claimed_files_inspected": outcome.claimed_files_inspected,
                "orphaned_jobs_requeued": outcome.orphaned_jobs_requeued,
                "orphaned_jobs_failed": outcome.orphaned_jobs_failed,
                "torn_states_recovered": outcome.torn_states_recovered,
                "still_active": outcome.still_active,
                "reason": outcome.reason,
                "doctor_remediation": matches!(outcome.status, RuntimeQueueReconcileStatus::Blocked | RuntimeQueueReconcileStatus::Failed),
            }),
        );
    } else if matches!(
        outcome.status,
        RuntimeQueueReconcileStatus::Blocked | RuntimeQueueReconcileStatus::Failed
    ) {
        let detail = outcome.reason.as_deref().unwrap_or("unknown");
        eprintln!(
            "worker: runtime claimed reconcile {status}: {detail}. remediation: `apm2 fac doctor --fix`"
        );
    }
}

#[cfg(target_os = "linux")]
pub(super) fn spawn_queue_watch_thread(
    queue_root: &Path,
    wake_tx: SyncSender<WorkerWakeSignal>,
) -> Result<std::thread::JoinHandle<()>, String> {
    let pending_dir = queue_root.join(PENDING_DIR);
    let claimed_dir = queue_root.join(CLAIMED_DIR);
    let watch_mask = AddWatchFlags::IN_CREATE
        | AddWatchFlags::IN_CLOSE_WRITE
        | AddWatchFlags::IN_DELETE
        | AddWatchFlags::IN_MOVED_FROM
        | AddWatchFlags::IN_MOVED_TO;

    let inotify = Inotify::init(InitFlags::IN_CLOEXEC)
        .map_err(|error| format!("inotify init failed: {error}"))?;
    let pending_watch = inotify
        .add_watch(&pending_dir, watch_mask)
        .map_err(|error| format!("inotify add watch pending failed: {error}"))?;
    let claimed_watch = inotify
        .add_watch(&claimed_dir, watch_mask)
        .map_err(|error| format!("inotify add watch claimed failed: {error}"))?;

    Ok(std::thread::spawn(move || {
        let inotify = inotify;

        loop {
            let events = match inotify.read_events() {
                Ok(events) => events,
                Err(error) => {
                    send_critical_worker_signal(
                        &wake_tx,
                        WorkerWakeSignal::WatcherUnavailable {
                            reason: format!("inotify read failed: {error}"),
                        },
                    );
                    break;
                },
            };

            let mut pending_changed = false;
            let mut claimed_changed = false;
            for event in events {
                if event.mask.contains(AddWatchFlags::IN_Q_OVERFLOW) {
                    send_critical_worker_signal(
                        &wake_tx,
                        WorkerWakeSignal::WatcherOverflow {
                            reason: "inotify queue overflow (events may be lost)".to_string(),
                        },
                    );
                    return;
                }
                if event.wd == pending_watch {
                    pending_changed = true;
                } else if event.wd == claimed_watch {
                    claimed_changed = true;
                }
            }

            if pending_changed {
                try_send_worker_signal(
                    &wake_tx,
                    WorkerWakeSignal::Wake(WorkerWakeReason::PendingQueueChanged),
                );
            }
            if claimed_changed {
                try_send_worker_signal(
                    &wake_tx,
                    WorkerWakeSignal::Wake(WorkerWakeReason::ClaimedQueueChanged),
                );
            }
        }
    }))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn spawn_queue_watch_thread(
    _queue_root: &Path,
    _wake_tx: SyncSender<WorkerWakeSignal>,
) -> Result<std::thread::JoinHandle<()>, String> {
    Err(
        "queue watcher unavailable on this platform; runtime falls back to safety nudge mode"
            .to_string(),
    )
}

/// Runs the FAC worker, returning an exit code.
///
/// The worker scans the pending queue, validates each job spec against
/// RFC-0028 and RFC-0029, and atomically claims valid jobs. In default
/// mode, the broker and worker share a single process: the same
/// `FacBroker` instance issues tokens and provides the verifying key.
///
/// # Arguments
///
/// * `once` - If true, process at most one job and exit.
/// * `max_jobs` - Maximum total jobs to process before exiting (0 = unlimited).
/// * `json_output` - If true, emit JSON output.
/// * `print_unit` - If true, print systemd unit directives/properties for each
///   job.
pub(super) fn run_fac_worker_impl(
    once: bool,
    max_jobs: u64,
    json_output: bool,
    print_unit: bool,
) -> u8 {
    let safety_nudge_secs = DEGRADED_SAFETY_NUDGE_SECS;
    if json_output {
        emit_worker_event(
            "worker_started",
            serde_json::json!({
                "once": once,
                "safety_nudge_secs": safety_nudge_secs,
                "max_jobs": max_jobs,
                "queue_activation_mode": "event_driven_with_degraded_safety_nudge",
            }),
        );
    }

    // FU-003 (TCK-00625): Emit binary identity event at startup for
    // postmortem correlation. Includes resolved exe path, SHA-256 digest,
    // PID, and timestamp. This aids diagnosis of INV-PADOPT-004-class
    // binary drift incidents.
    emit_binary_identity_event(json_output);

    // Resolve queue root directory
    let queue_root = match resolve_queue_root() {
        Ok(root) => root,
        Err(e) => {
            output_worker_error(json_output, &format!("cannot resolve queue root: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };
    let fac_root = match resolve_fac_root() {
        Ok(root) => root,
        Err(e) => {
            output_worker_error(json_output, &format!("cannot resolve FAC root: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };

    // TCK-00565 MAJOR-1 fix: Load the actual boundary_id from FAC node identity
    // instead of using a hardcoded constant. Falls back to FALLBACK_BOUNDARY_ID
    // only when APM2 home cannot be resolved (no-home edge case).
    let boundary_id = resolve_apm2_home()
        .and_then(|home| load_or_default_boundary_id(&home).ok())
        .unwrap_or_else(|| FALLBACK_BOUNDARY_ID.to_string());

    // Ensure queue directories exist
    if let Err(e) = ensure_queue_dirs(&queue_root) {
        output_worker_error(
            json_output,
            &format!("cannot create queue directories: {e}"),
        );
        return exit_codes::GENERIC_ERROR;
    }

    let ownership_backend = match resolve_ownership_backend(json_output) {
        Ok(backend) => backend,
        Err(e) => {
            output_worker_error(json_output, &e);
            return exit_codes::GENERIC_ERROR;
        },
    };

    if let Err(msg) =
        validate_worker_service_user_ownership(&fac_root, &queue_root, ownership_backend)
    {
        output_worker_error(json_output, &msg);
        return exit_codes::GENERIC_ERROR;
    }

    // Load persistent signing key for stable broker identity and receipts across
    // restarts.
    let persistent_signer = match load_or_generate_persistent_signer() {
        Ok(signer) => signer,
        Err(e) => {
            output_worker_error(json_output, &format!("cannot load signing key: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };
    let persistent_signer_key_bytes = persistent_signer.secret_key_bytes().to_vec();

    let signer = match Signer::from_bytes(&persistent_signer_key_bytes) {
        Ok(s) => s,
        Err(e) => {
            output_worker_error(
                json_output,
                &format!("cannot initialize receipt signer: {e}"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    };

    let mk_default_state_broker = || {
        let default_state = apm2_core::fac::broker::BrokerState::default();
        let signer = Signer::from_bytes(&persistent_signer_key_bytes).ok()?;
        FacBroker::from_signer_and_state(signer, default_state).ok()
    };

    // Create broker for token verification and admission evaluation.
    // In default mode, the broker and worker share a process: the same
    // FacBroker instance issues tokens AND verifies them. This is documented
    // as a limitation of default-mode operation. Distributed workers would
    // need to load the broker's persisted verifying key.
    let mut broker = load_broker_state().map_or_else(
        || mk_default_state_broker().unwrap_or_else(FacBroker::new),
        |state| {
            Signer::from_bytes(&persistent_signer_key_bytes)
                .ok()
                .and_then(|signer| FacBroker::from_signer_and_state(signer, state).ok())
                .unwrap_or_else(|| mk_default_state_broker().unwrap_or_else(FacBroker::new))
        },
    );

    // TCK-00566: Load persisted token ledger if available. The ledger
    // survives restarts so replay protection is not lost on daemon restart.
    // INV-TL-009: Load errors from an existing file are hard security faults.
    match load_token_ledger(broker.current_tick()) {
        Ok(Some(ledger)) => {
            broker.set_token_ledger(ledger);
        },
        Ok(None) => {
            // No persisted ledger (first run). Fresh ledger already
            // initialized.
        },
        Err(e) => {
            let msg = format!("FATAL: token ledger load failed (fail-closed): {e}");
            output_worker_error(json_output, &msg);
            return exit_codes::GENERIC_ERROR;
        },
    }

    let (mut queue_state, mut cost_model) = match load_scheduler_state(&fac_root) {
        Ok(Some(saved)) => {
            let cm = saved
                .cost_model
                .clone()
                .unwrap_or_else(apm2_core::economics::CostModelV1::with_defaults);
            (QueueSchedulerState::from_persisted(&saved), cm)
        },
        Ok(None) => {
            let recovery = SchedulerRecoveryReceipt {
                schema: SCHEDULER_RECOVERY_SCHEMA.to_string(),
                reason: "scheduler state missing, reconstructing conservatively".to_string(),
                timestamp_secs: current_timestamp_epoch_secs(),
            };
            if json_output {
                emit_worker_event(
                    "scheduler_recovery",
                    serde_json::json!({
                        "schema": recovery.schema,
                        "reason": recovery.reason,
                        "timestamp_secs": recovery.timestamp_secs,
                    }),
                );
            } else {
                eprintln!(
                    "INFO: scheduler state reconstructed: {} ({}, {})",
                    recovery.schema, recovery.reason, recovery.timestamp_secs
                );
            }
            (
                QueueSchedulerState::new(),
                apm2_core::economics::CostModelV1::with_defaults(),
            )
        },
        Err(e) => {
            let recovery = SchedulerRecoveryReceipt {
                schema: SCHEDULER_RECOVERY_SCHEMA.to_string(),
                reason: "scheduler state missing or corrupt, reconstructing conservatively"
                    .to_string(),
                timestamp_secs: current_timestamp_epoch_secs(),
            };
            if json_output {
                emit_worker_event(
                    "scheduler_recovery",
                    serde_json::json!({
                        "schema": recovery.schema,
                        "reason": recovery.reason,
                        "timestamp_secs": recovery.timestamp_secs,
                        "load_error": e,
                    }),
                );
            } else {
                eprintln!("WARNING: failed to load scheduler state: {e}, starting fresh");
                eprintln!(
                    "INFO: scheduler state reconstructed: {} ({}, {})",
                    recovery.schema, recovery.reason, recovery.timestamp_secs
                );
            }
            (
                QueueSchedulerState::new(),
                apm2_core::economics::CostModelV1::with_defaults(),
            )
        },
    };

    // Perform admission health gate check so the broker can issue tokens.
    // In default (local) mode we use minimal health check inputs.
    let mut checker = apm2_core::fac::broker_health::BrokerHealthChecker::new();

    // Issue a time authority envelope from the broker so RFC-0029 admission
    // has valid TP-EIO29-001 authority. Without this, admission always denies
    // fail-closed due to missing envelope.
    let current_tick = broker.current_tick();
    let tick_end = current_tick.saturating_add(1);
    let eval_window = broker
        .build_evaluation_window(
            &boundary_id,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .unwrap_or_else(|_| make_default_eval_window(&boundary_id));

    // Advance freshness to keep startup checks in sync with the first
    // admission window.
    broker.advance_freshness_horizon(tick_end);

    let startup_envelope = broker
        .issue_time_authority_envelope_default_ttl(
            &boundary_id,
            DEFAULT_AUTHORITY_CLOCK,
            current_tick,
            tick_end,
        )
        .ok();

    let _health = broker.check_health(startup_envelope.as_ref(), &eval_window, &[], &mut checker);
    if let Err(e) =
        broker.evaluate_admission_health_gate(&checker, &eval_window, WorkerHealthPolicy::default())
    {
        output_worker_error(json_output, &format!("admission health gate failed: {e}"));
        return exit_codes::GENERIC_ERROR;
    }

    let (policy_hash, policy_digest, policy) = match load_or_create_policy(&fac_root) {
        Ok(policy) => policy,
        Err(e) => {
            output_worker_error(json_output, &format!("cannot load fac policy: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };

    // TCK-00579: Derive job spec validation policy from FAC policy.
    // This enables repo_id allowlist, bytes_backend allowlist, and
    // filesystem-path rejection at worker pre-claim time.
    let job_spec_policy = match policy.job_spec_validation_policy() {
        Ok(p) => p,
        Err(e) => {
            output_worker_error(
                json_output,
                &format!("cannot derive job spec validation policy: {e}"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    };

    let budget_cas = MemoryCas::new();
    let baseline_profile = EconomicsProfile::default_baseline();
    if let Err(e) = baseline_profile.store_in_cas(&budget_cas) {
        output_worker_error(
            json_output,
            &format!("cannot seed baseline economics profile in CAS: {e}"),
        );
        return exit_codes::GENERIC_ERROR;
    }
    // Verify that the policy's economics_profile_hash is resolvable from CAS.
    // Currently only the baseline profile is available. If the policy references
    // a different hash (future custom profile), we cannot resolve it — fail
    // explicitly rather than silently denying all jobs.
    let baseline_hash = baseline_profile.profile_hash().unwrap_or([0u8; 32]);
    if policy.economics_profile_hash != baseline_hash && policy.economics_profile_hash != [0u8; 32]
    {
        output_worker_error(
            json_output,
            &format!(
                "fac policy references economics profile hash {:x?} which is not loaded in CAS; \
                 only baseline profile (hash {:x?}) is currently supported",
                &policy.economics_profile_hash[..8],
                &baseline_hash[..8],
            ),
        );
        return exit_codes::GENERIC_ERROR;
    }

    if let Err(e) = broker.admit_policy_digest(policy_digest) {
        output_worker_error(json_output, &format!("cannot admit fac policy digest: {e}"));
        return exit_codes::GENERIC_ERROR;
    }

    let current_tuple = CanonicalizerTupleV1::from_current();
    let current_tuple_digest = compute_canonicalizer_tuple_digest();
    match check_or_admit_canonicalizer_tuple(&fac_root) {
        Ok(CanonicalizerTupleCheck::Matched) => {},
        Ok(CanonicalizerTupleCheck::Missing) => {
            output_worker_error(
                json_output,
                "no admitted canonicalizer tuple found. run `apm2 fac canonicalizer admit` to bootstrap",
            );
            return exit_codes::GENERIC_ERROR;
        },
        Ok(CanonicalizerTupleCheck::Mismatch(admitted_tuple)) => {
            output_worker_error(
                json_output,
                &format!(
                    "canonicalizer tuple mismatch (current={}/{}, admitted={}/{}). remedy: re-run broker admission or update binary",
                    current_tuple.canonicalizer_id,
                    current_tuple.canonicalizer_version,
                    admitted_tuple.canonicalizer_id,
                    admitted_tuple.canonicalizer_version
                ),
            );
            return exit_codes::GENERIC_ERROR;
        },
        Err(e) => {
            output_worker_error(
                json_output,
                &format!("cannot initialize canonicalizer tuple: {e}"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    }

    let verifying_key = broker.verifying_key();

    // TCK-00534: Crash recovery — reconcile queue/claimed and lane leases on
    // worker startup. Detects stale leases (PID dead, lock released) and
    // orphaned claimed jobs, then recovers them deterministically with receipts.
    {
        let _ = apm2_core::fac::sd_notify::notify_status("reconciling queue and lane state");
        match apm2_core::fac::reconcile_on_startup(
            &fac_root,
            &queue_root,
            apm2_core::fac::OrphanedJobPolicy::Requeue,
            false, // apply mutations
        ) {
            Ok(receipt) => {
                let recovered = receipt.stale_leases_recovered
                    + receipt.orphaned_jobs_requeued
                    + receipt.orphaned_jobs_failed;
                if json_output {
                    emit_worker_event(
                        "reconcile_complete",
                        serde_json::json!({
                            "schema": receipt.schema,
                            "lanes_inspected": receipt.lanes_inspected,
                            "stale_leases_recovered": receipt.stale_leases_recovered,
                            "orphaned_jobs_requeued": receipt.orphaned_jobs_requeued,
                            "orphaned_jobs_failed": receipt.orphaned_jobs_failed,
                            "lanes_marked_corrupt": receipt.lanes_marked_corrupt,
                            "claimed_files_inspected": receipt.claimed_files_inspected,
                        }),
                    );
                } else if recovered > 0 {
                    eprintln!(
                        "INFO: reconciliation recovered {} items \
                         (stale_leases={}, requeued={}, failed={}, corrupt={})",
                        recovered,
                        receipt.stale_leases_recovered,
                        receipt.orphaned_jobs_requeued,
                        receipt.orphaned_jobs_failed,
                        receipt.lanes_marked_corrupt,
                    );
                }
            },
            Err(e) => {
                // Reconciliation failure is fatal: the worker must not process
                // new jobs while queue/lane state may be inconsistent from a
                // prior crash. Fail-closed to prevent duplicate execution or
                // stale state interference (INV-RECON-001, INV-RECON-002).
                if json_output {
                    emit_worker_event(
                        "reconcile_error",
                        serde_json::json!({ "error": e.to_string() }),
                    );
                } else {
                    eprintln!("ERROR: reconciliation failed, cannot start worker: {e}");
                }
                return exit_codes::GENERIC_ERROR;
            },
        }
    }

    // TCK-00538: Resolve toolchain fingerprint with cache-first strategy.
    // Fail-closed: if fingerprint resolution fails, the worker refuses to
    // start. The fingerprint is required for receipt integrity and lane
    // target namespacing.
    //
    // Cache path: $APM2_HOME/private/fac/toolchain/fingerprint.v1.json
    // Cache validation: re-derive fingerprint from stored raw_versions and
    // compare (INV-TC-004). If mismatch, recompute fresh.
    let toolchain_fingerprint: String = {
        let mut probe_env = std::collections::BTreeMap::new();
        if let Ok(path) = std::env::var("PATH") {
            probe_env.insert("PATH".to_string(), path);
        }
        if let Ok(home) = std::env::var("HOME") {
            probe_env.insert("HOME".to_string(), home);
        }
        if let Ok(user) = std::env::var("USER") {
            probe_env.insert("USER".to_string(), user);
        }

        // Step 1: Try loading cache (bounded read, O_NOFOLLOW via
        // fac_secure_io::read_bounded).
        let cache_path = toolchain_cache_file_path(&fac_root);
        let cache_bytes = if cache_path.exists() {
            fac_secure_io::read_bounded(&cache_path, TOOLCHAIN_MAX_CACHE_FILE_BYTES).ok()
        } else {
            None
        };

        // Step 2: Resolve fingerprint (cache-first, fresh fallback).
        match resolve_toolchain_fingerprint_cached(&probe_env, cache_bytes.as_deref()) {
            Ok((fp, versions)) => {
                // Step 3: Persist cache atomically if we computed fresh
                // (i.e. cache was missing or invalid). We detect this by
                // checking whether the returned fingerprint differs from
                // what was in the cache.
                let cache_was_valid = cache_bytes
                    .as_deref()
                    .and_then(apm2_core::fac::validate_cached_fingerprint)
                    .is_some_and(|cached_fp| cached_fp == fp);

                if !cache_was_valid {
                    // Ensure cache directory exists with restricted perms
                    // (dir 0o700).
                    let tc_cache_dir = toolchain_cache_dir(&fac_root);
                    if let Err(e) = fac_permissions::ensure_dir_with_mode(&tc_cache_dir) {
                        // Cache write failure is non-fatal: log and continue.
                        // The fingerprint was successfully computed.
                        if json_output {
                            emit_worker_event(
                                "toolchain_cache_dir_error",
                                serde_json::json!({
                                    "path": tc_cache_dir.display().to_string(),
                                    "error": e.to_string(),
                                }),
                            );
                        }
                    } else if let Ok(cache_data) = serialize_cache(&fp, &versions) {
                        // Atomic write with restricted perms (file 0o600,
                        // O_NOFOLLOW, symlink-safe via
                        // write_fac_file_with_mode).
                        if let Err(e) =
                            fac_permissions::write_fac_file_with_mode(&cache_path, &cache_data)
                        {
                            // Cache write failure is non-fatal.
                            if json_output {
                                emit_worker_event(
                                    "toolchain_cache_write_error",
                                    serde_json::json!({
                                        "path": cache_path.display().to_string(),
                                        "error": e.to_string(),
                                    }),
                                );
                            }
                        }
                    }
                }
                fp
            },
            Err(e) => {
                output_worker_error(
                    json_output,
                    &format!(
                        "toolchain fingerprint computation failed: {e} \
                         (fail-closed: fingerprint required for receipts and lane target namespacing)"
                    ),
                );
                return exit_codes::GENERIC_ERROR;
            },
        }
    };

    let mut total_processed: u64 = 0;
    let mut cycle_count: u64 = 0;
    let mut summary = WorkerSummary {
        jobs_processed: 0,
        jobs_completed: 0,
        jobs_denied: 0,
        jobs_quarantined: 0,
        jobs_skipped: 0,
    };

    // TCK-00600: Notify systemd that the worker is ready and spawn a
    // background thread for watchdog pings. The background thread pings
    // independently of the job processing loop, preventing systemd from
    // restarting the worker during long-running jobs (process_job can
    // take minutes). The daemon already uses this pattern (background
    // poller task). The thread is marked as a daemon thread and will
    // exit when the main worker thread exits.
    let _ = apm2_core::fac::sd_notify::notify_ready();
    let _ =
        apm2_core::fac::sd_notify::notify_status("worker ready, waiting for queue wake signals");

    // Spawn a background thread for watchdog pings, independent of job
    // processing. This follows the same pattern as the daemon's poller
    // task which pings in a background tokio::spawn.
    //
    // Synchronization protocol (RS-21):
    // - Protected data: `watchdog_stop` AtomicBool.
    // - Writer: main thread sets `true` on exit (Release).
    // - Reader: background thread checks with Acquire ordering.
    // - Happens-before: Release store → Acquire load ensures the stop signal is
    //   visible to the background thread.
    let watchdog_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog_stop_bg = std::sync::Arc::clone(&watchdog_stop);
    let _watchdog_thread = {
        let ticker = apm2_core::fac::sd_notify::WatchdogTicker::new();
        if ticker.is_enabled() {
            let ping_interval = Duration::from_secs(ticker.ping_interval_secs());
            Some(std::thread::spawn(move || {
                let mut bg_ticker = ticker;
                loop {
                    std::thread::sleep(ping_interval);
                    if watchdog_stop_bg.load(std::sync::atomic::Ordering::Acquire) {
                        break;
                    }
                    bg_ticker.ping_if_due();
                }
            }))
        } else {
            None
        }
    };

    let (wake_tx, wake_rx) = mpsc::sync_channel::<WorkerWakeSignal>(WORKER_WAKE_SIGNAL_BUFFER);
    let mut watcher_mode = QueueWatcherMode::Active;
    let _queue_watcher_thread = match spawn_queue_watch_thread(&queue_root, wake_tx.clone()) {
        Ok(handle) => Some(handle),
        Err(reason) => {
            watcher_mode.transition_to_degraded(reason.clone());
            emit_watcher_degraded_diagnostic(json_output, &reason, safety_nudge_secs);
            None
        },
    };

    let mut repair_coordinator = RuntimeRepairCoordinator::new(RuntimeQueueReconcileConfig {
        orphan_policy: OrphanedJobPolicy::Requeue,
        limits: QueueReconcileLimits::default(),
    });
    let mut pending_wake_reason = Some(if watcher_mode.is_degraded() {
        WorkerWakeReason::WatcherDegraded
    } else {
        WorkerWakeReason::Startup
    });

    loop {
        let effective_wake_reason = pending_wake_reason.take().map_or_else(
            || match wait_for_worker_signal(&wake_rx, &watcher_mode, safety_nudge_secs) {
                WorkerWakeSignal::Wake(reason) => reason,
                WorkerWakeSignal::WatcherUnavailable { reason }
                | WorkerWakeSignal::WatcherOverflow { reason } => {
                    if watcher_mode.transition_to_degraded(reason.clone()) {
                        emit_watcher_degraded_diagnostic(json_output, &reason, safety_nudge_secs);
                    }
                    WorkerWakeReason::WatcherDegraded
                },
            },
            std::convert::identity,
        );
        request_runtime_repair_for_wake(
            &mut repair_coordinator,
            &wake_tx,
            &watcher_mode,
            effective_wake_reason,
            json_output,
        );

        cycle_count = cycle_count.saturating_add(1);
        if matches!(effective_wake_reason, WorkerWakeReason::SafetyNudge) && json_output {
            emit_worker_event(
                "worker_safety_nudge",
                serde_json::json!({
                    "reason": watcher_mode.reason(),
                    "safety_nudge_secs": safety_nudge_secs,
                }),
            );
        }
        let heartbeat_status = if watcher_mode.is_degraded() {
            "degraded"
        } else {
            "healthy"
        };

        // TCK-00600: Write worker heartbeat file for `services status`.
        if let Err(e) = apm2_core::fac::worker_heartbeat::write_heartbeat(
            &fac_root,
            cycle_count,
            summary.jobs_completed as u64,
            summary.jobs_denied as u64,
            summary.jobs_quarantined as u64,
            heartbeat_status,
        ) {
            // Non-fatal: heartbeat is observability, not correctness.
            if !json_output {
                eprintln!("WARNING: heartbeat write failed: {e}");
            }
        }

        // S10: Proactively reap orphaned LEASED lanes on each wake cycle.
        reap_orphaned_leases_on_tick(&fac_root, json_output);

        // TCK-00586: Multi-worker fairness — try scan lock before scanning.
        //
        // When multiple workers poll the same queue, redundant directory scans
        // cause a CPU/IO stampede. The optional scan lock ensures at most one
        // worker scans per cycle; others wait with jitter and rely on atomic
        // claim (rename) for correctness.
        //
        // The lock is purely advisory: if acquisition fails due to I/O error
        // the worker falls through to scan anyway (fail-open for availability,
        // correctness preserved by atomic rename).
        let scan_lock_guard = match try_acquire_scan_lock(&queue_root) {
            Ok(ScanLockResult::Acquired(guard)) => Some(guard),
            Ok(ScanLockResult::Held) => {
                // Another worker holds the scan lock. Check for stuck lock
                // and emit receipt if detected.
                if let Ok(Some(stuck_receipt)) = check_stuck_scan_lock(&queue_root) {
                    if json_output {
                        emit_worker_event(
                            "scan_lock_stuck",
                            serde_json::json!({
                                "schema": stuck_receipt.schema,
                                "stuck_holder_pid": stuck_receipt.stuck_holder_pid,
                                "acquired_epoch_secs": stuck_receipt.acquired_epoch_secs,
                                "detected_epoch_secs": stuck_receipt.detected_epoch_secs,
                                "held_duration_secs": stuck_receipt.held_duration_secs,
                            }),
                        );
                    } else {
                        eprintln!(
                            "WARNING: scan lock stuck (holder_pid={}, held={}s)",
                            stuck_receipt.stuck_holder_pid, stuck_receipt.held_duration_secs,
                        );
                    }
                    // Persist stuck receipt for audit.
                    let receipt_json =
                        serde_json::to_string_pretty(&stuck_receipt).unwrap_or_default();
                    let _ = persist_scan_lock_stuck_receipt(&fac_root, &receipt_json);
                }

                // Skip scan this cycle; sleep with jitter to avoid thundering
                // herd retries.
                repair_coordinator.mark_scan_lock_awaiting();
                if once {
                    // In --once mode we cannot skip; fall through to scan
                    // regardless (correctness via atomic rename).
                    None
                } else {
                    let jitter =
                        apm2_core::fac::scan_lock::scan_lock_jitter_duration(safety_nudge_secs);
                    std::thread::sleep(jitter);
                    continue;
                }
            },
            Ok(ScanLockResult::Unavailable) => None, // No queue dir yet; scan anyway.
            Err(e) => {
                // I/O error acquiring lock; log and fall through to scan.
                // Fail-open: availability over efficiency.
                if !json_output {
                    eprintln!("WARNING: scan lock acquisition failed: {e}");
                }
                None
            },
        };

        // TCK-00577: Promote broker requests from non-service-user
        // callers into pending/ before scanning. The loaded FAC policy's
        // queue_bounds_policy is threaded through to ensure broker
        // promotion enforces the same configured limits as enqueue_direct.
        promote_broker_requests(&queue_root, &policy.queue_bounds_policy);

        if let Some(runtime_outcome) =
            repair_coordinator.attempt(&fac_root, &queue_root, scan_lock_guard.is_some())
        {
            emit_runtime_reconcile_outcome(json_output, &runtime_outcome);
            repair_coordinator.settle_idle();
        }

        // Scan pending directory (quarantines malformed files inline).
        let candidates = match scan_pending(
            &queue_root,
            &fac_root,
            &current_tuple_digest,
            Some(toolchain_fingerprint.as_str()),
        ) {
            Ok(c) => c,
            Err(e) => {
                output_worker_error(json_output, &format!("scan error: {e}"));
                if once {
                    if let Err(persist_err) = persist_queue_scheduler_state(
                        &fac_root,
                        &queue_state,
                        broker.current_tick(),
                        Some(&cost_model),
                    ) {
                        output_worker_error(json_output, &persist_err);
                    }
                    return exit_codes::GENERIC_ERROR;
                }
                std::thread::sleep(Duration::from_secs(safety_nudge_secs.max(1)));
                pending_wake_reason = Some(WorkerWakeReason::SafetyNudge);
                continue;
            },
        };

        // Drop the scan lock guard now that scanning is complete.
        // This releases the flock so other workers can proceed.
        drop(scan_lock_guard);

        let mut cycle_scheduler = queue_state.clone();
        let mut completed_gates_cache: Option<CompletedGatesCache> = None;

        if candidates.is_empty() {
            if once {
                if let Err(persist_err) = persist_queue_scheduler_state(
                    &fac_root,
                    &cycle_scheduler,
                    broker.current_tick(),
                    Some(&cost_model),
                ) {
                    output_worker_error(json_output, &persist_err);
                    return exit_codes::GENERIC_ERROR;
                }
                let _ = save_broker_state(&broker);
                if let Err(e) = save_token_ledger(&mut broker) {
                    output_worker_error(json_output, &format!("token ledger save failed: {e}"));
                    return exit_codes::GENERIC_ERROR;
                }
                if json_output {
                    emit_worker_summary(&summary);
                } else {
                    eprintln!("worker: no pending jobs found");
                }
                return exit_codes::SUCCESS;
            }
            continue;
        }

        // TCK-00587: Anti-starvation two-pass semantics. Candidates are
        // sorted by (priority ASC, enqueue_time ASC, job_id ASC) where
        // StopRevoke priority = 0 (highest). This ordering guarantees all
        // stop_revoke jobs in the cycle are processed before any lower-
        // priority lane, providing first-pass anti-starvation without
        // requiring a separate scan pass. The StopRevokeAdmissionTrace
        // records `worker_first_pass: true` to document this guarantee.
        for candidate in &candidates {
            if max_jobs > 0 && total_processed >= max_jobs {
                break;
            }
            if json_output {
                emit_worker_event(
                    "job_started",
                    serde_json::json!({
                        "job_id": candidate.spec.job_id,
                        "queue_lane": candidate.spec.queue_lane,
                    }),
                );
            }

            let job_started = Instant::now();
            let lane = parse_queue_lane(&candidate.spec.queue_lane);
            let outcome = if let Err(e) = cycle_scheduler.record_admission(lane) {
                JobOutcome::Denied {
                    reason: format!("scheduler admission reservation failed: {e}"),
                }
            } else {
                let mut orchestrator = WorkerOrchestrator::new();
                let mut staged_outcome: Option<JobOutcome> = None;
                let lane_id = candidate.spec.queue_lane.clone();
                let mut transition_count = 0usize;
                let outcome = loop {
                    transition_count = transition_count.saturating_add(1);
                    if transition_count > 16 {
                        break JobOutcome::skipped(
                            "orchestrator transition budget exceeded before completion",
                        );
                    }

                    match orchestrator.step() {
                        StepOutcome::Advanced => match orchestrator.state() {
                            OrchestratorState::Idle => {
                                orchestrator.transition(OrchestratorState::Claimed {
                                    job_id: candidate.spec.job_id.clone(),
                                });
                            },
                            OrchestratorState::Claimed { .. } => {
                                orchestrator.transition(OrchestratorState::LaneAcquired {
                                    job_id: candidate.spec.job_id.clone(),
                                    lane_id: lane_id.clone(),
                                });
                            },
                            OrchestratorState::LaneAcquired { .. } => {
                                orchestrator.transition(OrchestratorState::LeasePersisted {
                                    job_id: candidate.spec.job_id.clone(),
                                    lane_id: lane_id.clone(),
                                });
                            },
                            OrchestratorState::LeasePersisted { .. } => {
                                orchestrator.transition(OrchestratorState::Executing {
                                    job_id: candidate.spec.job_id.clone(),
                                    lane_id: lane_id.clone(),
                                });
                            },
                            OrchestratorState::Executing { .. } => {
                                orchestrator.transition(OrchestratorState::Committing {
                                    job_id: candidate.spec.job_id.clone(),
                                    lane_id: lane_id.clone(),
                                });
                            },
                            OrchestratorState::Committing { .. } => {
                                if staged_outcome.is_none() {
                                    staged_outcome = Some(process_job(
                                        candidate,
                                        &queue_root,
                                        &fac_root,
                                        &mut completed_gates_cache,
                                        &verifying_key,
                                        &cycle_scheduler,
                                        lane,
                                        &mut broker,
                                        &signer,
                                        &policy_hash,
                                        &policy_digest,
                                        &policy,
                                        &job_spec_policy,
                                        &budget_cas,
                                        candidates.len(),
                                        print_unit,
                                        &current_tuple_digest,
                                        &boundary_id,
                                        cycle_count,
                                        summary.jobs_completed as u64,
                                        summary.jobs_denied as u64,
                                        summary.jobs_quarantined as u64,
                                        &cost_model,
                                        Some(toolchain_fingerprint.as_str()),
                                    ));
                                }
                                let committed_outcome =
                                    staged_outcome.take().unwrap_or_else(|| {
                                        JobOutcome::skipped(
                                            "orchestrator reached committing without staged outcome",
                                        )
                                    });
                                orchestrator.complete_with_outcome(
                                    candidate.spec.job_id.clone(),
                                    committed_outcome,
                                );
                            },
                            OrchestratorState::Completed { .. } => {},
                        },
                        StepOutcome::Done(done) => break done,
                        StepOutcome::Skipped(reason) => {
                            break staged_outcome
                                .take()
                                .unwrap_or_else(|| JobOutcome::skipped(reason));
                        },
                    }
                };
                cycle_scheduler.record_completion(lane);
                outcome
            };
            let duration_secs = job_started.elapsed().as_secs();
            let _orchestration_classification =
                classify_job_outcome_for_orchestration(&candidate.spec.job_id, &outcome);

            match &outcome {
                JobOutcome::Quarantined { reason } => {
                    summary.jobs_quarantined += 1;
                    if json_output {
                        emit_worker_event(
                            "job_failed",
                            serde_json::json!({
                                "job_id": candidate.spec.job_id,
                                "outcome": "quarantined",
                                "queue_lane": candidate.spec.queue_lane,
                                "duration_secs": duration_secs,
                                "reason": reason,
                            }),
                        );
                    }
                    if !json_output {
                        eprintln!("worker: quarantined {}: {reason}", candidate.path.display());
                    }
                },
                JobOutcome::Aborted { reason } => {
                    summary.jobs_denied += 1;
                    if !json_output {
                        eprintln!("worker: aborted {}: {reason}", candidate.spec.job_id);
                    }
                },
                JobOutcome::Denied { reason } => {
                    summary.jobs_denied += 1;
                    if json_output {
                        emit_worker_event(
                            "job_failed",
                            serde_json::json!({
                                "job_id": candidate.spec.job_id,
                                "outcome": "denied",
                                "queue_lane": candidate.spec.queue_lane,
                                "duration_secs": duration_secs,
                                "reason": reason,
                            }),
                        );
                    }
                    if !json_output {
                        eprintln!("worker: denied {}: {reason}", candidate.spec.job_id);
                    }
                },
                JobOutcome::Completed {
                    job_id,
                    observed_cost,
                } => {
                    summary.jobs_completed += 1;
                    append_completed_gates_fingerprint_if_loaded(
                        &mut completed_gates_cache,
                        &candidate.spec,
                        &current_tuple_digest,
                    );

                    if let Some(cost) = observed_cost {
                        let job_kind = &candidate.spec.kind;
                        if let Err(cal_err) = cost_model.calibrate(job_kind, cost) {
                            if !json_output {
                                eprintln!(
                                    "worker: cost model calibration warning for kind \
                                     '{job_kind}': {cal_err}"
                                );
                            }
                        }
                    }
                    if json_output {
                        emit_worker_event(
                            "job_completed",
                            serde_json::json!({
                                "job_id": job_id,
                                "outcome": "completed",
                                "queue_lane": candidate.spec.queue_lane,
                                "duration_secs": duration_secs,
                            }),
                        );
                    }
                    if !json_output {
                        eprintln!("worker: completed {job_id}");
                    }
                },
                JobOutcome::Skipped {
                    reason,
                    disposition,
                } => {
                    summary.jobs_skipped += 1;
                    if *disposition == JobSkipDisposition::PipelineCommitFailed {
                        repair_coordinator.request(&wake_tx, json_output, "commit_pipeline_failed");
                    }
                    if json_output {
                        emit_worker_event(
                            "job_skipped",
                            serde_json::json!({
                                "job_id": candidate.spec.job_id,
                                "outcome": "skipped",
                                "queue_lane": candidate.spec.queue_lane,
                                "duration_secs": duration_secs,
                                "reason": reason,
                            }),
                        );
                    }
                    if !json_output {
                        eprintln!("worker: skipped: {reason}");
                    }
                },
            }

            summary.jobs_processed += 1;
            total_processed += 1;

            if matches!(
                &outcome,
                JobOutcome::Skipped {
                    disposition: JobSkipDisposition::NoLaneAvailable,
                    ..
                }
            ) {
                break;
            }
            if matches!(&outcome, JobOutcome::Aborted { .. }) {
                break;
            }

            if once {
                if let Err(persist_err) = persist_queue_scheduler_state(
                    &fac_root,
                    &cycle_scheduler,
                    broker.current_tick(),
                    Some(&cost_model),
                ) {
                    output_worker_error(json_output, &persist_err);
                    return exit_codes::GENERIC_ERROR;
                }
                let _ = save_broker_state(&broker);
                if let Err(e) = save_token_ledger(&mut broker) {
                    output_worker_error(json_output, &format!("token ledger save failed: {e}"));
                    return exit_codes::GENERIC_ERROR;
                }
                if json_output {
                    emit_worker_summary(&summary);
                }
                return exit_codes::SUCCESS;
            }
        }

        if let Err(persist_err) = persist_queue_scheduler_state(
            &fac_root,
            &cycle_scheduler,
            broker.current_tick(),
            Some(&cost_model),
        ) {
            output_worker_error(json_output, &persist_err);
            return exit_codes::GENERIC_ERROR;
        }
        queue_state = cycle_scheduler;

        if max_jobs > 0 && total_processed >= max_jobs {
            break;
        }

        if once {
            break;
        }
    }

    // Signal the background watchdog thread to stop.
    watchdog_stop.store(true, std::sync::atomic::Ordering::Release);

    if json_output {
        emit_worker_summary(&summary);
    }

    if let Err(persist_err) = persist_queue_scheduler_state(
        &fac_root,
        &queue_state,
        broker.current_tick(),
        Some(&cost_model),
    ) {
        output_worker_error(json_output, &persist_err);
        return exit_codes::GENERIC_ERROR;
    }
    let _ = save_broker_state(&broker);
    if let Err(e) = save_token_ledger(&mut broker) {
        output_worker_error(json_output, &format!("token ledger save failed: {e}"));
        return exit_codes::GENERIC_ERROR;
    }
    exit_codes::SUCCESS
}

pub(super) fn emit_binary_identity_event(json_output: bool) {
    use std::io::Read;

    use sha2::{Digest, Sha256};

    let pid = std::process::id();
    let ts = worker_ts_now();

    let exe_path = match std::env::current_exe() {
        Ok(p) => p.canonicalize().unwrap_or(p),
        Err(e) => {
            if json_output {
                emit_worker_event(
                    "binary_identity",
                    serde_json::json!({
                        "pid": pid,
                        "error": format!("cannot resolve current_exe: {e}"),
                    }),
                );
            } else {
                eprintln!(
                    "INFO: binary_identity: pid={pid} error=\"cannot resolve current_exe: {e}\""
                );
            }
            return;
        },
    };

    let digest = std::fs::File::open(&exe_path).map_or_else(
        |_| "open_error".to_string(),
        |file| {
            let metadata_ok = file
                .metadata()
                .is_ok_and(|m| m.len() <= MAX_STARTUP_BINARY_DIGEST_SIZE);
            if metadata_ok {
                let mut reader = std::io::BufReader::new(file.take(MAX_STARTUP_BINARY_DIGEST_SIZE));
                let mut hasher = Sha256::new();
                let mut buf = [0u8; 8192];
                let mut ok = true;
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => hasher.update(&buf[..n]),
                        Err(_) => {
                            ok = false;
                            break;
                        },
                    }
                }
                if ok {
                    format!("sha256:{:x}", hasher.finalize())
                } else {
                    "read_error".to_string()
                }
            } else {
                "oversized_or_unreadable".to_string()
            }
        },
    );

    let exe_display = exe_path.display().to_string();

    if json_output {
        emit_worker_event(
            "binary_identity",
            serde_json::json!({
                "binary_path": exe_display,
                "binary_digest": digest,
                "pid": pid,
            }),
        );
    } else {
        eprintln!("INFO: binary_identity: path={exe_display} digest={digest} pid={pid} ts={ts}");
    }
}
