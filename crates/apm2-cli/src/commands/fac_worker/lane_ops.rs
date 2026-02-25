#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn reap_orphaned_leases_on_tick(fac_root: &Path, json_output: bool) {
    let lane_mgr = match LaneManager::new(fac_root.to_path_buf()) {
        Ok(manager) => manager,
        Err(err) => {
            tracing::warn!(error = %err, "lane maintenance skipped: cannot initialize lane manager");
            return;
        },
    };

    for lane_id in LaneManager::default_lane_ids() {
        let lane_dir = lane_mgr.lane_dir(&lane_id);
        let status = match lane_mgr.lane_status(&lane_id) {
            Ok(status) => status,
            Err(err) => {
                tracing::warn!(lane_id = lane_id.as_str(), error = %err, "lane maintenance status read failed");
                continue;
            },
        };
        let loaded_lease = match LaneLeaseV1::load(&lane_dir) {
            Ok(lease) => lease,
            Err(err) => {
                tracing::warn!(
                    lane_id = lane_id.as_str(),
                    error = %err,
                    "lane maintenance lease load failed"
                );
                None
            },
        };
        let orphaned = match loaded_lease.as_ref() {
            Some(lease) => {
                lease.state == LaneState::Leased
                    && matches!(
                        check_process_identity(lease),
                        ProcessIdentity::Dead | ProcessIdentity::AliveMismatch
                    )
            },
            None => status.state == LaneState::Leased && status.pid.is_none(),
        };
        if !orphaned {
            continue;
        }

        let expected_runtime_secs = load_lane_expected_runtime_secs(&lane_mgr, &lane_id);
        let warning_threshold_secs =
            expected_runtime_secs.saturating_mul(ORPHAN_LEASE_WARNING_MULTIPLIER);
        let now_epoch_secs = current_timestamp_epoch_secs();
        let started_at_raw = loaded_lease
            .as_ref()
            .map(|lease| lease.started_at.clone())
            .or_else(|| status.started_at.clone());
        let started_at_canonical = loaded_lease
            .as_ref()
            .and_then(LaneLeaseV1::started_at_rfc3339);
        let age_secs = loaded_lease
            .as_ref()
            .and_then(|lease| lease.age_secs(now_epoch_secs));
        if age_secs.is_none_or(|age| age >= warning_threshold_secs) {
            if json_output {
                emit_worker_event(
                    "lane_orphan_lease_warning",
                    serde_json::json!({
                        "lane_id": lane_id,
                        "state": status.state.to_string(),
                        "pid": status.pid,
                        "pid_alive": status.pid_alive,
                        "started_at_raw": started_at_raw,
                        "started_at_canonical": started_at_canonical,
                        "age_secs": age_secs,
                        "warning_threshold_secs": warning_threshold_secs,
                    }),
                );
            } else {
                eprintln!(
                    "WARNING: orphaned lane lease detected (lane={}, pid={:?}, pid_alive={:?}, started_at_raw={:?}, started_at_canonical={:?}, age_secs={:?}, threshold_secs={})",
                    lane_id,
                    status.pid,
                    status.pid_alive,
                    started_at_raw,
                    started_at_canonical,
                    age_secs,
                    warning_threshold_secs
                );
            }
        }

        match lane_mgr.try_lock(&lane_id) {
            Ok(Some(_guard)) => {
                if let Some(lease) = loaded_lease.as_ref() {
                    let liveness = check_fac_unit_liveness(&lane_id, &lease.job_id);
                    if !matches!(liveness, FacUnitLiveness::Inactive) {
                        let reason = build_orphaned_systemd_lane_reason(&lane_id, lease, &liveness);
                        tracing::warn!(
                            lane_id = lane_id.as_str(),
                            job_id = lease.job_id.as_str(),
                            pid = lease.pid,
                            reason = reason.as_str(),
                            "orphaned lease reap blocked due to orphaned systemd unit evidence"
                        );
                        if let Err(err) = persist_corrupt_marker_with_retries(
                            lane_mgr.fac_root(),
                            &lane_id,
                            &reason,
                            None,
                        ) {
                            tracing::error!(
                                lane_id = lane_id.as_str(),
                                error = %err,
                                "failed to persist corrupt marker for blocked orphan-lease reap"
                            );
                        }
                        if json_output {
                            emit_worker_event(
                                "lane_orphan_lease_reap_blocked",
                                serde_json::json!({
                                    "lane_id": lane_id,
                                    "job_id": lease.job_id,
                                    "pid": lease.pid,
                                    "reason_code": ORPHANED_SYSTEMD_UNIT_REASON_CODE,
                                    "reason": reason,
                                }),
                            );
                        }
                        continue;
                    }
                }
                match LaneLeaseV1::remove(&lane_dir) {
                    Ok(()) => {
                        tracing::warn!(
                            lane_id = lane_id.as_str(),
                            pid = ?status.pid,
                            pid_alive = ?status.pid_alive,
                            "reaped orphaned lane lease during poll tick"
                        );
                        if json_output {
                            emit_worker_event(
                                "lane_orphan_lease_reaped",
                                serde_json::json!({
                                    "lane_id": lane_id,
                                    "pid": status.pid,
                                    "pid_alive": status.pid_alive,
                                }),
                            );
                        }
                    },
                    Err(err) => {
                        tracing::warn!(
                            lane_id = lane_id.as_str(),
                            error = %err,
                            "failed to remove orphaned lease during poll tick"
                        );
                    },
                }
            },
            Ok(None) => {
                tracing::debug!(
                    lane_id = lane_id.as_str(),
                    "orphaned lease reap deferred: lane lock held"
                );
            },
            Err(err) => {
                tracing::warn!(
                    lane_id = lane_id.as_str(),
                    error = %err,
                    "orphaned lease reap failed: could not acquire lane lock"
                );
            },
        }
    }
}

pub(super) fn load_lane_expected_runtime_secs(lane_mgr: &LaneManager, lane_id: &str) -> u64 {
    let lane_dir = lane_mgr.lane_dir(lane_id);
    LaneProfileV1::load(&lane_dir)
        .map(|profile| profile.timeouts.job_runtime_max_seconds)
        .unwrap_or(1_800)
}

pub(super) fn build_running_lane_lease(
    lane_id: &str,
    job_id: &str,
    pid: u32,
    lane_profile_hash: &str,
    toolchain_fingerprint: &str,
) -> Result<LaneLeaseV1, apm2_core::fac::lane::LaneError> {
    let lease_started_at = current_time_iso8601();
    LaneLeaseV1::new(
        lane_id,
        job_id,
        pid,
        LaneState::Running,
        &lease_started_at,
        lane_profile_hash,
        toolchain_fingerprint,
    )
}

pub(super) fn owns_sccache_server(
    containment_trace: Option<&apm2_core::fac::containment::ContainmentTrace>,
) -> bool {
    let Some(trace) = containment_trace else {
        return false;
    };
    let Some(ref sc) = trace.sccache_server_containment else {
        return false;
    };
    if !sc.protocol_executed {
        return false;
    }
    // This unit started a new server — must stop it regardless of auto_disabled.
    if sc.server_started || sc.started_server_pid.is_some() {
        return true;
    }
    // This unit adopted a pre-existing in-cgroup server.
    if sc.preexisting_server_detected && sc.preexisting_server_in_cgroup == Some(true) {
        return true;
    }
    false
}

/// Check lease process identity using PID + proc start-time binding.
///
/// Returns `AliveMismatch` when PID was reused and now points to another
/// process, allowing stale lease recovery without treating the lane as active.
pub(super) fn check_process_identity(lease: &LaneLeaseV1) -> ProcessIdentity {
    verify_pid_identity(lease.pid, lease.proc_start_time_ticks)
}

/// Emit a structured reset recommendation for a corrupt lane to **stderr**.
///
/// Channel contract (RFC-0032::REQ-0220 scope):
/// - **stderr** carries machine-readable NDJSON recommendations (this fn) as
///   `apm2.fac.lane_reset_recommendation.v1` JSON lines.
/// - All other diagnostics in `acquire_worker_lane` use `tracing::warn!` /
///   `tracing::info!` / `tracing::error!` (structured logging), never raw
///   `eprintln!`, so the only `eprintln!` output from the lane-acquisition path
///   is the JSON recommendation itself.  This keeps the stderr channel
///   JSON-only for downstream automation.
///
/// Every line written to stderr by this function is a valid, parseable JSON
/// object.  Human-readable context is encoded inside the `message` field of
/// the JSON payload rather than emitted as a separate plain-text line.
///
/// This is a best-effort diagnostic -- the worker must not abort lane
/// scanning due to a recommendation emission failure.  Serialization
/// errors are routed through `tracing::warn!` (structured logging) so they
/// never pollute the JSON-only stderr recommendation stream.
pub(super) fn emit_lane_reset_recommendation(lane_id: &str, reason: &str) {
    let rec = LaneResetRecommendation {
        schema: LANE_RESET_RECOMMENDATION_SCHEMA,
        lane_id: lane_id.to_string(),
        message: format!("worker: RECOMMENDATION: lane {lane_id} needs reset"),
        reason: reason.to_string(),
        recommended_action: "apm2 fac doctor --fix",
    };
    match serde_json::to_string(&rec) {
        Ok(json) => {
            // Write to stderr — the machine-readable NDJSON recommendation
            // channel (RFC-0032::REQ-0220 scope: "JSON to stderr").  All other
            // diagnostics in acquire_worker_lane use tracing::* macros,
            // keeping the only eprintln! output as this JSON line.
            eprintln!("{json}");
        },
        Err(e) => tracing::warn!(
            lane_id = lane_id,
            error = %e,
            "failed to serialize reset recommendation (non-fatal)"
        ),
    }
}

pub(super) fn build_orphaned_systemd_lane_reason(
    lane_id: &str,
    lease: &LaneLeaseV1,
    liveness: &FacUnitLiveness,
) -> String {
    let detail = match liveness {
        FacUnitLiveness::Active { active_units } => {
            let preview = active_units
                .iter()
                .take(4)
                .map(std::string::String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            if preview.is_empty() {
                format!(
                    "associated systemd units still active (count={})",
                    active_units.len()
                )
            } else {
                let suffix = if active_units.len() > 4 { " +more" } else { "" };
                format!(
                    "associated systemd units still active (count={}, units=[{preview}]{suffix})",
                    active_units.len()
                )
            }
        },
        FacUnitLiveness::Unknown { reason } => {
            format!("systemd liveness probe inconclusive ({reason}); fail-closed")
        },
        FacUnitLiveness::Inactive => "no active associated systemd units".to_string(),
    };
    truncate_receipt_reason(&format!(
        "{ORPHANED_SYSTEMD_UNIT_REASON_CODE}: lane={lane_id} job_id={} pid={} reclaim blocked: {detail}",
        lease.job_id, lease.pid
    ))
}

pub(super) fn acquire_worker_lane(
    lane_mgr: &LaneManager,
    lane_ids: &[String],
) -> Option<(LaneLockGuard, String)> {
    for lane_id in lane_ids {
        let guard = match lane_mgr.try_lock(lane_id) {
            Ok(Some(guard)) => guard,
            Ok(None) => continue,
            Err(err) => {
                tracing::warn!(
                    lane_id = lane_id.as_str(),
                    error = %err,
                    "failed to probe lane"
                );
                continue;
            },
        };

        match LaneCorruptMarkerV1::load(lane_mgr.fac_root(), lane_id) {
            Ok(Some(marker)) => {
                tracing::warn!(
                    lane_id = lane_id.as_str(),
                    reason = marker.reason.as_str(),
                    "skipping corrupt lane"
                );
                // RFC-0032::REQ-0220: Emit structured reset recommendation for corrupt lane.
                emit_lane_reset_recommendation(lane_id, &marker.reason);
            },
            Ok(None) => {
                let lane_dir = lane_mgr.lane_dir(lane_id);
                match LaneLeaseV1::load(&lane_dir) {
                    Ok(Some(lease)) => match lease.state {
                        LaneState::Corrupt => {
                            tracing::warn!(
                                lane_id = lane_id.as_str(),
                                state = %lease.state,
                                "skipping corrupt lease lane"
                            );
                            // RFC-0032::REQ-0220: Emit structured reset recommendation for
                            // corrupt lease state.
                            emit_lane_reset_recommendation(
                                lane_id,
                                &format!("lease state is {}", lease.state),
                            );
                        },
                        LaneState::Running | LaneState::Cleanup => {
                            match check_process_identity(&lease) {
                                identity @ (ProcessIdentity::Dead
                                | ProcessIdentity::AliveMismatch) => {
                                    let reclaim_observation =
                                        if matches!(identity, ProcessIdentity::Dead) {
                                            "pid is dead"
                                        } else {
                                            "pid identity mismatch (PID reuse)"
                                        };
                                    let liveness = check_fac_unit_liveness(lane_id, &lease.job_id);
                                    if matches!(liveness, FacUnitLiveness::Inactive) {
                                        tracing::info!(
                                            lane_id = lane_id.as_str(),
                                            pid = lease.pid,
                                            job_id = lease.job_id.as_str(),
                                            observation = reclaim_observation,
                                            "stale lease recovery: reclaiming lane"
                                        );
                                        let _ = LaneLeaseV1::remove(&lane_dir);
                                        return Some((guard, lane_id.clone()));
                                    }

                                    let reason = build_orphaned_systemd_lane_reason(
                                        lane_id, &lease, &liveness,
                                    );
                                    tracing::warn!(
                                        lane_id = lane_id.as_str(),
                                        pid = lease.pid,
                                        job_id = lease.job_id.as_str(),
                                        observation = reclaim_observation,
                                        reason = reason.as_str(),
                                        "stale lease reclaim blocked due to orphaned systemd unit evidence"
                                    );
                                    if let Err(err) = persist_corrupt_marker_with_retries(
                                        lane_mgr.fac_root(),
                                        lane_id,
                                        &reason,
                                        None,
                                    ) {
                                        tracing::error!(
                                            lane_id = lane_id.as_str(),
                                            error = %err,
                                            "failed to persist corrupt marker for blocked stale lease reclaim"
                                        );
                                    }
                                    emit_lane_reset_recommendation(lane_id, &reason);
                                },
                                ProcessIdentity::AliveMatch => {
                                    // Process identity still matches the lease owner.
                                    // We have the flock but the owner appears alive —
                                    // unexpected/inconsistent. Mark as corrupt.
                                    let reason = format!(
                                        "lane has RUNNING lease for pid {} with matching identity while flock is held (unexpected)",
                                        lease.pid
                                    );
                                    tracing::warn!(
                                        lane_id = lane_id.as_str(),
                                        reason = reason.as_str(),
                                        "marking lane as corrupt"
                                    );
                                    if let Err(err) = persist_corrupt_marker_with_retries(
                                        lane_mgr.fac_root(),
                                        lane_id,
                                        &reason,
                                        None,
                                    ) {
                                        tracing::error!(
                                            lane_id = lane_id.as_str(),
                                            error = %err,
                                            "failed to persist corrupt marker for lane"
                                        );
                                    }
                                    // RFC-0032::REQ-0220: Emit structured reset recommendation
                                    // after marking lane corrupt.
                                    emit_lane_reset_recommendation(lane_id, &reason);
                                },
                                ProcessIdentity::Unknown => {
                                    let reason = if lease.proc_start_time_ticks.is_none() {
                                        "lease missing proc_start_time_ticks; cannot verify identity".to_string()
                                    } else {
                                        "process identity verification failed (procfs or liveness probe error)".to_string()
                                    };
                                    tracing::warn!(
                                        lane_id = lane_id.as_str(),
                                        pid = lease.pid,
                                        reason = reason.as_str(),
                                        recommended_action = "apm2 fac doctor --fix",
                                        "skipping lane because lease identity is unknown"
                                    );
                                },
                            }
                        },
                        _ => {
                            return Some((guard, lane_id.clone()));
                        },
                    },
                    Ok(None) => return Some((guard, lane_id.clone())),
                    Err(err) => {
                        tracing::warn!(
                            lane_id = lane_id.as_str(),
                            error = %err,
                            "skipping lane after lease load failed"
                        );
                    },
                }
            },
            Err(err) => {
                tracing::warn!(
                    lane_id = lane_id.as_str(),
                    error = %err,
                    "skipping lane after corrupt marker check failed"
                );
            },
        }
    }

    None
}

/// Build a `LogRetentionConfig` from `FacPolicyV1` fields (RFC-0032::REQ-0221).
///
/// This is the single conversion point ensuring post-job cleanup and GC
/// derive their retention config from the same policy fields.
pub(super) fn log_retention_from_policy(policy: &FacPolicyV1) -> LogRetentionConfig {
    LogRetentionConfig {
        per_lane_log_max_bytes: policy.per_lane_log_max_bytes,
        per_job_log_ttl_secs: u64::from(policy.per_job_log_ttl_days).saturating_mul(24 * 3600),
        keep_last_n_jobs_per_lane: policy.keep_last_n_jobs_per_lane,
    }
}

/// Run lane cleanup and emit cleanup receipts.
/// On failure, mark the lane as corrupt.
///
/// RFC-0032::REQ-0221 (CQ-BLOCKER-1 fix): Accepts a `LogRetentionConfig` to
/// ensure post-job cleanup enforces the same retention policy as GC. The config
/// is derived from `FacPolicyV1` fields (`per_lane_log_max_bytes`,
/// `per_job_log_ttl_days`, `keep_last_n_jobs_per_lane`).
pub(super) fn execute_lane_cleanup(
    fac_root: &Path,
    lane_mgr: &LaneManager,
    lane_id: &str,
    lane_workspace: &Path,
    log_retention: &LogRetentionConfig,
) -> Result<(), LaneCleanupError> {
    let cleanup_timestamp = current_timestamp_epoch_secs();

    match lane_mgr.run_lane_cleanup_with_retention(lane_id, lane_workspace, log_retention) {
        Ok(steps_completed) => {
            if let Err(receipt_err) = emit_lane_cleanup_receipt(
                fac_root,
                lane_id,
                LaneCleanupOutcome::Success,
                steps_completed.clone(),
                None,
                cleanup_timestamp,
            ) {
                eprintln!(
                    "worker: ERROR: failed to emit lane cleanup success receipt for {lane_id}: {receipt_err}"
                );
                let failure_reason = "cleanup receipt persistence failed";
                handle_cleanup_corruption(
                    fac_root,
                    lane_id,
                    failure_reason,
                    steps_completed,
                    cleanup_timestamp,
                )?;
                return Err(LaneCleanupError::CleanupFailed {
                    reason: failure_reason.to_string(),
                });
            }
            Ok(())
        },
        Err(err) => {
            let reason = format!("lane cleanup failed: {err}");
            let steps_completed = err.steps_completed().to_vec();
            let failure_step = err.failure_step().map(std::string::ToString::to_string);

            let failure_reason = failure_step.as_deref().map_or_else(
                || reason.clone(),
                |step| format!("{reason} (failure_step={step})"),
            );

            handle_cleanup_corruption(
                fac_root,
                lane_id,
                &failure_reason,
                steps_completed,
                cleanup_timestamp,
            )?;
            Err(LaneCleanupError::CleanupFailed {
                reason: failure_reason,
            })
        },
    }
}

pub(super) fn handle_cleanup_corruption(
    fac_root: &Path,
    lane_id: &str,
    reason: &str,
    steps_completed: Vec<String>,
    cleanup_receipt_timestamp: u64,
) -> Result<(), LaneCleanupError> {
    let failure_reason = reason.to_string();
    let failed_receipt_digest = match emit_lane_cleanup_receipt(
        fac_root,
        lane_id,
        LaneCleanupOutcome::Failed,
        steps_completed,
        Some(&failure_reason),
        cleanup_receipt_timestamp,
    ) {
        Ok(receipt_digest) => Some(receipt_digest),
        Err(err) => {
            let emit_failure_reason =
                format!("failed to emit lane cleanup failure receipt for {lane_id}: {err}");
            tracing::warn!(lane_id = lane_id, reason = %emit_failure_reason, "lane cleanup failure receipt emission failed");
            if let Err(marker_err) =
                persist_corrupt_marker_with_retries(fac_root, lane_id, &emit_failure_reason, None)
            {
                return Err(LaneCleanupError::CorruptMarkerPersistenceFailed {
                    reason: format!(
                        "failed to persist corrupt marker after cleanup failure receipt emission failure for lane {lane_id}: {marker_err}"
                    ),
                });
            }
            return Err(LaneCleanupError::CleanupFailed {
                reason: reason.to_string(),
            });
        },
    };

    if let Err(err) = persist_corrupt_marker_with_retries(
        fac_root,
        lane_id,
        &failure_reason,
        failed_receipt_digest,
    ) {
        return Err(LaneCleanupError::CorruptMarkerPersistenceFailed { reason: err });
    }

    Ok(())
}

pub(super) fn persist_corrupt_marker_with_retries(
    fac_root: &Path,
    lane_id: &str,
    reason: &str,
    cleanup_receipt_digest: Option<String>,
) -> Result<(), String> {
    let marker = LaneCorruptMarkerV1 {
        schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
        lane_id: lane_id.to_string(),
        reason: reason.to_string(),
        cleanup_receipt_digest,
        detected_at: apm2_core::fac::current_time_iso8601(),
    };

    let mut last_error: Option<String> = None;
    for attempt in 1..=CORRUPT_MARKER_PERSIST_RETRIES {
        match persist_corrupt_marker_with_durability(fac_root, &marker) {
            Ok(()) => return Ok(()),
            Err(marker_err) => {
                last_error = Some(marker_err.clone());
                tracing::warn!(
                    lane_id = lane_id,
                    attempt = attempt,
                    max_attempts = CORRUPT_MARKER_PERSIST_RETRIES,
                    error = %marker_err,
                    "failed to persist corrupt lane marker"
                );
                let delay_ms =
                    CORRUPT_MARKER_PERSIST_RETRY_DELAY_MS.saturating_mul(1u64 << (attempt - 1));
                if attempt < CORRUPT_MARKER_PERSIST_RETRIES && delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(delay_ms));
                }
                if attempt == CORRUPT_MARKER_PERSIST_RETRIES {
                    return Err("failed to persist corrupt marker".to_string());
                }
            },
        }
    }

    Err(last_error.unwrap_or_else(|| "failed to persist corrupt marker".to_string()))
}

/// Persist a corrupt marker with full crash-safe durability.
///
/// Durability chain (MAJOR FIX for f-685-code_quality-2):
/// 1. `marker.persist()` -> `atomic_write()` which: a. Creates a temp file in
///    the same directory b. Writes all marker data to the temp file c. Calls
///    `file.sync_all()` to fsync the temp file data to disk d. Calls
///    `temp.persist(target)` to atomically rename the temp file
/// 2. This function then fsyncs the parent directory to ensure the directory
///    entry (rename result) is committed to storage media.
///
/// Together, steps 1c (fsync data) + 1d (atomic rename) + 2 (fsync dir)
/// ensure that a crash at any point either leaves no marker or leaves a
/// complete, valid marker. The lane will never appear IDLE when it should
/// be CORRUPT after a power loss.
pub(super) fn persist_corrupt_marker_with_durability(
    fac_root: &Path,
    marker: &LaneCorruptMarkerV1,
) -> Result<(), String> {
    marker.persist(fac_root).map_err(|e| e.to_string())?;

    // Fsync the parent directory to ensure the rename (from atomic_write)
    // is committed to the storage media's directory entry table.
    let lane_dir = fac_root.join("lanes").join(&marker.lane_id);
    let dir = fs::OpenOptions::new()
        .read(true)
        .open(&lane_dir)
        .map_err(|err| {
            format!(
                "opening corrupt marker directory {} for durability sync: {err}",
                lane_dir.display()
            )
        })?;
    dir.sync_all().map_err(|err| {
        format!(
            "fsyncing corrupt marker directory {} for durability: {err}",
            lane_dir.display()
        )
    })?;

    Ok(())
}

pub(super) fn emit_lane_cleanup_receipt(
    fac_root: &Path,
    lane_id: &str,
    outcome: LaneCleanupOutcome,
    steps_completed: Vec<String>,
    failure_reason: Option<&str>,
    timestamp_secs: u64,
) -> Result<String, String> {
    let receipt = LaneCleanupReceiptV1 {
        schema: FAC_LANE_CLEANUP_RECEIPT_SCHEMA.to_string(),
        receipt_id: format!("wkr-cleanup-{lane_id}-{timestamp_secs}"),
        lane_id: lane_id.to_string(),
        outcome,
        steps_completed,
        failure_reason: failure_reason.map(std::string::ToString::to_string),
        timestamp_secs,
        content_hash: String::new(),
    };

    let receipt_path = receipt
        .persist(&fac_root.join(FAC_RECEIPTS_DIR), timestamp_secs)
        .map_err(|e| format!("cannot persist lane cleanup receipt: {e}"))?;
    receipt_path
        .file_name()
        .and_then(|s| s.to_str())
        .map_or_else(
            || Err("receipt filename was not UTF-8".to_string()),
            |name| {
                let digest = name.trim_end_matches(".json");
                Ok(digest.to_string())
            },
        )
}
