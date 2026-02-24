#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn parse_queue_lane(lane_str: &str) -> QueueLane {
    match lane_str {
        "stop_revoke" => QueueLane::StopRevoke,
        "control" => QueueLane::Control,
        "consume" => QueueLane::Consume,
        "replay" => QueueLane::Replay,
        "projection_replay" => QueueLane::ProjectionReplay,
        "bulk" => QueueLane::Bulk,
        _ => {
            // Try serde deserialization as fallback for quoted JSON values.
            let quoted = format!("\"{lane_str}\"");
            serde_json::from_str::<QueueLane>(&quoted).unwrap_or(QueueLane::Bulk)
        },
    }
}

pub(super) fn parse_gate_profile(
    value: &str,
) -> Result<fac_review_api::GateThroughputProfile, String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "throughput" => Ok(fac_review_api::GateThroughputProfile::Throughput),
        "balanced" => Ok(fac_review_api::GateThroughputProfile::Balanced),
        "conservative" => Ok(fac_review_api::GateThroughputProfile::Conservative),
        other => Err(format!(
            "invalid gates gate_profile `{other}`; expected throughput|balanced|conservative"
        )),
    }
}

pub(super) fn parse_gates_job_options(spec: &FacJobSpecV1) -> Result<GatesJobOptions, String> {
    match spec.actuation.decoded_source.as_deref() {
        Some("fac_gates_worker") => {},
        Some(other) => {
            return Err(format!(
                "unsupported gates decoded_source hint: {other} (expected fac_gates_worker)"
            ));
        },
        None => {
            return Err("missing gates decoded_source hint".to_string());
        },
    }

    let patch_value = spec
        .source
        .patch
        .as_ref()
        .ok_or_else(|| "missing gates options payload".to_string())?;
    let payload: GatesJobOptionsV1 = serde_json::from_value(patch_value.clone())
        .map_err(|err| format!("invalid gates options payload: {err}"))?;
    if payload.schema != GATES_JOB_OPTIONS_SCHEMA {
        return Err(format!(
            "unsupported gates options schema: expected {GATES_JOB_OPTIONS_SCHEMA}, got {}",
            payload.schema
        ));
    }
    Ok(GatesJobOptions {
        force: payload.force,
        quick: payload.quick,
        timeout_seconds: payload.timeout_seconds,
        memory_max: payload.memory_max,
        pids_max: payload.pids_max,
        cpu_quota: payload.cpu_quota,
        gate_profile: parse_gate_profile(&payload.gate_profile)?,
        workspace_root: resolve_workspace_root(&payload.workspace_root, &spec.source.repo_id)?,
    })
}

pub(super) fn resolve_workspace_root(raw: &str, expected_repo_id: &str) -> Result<PathBuf, String> {
    let candidate = PathBuf::from(raw);
    if !candidate.is_dir() {
        return Err(format!(
            "workspace_root is not a directory: {}",
            candidate.display()
        ));
    }

    let canonical = candidate
        .canonicalize()
        .map_err(|err| format!("failed to canonicalize workspace_root {raw}: {err}"))?;

    // Explicitly block FAC-internal roots.
    let apm2_home = resolve_apm2_home().ok_or_else(|| "cannot resolve APM2_HOME".to_string())?;
    let apm2_home = apm2_home.canonicalize().unwrap_or(apm2_home);
    let blocked_roots = [
        apm2_home.join("private").join("fac"),
        apm2_home.join("queue"),
    ];
    if blocked_roots
        .iter()
        .any(|blocked| canonical == *blocked || canonical.starts_with(blocked))
    {
        return Err(format!(
            "workspace_root {} is within FAC-internal storage (denied)",
            canonical.display()
        ));
    }

    let allowed_roots = resolve_allowed_workspace_roots()?;
    if !is_within_allowed_workspace_roots(&canonical, &allowed_roots) {
        return Err(format!(
            "workspace_root {} is outside allowed workspace roots [{}]; configure {}",
            canonical.display(),
            format_allowed_workspace_roots(&allowed_roots),
            ALLOWED_WORKSPACE_ROOTS_ENV
        ));
    }

    // Must be a git toplevel root, not a nested path.
    let toplevel_output = Command::new("git")
        .arg("-C")
        .arg(&canonical)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to run git rev-parse --show-toplevel: {err}"))?;
    if !toplevel_output.status.success() {
        return Err(format!(
            "workspace_root {} is not a git worktree root",
            canonical.display()
        ));
    }
    let git_toplevel_raw = String::from_utf8_lossy(&toplevel_output.stdout)
        .trim()
        .to_string();
    let git_toplevel = PathBuf::from(git_toplevel_raw)
        .canonicalize()
        .map_err(|err| format!("failed to canonicalize git toplevel for {raw}: {err}"))?;
    if git_toplevel != canonical {
        return Err(format!(
            "workspace_root {} must equal git toplevel {} (denied)",
            canonical.display(),
            git_toplevel.display()
        ));
    }

    // Hard-bind job payload to expected repository identity.
    let resolved_repo_id = resolve_repo_id(&canonical);
    if !resolved_repo_id.eq_ignore_ascii_case(expected_repo_id) {
        return Err(format!(
            "workspace_root repo mismatch: expected {expected_repo_id}, resolved {resolved_repo_id}"
        ));
    }

    Ok(canonical)
}

pub(super) fn resolve_allowed_workspace_roots() -> Result<Vec<PathBuf>, String> {
    let mut allowed = Vec::new();

    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if home.is_dir() {
            if let Ok(canonical_home) = home.canonicalize() {
                allowed.push(canonical_home);
            }
        }
    }

    if let Some(repo_root) = resolve_current_git_toplevel() {
        allowed.push(repo_root);
    }

    if let Some(raw) = std::env::var_os(ALLOWED_WORKSPACE_ROOTS_ENV) {
        for root in std::env::split_paths(&raw) {
            if root.as_os_str().is_empty() {
                continue;
            }
            if !root.is_dir() {
                return Err(format!(
                    "{} entry is not a directory: {}",
                    ALLOWED_WORKSPACE_ROOTS_ENV,
                    root.display()
                ));
            }
            let canonical_root = root.canonicalize().map_err(|err| {
                format!(
                    "failed to canonicalize {} entry {}: {err}",
                    ALLOWED_WORKSPACE_ROOTS_ENV,
                    root.display()
                )
            })?;
            allowed.push(canonical_root);
        }
    }

    allowed.sort();
    allowed.dedup();
    if allowed.is_empty() {
        return Err(format!(
            "no allowed workspace roots resolved; set {ALLOWED_WORKSPACE_ROOTS_ENV}"
        ));
    }
    Ok(allowed)
}

pub(super) fn resolve_current_git_toplevel() -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let path = PathBuf::from(raw.trim());
    if !path.is_dir() {
        return None;
    }
    path.canonicalize().ok()
}

pub(super) fn is_within_allowed_workspace_roots(
    candidate: &Path,
    allowed_roots: &[PathBuf],
) -> bool {
    allowed_roots
        .iter()
        .any(|root| candidate == root || candidate.starts_with(root))
}

pub(super) fn format_allowed_workspace_roots(allowed_roots: &[PathBuf]) -> String {
    allowed_roots
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn resolve_repo_id(workspace_root: &Path) -> String {
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

pub(super) fn resolve_origin_remote_url(workspace_root: &Path) -> Option<String> {
    Command::new("git")
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

pub(super) fn sanitize_repo_segment(raw: &str) -> String {
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

pub(super) fn build_queued_gates_bounded_unit_base(lane_id: &str, job_id: &str) -> String {
    let safe_lane_id = sanitize_repo_segment(lane_id);
    let safe_job_id = sanitize_repo_segment(job_id);
    let mut base = format!("{FAC_JOB_UNIT_BASE_PREFIX}{safe_lane_id}-{safe_job_id}");
    if base.len() > MAX_QUEUED_GATES_UNIT_BASE_LEN {
        base.truncate(MAX_QUEUED_GATES_UNIT_BASE_LEN);
        while base.ends_with('-') || base.ends_with('.') || base.ends_with('_') {
            base.pop();
        }
        if base.len() <= FAC_JOB_UNIT_BASE_PREFIX.len() {
            return format!(
                "{FAC_JOB_UNIT_BASE_PREFIX}{UNKNOWN_REPO_SEGMENT}-{UNKNOWN_REPO_SEGMENT}"
            );
        }
    }
    base
}

pub(super) fn resolve_workspace_head(workspace_root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| format!("failed to run git rev-parse HEAD: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Err("git rev-parse HEAD failed".to_string());
        }
        return Err(format!("git rev-parse HEAD failed: {stderr}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_gates_in_workspace(
    options: &GatesJobOptions,
    fac_root: &Path,
    heartbeat_cycle_count: u64,
    heartbeat_jobs_completed: u64,
    heartbeat_jobs_denied: u64,
    heartbeat_jobs_quarantined: u64,
    heartbeat_job_id: &str,
    bounded_unit_base: Option<&str>,
    lease_job_id: Option<&str>,
    lease_toolchain_fingerprint: Option<&str>,
) -> Result<fac_review_api::LocalGatesRunResult, String> {
    let stop_refresh = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_refresh_bg = std::sync::Arc::clone(&stop_refresh);
    let heartbeat_fac_root = fac_root.to_path_buf();
    let heartbeat_job_id = heartbeat_job_id.to_string();
    let heartbeat_handle = std::thread::spawn(move || {
        while !stop_refresh_bg.load(std::sync::atomic::Ordering::Acquire) {
            if let Err(error) = apm2_core::fac::worker_heartbeat::write_heartbeat(
                &heartbeat_fac_root,
                heartbeat_cycle_count,
                heartbeat_jobs_completed,
                heartbeat_jobs_denied,
                heartbeat_jobs_quarantined,
                "healthy",
            ) {
                eprintln!(
                    "worker: WARNING: heartbeat refresh failed during gates job {heartbeat_job_id}: {error}"
                );
            }
            for _ in 0..(GATES_HEARTBEAT_REFRESH_SECS * 10) {
                if stop_refresh_bg.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    });

    let run_result = fac_review_api::run_gates_local_worker(
        options.force,
        options.quick,
        options.timeout_seconds,
        &options.memory_max,
        options.pids_max,
        &options.cpu_quota,
        options.gate_profile,
        &options.workspace_root,
        bounded_unit_base,
        lease_job_id,
        lease_toolchain_fingerprint,
    );

    stop_refresh.store(true, std::sync::atomic::Ordering::Release);
    let _ = heartbeat_handle.join();
    run_result
}

pub(super) fn apply_gates_job_lifecycle_events(
    spec: &FacJobSpecV1,
    passed: bool,
) -> Result<usize, String> {
    fac_review_api::apply_gate_result_lifecycle_for_repo_sha(
        &spec.source.repo_id,
        &spec.source.head_sha,
        passed,
    )
    .map_err(|err| {
        format!(
            "failed to persist lifecycle gate sequence for repo {} sha {}: {err}",
            spec.source.repo_id, spec.source.head_sha
        )
    })
}

fn release_claimed_lock_before_terminal_transition(
    claimed_lock_file: &mut Option<fs::File>,
    job_id: &str,
    phase: &str,
) {
    if claimed_lock_file.take().is_some() {
        tracing::debug!(
            job_id,
            phase,
            "released claimed-file lock before terminal queue transition"
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_queued_gates_job(
    spec: &FacJobSpecV1,
    claimed_path: &Path,
    claimed_file_name: &str,
    claimed_lock_file: fs::File,
    queue_root: &Path,
    fac_root: &Path,
    boundary_trace: &ChannelBoundaryTrace,
    queue_trace: &JobQueueAdmissionTrace,
    budget_trace: Option<&FacBudgetAdmissionTrace>,
    canonicalizer_tuple_digest: &str,
    policy_hash: &str,
    sbx_hash: &str,
    net_hash: &str,
    heartbeat_cycle_count: u64,
    heartbeat_jobs_completed: u64,
    heartbeat_jobs_denied: u64,
    heartbeat_jobs_quarantined: u64,
    // TCK-00538: Toolchain fingerprint computed at worker startup.
    toolchain_fingerprint: Option<&str>,
) -> JobOutcome {
    let mut claimed_lock_file = Some(claimed_lock_file);
    let job_wall_start = Instant::now();
    let options = match parse_gates_job_options(spec) {
        Ok(options) => options,
        Err(reason) => {
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            release_claimed_lock_before_terminal_transition(
                &mut claimed_lock_file,
                &spec.job_id,
                "gates_parse_options_denied",
            );
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied gates job (parse options)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };

    let current_head = match resolve_workspace_head(&options.workspace_root) {
        Ok(head) => head,
        Err(err) => {
            let reason = format!(
                "cannot resolve workspace HEAD for {}: {err}",
                options.workspace_root.display()
            );
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            release_claimed_lock_before_terminal_transition(
                &mut claimed_lock_file,
                &spec.job_id,
                "gates_resolve_head_denied",
            );
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied gates job (resolve HEAD)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };
    if !current_head.eq_ignore_ascii_case(&spec.source.head_sha) {
        let reason = format!(
            "gates job head mismatch: worker workspace HEAD {current_head} does not match job head {}",
            spec.source.head_sha
        );
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        release_claimed_lock_before_terminal_transition(
            &mut claimed_lock_file,
            &spec.job_id,
            "gates_head_mismatch_denied",
        );
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(sbx_hash),
            Some(net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied gates job (head mismatch)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    let bounded_unit_base =
        build_queued_gates_bounded_unit_base(FAC_GATES_SYNTHETIC_LANE_ID, &spec.job_id);
    let gate_run_result = match run_gates_in_workspace(
        &options,
        fac_root,
        heartbeat_cycle_count,
        heartbeat_jobs_completed,
        heartbeat_jobs_denied,
        heartbeat_jobs_quarantined,
        &spec.job_id,
        Some(bounded_unit_base.as_str()),
        Some(spec.job_id.as_str()),
        toolchain_fingerprint,
    ) {
        Ok(code) => code,
        Err(err) => {
            let reason = format!("failed to execute gates in workspace: {err}");
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            release_claimed_lock_before_terminal_transition(
                &mut claimed_lock_file,
                &spec.job_id,
                "gates_execution_error_denied",
            );
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied gates job (execution error)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };

    let lifecycle_update_result =
        apply_gates_job_lifecycle_events(spec, gate_run_result.exit_code == exit_codes::SUCCESS);

    if gate_run_result.exit_code == exit_codes::SUCCESS {
        if let Err(err) = lifecycle_update_result {
            let reason = format!("gates passed but lifecycle update failed: {err}");
            release_claimed_lock_before_terminal_transition(
                &mut claimed_lock_file,
                &spec.job_id,
                "gates_lifecycle_update_denied",
            );
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied gates job (lifecycle update failure after pass)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        }

        let observed_cost = observed_cost_from_elapsed(job_wall_start.elapsed());
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        release_claimed_lock_before_terminal_transition(
            &mut claimed_lock_file,
            &spec.job_id,
            "gates_completed_commit",
        );
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Completed,
            None,
            "gates completed",
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            Some(observed_cost),
            Some(sbx_hash),
            Some(net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "completed gates job",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }

        // TCK-00540 BLOCKER fix: After the receipt is committed, rebind
        // the gate cache with real RFC-0028/0029 receipt evidence. This
        // promotes the fail-closed default (`false`) to `true` only when
        // the durable receipt contains the required bindings.
        let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
        if let Ok(signer) = fac_key_material::load_or_generate_persistent_signer(fac_root) {
            fac_review_api::rebind_gate_cache_after_receipt(
                &spec.source.head_sha,
                &receipts_dir,
                &spec.job_id,
                &signer,
            );
            // TCK-00541 round-3 MAJOR fix: Also rebind the v3 gate cache.
            // Without this, v3 entries persist with `rfc0028_receipt_bound =
            // false` and `rfc0029_receipt_bound = false`, causing
            // `check_reuse` to deny all hits and defeating v3 cache reuse.
            fac_review_api::rebind_v3_gate_cache_after_receipt(
                &spec.source.head_sha,
                policy_hash,
                sbx_hash,
                net_hash,
                &receipts_dir,
                &spec.job_id,
                &signer,
            );
        }

        return JobOutcome::Completed {
            job_id: spec.job_id.clone(),
            observed_cost: Some(observed_cost),
        };
    }

    // Gates failed: commit claimed job to denied via pipeline.
    let base_reason = match lifecycle_update_result {
        Ok(_) => format!("gates failed with exit code {}", gate_run_result.exit_code),
        Err(err) => format!(
            "gates failed with exit code {}; {err}",
            gate_run_result.exit_code
        ),
    };
    let reason = match gate_run_result.failure_summary.as_deref() {
        Some(summary) if !summary.trim().is_empty() => {
            truncate_receipt_reason(&format!("{base_reason}; {summary}"))
        },
        _ => truncate_receipt_reason(&base_reason),
    };
    // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
    release_claimed_lock_before_terminal_transition(
        &mut claimed_lock_file,
        &spec.job_id,
        "gates_failed_denied_commit",
    );
    if let Err(commit_err) = commit_claimed_job_via_pipeline(
        fac_root,
        queue_root,
        spec,
        claimed_path,
        claimed_file_name,
        FacJobOutcome::Denied,
        Some(DenialReasonCode::ValidationFailed),
        &reason,
        Some(boundary_trace),
        Some(queue_trace),
        budget_trace,
        None,
        Some(canonicalizer_tuple_digest),
        policy_hash,
        None,
        None,
        Some(sbx_hash),
        Some(net_hash),
        None, // stop_revoke_admission
        None, // bytes_backend
        toolchain_fingerprint,
    ) {
        return handle_pipeline_commit_failure(
            &commit_err,
            "denied gates job (gate failure)",
            claimed_path,
            queue_root,
            claimed_file_name,
        );
    }
    JobOutcome::Denied { reason }
}

pub(super) fn serialize_denial_reason_code(denial_reason: DenialReasonCode) -> String {
    serde_json::to_value(denial_reason)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "missing_denial_reason_code".to_string())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_stop_revoke(
    spec: &FacJobSpecV1,
    claimed_path: &Path,
    claimed_file_name: &str,
    queue_root: &Path,
    fac_root: &Path,
    boundary_trace: &ChannelBoundaryTrace,
    queue_trace: &JobQueueAdmissionTrace,
    budget_trace: Option<&FacBudgetAdmissionTrace>,
    canonicalizer_tuple_digest: &str,
    policy_hash: &str,
    sbx_hash: &str,
    net_hash: &str,
    job_wall_start: Instant,
    // TCK-00587: Stop/revoke admission trace for receipt binding.
    sr_trace: Option<&apm2_core::economics::queue_admission::StopRevokeAdmissionTrace>,
    // TCK-00538: Toolchain fingerprint computed at worker startup.
    toolchain_fingerprint: Option<&str>,
) -> JobOutcome {
    let target_job_id = match &spec.cancel_target_job_id {
        Some(id) if !id.is_empty() => id.as_str(),
        _ => {
            let reason = "stop_revoke job missing cancel_target_job_id".to_string();
            eprintln!(
                "worker: stop_revoke job {} missing cancel_target_job_id",
                spec.job_id
            );
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::MalformedSpec),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                sr_trace, // stop_revoke_admission
                None,     // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied stop_revoke (missing target)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };

    // Step 1: Locate target job in claimed/ directory.
    let target_path = find_target_job_in_dir(&queue_root.join(CLAIMED_DIR), target_job_id);

    // MAJOR 3 fail-closed: if target not in claimed/, check if it's already
    // in a terminal state (completed/cancelled).  If so, the cancellation
    // is a no-op.  If the target is truly unknown, fail with structured error.
    let Some(target_file_path) = target_path else {
        // Check terminal directories.
        let in_completed =
            find_target_job_in_dir(&queue_root.join(COMPLETED_DIR), target_job_id).is_some();
        let in_cancelled =
            find_target_job_in_dir(&queue_root.join(CANCELLED_DIR), target_job_id).is_some();

        if in_completed || in_cancelled {
            let terminal_state = if in_completed {
                "completed"
            } else {
                "cancelled"
            };
            eprintln!(
                "worker: stop_revoke: target {target_job_id} already in {terminal_state}/, treating as success"
            );
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            let observed = observed_cost_from_elapsed(job_wall_start.elapsed());
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Completed,
                None,
                &format!("stop_revoke: target {target_job_id} already {terminal_state}"),
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                Some(observed),
                Some(sbx_hash),
                Some(net_hash),
                sr_trace, // stop_revoke_admission
                None,     // bytes_backend
                toolchain_fingerprint,
            ) {
                eprintln!(
                    "worker: pipeline commit failed for stop_revoke (target already terminal): {commit_err}"
                );
                return JobOutcome::skipped_pipeline_commit(format!(
                    "pipeline commit failed: {commit_err}"
                ));
            }
            return JobOutcome::Completed {
                job_id: spec.job_id.clone(),
                observed_cost: Some(observed),
            };
        }

        // Target not found anywhere -- fail-closed.
        let reason = format!(
            "stop_revoke: target job {target_job_id} not found in claimed/ or any terminal directory"
        );
        eprintln!("worker: {reason}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(sbx_hash),
            Some(net_hash),
            sr_trace, // stop_revoke_admission
            None,     // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied stop_revoke (target not found)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    };

    let target_file_name = target_file_path.file_name().map_or_else(
        || format!("{target_job_id}.json"),
        |n| n.to_string_lossy().to_string(),
    );

    // Step 2: Read target spec for receipt emission and exact unit name.
    let target_spec_opt = read_bounded(&target_file_path, MAX_JOB_SPEC_SIZE)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<FacJobSpecV1>(&bytes).ok());

    // MAJOR 7: Construct exact unit name from the target spec's queue_lane.
    // No wildcard matching.
    let target_lane = target_spec_opt
        .as_ref()
        .map_or("unknown", |s| s.queue_lane.as_str());
    let stop_result = stop_target_unit_exact(target_lane, target_job_id);
    if let Err(ref e) = stop_result {
        eprintln!(
            "worker: stop_revoke: unit stop for target {target_job_id} (lane {target_lane}) failed: {e}"
        );
        // MAJOR 3 fail-closed: if systemctl stop fails, emit failure receipt.
        let reason =
            format!("stop_revoke failed: systemctl stop failed for target {target_job_id}: {e}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(sbx_hash),
            Some(net_hash),
            sr_trace, // stop_revoke_admission
            None,     // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied stop_revoke (systemctl stop failed)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    // MAJOR 2 fix (round 3): Receipt persistence is REQUIRED before any
    // terminal state transition.  Reordered steps:
    //   3a. Build + persist cancellation receipt for target job
    //   3b. Only THEN move target to cancelled/
    //   4a. Build + persist completion receipt for stop_revoke job
    //   4b. Only THEN move stop_revoke to completed/
    // If any receipt build or persist fails, the job stays in claimed/
    // (or is moved to denied/) — never transitions to a terminal state
    // without a persisted receipt.

    // Step 3a: Build and persist cancellation receipt for the target job
    // BEFORE moving it to cancelled/.
    if let Some(ref target_spec) = target_spec_opt {
        let cancel_reason = spec
            .actuation
            .decoded_source
            .as_deref()
            .unwrap_or("stop_revoke");
        let reason = format!(
            "cancelled by stop_revoke job {}: {cancel_reason}",
            spec.job_id
        );
        let bounded_reason = truncate_receipt_reason(&reason);

        let receipt_id = format!(
            "cancel-{}-{}",
            target_job_id,
            current_timestamp_epoch_secs()
        );
        let mut builder = FacJobReceiptV1Builder::new(
            receipt_id,
            &target_spec.job_id,
            &target_spec.job_spec_digest,
        )
        .policy_hash(policy_hash)
        .outcome(FacJobOutcome::Cancelled)
        .denial_reason(DenialReasonCode::Cancelled)
        .reason(&bounded_reason)
        .timestamp_secs(current_timestamp_epoch_secs());
        // TCK-00538: Bind toolchain fingerprint to cancellation receipt.
        if let Some(fp) = toolchain_fingerprint {
            builder = builder.toolchain_fingerprint(fp);
        }

        let receipt = match builder.try_build() {
            Ok(r) => r,
            Err(e) => {
                // Fail-closed: cannot build receipt -> deny stop_revoke.
                let deny_reason = format!(
                    "stop_revoke failed: cannot build cancellation receipt for target {target_job_id}: {e}"
                );
                eprintln!("worker: {deny_reason}");
                // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
                if let Err(commit_err) = commit_claimed_job_via_pipeline(
                    fac_root,
                    queue_root,
                    spec,
                    claimed_path,
                    claimed_file_name,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::StopRevokeFailed),
                    &deny_reason,
                    Some(boundary_trace),
                    Some(queue_trace),
                    budget_trace,
                    None,
                    Some(canonicalizer_tuple_digest),
                    policy_hash,
                    None,
                    None,
                    Some(sbx_hash),
                    Some(net_hash),
                    sr_trace, // stop_revoke_admission
                    None,     // bytes_backend
                    toolchain_fingerprint,
                ) {
                    return handle_pipeline_commit_failure(
                        &commit_err,
                        "denied stop_revoke (receipt build failed)",
                        claimed_path,
                        queue_root,
                        claimed_file_name,
                    );
                }
                return JobOutcome::Denied {
                    reason: deny_reason,
                };
            },
        };

        let receipts_dir_sr = fac_root.join(FAC_RECEIPTS_DIR);
        if let Err(e) = persist_content_addressed_receipt(&receipts_dir_sr, &receipt) {
            // Fail-closed: cannot persist receipt -> deny stop_revoke.
            let deny_reason = format!(
                "stop_revoke failed: cannot persist cancellation receipt for target {target_job_id}: {e}"
            );
            eprintln!("worker: {deny_reason}");
            // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::StopRevokeFailed),
                &deny_reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                None,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                None,
                None,
                Some(sbx_hash),
                Some(net_hash),
                sr_trace, // stop_revoke_admission
                None,     // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied stop_revoke (receipt persist failed)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied {
                reason: deny_reason,
            };
        }
        // TCK-00576: Best-effort signed envelope alongside cancellation receipt.
        if let Ok(signer) = fac_key_material::load_or_generate_persistent_signer(fac_root) {
            let content_hash = apm2_core::fac::compute_job_receipt_content_hash(&receipt);
            let envelope = apm2_core::fac::sign_receipt(&content_hash, &signer, "fac-worker");
            if let Err(e) = apm2_core::fac::persist_signed_envelope(&receipts_dir_sr, &envelope) {
                tracing::warn!(
                    error = %e,
                    "signed cancellation receipt envelope failed (non-fatal)"
                );
            }
        }
    }

    // Step 3b: Move target job to cancelled/ — receipt is already persisted.
    if let Err(e) = move_to_dir_safe(
        &target_file_path,
        &queue_root.join(CANCELLED_DIR),
        &target_file_name,
    ) {
        let reason =
            format!("stop_revoke failed: cannot move target {target_job_id} to cancelled: {e}");
        eprintln!("worker: {reason}");
        // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::StopRevokeFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            None,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            None,
            None,
            Some(sbx_hash),
            Some(net_hash),
            sr_trace, // stop_revoke_admission
            None,     // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied stop_revoke (move to cancelled failed)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }
    eprintln!("worker: stop_revoke: moved target {target_job_id} to cancelled/");

    // Step 4: TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
    // Receipt persistence, index update, and job move happen in a crash-safe
    // order via a single ReceiptWritePipeline::commit() call.
    let observed = observed_cost_from_elapsed(job_wall_start.elapsed());
    if let Err(commit_err) = commit_claimed_job_via_pipeline(
        fac_root,
        queue_root,
        spec,
        claimed_path,
        claimed_file_name,
        FacJobOutcome::Completed,
        None,
        &format!("stop_revoke completed for target {target_job_id}"),
        Some(boundary_trace),
        Some(queue_trace),
        budget_trace,
        None,
        Some(canonicalizer_tuple_digest),
        policy_hash,
        None,
        Some(observed),
        Some(sbx_hash),
        Some(net_hash),
        sr_trace, // stop_revoke_admission
        None,     // bytes_backend
        toolchain_fingerprint,
    ) {
        // Fail-closed: pipeline commit failed — stop_revoke job stays in claimed/.
        let reason = format!(
            "stop_revoke pipeline commit failed for job {}: {commit_err}",
            spec.job_id
        );
        eprintln!("worker: {reason}");
        return JobOutcome::skipped_pipeline_commit(reason);
    }

    JobOutcome::Completed {
        job_id: spec.job_id.clone(),
        observed_cost: Some(observed),
    }
}

/// Execute a warm job: parse phases, run warm execution, persist receipt.
///
/// This handler is dispatched by `process_job` when `spec.kind == "warm"`.
/// Warm jobs prime the build cache in the lane workspace by running
/// user-selected phases (fetch/build/nextest/clippy/doc). The warm receipt
/// is persisted to the FAC receipts directory.
///
/// # Lane Lifecycle
///
/// The lane lease is cleaned up after job completion. On receipt emission
/// failure, the lease is removed and the job is returned to pending.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_warm_job(
    spec: &FacJobSpecV1,
    claimed_path: &Path,
    claimed_file_name: &str,
    queue_root: &Path,
    fac_root: &Path,
    signer: &Signer,
    lane_workspace: &Path,
    lane_dir: &Path,
    acquired_lane_id: &str,
    lane_profile_hash: &str,
    boundary_trace: &ChannelBoundaryTrace,
    queue_trace: &JobQueueAdmissionTrace,
    budget_trace: Option<&FacBudgetAdmissionTrace>,
    patch_digest: Option<&str>,
    canonicalizer_tuple_digest: &str,
    policy_hash: &str,
    containment_trace: Option<&apm2_core::fac::containment::ContainmentTrace>,
    lane_mgr: &LaneManager,
    _raw_bytes: &[u8],
    policy: &FacPolicyV1,
    lane_systemd_properties: &SystemdUnitProperties,
    sbx_hash: &str,
    net_hash: &str,
    heartbeat_cycle_count: u64,
    heartbeat_jobs_completed: u64,
    heartbeat_jobs_denied: u64,
    heartbeat_jobs_quarantined: u64,
    job_wall_start: Instant,
    // TCK-00538: Toolchain fingerprint computed at worker startup.
    toolchain_fingerprint: Option<&str>,
    // TCK-00554 BLOCKER-1 fix: Effective sccache enablement derived from
    // server containment protocol. When false, RUSTC_WRAPPER/SCCACHE_* are
    // stripped from the warm execution environment even if
    // `policy.sccache_enabled` is true. This prevents builds from using an
    // untrusted sccache server that was refused by containment verification.
    effective_sccache_enabled: bool,
) -> JobOutcome {
    use apm2_core::fac::warm::{WarmContainment, WarmPhase, execute_warm};

    // Parse warm phases from decoded_source (comma-separated phase names).
    let phases: Vec<WarmPhase> = match &spec.actuation.decoded_source {
        Some(phases_csv) if !phases_csv.is_empty() => {
            let mut parsed = Vec::new();
            for name in phases_csv
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                match WarmPhase::parse(name) {
                    Ok(p) => parsed.push(p),
                    Err(e) => {
                        let reason = format!("invalid warm phase '{name}': {e}");
                        eprintln!("worker: warm job {}: {reason}", spec.job_id);
                        let _ = LaneLeaseV1::remove(lane_dir);
                        // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
                        // (claimed/ -> denied/ transition).
                        if let Err(commit_err) = commit_claimed_job_via_pipeline(
                            fac_root,
                            queue_root,
                            spec,
                            claimed_path,
                            claimed_file_name,
                            FacJobOutcome::Denied,
                            Some(DenialReasonCode::ValidationFailed),
                            &reason,
                            Some(boundary_trace),
                            Some(queue_trace),
                            budget_trace,
                            patch_digest,
                            Some(canonicalizer_tuple_digest),
                            policy_hash,
                            containment_trace,
                            None,
                            Some(sbx_hash),
                            Some(net_hash),
                            None, // stop_revoke_admission
                            None, // bytes_backend
                            toolchain_fingerprint,
                        ) {
                            return handle_pipeline_commit_failure(
                                &commit_err,
                                "denied warm job (invalid phase)",
                                claimed_path,
                                queue_root,
                                claimed_file_name,
                            );
                        }
                        return JobOutcome::Denied { reason };
                    },
                }
            }
            parsed
        },
        _ => apm2_core::fac::warm::DEFAULT_WARM_PHASES.to_vec(),
    };

    // Set up CARGO_HOME and CARGO_TARGET_DIR within the lane.
    // TCK-00538: Namespace CARGO_TARGET_DIR by toolchain fingerprint so that
    // toolchain changes get a fresh build directory, preventing stale artifacts
    // from a different compiler version from corrupting incremental builds.
    let cargo_home = lane_dir.join("cargo_home");
    // Defensive: if fingerprint is somehow invalid (should not happen since
    // worker startup validates it), fall back to plain "target".
    let target_dir_name = toolchain_fingerprint
        .and_then(fingerprint_short_hex)
        .map_or_else(|| "target".to_string(), |hex16| format!("target-{hex16}"));
    let cargo_target_dir = lane_dir.join(&target_dir_name);
    if let Err(e) = std::fs::create_dir_all(&cargo_home) {
        let reason = format!("cannot create lane CARGO_HOME: {e}");
        let _ = LaneLeaseV1::remove(lane_dir);
        // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
        // (claimed/ -> denied/ transition).
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            patch_digest,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            containment_trace,
            None,
            Some(sbx_hash),
            Some(net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (CARGO_HOME creation failed)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }
    if let Err(e) = std::fs::create_dir_all(&cargo_target_dir) {
        let reason = format!("cannot create lane CARGO_TARGET_DIR: {e}");
        let _ = LaneLeaseV1::remove(lane_dir);
        // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
        // (claimed/ -> denied/ transition).
        if let Err(commit_err) = commit_claimed_job_via_pipeline(
            fac_root,
            queue_root,
            spec,
            claimed_path,
            claimed_file_name,
            FacJobOutcome::Denied,
            Some(DenialReasonCode::ValidationFailed),
            &reason,
            Some(boundary_trace),
            Some(queue_trace),
            budget_trace,
            patch_digest,
            Some(canonicalizer_tuple_digest),
            policy_hash,
            containment_trace,
            None,
            Some(sbx_hash),
            Some(net_hash),
            None, // stop_revoke_admission
            None, // bytes_backend
            toolchain_fingerprint,
        ) {
            return handle_pipeline_commit_failure(
                &commit_err,
                "denied warm job (CARGO_TARGET_DIR creation failed)",
                claimed_path,
                queue_root,
                claimed_file_name,
            );
        }
        return JobOutcome::Denied { reason };
    }

    eprintln!(
        "worker: warm job {}: executing {} phase(s) in {}",
        spec.job_id,
        phases.len(),
        lane_workspace.display(),
    );

    // [INV-WARM-009] Build hardened environment via policy-driven default-deny
    // construction. This ensures warm subprocesses (which compile untrusted
    // repository code including build.rs and proc-macros) cannot access
    // FAC-private state, secrets, or worker authority context.
    let apm2_home = resolve_apm2_home().unwrap_or_else(|| {
        // Fallback: derive from fac_root (which is $APM2_HOME/private/fac).
        fac_root
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf()
    });
    let ambient_env: Vec<(String, String)> = std::env::vars().collect();
    let mut hardened_env = build_job_environment(policy, &ambient_env, &apm2_home);

    // fix-round-4 MAJOR: Override SCCACHE_DIR with lane-scoped path to prevent
    // server lifecycle collisions across concurrent lanes. build_job_environment
    // injects the global resolve_sccache_dir() path; we narrow it to a per-lane
    // subdirectory so each lane has its own sccache server Unix domain socket.
    if effective_sccache_enabled {
        let lane_sccache_dir = policy
            .resolve_sccache_dir(&apm2_home)
            .join(acquired_lane_id);
        hardened_env.insert(
            "SCCACHE_DIR".to_string(),
            lane_sccache_dir.to_string_lossy().to_string(),
        );
    }

    // TCK-00554 BLOCKER-1 fix: If the server containment protocol auto-disabled
    // sccache, strip RUSTC_WRAPPER and SCCACHE_* from the hardened environment.
    // `build_job_environment` injects these when `policy.sccache_enabled` is true,
    // but the containment protocol may have determined that the server is
    // untrusted. Fail-closed: an untrusted server MUST NOT be used for
    // compilation.
    if !effective_sccache_enabled && policy.sccache_enabled {
        eprintln!(
            "worker: warm job {}: sccache auto-disabled by containment — \
             stripping RUSTC_WRAPPER and SCCACHE_* from environment",
            spec.job_id,
        );
        hardened_env.remove("RUSTC_WRAPPER");
        hardened_env.retain(|key, _| !key.starts_with("SCCACHE_"));
    }

    // TCK-00596: Plumb credential mount metadata into execution environment.
    // This selectively re-introduces credential env vars (for example
    // GITHUB_TOKEN) after policy default-deny filtering when a validated
    // credential mount is available. Secret values are resolved at runtime and
    // are never serialized into receipts/job specs.
    if let Some(credential_mount) = build_github_credential_mount() {
        if let Err(error) =
            apply_credential_mount_to_env(&credential_mount, &mut hardened_env, &ambient_env)
        {
            let reason = format!("credential mount injection failed: {error}");
            eprintln!("worker: warm job {}: {reason}", spec.job_id);
            let _ = LaneLeaseV1::remove(lane_dir);
            // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
            // (claimed/ -> denied/ transition).
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                patch_digest,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                containment_trace,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied warm job (credential mount injection failed)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        }
    }

    // [INV-WARM-014] Construct systemd-run containment for warm phase
    // subprocesses. This wraps each cargo command in a transient unit with
    // MemoryMax/CPUQuota/TasksMax/RuntimeMaxSec from the lane profile,
    // matching the containment model used by standard bounded test execution.
    //
    // Uses select_and_validate_backend() for consistency with other components
    // (bounded test runner, gate execution). This validates prerequisites
    // (user bus for user-mode, systemd-run for system-mode) in one call.
    //
    // Fail-closed: only fall back to uncontained execution when the platform
    // genuinely doesn't support systemd-run (container environments, no user
    // D-Bus session in auto mode). Configuration errors (invalid backend
    // value, invalid service user, env var issues) deny the job — they
    // indicate operator misconfiguration that should be fixed, not silently
    // degraded.
    let warm_containment = match select_and_validate_backend() {
        Ok(backend) => {
            let system_config = if backend == ExecutionBackend::SystemMode {
                match SystemModeConfig::from_env() {
                    Ok(cfg) => Some(cfg),
                    Err(e) => {
                        // System-mode config failure is a configuration error
                        // (invalid service user, env var issues) — fail the job.
                        let reason = format!(
                            "warm containment denied: system-mode config error \
                             (not a platform limitation): {e}"
                        );
                        eprintln!("worker: warm job {}: {reason}", spec.job_id);
                        let _ = LaneLeaseV1::remove(lane_dir);
                        // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
                        // (claimed/ -> denied/ transition).
                        if let Err(commit_err) = commit_claimed_job_via_pipeline(
                            fac_root,
                            queue_root,
                            spec,
                            claimed_path,
                            claimed_file_name,
                            FacJobOutcome::Denied,
                            Some(DenialReasonCode::ValidationFailed),
                            &reason,
                            Some(boundary_trace),
                            Some(queue_trace),
                            budget_trace,
                            patch_digest,
                            Some(canonicalizer_tuple_digest),
                            policy_hash,
                            containment_trace,
                            None,
                            Some(sbx_hash),
                            Some(net_hash),
                            None, // stop_revoke_admission
                            None, // bytes_backend
                            toolchain_fingerprint,
                        ) {
                            return handle_pipeline_commit_failure(
                                &commit_err,
                                "denied warm job (system-mode config error)",
                                claimed_path,
                                queue_root,
                                claimed_file_name,
                            );
                        }
                        return JobOutcome::Denied { reason };
                    },
                }
            } else {
                None
            };
            Some(WarmContainment {
                backend,
                properties: lane_systemd_properties.clone(),
                system_config,
            })
        },
        Err(e) => {
            if e.is_platform_unavailable() {
                // Platform doesn't support systemd-run — acceptable fallback
                // to uncontained execution with a logged warning.
                eprintln!(
                    "worker: WARNING: warm job {} executing WITHOUT systemd-run containment \
                     (platform unavailable: {e}) — warm phase subprocesses (including build.rs \
                     and proc-macros) are not resource-limited by transient unit properties",
                    spec.job_id,
                );
                None
            } else {
                // Configuration/invariant error — fail-closed, deny the job.
                let reason = format!(
                    "warm containment denied: backend configuration error \
                     (not a platform limitation): {e}"
                );
                eprintln!("worker: warm job {}: {reason}", spec.job_id);
                let _ = LaneLeaseV1::remove(lane_dir);
                // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
                // (claimed/ -> denied/ transition).
                if let Err(commit_err) = commit_claimed_job_via_pipeline(
                    fac_root,
                    queue_root,
                    spec,
                    claimed_path,
                    claimed_file_name,
                    FacJobOutcome::Denied,
                    Some(DenialReasonCode::ValidationFailed),
                    &reason,
                    Some(boundary_trace),
                    Some(queue_trace),
                    budget_trace,
                    patch_digest,
                    Some(canonicalizer_tuple_digest),
                    policy_hash,
                    containment_trace,
                    None,
                    Some(sbx_hash),
                    Some(net_hash),
                    None, // stop_revoke_admission
                    None, // bytes_backend
                    toolchain_fingerprint,
                ) {
                    return handle_pipeline_commit_failure(
                        &commit_err,
                        "denied warm job (backend configuration error)",
                        claimed_path,
                        queue_root,
                        claimed_file_name,
                    );
                }
                return JobOutcome::Denied { reason };
            }
        },
    };
    if warm_containment.is_none() {
        eprintln!(
            "worker: WARNING: warm job {} executing WITHOUT systemd-run containment — \
             warm phase subprocesses (including build.rs and proc-macros) are not \
             resource-limited by transient unit properties",
            spec.job_id,
        );
    }

    // [INV-WARM-015] Build heartbeat refresh closure for the warm phase
    // polling loop. This prevents the worker heartbeat file from going stale
    // during long-running warm phases (which can take hours for large
    // projects). The heartbeat is refreshed every HEARTBEAT_REFRESH_INTERVAL
    // (5s) inside the try_wait loop.
    //
    // The closure captures the last known cycle_count and job counters from
    // the worker's main loop so that observers see accurate state during
    // long warm phases, rather than misleading zeroed counters.
    //
    // Synchronization: heartbeat_fn captures fac_root by value (Path clone)
    // and counter values by copy. Invoked synchronously from the same
    // thread that calls execute_warm_phase. No cross-thread sharing or
    // interior mutability.
    let heartbeat_fac_root = fac_root.to_path_buf();
    let heartbeat_job_id = spec.job_id.clone();
    let heartbeat_fn = move || {
        if let Err(e) = apm2_core::fac::worker_heartbeat::write_heartbeat(
            &heartbeat_fac_root,
            heartbeat_cycle_count,
            heartbeat_jobs_completed,
            heartbeat_jobs_denied,
            heartbeat_jobs_quarantined,
            "warm-executing",
        ) {
            // Non-fatal: heartbeat is observability, not correctness.
            eprintln!(
                "worker: WARNING: heartbeat refresh failed during warm job {heartbeat_job_id}: {e}",
            );
        }
    };

    // Execute warm phases.
    let start_epoch_secs = current_timestamp_epoch_secs();
    let warm_result = execute_warm(
        &phases,
        acquired_lane_id,
        lane_profile_hash,
        lane_workspace,
        &cargo_home,
        &cargo_target_dir,
        &spec.source.head_sha,
        start_epoch_secs,
        &hardened_env,
        warm_containment.as_ref(),
        Some(&heartbeat_fn),
        &spec.job_id,
    );

    let receipt = match warm_result {
        Ok(r) => r,
        Err(e) => {
            let reason = format!("warm execution failed: {e}");
            eprintln!("worker: warm job {}: {reason}", spec.job_id);
            // Warm execution failure is still a completed job (the phases ran,
            // just some may have failed). But structural errors (too many phases,
            // field too long) are denials.
            let _ = LaneLeaseV1::remove(lane_dir);
            // TCK-00564 MAJOR-1: Use ReceiptWritePipeline for atomic commit
            // (claimed/ -> denied/ transition).
            if let Err(commit_err) = commit_claimed_job_via_pipeline(
                fac_root,
                queue_root,
                spec,
                claimed_path,
                claimed_file_name,
                FacJobOutcome::Denied,
                Some(DenialReasonCode::ValidationFailed),
                &reason,
                Some(boundary_trace),
                Some(queue_trace),
                budget_trace,
                patch_digest,
                Some(canonicalizer_tuple_digest),
                policy_hash,
                containment_trace,
                None,
                Some(sbx_hash),
                Some(net_hash),
                None, // stop_revoke_admission
                None, // bytes_backend
                toolchain_fingerprint,
            ) {
                return handle_pipeline_commit_failure(
                    &commit_err,
                    "denied warm job (execution failed)",
                    claimed_path,
                    queue_root,
                    claimed_file_name,
                );
            }
            return JobOutcome::Denied { reason };
        },
    };

    // Persist the warm receipt to the FAC receipts directory.
    // [Finding #8] GateReceipt emission depends on successful persistence.
    // If the warm receipt cannot be persisted, the GateReceipt is emitted
    // with passed=false to reflect the incomplete measurement.
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let persist_ok = match receipt.persist(&receipts_dir) {
        Ok(_) => {
            eprintln!(
                "worker: warm receipt persisted for {} (hash: {})",
                spec.job_id, receipt.content_hash
            );
            true
        },
        Err(e) => {
            eprintln!(
                "worker: warm receipt persistence failed for {}: {e}",
                spec.job_id
            );
            false
        },
    };

    // [Finding #1/#4] Compute payload_hash from the serialized WarmReceiptV1,
    // not from the input job spec bytes. This binds the GateReceipt to the
    // actual warm execution output.
    let receipt_json = serde_json::to_vec(&receipt).unwrap_or_default();
    let warm_receipt_hash = compute_evidence_hash(&receipt_json);
    let changeset_digest = compute_evidence_hash(spec.source.head_sha.as_bytes());
    let receipt_id = format!("wkr-{}-{}", spec.job_id, current_timestamp_epoch_secs());
    let gate_receipt =
        GateReceiptBuilder::new(&receipt_id, "fac-worker-warm", &spec.actuation.lease_id)
            .changeset_digest(changeset_digest)
            .executor_actor_id("fac-worker")
            .receipt_version(1)
            .payload_kind("warm-receipt")
            .payload_schema_version(1)
            .payload_hash(warm_receipt_hash)
            .evidence_bundle_hash(warm_receipt_hash)
            .job_spec_digest(&spec.job_spec_digest)
            .sandbox_hardening_hash(sbx_hash)
            .network_policy_hash(net_hash)
            .passed(persist_ok)
            .build_and_sign(signer);

    let observed_cost = observed_cost_from_elapsed(job_wall_start.elapsed());

    // Persist the gate receipt alongside the completed job (before atomic commit).
    write_gate_receipt(queue_root, claimed_file_name, &gate_receipt);

    // TCK-00564 BLOCKER-1: Use ReceiptWritePipeline for atomic commit.
    // Receipt persistence, index update, and job move happen in a crash-safe
    // order via a single ReceiptWritePipeline::commit() call.
    if let Err(commit_err) = commit_claimed_job_via_pipeline(
        fac_root,
        queue_root,
        spec,
        claimed_path,
        claimed_file_name,
        FacJobOutcome::Completed,
        None,
        "warm completed",
        Some(boundary_trace),
        Some(queue_trace),
        budget_trace,
        patch_digest,
        Some(canonicalizer_tuple_digest),
        policy_hash,
        containment_trace,
        Some(observed_cost),
        Some(sbx_hash),
        Some(net_hash),
        None, // stop_revoke_admission
        None, // bytes_backend
        toolchain_fingerprint,
    ) {
        eprintln!("worker: pipeline commit failed for warm job: {commit_err}");
        let _ = LaneLeaseV1::remove(lane_dir);
        return handle_pipeline_commit_failure(
            &commit_err,
            "completed warm job",
            claimed_path,
            queue_root,
            claimed_file_name,
        );
    }

    // Post-completion lane cleanup (same as standard jobs).
    if let Err(cleanup_err) = execute_lane_cleanup(
        fac_root,
        lane_mgr,
        acquired_lane_id,
        lane_workspace,
        &log_retention_from_policy(policy),
    ) {
        eprintln!(
            "worker: WARNING: post-completion lane cleanup failed for warm job on {acquired_lane_id}: {cleanup_err}"
        );
    }

    JobOutcome::Completed {
        job_id: spec.job_id.clone(),
        observed_cost: Some(observed_cost),
    }
}

pub(super) fn build_stop_revoke_lane_candidates(lane_hint: &str) -> Vec<String> {
    let mut lanes = BTreeSet::new();
    lanes.insert(lane_hint.to_string());
    lanes.extend(LaneManager::default_lane_ids());
    lanes.into_iter().collect()
}

pub(super) fn stop_systemd_units_both_scopes(unit_names: &[String]) -> Result<(), String> {
    if unit_names.is_empty() {
        return Ok(());
    }
    let mut last_err = String::new();
    let mut any_stop_succeeded = false;
    let mut not_found_count: u32 = 0;
    let scopes: &[&str] = &["--user", "--system"];
    let joined_units = unit_names.join(", ");

    for mode_flag in scopes {
        eprintln!("worker: stop_revoke: stopping units [{joined_units}] ({mode_flag})");
        let mut args = vec![mode_flag.to_string(), "stop".to_string(), "--".to_string()];
        args.extend(unit_names.iter().cloned());
        let stop_result = std::process::Command::new("systemctl").args(&args).output();
        match stop_result {
            Ok(out) if out.status.success() => {
                any_stop_succeeded = true;
            },
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if out.status.code() == Some(5) {
                    not_found_count = not_found_count.saturating_add(1);
                } else {
                    last_err = format!("{mode_flag}: {}", stderr.trim());
                }
            },
            Err(e) => {
                last_err = format!("{mode_flag}: {e}");
            },
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    let total_scopes = scopes.len() as u32;
    if any_stop_succeeded || not_found_count == total_scopes {
        return Ok(());
    }

    Err(format!(
        "systemctl stop failed for units [{joined_units}]: {last_err}"
    ))
}

/// Attempts to stop all associated systemd units for a target job.
///
/// Uses the same unit association model as `check_fac_unit_liveness`
/// (exact FAC unit, suffixed FAC units, and warm units) and fail-closes
/// if unit liveness cannot be verified before or after stop attempts.
pub(super) fn stop_target_unit_exact(lane: &str, target_job_id: &str) -> Result<(), String> {
    // MAJOR-1 fix: Sanitize queue_lane to only allow [A-Za-z0-9_-].
    // Fail-closed: reject lanes containing unsafe characters to prevent
    // command injection via crafted unit names.
    if lane.is_empty()
        || !lane
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "unsafe queue_lane value {lane:?}: only [A-Za-z0-9_-] allowed"
        ));
    }
    if target_job_id.is_empty()
        || !target_job_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(format!(
            "unsafe target_job_id value {target_job_id:?}: only [A-Za-z0-9_.-] allowed"
        ));
    }
    let lane_candidates = build_stop_revoke_lane_candidates(lane);
    let mut units_to_stop: BTreeSet<String> = BTreeSet::new();

    for lane_id in &lane_candidates {
        match check_fac_unit_liveness(lane_id, target_job_id) {
            FacUnitLiveness::Inactive => {},
            FacUnitLiveness::Active { active_units } => {
                units_to_stop.extend(active_units);
            },
            FacUnitLiveness::Unknown { reason } => {
                return Err(format!(
                    "cannot verify associated units for lane {lane_id}: {reason}"
                ));
            },
        }
    }

    if units_to_stop.is_empty() {
        eprintln!(
            "worker: stop_revoke: no active associated units found for job {target_job_id}; \
             treating as already stopped"
        );
        return Ok(());
    }

    let mut stop_errors = Vec::new();
    let units: Vec<String> = units_to_stop.into_iter().collect();
    for batch in units.chunks(STOP_REVOKE_BATCH_SIZE) {
        if let Err(err) = stop_systemd_units_both_scopes(batch) {
            stop_errors.push(err);
        }
    }
    if !stop_errors.is_empty() {
        return Err(format!(
            "failed to stop associated units for job {target_job_id}: {}",
            stop_errors.join("; ")
        ));
    }

    let mut lingering_units = Vec::new();
    for lane_id in &lane_candidates {
        match check_fac_unit_liveness(lane_id, target_job_id) {
            FacUnitLiveness::Inactive => {},
            FacUnitLiveness::Active { active_units } => {
                lingering_units.extend(active_units);
            },
            FacUnitLiveness::Unknown { reason } => {
                return Err(format!(
                    "post-stop verification inconclusive for lane {lane_id}: {reason}"
                ));
            },
        }
    }

    lingering_units.sort();
    lingering_units.dedup();
    if lingering_units.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "stop_revoke incomplete for job {target_job_id}: associated units still active [{}]",
            lingering_units.join(", ")
        ))
    }
}

#[cfg(test)]
mod lock_lifecycle_tests {
    use std::fs::OpenOptions;

    use fs2::FileExt;
    use tempfile::tempdir;

    use super::release_claimed_lock_before_terminal_transition;

    #[test]
    fn claimed_lock_is_released_when_terminal_transition_begins() {
        let tmp = tempdir().expect("tempdir should be created");
        let lock_path = tmp.path().join("claimed.lock");
        let claimed_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .expect("claimed lock file should open");
        claimed_file
            .lock_exclusive()
            .expect("claimed lock should be acquired");
        let mut claimed_lock_file = Some(claimed_file);

        release_claimed_lock_before_terminal_transition(
            &mut claimed_lock_file,
            "job-lock-test",
            "before_commit",
        );

        let competing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .expect("competing lock file should open");
        assert!(
            competing_file.try_lock_exclusive().is_ok(),
            "competing lock acquisition must succeed after claimed lock release"
        );
        let _ = competing_file.unlock();
    }
}
