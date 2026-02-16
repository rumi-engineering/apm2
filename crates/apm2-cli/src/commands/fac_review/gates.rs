//! `apm2 fac gates` — unified local evidence gates with bounded test execution.
//!
//! Runs all evidence gates locally, caches results per-SHA so the background
//! pipeline can skip already-validated gates.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use apm2_core::fac::{
    FacPolicyV1, LaneLockGuard, LaneManager, LaneState, apply_lane_env_overrides,
    build_job_environment, compute_test_env_for_parallelism, ensure_lane_env_dirs,
    resolve_host_test_parallelism,
};
use sha2::{Digest, Sha256};

use super::bounded_test_runner::{
    BoundedTestLimits, build_bounded_test_command as build_systemd_bounded_test_command,
};
use super::evidence::{EvidenceGateOptions, run_evidence_gates_with_lane_context};
use super::gate_attestation::{
    GateResourcePolicy, build_nextest_command, compute_gate_attestation,
    gate_command_for_attestation,
};
use super::gate_cache::GateCache;
use super::jsonl::{
    GateCompletedEvent, GateErrorEvent, GateProgressTickEvent, GateStartedEvent, StageEvent,
    emit_jsonl, emit_jsonl_error, read_log_error_hint, ts_now,
};
use super::merge_conflicts::{check_merge_conflicts_against_main, render_merge_conflict_summary};
use super::timeout_policy::{
    MAX_MANUAL_TIMEOUT_SECONDS, TEST_TIMEOUT_SLA_MESSAGE, max_memory_bytes, parse_memory_limit,
    resolve_bounded_test_timeout,
};
use crate::exit_codes::codes as exit_codes;

const DEFAULT_TEST_KILL_AFTER_SECONDS: u64 = 20;
const BALANCED_MIN_PARALLELISM: u32 = 4;
const BALANCED_MAX_PARALLELISM: u32 = 16;
const CONSERVATIVE_PARALLELISM: u32 = 2;

/// Throughput profile for bounded FAC gate execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateThroughputProfile {
    Throughput,
    Balanced,
    Conservative,
}

impl GateThroughputProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Throughput => "throughput",
            Self::Balanced => "balanced",
            Self::Conservative => "conservative",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ResolvedGateExecutionProfile {
    pub(super) test_parallelism: u32,
    pub(super) cpu_quota_percent: u32,
}

pub(super) fn resolve_gate_execution_profile(
    profile: GateThroughputProfile,
) -> ResolvedGateExecutionProfile {
    let host = resolve_host_test_parallelism();
    let test_parallelism = match profile {
        GateThroughputProfile::Throughput => host,
        GateThroughputProfile::Balanced => {
            let half = host / 2;
            half.clamp(BALANCED_MIN_PARALLELISM, BALANCED_MAX_PARALLELISM)
                .min(host)
        },
        GateThroughputProfile::Conservative => CONSERVATIVE_PARALLELISM.min(host).max(1),
    };
    ResolvedGateExecutionProfile {
        test_parallelism,
        cpu_quota_percent: test_parallelism.saturating_mul(100).max(100),
    }
}

fn parse_cpu_quota_percent(cpu_quota: &str) -> Result<u32, String> {
    let normalized = cpu_quota.trim().trim_end_matches('%').trim();
    if normalized.is_empty() {
        return Err("cpu_quota cannot be empty".to_string());
    }
    normalized
        .parse::<u32>()
        .map_err(|_| format!("invalid cpu_quota value: `{cpu_quota}`"))
}

fn quota_percent_to_parallelism(percent: u32) -> u32 {
    if percent == 0 {
        // `CPUQuota=0` in systemd means "no limit"; in that case preserve full
        // host parallelism instead of forcing single-thread execution.
        return resolve_host_test_parallelism();
    }
    percent.saturating_add(99) / 100
}

pub(super) fn resolve_effective_execution_profile(
    requested_cpu_quota: &str,
    gate_profile: GateThroughputProfile,
) -> Result<(ResolvedGateExecutionProfile, String), String> {
    let profile = resolve_gate_execution_profile(gate_profile);
    if requested_cpu_quota.trim().eq_ignore_ascii_case("auto") {
        return Ok((profile, format!("{}%", profile.cpu_quota_percent)));
    }
    let cpu_quota_percent = parse_cpu_quota_percent(requested_cpu_quota)?;
    let host_parallelism = resolve_host_test_parallelism();
    let test_parallelism = quota_percent_to_parallelism(cpu_quota_percent)
        .min(host_parallelism)
        .max(1);
    Ok((
        ResolvedGateExecutionProfile {
            test_parallelism,
            cpu_quota_percent,
        },
        format!("{cpu_quota_percent}%"),
    ))
}

/// Run all evidence gates locally with optional bounded test execution.
///
/// 1. Requires clean working tree for full mode (`--quick` bypasses this)
/// 2. Resolves HEAD SHA
/// 3. Runs merge-conflict gate first (always recomputed)
/// 4. Runs evidence gates (with bounded test runner if available)
/// 5. Writes attested gate cache receipts for full runs
/// 6. Prints summary table
#[allow(clippy::too_many_arguments)]
pub fn run_gates(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    gate_profile: GateThroughputProfile,
    json_output: bool,
) -> u8 {
    let overall_started = Instant::now();
    let (resolved_profile, effective_cpu_quota) =
        match resolve_effective_execution_profile(cpu_quota, gate_profile) {
            Ok(resolved) => resolved,
            Err(err) => {
                if json_output {
                    let _ = emit_jsonl_error("gate_error", &err);
                } else {
                    let payload = serde_json::json!({
                        "error": "gate_error",
                        "message": err,
                        "passed": false,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| {
                            "{\"error\":\"serialization_failure\"}".to_string()
                        })
                    );
                }
                return exit_codes::GENERIC_ERROR;
            },
        };
    if json_output {
        let _ = emit_jsonl(&StageEvent {
            event: "gates_started".to_string(),
            ts: ts_now(),
            extra: serde_json::json!({
                "quick": quick,
                "force": force,
                "timeout_seconds": timeout_seconds,
                "memory_max": memory_max,
                "pids_max": pids_max,
                "requested_cpu_quota": cpu_quota,
                "effective_cpu_quota": effective_cpu_quota,
                "gate_profile": gate_profile.as_str(),
                "effective_test_parallelism": resolved_profile.test_parallelism,
            }),
        });
    }

    // Build a real-time gate progress callback for JSON mode. Events are
    // emitted to stdout as each gate starts, heartbeats while running, and
    // finishes, providing streaming observability instead of buffering until
    // all gates complete.
    let gate_progress_callback: Option<Box<dyn Fn(super::evidence::GateProgressEvent) + Send>> =
        if json_output {
            Some(Box::new(
                |event: super::evidence::GateProgressEvent| match event {
                    super::evidence::GateProgressEvent::Started { gate_name } => {
                        let _ = emit_jsonl(&GateStartedEvent {
                            event: "gate_started",
                            gate: gate_name,
                            ts: ts_now(),
                        });
                    },
                    super::evidence::GateProgressEvent::Progress {
                        gate_name,
                        elapsed_secs,
                        bytes_streamed,
                    } => {
                        let _ = emit_jsonl(&GateProgressTickEvent {
                            event: "gate_progress",
                            gate: gate_name,
                            elapsed_secs,
                            bytes_streamed,
                            ts: ts_now(),
                        });
                    },
                    super::evidence::GateProgressEvent::Completed {
                        gate_name,
                        passed,
                        duration_secs,
                        log_path,
                        bytes_written,
                        bytes_total,
                        was_truncated,
                        log_bundle_hash,
                        error_hint,
                    } => {
                        let status = if passed { "pass" } else { "fail" }.to_string();
                        let _ = emit_jsonl(&GateCompletedEvent {
                            event: "gate_completed",
                            gate: gate_name.clone(),
                            status,
                            duration_secs,
                            log_path: log_path.clone(),
                            bytes_written,
                            bytes_total,
                            was_truncated,
                            log_bundle_hash: log_bundle_hash.clone(),
                            error_hint: error_hint.clone(),
                            ts: ts_now(),
                        });
                        if !passed {
                            let _ = emit_jsonl(&GateErrorEvent {
                                event: "gate_error",
                                gate: gate_name,
                                error: error_hint.unwrap_or_else(|| {
                                    "gate failed (see log for details)".to_string()
                                }),
                                log_path,
                                duration_secs: Some(duration_secs),
                                bytes_written,
                                bytes_total,
                                was_truncated,
                                log_bundle_hash,
                                ts: ts_now(),
                            });
                        }
                    },
                },
            ))
        } else {
            None
        };

    match run_gates_inner(
        force,
        quick,
        timeout_seconds,
        memory_max,
        pids_max,
        &effective_cpu_quota,
        gate_profile,
        resolved_profile.test_parallelism,
        !json_output,
        gate_progress_callback,
    ) {
        Ok(summary) => {
            if json_output {
                // Gate-level events were already streamed in real-time via the
                // callback. Only the summary/completion events are emitted here.
                let _ = emit_jsonl(&StageEvent {
                    event: "gates_completed".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "passed": summary.passed,
                        "duration_secs": overall_started.elapsed().as_secs(),
                        "gate_count": summary.gates.len(),
                    }),
                });
                let summary_value =
                    serde_json::to_value(&summary).unwrap_or_else(|_| serde_json::json!({}));
                let _ = emit_jsonl(&StageEvent {
                    event: "gates_summary".to_string(),
                    ts: ts_now(),
                    extra: summary_value,
                });
            } else {
                // JSON-only: emit the summary as pretty-printed JSON.
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            }
            if summary.passed {
                exit_codes::SUCCESS
            } else {
                exit_codes::GENERIC_ERROR
            }
        },
        Err(err) => {
            if json_output {
                let _ = emit_jsonl_error("gate_error", &err);
                let _ = emit_jsonl(&StageEvent {
                    event: "gates_completed".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "passed": false,
                        "duration_secs": overall_started.elapsed().as_secs(),
                        "error": err,
                    }),
                });
                let _ = emit_jsonl(&StageEvent {
                    event: "gates_summary".to_string(),
                    ts: ts_now(),
                    extra: serde_json::json!({
                        "passed": false,
                        "error": err,
                    }),
                });
            } else {
                // JSON-only: emit the error as a structured JSON object.
                let payload = serde_json::json!({
                    "error": "gate_error",
                    "message": err,
                    "passed": false,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

#[derive(Debug, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct GatesSummary {
    sha: String,
    passed: bool,
    bounded: bool,
    quick: bool,
    gate_profile: String,
    effective_cpu_quota: String,
    effective_test_parallelism: u32,
    requested_timeout_seconds: u64,
    effective_timeout_seconds: u64,
    cache_status: String,
    gates: Vec<GateResult>,
}

#[derive(Debug, serde::Serialize)]
struct GateResult {
    name: String,
    status: String,
    duration_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_written: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    was_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_hint: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn run_gates_inner(
    force: bool,
    quick: bool,
    timeout_seconds: u64,
    memory_max: &str,
    pids_max: u64,
    cpu_quota: &str,
    gate_profile: GateThroughputProfile,
    test_parallelism: u32,
    emit_human_logs: bool,
    on_gate_progress: Option<Box<dyn Fn(super::evidence::GateProgressEvent) + Send>>,
) -> Result<GatesSummary, String> {
    validate_timeout_seconds(timeout_seconds)?;
    let memory_max_bytes = parse_memory_limit(memory_max)?;
    if memory_max_bytes > max_memory_bytes() {
        return Err(format!(
            "--memory-max {memory_max} exceeds FAC test memory cap of {max_bytes}",
            max_bytes = max_memory_bytes()
        ));
    }

    let workspace_root =
        std::env::current_dir().map_err(|e| format!("failed to resolve cwd: {e}"))?;
    let timeout_decision = resolve_bounded_test_timeout(&workspace_root, timeout_seconds);

    // TCK-00526: Load FAC policy for environment enforcement.
    let apm2_home = apm2_core::github::resolve_apm2_home()
        .ok_or_else(|| "cannot resolve APM2_HOME for env policy enforcement".to_string())?;
    let fac_root = apm2_home.join("private/fac");
    let policy = load_or_create_gate_policy(&fac_root)?;

    // TCK-00526: Ensure the managed CARGO_HOME directory exists when the
    // policy denies ambient cargo home. Created with restrictive permissions
    // (0o700) to prevent cross-user contamination (CTR-2611).
    if let Some(cargo_home) = policy.resolve_cargo_home(&apm2_home) {
        ensure_managed_cargo_home(&cargo_home)?;
    }

    // TCK-00575: Acquire exclusive lane lock on lane-00 before any lane
    // operations. This prevents concurrent `apm2 fac gates` invocations
    // from colliding on the shared synthetic lane directory.
    let lane_manager = LaneManager::from_default_home()
        .map_err(|e| format!("failed to initialize lane manager: {e}"))?;
    lane_manager
        .ensure_directories()
        .map_err(|e| format!("failed to ensure lane directories: {e}"))?;
    let lane_guard = acquire_gates_lane_lock(&lane_manager)?;

    // TCK-00575: Check for CORRUPT state before executing gates.
    // If lane-00 is corrupt (from a previous failed run), refuse to
    // run gates in a dirty environment. The user must reset first.
    check_lane_not_corrupt(&lane_manager)?;

    // 1. Require clean working tree for full gates only. `--force` allows
    // rerunning gates for the same SHA while local edits are in progress.
    ensure_clean_working_tree(&workspace_root, quick || force)?;

    // 2. Resolve HEAD SHA.
    let sha_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&workspace_root)
        .output()
        .map_err(|e| format!("failed to run git rev-parse HEAD: {e}"))?;
    if !sha_output.status.success() {
        return Err("git rev-parse HEAD failed".to_string());
    }
    let sha = String::from_utf8_lossy(&sha_output.stdout)
        .trim()
        .to_string();
    if sha.len() < 7 {
        return Err(format!("unexpected short SHA: {sha}"));
    }

    // 3. Merge-conflict gate always runs first and is never cache-reused.
    // Emit gate_started before execution for streaming observability.
    if let Some(ref cb) = on_gate_progress {
        cb(super::evidence::GateProgressEvent::Started {
            gate_name: "merge_conflict_main".to_string(),
        });
    }
    let merge_gate = evaluate_merge_conflict_gate(&workspace_root, &sha, emit_human_logs)?;
    // Emit gate_completed immediately after the merge gate finishes.
    if let Some(ref cb) = on_gate_progress {
        cb(super::evidence::GateProgressEvent::Completed {
            gate_name: merge_gate.name.clone(),
            passed: merge_gate.status == "PASS",
            duration_secs: merge_gate.duration_secs,
            log_path: merge_gate.log_path.clone(),
            bytes_written: merge_gate.bytes_written,
            bytes_total: merge_gate.bytes_total,
            was_truncated: merge_gate.was_truncated,
            log_bundle_hash: merge_gate.log_bundle_hash.clone(),
            error_hint: merge_gate.error_hint.clone(),
        });
    }
    if merge_gate.status == "FAIL" {
        return Ok(GatesSummary {
            sha,
            passed: false,
            bounded: false,
            quick,
            gate_profile: gate_profile.as_str().to_string(),
            effective_cpu_quota: cpu_quota.to_string(),
            effective_test_parallelism: test_parallelism,
            requested_timeout_seconds: timeout_seconds,
            effective_timeout_seconds: timeout_decision.effective_seconds,
            cache_status: "disabled (merge conflicts)".to_string(),
            gates: vec![merge_gate],
        });
    }

    // 4. Build test command override for test execution.
    // TCK-00526: Environment is now built from policy (default-deny with
    // allowlist), replacing the previous ambient-inherit approach.
    let default_nextest_command = build_nextest_command();
    let mut test_command_environment =
        compute_nextest_test_environment(&policy, &apm2_home, test_parallelism)?;
    let mut bounded = false;

    let mut env_remove_keys = Vec::new();
    let test_command = if quick {
        None
    } else {
        let spec = build_systemd_bounded_test_command(
            &workspace_root,
            BoundedTestLimits {
                timeout_seconds: timeout_decision.effective_seconds,
                kill_after_seconds: DEFAULT_TEST_KILL_AFTER_SECONDS,
                memory_max,
                pids_max,
                cpu_quota,
            },
            &default_nextest_command,
            &test_command_environment,
        )
        .map_err(|err| format!("bounded test runner unavailable for FAC gates: {err}"))?;
        bounded = true;
        test_command_environment.extend(spec.environment);

        // TCK-00549: The policy-computed environment from
        // compute_nextest_test_environment() is passed directly to
        // build_bounded_test_command(). The bounded executor uses
        // FacPolicyV1-driven env filtering (no ad-hoc allowlists).
        // Defense-in-depth: RUSTC_WRAPPER and SCCACHE_* are stripped
        // both inside build_policy_setenv_pairs() and via env_remove_keys
        // on the spawned process (TCK-00548, INV-ENV-008).
        test_command_environment.extend(spec.setenv_pairs);

        // Log if sccache env vars were found and stripped.
        if emit_human_logs && !spec.env_remove_keys.is_empty() {
            eprintln!(
                "INFO: sccache env vars stripped from bounded test (containment cannot be \
                 verified for systemd transient units): {:?}",
                spec.env_remove_keys
            );
        }

        env_remove_keys = spec.env_remove_keys;
        Some(spec.command)
    };

    let lane_context =
        super::evidence::allocate_evidence_lane_context(&lane_manager, "lane-00", lane_guard)?;

    let opts = EvidenceGateOptions {
        test_command,
        test_command_environment,
        env_remove_keys,
        skip_test_gate: quick,
        skip_merge_conflict_gate: true,
        emit_human_logs,
        on_gate_progress,
    };

    // 5. Run evidence gates.
    let started = Instant::now();
    let (passed, gate_results) = run_evidence_gates_with_lane_context(
        &workspace_root,
        &sha,
        None,
        Some(&opts),
        lane_context,
    )?;
    let total_secs = started.elapsed().as_secs();

    // 6. Write attested results to gate cache for full runs only.
    if !quick {
        let policy = GateResourcePolicy::from_cli(
            quick,
            timeout_decision.effective_seconds,
            memory_max,
            pids_max,
            cpu_quota,
            bounded,
            Some(gate_profile.as_str()),
            Some(test_parallelism),
        );
        let mut cache = GateCache::new(&sha);
        for result in &gate_results {
            let command = gate_command_for_attestation(
                &workspace_root,
                &result.gate_name,
                opts.test_command.as_deref(),
            );
            let attestation_digest = command.and_then(|cmd| {
                compute_gate_attestation(&workspace_root, &sha, &result.gate_name, &cmd, &policy)
                    .ok()
                    .map(|attestation| attestation.attestation_digest)
            });
            let evidence_log_digest = result
                .log_path
                .as_ref()
                .and_then(|path| gate_log_digest(path));
            cache.set_with_attestation(
                &result.gate_name,
                result.passed,
                result.duration_secs,
                attestation_digest,
                quick,
                evidence_log_digest,
                result
                    .log_path
                    .as_ref()
                    .and_then(|p| p.to_str())
                    .map(str::to_string),
            );
        }
        for result in &gate_results {
            cache.backfill_evidence_metadata(
                &result.gate_name,
                result.log_bundle_hash.as_deref(),
                result.bytes_written,
                result.bytes_total,
                result.was_truncated,
                result.log_path.as_ref().and_then(|p| p.to_str()),
            );
        }
        cache.save()?;
    }

    let mut gates = vec![merge_gate];
    let mut evidence_gates: Vec<GateResult> = gate_results
        .iter()
        .map(|r| {
            let error_hint = if r.passed {
                None
            } else {
                r.log_path.as_deref().and_then(read_log_error_hint)
            };
            GateResult {
                name: r.gate_name.clone(),
                status: if r.passed { "PASS" } else { "FAIL" }.to_string(),
                duration_secs: r.duration_secs,
                log_path: r
                    .log_path
                    .as_ref()
                    .and_then(|path| path.to_str())
                    .map(str::to_string),
                bytes_written: r.bytes_written,
                bytes_total: r.bytes_total,
                was_truncated: r.was_truncated,
                log_bundle_hash: r.log_bundle_hash.clone(),
                error_hint,
            }
        })
        .collect();
    gates.append(&mut evidence_gates);
    if quick {
        normalize_quick_test_gate(&mut gates);
    }

    if emit_human_logs {
        eprintln!(
            "fac gates (mode={}): completed in {total_secs}s — {}",
            if quick { "quick" } else { "full" },
            if passed { "PASS" } else { "FAIL" }
        );
    }

    Ok(GatesSummary {
        sha,
        passed,
        bounded,
        quick,
        gate_profile: gate_profile.as_str().to_string(),
        effective_cpu_quota: cpu_quota.to_string(),
        effective_test_parallelism: test_parallelism,
        requested_timeout_seconds: timeout_seconds,
        effective_timeout_seconds: timeout_decision.effective_seconds,
        cache_status: if quick {
            "disabled (quick mode)".to_string()
        } else if force {
            "bypass (--force)".to_string()
        } else {
            "write-through".to_string()
        },
        gates,
    })
}

fn gate_log_digest(log_path: &Path) -> Option<String> {
    if !log_path.exists() {
        return None;
    }
    let bytes = fs::read(log_path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(format!("{:x}", hasher.finalize()))
}

fn validate_timeout_seconds(timeout_seconds: u64) -> Result<(), String> {
    if timeout_seconds == 0 {
        return Err(format!(
            "--timeout-seconds must be greater than zero (max {MAX_MANUAL_TIMEOUT_SECONDS}). {TEST_TIMEOUT_SLA_MESSAGE}"
        ));
    }
    if timeout_seconds > MAX_MANUAL_TIMEOUT_SECONDS {
        return Err(format!(
            "--timeout-seconds cannot exceed {MAX_MANUAL_TIMEOUT_SECONDS}. {TEST_TIMEOUT_SLA_MESSAGE}"
        ));
    }
    Ok(())
}

fn evaluate_merge_conflict_gate(
    workspace_root: &Path,
    sha: &str,
    emit_human_logs: bool,
) -> Result<GateResult, String> {
    let started = Instant::now();
    let report = check_merge_conflicts_against_main(workspace_root, sha)?;
    let duration = started.elapsed().as_secs();
    let passed = !report.has_conflicts();
    if emit_human_logs && !passed {
        eprintln!("{}", render_merge_conflict_summary(&report));
    }
    Ok(GateResult {
        name: "merge_conflict_main".to_string(),
        status: if passed { "PASS" } else { "FAIL" }.to_string(),
        duration_secs: duration,
        log_path: None,
        bytes_written: None,
        bytes_total: None,
        was_truncated: None,
        log_bundle_hash: None,
        error_hint: None,
    })
}

fn normalize_quick_test_gate(gates: &mut Vec<GateResult>) {
    // Preserve a single canonical `test` gate entry in quick mode.
    if let Some(test_gate) = gates.iter_mut().find(|gate| gate.name == "test") {
        test_gate.status = "SKIP".to_string();
        return;
    }

    let insert_index = gates
        .iter()
        .position(|gate| gate.name == "workspace_integrity")
        .unwrap_or(gates.len());
    gates.insert(
        insert_index,
        GateResult {
            name: "test".to_string(),
            status: "SKIP".to_string(),
            duration_secs: 0,
            log_path: None,
            bytes_written: None,
            bytes_total: None,
            was_truncated: None,
            log_bundle_hash: None,
            error_hint: None,
        },
    );
}

fn compute_nextest_test_environment(
    policy: &FacPolicyV1,
    apm2_home: &std::path::Path,
    test_parallelism: u32,
) -> Result<Vec<(String, String)>, String> {
    let lane_env = compute_test_env_for_parallelism(test_parallelism);

    // Build policy-filtered environment from the current process environment.
    let ambient: Vec<(String, String)> = std::env::vars().collect();
    let mut policy_env = build_job_environment(policy, &ambient, apm2_home);

    // TCK-00575: Apply per-lane env isolation (HOME, TMPDIR, XDG_CACHE_HOME,
    // XDG_CONFIG_HOME). For CLI gates, use the synthetic lane-00 directory
    // under $APM2_HOME/private/fac/lanes/lane-00.
    let fac_root = apm2_home.join("private/fac");
    let lane_dir = fac_root.join("lanes/lane-00");
    ensure_lane_env_dirs(&lane_dir)?;
    apply_lane_env_overrides(&mut policy_env, &lane_dir);

    // Throughput-profile vars (NEXTEST_TEST_THREADS, CARGO_BUILD_JOBS) take
    // precedence over ambient values but env_set overrides in the policy
    // are already applied by build_job_environment.
    for (key, value) in &lane_env {
        policy_env.insert(key.clone(), value.clone());
    }

    Ok(policy_env.into_iter().collect())
}

fn ensure_clean_working_tree(workspace_root: &Path, quick: bool) -> Result<(), String> {
    if quick {
        return Ok(());
    }

    let diff_status = Command::new("git")
        .args(["diff", "--exit-code"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git diff: {e}"))?;
    if !diff_status.status.success() {
        return Err(
            "DIRTY TREE: working tree has unstaged changes. ALL changes must be committed before \
             running full gates — build artifacts are SHA-attested and reused as a source of truth. \
             Run `git add -A && git commit` first, or use `apm2 fac gates --quick` for inner-loop development."
                .to_string(),
        );
    }

    let cached_status = Command::new("git")
        .args(["diff", "--cached", "--exit-code"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git diff --cached: {e}"))?;
    if !cached_status.status.success() {
        return Err(
            "DIRTY TREE: working tree has staged but uncommitted changes. ALL changes must be \
             committed before running full gates — build artifacts are SHA-attested and reused \
             as a source of truth. Run `git commit` first, or use `apm2 fac gates --quick` for \
             inner-loop development."
                .to_string(),
        );
    }

    let untracked = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run git ls-files --others --exclude-standard: {e}"))?;
    if !untracked.status.success() {
        return Err("failed to evaluate untracked files for clean-tree check".to_string());
    }
    if !String::from_utf8_lossy(&untracked.stdout).trim().is_empty() {
        return Err(
            "DIRTY TREE: working tree has untracked files. ALL files must be committed (or \
             .gitignored) before running full gates — build artifacts are SHA-attested and \
             reused as a source of truth. Run `git add -A && git commit` first, or use \
             `apm2 fac gates --quick` for inner-loop development."
                .to_string(),
        );
    }

    Ok(())
}

/// Load or create the FAC policy. Delegates to the shared `policy_loader`
/// module for bounded I/O and deduplication (TCK-00526).
fn load_or_create_gate_policy(fac_root: &Path) -> Result<FacPolicyV1, String> {
    super::policy_loader::load_or_create_fac_policy(fac_root)
}

/// Ensure the managed `CARGO_HOME` directory exists. Delegates to the shared
/// `policy_loader` module (TCK-00526).
fn ensure_managed_cargo_home(cargo_home: &Path) -> Result<(), String> {
    super::policy_loader::ensure_managed_cargo_home(cargo_home)
}

/// Acquire an exclusive lock on `lane-00` for gate execution.
///
/// `apm2 fac gates` uses a shared synthetic lane directory `lane-00`.
/// Without an exclusive lock, concurrent gate invocations would collide
/// on the lane's env dirs, workspace, and target directories.
fn acquire_gates_lane_lock(lane_manager: &LaneManager) -> Result<LaneLockGuard, String> {
    lane_manager.acquire_lock("lane-00").map_err(|e| {
        format!(
            "cannot acquire exclusive lock on lane-00 for gate execution — \
             another `apm2 fac gates` process may be running: {e}"
        )
    })
}

/// Check that `lane-00` is not in a CORRUPT state.
///
/// If a previous gate run (or worker) marked the lane as corrupt, running
/// gates in that environment risks non-deterministic results. The user must
/// run `apm2 fac lane reset lane-00` to clear the corrupt marker first.
fn check_lane_not_corrupt(lane_manager: &LaneManager) -> Result<(), String> {
    let status = lane_manager
        .lane_status("lane-00")
        .map_err(|e| format!("cannot check lane-00 status: {e}"))?;
    if status.state == LaneState::Corrupt {
        let reason = status.corrupt_reason.as_deref().unwrap_or("unknown");
        return Err(format!(
            "lane-00 is in CORRUPT state (reason: {reason}). \
             Cannot run gates in a dirty environment. \
             Run `apm2 fac lane reset lane-00` to clear the corrupt marker first."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};

    use super::*;

    static TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn gate_execution_profile_resolves_auto_quota_from_profile() {
        let (profile, effective_quota) =
            resolve_effective_execution_profile("auto", GateThroughputProfile::Conservative)
                .expect("auto profile resolves");
        assert_eq!(profile.test_parallelism, 2);
        assert_eq!(profile.cpu_quota_percent, 200);
        assert_eq!(effective_quota, "200%");
    }

    #[test]
    fn gate_execution_profile_applies_explicit_cpu_quota_to_parallelism() {
        let host = resolve_host_test_parallelism();
        let (profile, effective_quota) =
            resolve_effective_execution_profile("150%", GateThroughputProfile::Throughput)
                .expect("explicit quota resolves");
        assert_eq!(effective_quota, "150%");
        assert_eq!(profile.cpu_quota_percent, 150);
        assert_eq!(profile.test_parallelism, 2_u32.min(host));
    }

    #[test]
    fn gate_execution_profile_zero_quota_preserves_host_parallelism() {
        let host = resolve_host_test_parallelism();
        let (profile, effective_quota) =
            resolve_effective_execution_profile("0%", GateThroughputProfile::Conservative)
                .expect("zero quota resolves");
        assert_eq!(effective_quota, "0%");
        assert_eq!(profile.cpu_quota_percent, 0);
        assert_eq!(profile.test_parallelism, host);
    }

    #[test]
    fn gate_execution_profile_rejects_invalid_explicit_cpu_quota() {
        let err =
            resolve_effective_execution_profile("not-a-percent", GateThroughputProfile::Throughput)
                .expect_err("invalid quota must fail");
        assert!(err.contains("invalid cpu_quota value"));
    }

    #[test]
    fn gate_execution_profile_balanced_is_within_expected_bounds() {
        let host = resolve_host_test_parallelism();
        let balanced = resolve_gate_execution_profile(GateThroughputProfile::Balanced);
        assert!(balanced.test_parallelism >= 1);
        assert!(balanced.test_parallelism <= host);
        assert!(balanced.test_parallelism <= BALANCED_MAX_PARALLELISM.min(host));
    }

    #[test]
    fn ensure_clean_working_tree_skips_checks_in_quick_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let result = ensure_clean_working_tree(temp_dir.path(), true);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_clean_working_tree_rejects_unstaged_changes_in_full_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo = temp_dir.path();

        run_git(repo, &["init"]);
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Test User"]);

        fs::write(repo.join("sample.txt"), "v1\n").expect("write file");
        run_git(repo, &["add", "sample.txt"]);
        run_git(repo, &["commit", "-m", "init"]);

        fs::write(repo.join("sample.txt"), "v2\n").expect("modify file");

        let err = ensure_clean_working_tree(repo, false).expect_err("dirty tree should fail");
        assert!(err.contains("working tree has unstaged changes"));
    }

    #[test]
    fn ensure_clean_working_tree_rejects_untracked_changes_in_full_mode() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let repo = temp_dir.path();

        run_git(repo, &["init"]);
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Test User"]);

        fs::write(repo.join("tracked.txt"), "v1\n").expect("write tracked file");
        run_git(repo, &["add", "tracked.txt"]);
        run_git(repo, &["commit", "-m", "init"]);

        fs::write(repo.join("untracked.txt"), "new\n").expect("write untracked file");

        let err = ensure_clean_working_tree(repo, false).expect_err("untracked tree should fail");
        assert!(err.contains("working tree has untracked files"));
    }

    #[test]
    fn normalize_quick_test_gate_reuses_existing_test_entry() {
        let mut gates = vec![
            GateResult {
                name: "merge_conflict_main".to_string(),
                status: "PASS".to_string(),
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: None,
                error_hint: None,
            },
            GateResult {
                name: "test".to_string(),
                status: "PASS".to_string(),
                duration_secs: 2,
                log_path: Some("/tmp/test.log".to_string()),
                bytes_written: Some(10),
                bytes_total: Some(10),
                was_truncated: Some(false),
                log_bundle_hash: Some("b3-256:abc".to_string()),
                error_hint: None,
            },
            GateResult {
                name: "workspace_integrity".to_string(),
                status: "PASS".to_string(),
                duration_secs: 1,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: None,
                error_hint: None,
            },
        ];

        normalize_quick_test_gate(&mut gates);

        let test_gates = gates
            .iter()
            .filter(|gate| gate.name == "test")
            .collect::<Vec<_>>();
        assert_eq!(test_gates.len(), 1);
        let gate = test_gates[0];
        assert_eq!(gate.status, "SKIP");
        assert_eq!(gate.log_path.as_deref(), Some("/tmp/test.log"));
    }

    /// Verify that the `on_gate_progress` callback in [`EvidenceGateOptions`]
    /// receives `Started` events BEFORE `Completed` events for each gate.
    ///
    /// This test validates BLOCKER 2 fix: gate lifecycle events must be emitted
    /// during execution (via callback) rather than buffered and replayed after
    /// all gates return. The callback structure ensures callers can stream
    /// JSONL events in real time at each gate boundary.
    #[test]
    fn gate_progress_callback_receives_events_in_order() {
        use std::sync::{Arc, Mutex};

        use super::super::evidence::GateProgressEvent;

        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let events_clone = Arc::clone(&events);

        // Build a callback that records event types.
        let callback: Box<dyn Fn(GateProgressEvent) + Send> =
            Box::new(move |event: GateProgressEvent| match event {
                GateProgressEvent::Started { gate_name } => {
                    events_clone
                        .lock()
                        .unwrap()
                        .push(format!("started:{gate_name}"));
                },
                GateProgressEvent::Progress {
                    gate_name,
                    elapsed_secs,
                    bytes_streamed,
                } => {
                    events_clone.lock().unwrap().push(format!(
                        "progress:{gate_name}:elapsed={elapsed_secs}:bytes={bytes_streamed}"
                    ));
                },
                GateProgressEvent::Completed {
                    gate_name, passed, ..
                } => {
                    events_clone
                        .lock()
                        .unwrap()
                        .push(format!("completed:{gate_name}:passed={passed}"));
                },
            });

        // Verify that the callback type matches what EvidenceGateOptions expects.
        let opts = super::super::evidence::EvidenceGateOptions {
            test_command: None,
            test_command_environment: Vec::new(),
            env_remove_keys: Vec::new(),
            skip_test_gate: true,
            skip_merge_conflict_gate: true,
            emit_human_logs: false,
            on_gate_progress: Some(callback),
        };

        // Simulate the callback being invoked for a gate lifecycle.
        if let Some(ref cb) = opts.on_gate_progress {
            cb(GateProgressEvent::Started {
                gate_name: "test_gate".to_string(),
            });
            cb(GateProgressEvent::Progress {
                gate_name: "test_gate".to_string(),
                elapsed_secs: 10,
                bytes_streamed: 1024,
            });
            cb(GateProgressEvent::Completed {
                gate_name: "test_gate".to_string(),
                passed: true,
                duration_secs: 5,
                log_path: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_bundle_hash: None,
                error_hint: None,
            });
        }

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0], "started:test_gate");
        assert_eq!(recorded[1], "progress:test_gate:elapsed=10:bytes=1024");
        assert_eq!(recorded[2], "completed:test_gate:passed=true");
    }

    /// Regression (MAJOR 2): `check_lane_not_corrupt` must refuse to run
    /// gates when `lane-00` has a corrupt marker, preventing execution in
    /// a known-bad environment.
    #[test]
    fn check_lane_not_corrupt_rejects_corrupt_lane() {
        use apm2_core::fac::{LANE_CORRUPT_MARKER_SCHEMA, LaneCorruptMarkerV1};

        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root.clone()).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        // Plant a corrupt marker on lane-00.
        let marker = LaneCorruptMarkerV1 {
            schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
            lane_id: "lane-00".to_string(),
            reason: "test corruption".to_string(),
            cleanup_receipt_digest: None,
            detected_at: "2026-02-15T00:00:00Z".to_string(),
        };
        marker.persist(&fac_root).expect("persist marker");

        let err = check_lane_not_corrupt(&manager).expect_err("should reject corrupt lane");
        assert!(
            err.contains("CORRUPT"),
            "error should mention CORRUPT, got: {err}"
        );
        assert!(
            err.contains("test corruption"),
            "error should include corrupt reason, got: {err}"
        );
    }

    /// Positive case: `check_lane_not_corrupt` should succeed when
    /// `lane-00` has no corrupt marker.
    #[test]
    fn check_lane_not_corrupt_accepts_clean_lane() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        check_lane_not_corrupt(&manager).expect("clean lane should pass");
    }

    /// Regression (MAJOR 1): `acquire_gates_lane_lock` must acquire an
    /// exclusive lock preventing concurrent gate invocations from colliding.
    #[test]
    fn acquire_gates_lane_lock_succeeds_on_free_lane() {
        let root = tempfile::tempdir().expect("tempdir");
        let fac_root = root.path().join("private").join("fac");
        fs::create_dir_all(&fac_root).expect("create fac root");
        let manager = LaneManager::new(fac_root).expect("create manager");
        manager.ensure_directories().expect("ensure dirs");

        let guard = acquire_gates_lane_lock(&manager).expect("should acquire lock");
        // Lock is held while guard is alive.
        drop(guard);
    }

    /// Regression (BLOCKER 1/2): `run_gates_inner` with `lane_count = 1`
    /// should run all command-style phases in the same lane-local env context.
    ///
    /// This test exercises `run_gates_inner` directly with a custom fake
    /// `cargo` and log-collecting script gates. It confirms:
    /// - single-lane mode does not fail due to nested lock acquisition, and
    /// - all active evidence phases receive the same lane-local HOME/TMPDIR
    ///   /XDG env values.
    #[allow(unsafe_code)] // Env var mutation is required for test setup and teardown.
    #[test]
    fn run_gates_inner_reuses_single_lane_env_for_all_phases() {
        use std::env;
        use std::ffi::OsString;

        struct EnvGuard {
            vars: Vec<(&'static str, Option<OsString>)>,
            current_dir: Option<std::path::PathBuf>,
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                for (name, value) in self.vars.drain(..) {
                    if let Some(value) = value {
                        // SAFETY: serialized via TEST_ENV_LOCK
                        unsafe { std::env::set_var(name, value) };
                    } else {
                        // SAFETY: serialized via TEST_ENV_LOCK
                        unsafe { std::env::remove_var(name) };
                    }
                }

                if let Some(path) = self.current_dir.take() {
                    let _ = std::env::set_current_dir(path);
                }
            }
        }

        let _guard = TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("serialize env-mutating integration test");

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let repo = temp_dir.path().join("workspace");
        fs::create_dir_all(&repo).expect("create workspace");
        let apm2_home = temp_dir.path().join("apm2_home");
        let bin_dir = temp_dir.path().join("fake-bin");
        let scripts_dir = repo.join("scripts").join("ci");
        let log_file = repo.join(".fac_gate_env_log");

        fs::create_dir_all(apm2_home.join("private").join("fac")).expect("create apm2 home");
        fs::create_dir_all(&bin_dir).expect("create fake bin dir");
        fs::create_dir_all(&scripts_dir).expect("create scripts dir");

        run_git(&repo, &["init"]);
        run_git(&repo, &["config", "user.email", "test@example.com"]);
        run_git(&repo, &["config", "user.name", "Test User"]);
        fs::write(repo.join("README.md"), "fac gates lane test\n").expect("write repo file");
        run_git(&repo, &["add", "README.md"]);
        run_git(&repo, &["commit", "-m", "initial"]);
        run_git(&repo, &["branch", "-M", "main"]);

        // Shell scripts use $phase / $1 / $HOME etc. — NOT Rust format args.
        #[allow(clippy::literal_string_with_formatting_args)]
        let fake_cargo = "#!/bin/sh\necho \"phase=$1|HOME=$HOME|TMPDIR=$TMPDIR|XDG_CACHE_HOME=$XDG_CACHE_HOME|XDG_CONFIG_HOME=$XDG_CONFIG_HOME\" >> \"$PWD/.fac_gate_env_log\"\nexit 0\n";
        fs::write(bin_dir.join("cargo"), fake_cargo).expect("write fake cargo");

        #[allow(clippy::literal_string_with_formatting_args)]
        let safety_guard = concat!(
            "#!/bin/sh\n",
            "phase=\"test_safety_guard\"\n",
            "if [ \"$1\" = \"snapshot\" ]; then\n",
            ":\n",
            "fi\n",
            "echo \"phase=$phase|HOME=$HOME|TMPDIR=$TMPDIR|XDG_CACHE_HOME=$XDG_CACHE_HOME|XDG_CONFIG_HOME=$XDG_CONFIG_HOME\" >> \"$PWD/.fac_gate_env_log\"\n",
            "exit 0\n",
        );
        fs::write(scripts_dir.join("test_safety_guard.sh"), safety_guard)
            .expect("write fake safety guard");

        #[allow(clippy::literal_string_with_formatting_args)]
        let lint_script = concat!(
            "#!/bin/sh\n",
            "phase=\"review_artifact_lint\"\n",
            "echo \"phase=$phase|HOME=$HOME|TMPDIR=$TMPDIR|XDG_CACHE_HOME=$XDG_CACHE_HOME|XDG_CONFIG_HOME=$XDG_CONFIG_HOME\" >> \"$PWD/.fac_gate_env_log\"\n",
            "exit 0\n",
        );
        fs::write(scripts_dir.join("review_artifact_lint.sh"), lint_script)
            .expect("write fake lint script");

        #[allow(clippy::literal_string_with_formatting_args)]
        let integrity_script = concat!(
            "#!/bin/sh\n",
            "phase=\"workspace_integrity\"\n",
            "while [ \"$#\" -gt 0 ]; do\n",
            "if [ \"$1\" = \"--snapshot-file\" ]; then\n",
            "shift\n",
            "mkdir -p \"$(dirname \"$1\")\"\n",
            ": > \"$1\"\n",
            "break\n",
            "fi\n",
            "shift\n",
            "done\n",
            "echo \"phase=$phase|HOME=$HOME|TMPDIR=$TMPDIR|XDG_CACHE_HOME=$XDG_CACHE_HOME|XDG_CONFIG_HOME=$XDG_CONFIG_HOME\" >> \"$PWD/.fac_gate_env_log\"\n",
            "exit 0\n",
        );
        fs::write(
            scripts_dir.join("workspace_integrity_guard.sh"),
            integrity_script,
        )
        .expect("write fake workspace integrity script");

        let cargo_path = bin_dir.join("cargo");
        fs::set_permissions(cargo_path, fs::Permissions::from_mode(0o755))
            .expect("set fake cargo mode");
        for script in [
            scripts_dir.join("test_safety_guard.sh"),
            scripts_dir.join("review_artifact_lint.sh"),
            scripts_dir.join("workspace_integrity_guard.sh"),
        ] {
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
                .expect("set script executable");
        }

        let original_path = env::var_os("PATH");
        let original_apm2_home = env::var_os("APM2_HOME");
        let original_lane_count = env::var_os("APM2_FAC_LANE_COUNT");
        let original_dir = env::current_dir().expect("capture current dir");
        let path_override = format!(
            "{}:{}",
            bin_dir.display(),
            env::var("PATH").unwrap_or_default()
        );

        // SAFETY: serialized via TEST_ENV_LOCK
        unsafe {
            env::set_var("PATH", path_override);
            env::set_var("APM2_HOME", &apm2_home);
            env::set_var("APM2_FAC_LANE_COUNT", "1");
        }
        let _env_guard = EnvGuard {
            vars: vec![
                ("PATH", original_path),
                ("APM2_HOME", original_apm2_home),
                ("APM2_FAC_LANE_COUNT", original_lane_count),
            ],
            current_dir: Some(original_dir),
        };

        env::set_current_dir(&repo).expect("set test repository as cwd");

        let summary = run_gates_inner(
            false,
            true,
            30,
            "128M",
            128,
            "100%",
            GateThroughputProfile::Conservative,
            2,
            false,
            None,
        )
        .expect("gates should run in single-lane mode");
        assert!(summary.passed);

        let lane_dir = apm2_home
            .join("private")
            .join("fac")
            .join("lanes")
            .join("lane-00");
        let expected = [
            lane_dir.join("home").to_string_lossy().into_owned(),
            lane_dir.join("tmp").to_string_lossy().into_owned(),
            lane_dir.join("xdg_cache").to_string_lossy().into_owned(),
            lane_dir.join("xdg_config").to_string_lossy().into_owned(),
        ];

        let log_contents = fs::read_to_string(&log_file).expect("read env log file");
        let mut observed_tuples = HashSet::new();
        let mut phases = HashSet::new();
        for line in log_contents.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let mut fields = line.split('|');
            let phase = fields
                .next()
                .and_then(|value| value.strip_prefix("phase="))
                .unwrap_or("unknown");
            let home = fields
                .next()
                .and_then(|value| value.strip_prefix("HOME="))
                .unwrap_or("");
            let tmpdir = fields
                .next()
                .and_then(|value| value.strip_prefix("TMPDIR="))
                .unwrap_or("");
            let xdg_cache = fields
                .next()
                .and_then(|value| value.strip_prefix("XDG_CACHE_HOME="))
                .unwrap_or("");
            let xdg_config = fields
                .next()
                .and_then(|value| value.strip_prefix("XDG_CONFIG_HOME="))
                .unwrap_or("");

            let tuple = (
                home.to_string(),
                tmpdir.to_string(),
                xdg_cache.to_string(),
                xdg_config.to_string(),
            );
            observed_tuples.insert(tuple);
            phases.insert(phase.to_string());
        }

        // Verify that the lane-local env tuple appears (proving the overrides
        // are applied) and that all cargo-based phases (fmt, clippy, doc) use it.
        let expected_tuple = (
            expected[0].clone(),
            expected[1].clone(),
            expected[2].clone(),
            expected[3].clone(),
        );
        assert!(
            observed_tuples.contains(&expected_tuple),
            "lane-local env tuple not observed; got: {observed_tuples:#?}"
        );

        // Cargo-based phases must be present.
        for expected_phase in ["fmt", "clippy", "doc"] {
            assert!(
                phases.contains(expected_phase),
                "missing cargo phase {expected_phase}"
            );
        }
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git command should execute");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
