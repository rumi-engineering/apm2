// AGENT-AUTHORED (TCK-00525)
//! `apm2 fac warm` — lane-scoped prewarm with receipts + economics +
//! authorization.
//!
//! Enqueues a warm job to the FAC queue (default) or optionally waits for
//! completion. Warm phases are selectable via `--phases`.
//!
//! The warm command:
//! 1. Resolves the FAC root and queue directories.
//! 2. Initializes the broker with proper health gate (matching worker flow).
//! 3. Obtains an RFC-0028 channel context token from the broker.
//! 4. Builds a `FacJobSpecV1(kind="warm")`.
//! 5. Enqueues to `queue/pending/`.
//! 6. Optionally waits for the receipt.
//!
//! The worker handles actual execution of warm phases using the lane target
//! namespace and FAC-managed `CARGO_HOME`.
//!
//! # Invariants
//!
//! - [INV-WARM-CLI-001] Warm jobs use the same broker token flow as gates.
//! - [INV-WARM-CLI-002] Phases are validated before enqueue.
//! - [INV-WARM-CLI-003] Queue writes are atomic (temp + rename).
//! - [INV-WARM-CLI-004] Broker health gate is opened before token issuance
//!   (fail-closed on missing/stale authority).
//! - [INV-WARM-CLI-005] Warm specs are validated against the FAC policy-derived
//!   `JobSpecValidationPolicy` before enqueue (TCK-00579). This enforces
//!   `repo_id` allowlist, `bytes_backend` allowlist, and filesystem-path
//!   rejection at enqueue time, matching the gates enqueue path.

use std::path::Path;
use std::time::{Duration, Instant};

use apm2_core::fac::broker::FacBroker;
use apm2_core::fac::job_spec::{
    Actuation, FacJobSpecV1, JobConstraints, JobSource, JobSpecValidationPolicy, LaneRequirements,
    MAX_QUEUE_LANE_LENGTH, validate_job_spec_with_policy,
};
use apm2_core::fac::warm::{DEFAULT_WARM_PHASES, MAX_WARM_PHASES, WarmPhase};
use apm2_core::fac::{check_disk_space, load_or_default_boundary_id, lookup_job_receipt};

use crate::commands::fac_queue_submit::{
    current_epoch_secs, enqueue_job, generate_job_suffix, init_broker, load_or_init_policy,
    resolve_fac_root, resolve_queue_root, resolve_repo_source_info,
};
use crate::exit_codes::codes as exit_codes;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default wait timeout for warm job completion (seconds).
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 1200;

/// Poll interval when waiting for receipt (seconds).
const WAIT_POLL_INTERVAL_SECS: u64 = 5;

/// Extra headroom iterations beyond the timeout-derived cap.
/// Provides a small buffer so the timeout check (elapsed >= timeout) fires
/// before the iteration cap in normal operation.
const POLL_ITERATION_HEADROOM: u64 = 10;

/// FAC receipts directory.
const FAC_RECEIPTS_DIR: &str = "receipts";

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run `apm2 fac warm`.
///
/// Returns an exit code.
#[allow(clippy::too_many_arguments, clippy::ref_option)]
pub fn run_fac_warm(
    phases_str: &Option<String>,
    lane: &Option<String>,
    wait: bool,
    wait_timeout_secs: u64,
    json_output: bool,
) -> u8 {
    // Resolve FAC root.
    let fac_root = match resolve_fac_root() {
        Ok(root) => root,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_resolve_root_failed",
                &msg,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Parse and validate phases.
    let phases = match parse_phases(phases_str) {
        Ok(p) => p,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_invalid_phases",
                &msg,
                exit_codes::VALIDATION_ERROR,
            );
        },
    };

    // Validate and resolve queue lane from --lane flag.
    let queue_lane = match validate_lane(lane) {
        Ok(l) => l,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_invalid_lane",
                &msg,
                exit_codes::VALIDATION_ERROR,
            );
        },
    };

    // Quick disk space check (full preflight is worker-owned).
    if let Ok(free) = check_disk_space(&fac_root) {
        // 100 MiB minimum for enqueueing.
        const MIN_ENQUEUE_BYTES: u64 = 100 * 1024 * 1024;
        if free < MIN_ENQUEUE_BYTES {
            return output_error(
                json_output,
                "warm_disk_space_low",
                &format!(
                    "insufficient disk space for enqueue: {free} bytes free (need {MIN_ENQUEUE_BYTES})",
                ),
                exit_codes::GENERIC_ERROR,
            );
        }
    }

    // Load boundary ID (fallback to "local" on error, matching worker pattern).
    let boundary_id =
        load_or_default_boundary_id(&fac_root).unwrap_or_else(|_| "local".to_string());

    // Load or initialize broker with proper health gate (matching worker flow).
    let mut broker = match init_broker(&fac_root, &boundary_id) {
        Ok(b) => b,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_broker_init_failed",
                &msg,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Load or initialize policy.
    let (policy_hash, policy_digest, fac_policy) = match load_or_init_policy(&fac_root) {
        Ok(p) => p,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_policy_load_failed",
                &msg,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // TCK-00579: Derive job spec validation policy from FAC policy for
    // enqueue-time enforcement of repo_id allowlist, bytes_backend
    // allowlist, and filesystem-path rejection.
    let job_spec_policy = match fac_policy.job_spec_validation_policy() {
        Ok(p) => p,
        Err(e) => {
            return output_error(
                json_output,
                "warm_job_spec_policy_failed",
                &format!("cannot derive job spec validation policy: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Admit the policy digest so the broker will accept token issuance.
    if let Err(e) = broker.admit_policy_digest(policy_digest) {
        return output_error(
            json_output,
            "warm_policy_admit_failed",
            &format!("cannot admit policy digest: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    // Generate job ID.
    let job_id = format!("warm-{}", generate_job_suffix());

    // Determine source info (repo identity + SHA + workspace root).
    let repo_source = resolve_repo_source_info();

    // Build the job spec.
    let lease_id = format!("warm-lease-{}", generate_job_suffix());
    let spec = match build_warm_job_spec(
        &job_id,
        &lease_id,
        &repo_source.repo_id,
        &repo_source.head_sha,
        &policy_digest,
        &phases,
        &queue_lane,
        &boundary_id,
        &mut broker,
        &job_spec_policy,
    ) {
        Ok(s) => s,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_spec_build_failed",
                &msg,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Enqueue the job.
    let queue_root = match resolve_queue_root() {
        Ok(path) => path,
        Err(msg) => {
            return output_error(
                json_output,
                "warm_resolve_queue_failed",
                &msg,
                exit_codes::GENERIC_ERROR,
            );
        },
    };
    if let Err(e) = enqueue_job(
        &queue_root,
        &fac_root,
        &spec,
        &fac_policy.queue_bounds_policy,
    ) {
        return output_error(
            json_output,
            "warm_enqueue_failed",
            &format!("failed to enqueue warm job: {e}"),
            exit_codes::GENERIC_ERROR,
        );
    }

    let output = serde_json::json!({
        "status": "enqueued",
        "job_id": job_id,
        "phases": phases.iter().map(|p| p.name()).collect::<Vec<_>>(),
        "queue_lane": spec.queue_lane,
        "policy_hash": policy_hash,
    });

    if json_output {
        println!("{}", serde_json::to_string(&output).unwrap_or_default());
    } else {
        eprintln!(
            "warm: enqueued job {job_id} with phases: {}",
            phases
                .iter()
                .map(|p| p.name())
                .collect::<Vec<_>>()
                .join(",")
        );
    }

    // Optionally wait for completion.
    if wait {
        let timeout = if wait_timeout_secs > 0 {
            Duration::from_secs(wait_timeout_secs)
        } else {
            Duration::from_secs(DEFAULT_WAIT_TIMEOUT_SECS)
        };

        match wait_for_receipt(&fac_root, &job_id, timeout, json_output) {
            Ok(()) => {},
            Err(msg) => {
                return output_error(
                    json_output,
                    "warm_wait_failed",
                    &msg,
                    exit_codes::GENERIC_ERROR,
                );
            },
        }
    }

    exit_codes::SUCCESS
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase Parsing
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::ref_option)]
fn parse_phases(phases_str: &Option<String>) -> Result<Vec<WarmPhase>, String> {
    match phases_str {
        None => Ok(DEFAULT_WARM_PHASES.to_vec()),
        Some(s) => {
            let parts: Vec<&str> = s
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() {
                return Err("no phases specified".to_string());
            }
            if parts.len() > MAX_WARM_PHASES {
                return Err(format!(
                    "too many phases: {} exceeds max {}",
                    parts.len(),
                    MAX_WARM_PHASES
                ));
            }
            let mut phases = Vec::with_capacity(parts.len());
            for part in parts {
                match WarmPhase::parse(part) {
                    Ok(p) => phases.push(p),
                    Err(e) => return Err(format!("invalid phase '{part}': {e}")),
                }
            }
            Ok(phases)
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lane Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Default queue lane for warm jobs when `--lane` is not specified.
const DEFAULT_QUEUE_LANE: &str = "bulk";

/// Validates and resolves the `--lane` flag value.
///
/// Returns the validated lane string (defaults to "bulk" when not specified).
/// Rejects empty, over-length, and unsafe lane names using the same character
/// set the worker enforces: `[A-Za-z0-9_-]`.
#[allow(clippy::ref_option)]
fn validate_lane(lane: &Option<String>) -> Result<String, String> {
    let lane_str = match lane {
        None => return Ok(DEFAULT_QUEUE_LANE.to_string()),
        Some(s) => s.trim(),
    };

    if lane_str.is_empty() {
        return Ok(DEFAULT_QUEUE_LANE.to_string());
    }

    if lane_str.len() > MAX_QUEUE_LANE_LENGTH {
        return Err(format!(
            "lane name too long: {} exceeds max {}",
            lane_str.len(),
            MAX_QUEUE_LANE_LENGTH
        ));
    }

    // Match the worker's queue_lane sanitization: only [A-Za-z0-9_-].
    if !lane_str
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "unsafe lane value {lane_str:?}: only [A-Za-z0-9_-] allowed"
        ));
    }

    Ok(lane_str.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Job Spec Construction
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn build_warm_job_spec(
    job_id: &str,
    lease_id: &str,
    repo_id: &str,
    head_sha: &str,
    policy_digest: &[u8; 32],
    phases: &[WarmPhase],
    queue_lane: &str,
    boundary_id: &str,
    broker: &mut FacBroker,
    job_spec_policy: &JobSpecValidationPolicy,
) -> Result<FacJobSpecV1, String> {
    let enqueue_time = format_iso8601(current_epoch_secs());
    let phases_csv = phases
        .iter()
        .map(|p| p.name())
        .collect::<Vec<_>>()
        .join(",");

    // Build the spec structure.
    let mut spec = FacJobSpecV1 {
        schema: apm2_core::fac::job_spec::JOB_SPEC_SCHEMA_ID.to_string(),
        job_id: job_id.to_string(),
        job_spec_digest: String::new(), // Computed below
        kind: "warm".to_string(),
        queue_lane: queue_lane.to_string(),
        priority: 50,
        enqueue_time,
        actuation: Actuation {
            lease_id: lease_id.to_string(),
            request_id: String::new(),   // Set after digest
            channel_context_token: None, // Set after token issuance
            decoded_source: Some(phases_csv),
        },
        source: JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: repo_id.to_string(),
            head_sha: head_sha.to_string(),
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
    };

    // Compute digest using the spec's own method (nulls token + digest fields).
    let digest = spec
        .compute_digest()
        .map_err(|e| format!("digest computation: {e}"))?;

    spec.job_spec_digest.clone_from(&digest);
    spec.actuation.request_id = digest;

    // Issue channel context token from broker.
    // Signature: issue_channel_context_token(&Hash, &str, &str, &str)
    // where Hash = [u8; 32].
    // Bind token policy fields to the admitted FAC policy digest while
    // keeping request_id bound to this concrete job spec digest.
    let token = broker
        .issue_channel_context_token(
            policy_digest,
            lease_id,
            &spec.actuation.request_id,
            boundary_id,
        )
        .map_err(|e| format!("broker token issuance: {e}"))?;
    spec.actuation.channel_context_token = Some(token);

    // TCK-00579: Validate the warm spec against the policy-derived validation
    // policy before enqueue, failing closed on validation error.  This mirrors
    // the gates enqueue path (INV-JS-005).
    validate_job_spec_with_policy(&spec, job_spec_policy)
        .map_err(|e| format!("validate warm job spec: {e}"))?;

    Ok(spec)
}

// ─────────────────────────────────────────────────────────────────────────────
// Wait for Receipt
// ─────────────────────────────────────────────────────────────────────────────

pub fn wait_for_receipt(
    fac_root: &Path,
    job_id: &str,
    timeout: Duration,
    json_output: bool,
) -> Result<(), String> {
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let start = Instant::now();
    let mut iterations: u64 = 0;

    // Derive the iteration cap from the effective timeout so that callers
    // passing wait_timeout > DEFAULT_WAIT_TIMEOUT_SECS are not cut short by
    // a fixed cap. The headroom ensures the elapsed-time check fires first
    // under normal conditions.
    let max_poll_iterations = timeout.as_secs() / WAIT_POLL_INTERVAL_SECS + POLL_ITERATION_HEADROOM;

    loop {
        if start.elapsed() >= timeout {
            return Err(format!(
                "warm job {} did not complete within {}s",
                job_id,
                timeout.as_secs()
            ));
        }

        iterations = iterations.saturating_add(1);
        if iterations > max_poll_iterations {
            return Err(format!(
                "warm job {job_id} exceeded max poll iterations ({max_poll_iterations})",
            ));
        }

        // Resolve the terminal outcome for this job.
        if let Some(receipt) = lookup_job_receipt(&receipts_dir, job_id) {
            return match receipt.outcome {
                apm2_core::fac::FacJobOutcome::Completed => {
                    if json_output {
                        let output = serde_json::json!({
                            "status": "completed",
                            "job_id": job_id,
                        });
                        println!("{}", serde_json::to_string(&output).unwrap_or_default());
                    } else {
                        eprintln!("warm: job {job_id} completed");
                    }
                    Ok(())
                },
                apm2_core::fac::FacJobOutcome::Denied => {
                    Err(format!("warm job {job_id} denied: {}", receipt.reason))
                },
                apm2_core::fac::FacJobOutcome::Quarantined => {
                    Err(format!("warm job {job_id} quarantined: {}", receipt.reason))
                },
                apm2_core::fac::FacJobOutcome::Cancelled => {
                    Err(format!("warm job {job_id} cancelled: {}", receipt.reason))
                },
                apm2_core::fac::FacJobOutcome::CancellationRequested => Err(format!(
                    "warm job {job_id} cancellation requested: {}",
                    receipt.reason
                )),
                _ => Err(format!(
                    "warm job {job_id} returned unsupported outcome: {:?}",
                    receipt.outcome
                )),
            };
        }

        std::thread::sleep(Duration::from_secs(WAIT_POLL_INTERVAL_SECS));
    }
}

/// Formats an epoch timestamp as ISO 8601 UTC.
fn format_iso8601(epoch_secs: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = epoch_secs / secs_per_day;
    let time_of_day = epoch_secs % secs_per_day;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Compute year/month/day from days since epoch (simplified Gregorian).
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
const fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days.wrapping_add(719_468);
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn output_error(json_output: bool, code: &str, message: &str, exit_code: u8) -> u8 {
    if json_output {
        let output = serde_json::json!({
            "status": "error",
            "error_code": code,
            "message": message,
        });
        println!("{}", serde_json::to_string(&output).unwrap_or_default());
    } else {
        eprintln!("warm: ERROR: [{code}] {message}");
    }
    exit_code
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use apm2_core::fac::{
        ChannelBoundaryTrace, DenialReasonCode, FacJobOutcome, FacJobReceiptV1Builder,
        QueueAdmissionTrace, persist_content_addressed_receipt,
    };

    use super::*;

    fn persist_job_receipt(
        fac_root: &Path,
        job_id: &str,
        outcome: FacJobOutcome,
        reason: &str,
    ) -> std::path::PathBuf {
        let receipt_id = format!("test-{job_id}-{}", current_epoch_secs());
        let job_digest = format!("b3-256:{}", "a".repeat(64));
        let mut builder = FacJobReceiptV1Builder::new(receipt_id, job_id, job_digest)
            .outcome(outcome)
            .reason(reason)
            .rfc0028_channel_boundary(ChannelBoundaryTrace {
                passed: outcome == FacJobOutcome::Completed,
                defect_count: u32::from(outcome != FacJobOutcome::Completed),
                defect_classes: Vec::new(),
                token_fac_policy_hash: None,
                token_canonicalizer_tuple_digest: None,
                token_boundary_id: None,
                token_issued_at_tick: None,
                token_expiry_tick: None,
            })
            .eio29_queue_admission(QueueAdmissionTrace {
                verdict: if outcome == FacJobOutcome::Completed {
                    "allow".to_string()
                } else {
                    "deny".to_string()
                },
                queue_lane: "bulk".to_string(),
                defect_reason: if outcome == FacJobOutcome::Completed {
                    None
                } else {
                    Some(reason.to_string())
                },
                cost_estimate_ticks: None,
            })
            .timestamp_secs(current_epoch_secs());
        if outcome != FacJobOutcome::Completed {
            builder = builder.denial_reason(DenialReasonCode::Cancelled);
        }
        let receipt = builder.try_build().expect("build receipt");
        persist_content_addressed_receipt(&fac_root.join(FAC_RECEIPTS_DIR), &receipt)
            .expect("persist receipt")
    }

    // ─────────────────────────────────────────────────────────────────────
    // validate_lane tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_lane_none_defaults_to_bulk() {
        assert_eq!(validate_lane(&None).unwrap(), "bulk");
    }

    #[test]
    fn test_validate_lane_empty_defaults_to_bulk() {
        assert_eq!(validate_lane(&Some(String::new())).unwrap(), "bulk");
        assert_eq!(validate_lane(&Some("  ".to_string())).unwrap(), "bulk");
    }

    #[test]
    fn test_validate_lane_valid_values() {
        for lane in &[
            "bulk", "control", "consume", "replay", "lane-01", "my_lane", "A-Z",
        ] {
            let result = validate_lane(&Some(lane.to_string()));
            assert!(
                result.is_ok(),
                "expected Ok for lane {lane:?}, got {result:?}"
            );
            assert_eq!(result.unwrap(), *lane);
        }
    }

    #[test]
    fn test_validate_lane_rejects_unsafe_chars() {
        for unsafe_lane in &["lane;rm", "lane foo", "lane/bar", "lane..baz", "lane\nX"] {
            let result = validate_lane(&Some(unsafe_lane.to_string()));
            assert!(
                result.is_err(),
                "expected Err for unsafe lane {unsafe_lane:?}, got {result:?}"
            );
            let err = result.unwrap_err();
            assert!(
                err.contains("unsafe lane value"),
                "error should mention unsafe lane: {err}"
            );
        }
    }

    #[test]
    fn test_validate_lane_rejects_overlong() {
        let long_lane = "x".repeat(MAX_QUEUE_LANE_LENGTH + 1);
        let result = validate_lane(&Some(long_lane));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_validate_lane_accepts_max_length() {
        let max_lane = "a".repeat(MAX_QUEUE_LANE_LENGTH);
        let result = validate_lane(&Some(max_lane.clone()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), max_lane);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Poll iteration cap tests (Fix #3)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_poll_iteration_cap_scales_with_timeout() {
        // For a 1200s timeout with 5s interval + 10 headroom: 250 iterations
        let cap_1200 = 1200u64 / WAIT_POLL_INTERVAL_SECS + POLL_ITERATION_HEADROOM;
        assert_eq!(cap_1200, 250);

        // For a 3600s timeout: should be 730, not 250
        let cap_3600 = 3600u64 / WAIT_POLL_INTERVAL_SECS + POLL_ITERATION_HEADROOM;
        assert_eq!(cap_3600, 730);

        // The cap for 3600s must exceed the old fixed cap of 250
        assert!(cap_3600 > cap_1200);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Phase parsing tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_phases_default() {
        let result = parse_phases(&None);
        assert!(result.is_ok());
        let phases = result.unwrap();
        assert!(!phases.is_empty());
    }

    #[test]
    fn test_parse_phases_empty_string_error() {
        let result = parse_phases(&Some(String::new()));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_phases_valid_single() {
        let result = parse_phases(&Some("fetch".to_string()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_parse_phases_valid_multiple() {
        let result = parse_phases(&Some("fetch,build".to_string()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_parse_phases_invalid_phase() {
        let result = parse_phases(&Some("nonexistent_phase".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn wait_for_receipt_reports_denied_outcome() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fac_root = temp.path();
        let job_id = "warm-test-denied";
        persist_job_receipt(fac_root, job_id, FacJobOutcome::Denied, "denied by worker");

        let result = wait_for_receipt(fac_root, job_id, Duration::from_secs(1), false);
        let err = result.expect_err("denied outcome should return error");
        assert!(err.contains("denied"), "unexpected error: {err}");
    }

    #[test]
    fn wait_for_receipt_accepts_completed_outcome() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fac_root = temp.path();
        let job_id = "warm-test-completed";
        persist_job_receipt(fac_root, job_id, FacJobOutcome::Completed, "ok");

        let result = wait_for_receipt(fac_root, job_id, Duration::from_secs(1), false);
        assert!(result.is_ok(), "unexpected result: {result:?}");
    }
}
