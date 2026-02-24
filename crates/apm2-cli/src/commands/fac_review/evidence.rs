//! Evidence gates (fmt, clippy, doc, test, native checks) for FAC push
//! pipeline.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use apm2_core::fac::gate_cache_v3::{GateCacheV3, V3CompoundKey};
use apm2_core::fac::{
    FacPolicyV1, LaneLockGuard, LaneManager, build_job_environment,
    compute_test_env_for_parallelism,
};
use blake3;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::bounded_test_runner::{
    BoundedTestLimits, build_bounded_gate_command as build_systemd_bounded_gate_command,
    build_bounded_test_command as build_systemd_bounded_test_command,
};
use super::ci_status::{CiStatus, PrBodyStatusUpdater};
use super::gate_attestation::{
    GateResourcePolicy, build_nextest_command, compute_gate_attestation,
    gate_command_for_attestation, short_digest,
};
use super::gate_cache::{CacheSource, GateCache, ReuseDecision};
use super::gate_checks;
use super::merge_conflicts::{
    check_merge_conflicts_against_main, render_merge_conflict_log, render_merge_conflict_summary,
};
use super::timeout_policy::{
    DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS, DEFAULT_TEST_MEMORY_MAX, TEST_TIMEOUT_SLA_MESSAGE,
    max_memory_bytes, parse_memory_limit, resolve_bounded_test_timeout,
};
use super::types::now_iso8601;

/// Env var keys unconditionally stripped from ALL gate phases as
/// defense-in-depth against wrapper injection (TCK-00526, TCK-00548). These are
/// stripped by `build_job_environment` at the policy level AND by
/// `env_remove()` on the spawned `Command` for belt-and-suspenders containment.
const WRAPPER_STRIP_KEYS: &[&str] = &["RUSTC_WRAPPER"];

/// Prefix for env vars unconditionally stripped from ALL gate phases.
const WRAPPER_STRIP_PREFIXES: &[&str] = &["SCCACHE_"];
const SYSTEMD_TRANSIENT_UNIT_NOT_FOUND_PREFIX: &str =
    "Failed to start transient service unit: Unit ";
const RETRY_LOG_SCAN_MAX_BYTES: usize = 8192;

/// Compute the full set of wrapper-stripping `env_remove_keys` by combining the
/// static `WRAPPER_STRIP_KEYS` with any variables matching
/// `WRAPPER_STRIP_PREFIXES` discovered from both the ambient process
/// environment AND the provided policy-filtered environment. This ensures that
/// variables introduced by `env_set` in the policy (not present in the ambient
/// env) are also stripped as defense-in-depth.
fn compute_gate_env_remove_keys(policy_env: Option<&[(String, String)]>) -> Vec<String> {
    let mut keys: Vec<String> = WRAPPER_STRIP_KEYS
        .iter()
        .map(|k| (*k).to_string())
        .collect();
    // Scan the ambient process environment.
    for (key, _) in std::env::vars() {
        if WRAPPER_STRIP_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
            && !keys.contains(&key)
        {
            keys.push(key);
        }
    }
    // Also scan the policy-filtered environment for policy-introduced variables
    // that were not in the ambient environment.
    if let Some(envs) = policy_env {
        for (key, _) in envs {
            if WRAPPER_STRIP_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix))
                && !keys.contains(key)
            {
                keys.push(key.clone());
            }
        }
    }
    keys
}

/// Progress events emitted throughout evidence gate execution.
///
/// Callers can provide a callback via [`EvidenceGateOptions::on_gate_progress`]
/// to receive these events in real time — enabling JSONL streaming of per-gate
/// lifecycle events during execution rather than after all gates complete.
#[derive(Debug, Clone)]
pub enum GateProgressEvent {
    /// Emitted immediately before a gate starts executing.
    Started { gate_name: String },
    /// Emitted periodically while a gate is still running.
    Progress {
        gate_name: String,
        elapsed_secs: u64,
        bytes_streamed: u64,
    },
    /// Emitted immediately after a gate finishes executing.
    Completed {
        gate_name: String,
        passed: bool,
        duration_secs: u64,
        error_hint: Option<String>,
        /// Structured cache reuse decision (TCK-00626, REQ-0037).
        /// Present when a cache lookup was performed for this gate.
        /// Used by the gates.rs callback handler in non-test builds.
        #[cfg_attr(test, allow(dead_code))]
        cache_decision: Option<apm2_core::fac::gate_cache_v3::CacheDecision>,
    },
}

/// Options for customizing evidence gate execution.
#[allow(clippy::struct_excessive_bools)]
pub struct EvidenceGateOptions {
    /// Override command for the test phase. When `Some`, the test gate uses
    /// this command instead of `cargo nextest run ...`.
    pub test_command: Option<Vec<String>>,
    /// Extra environment variables applied when invoking a bounded test runner.
    pub test_command_environment: Vec<(String, String)>,
    /// Env var keys to remove from the spawned test process environment.
    /// Prevents parent process env inheritance of `sccache`/`RUSTC_WRAPPER`
    /// keys that could bypass cgroup containment (TCK-00548).
    pub env_remove_keys: Vec<String>,
    /// Optional base unit name used for deterministic bounded gate units.
    /// When set, non-test bounded units are named `<base>-<gate_name>`.
    pub bounded_gate_unit_base: Option<String>,
    /// Skip the heavyweight test gate for quick inner-loop validation.
    pub skip_test_gate: bool,
    /// Skip merge-conflict gate when caller already pre-validated it.
    pub skip_merge_conflict_gate: bool,
    /// Emit human-oriented status/heartbeat lines to stderr.
    /// JSON streaming callers should set this to `false`.
    pub emit_human_logs: bool,
    /// Optional callback invoked throughout gate execution.
    ///
    /// When set, this callback receives [`GateProgressEvent::Started`] before
    /// each gate begins, [`GateProgressEvent::Progress`] heartbeats while a
    /// gate is running, and [`GateProgressEvent::Completed`] after each gate
    /// finishes. This enables real-time JSONL streaming of per-gate lifecycle
    /// progress instead of buffering all events until `run_evidence_gates`
    /// returns.
    pub on_gate_progress: Option<Box<dyn Fn(GateProgressEvent) + Send>>,
    /// TCK-00540 fix round 3: Gate resource policy for attestation digest
    /// computation during cache-reuse decisions. When `Some`, enables
    /// cache-reuse in `run_evidence_gates_with_lane_context` so that the
    /// fail-closed receipt-binding policy is evaluated against attested cache
    /// entries.
    pub gate_resource_policy: Option<GateResourcePolicy>,
}

/// Result of a single evidence gate execution.
#[derive(Debug, Clone, Default)]
pub struct EvidenceGateResult {
    pub gate_name: String,
    pub passed: bool,
    pub duration_secs: u64,
    pub log_path: Option<PathBuf>,
    pub bytes_written: Option<u64>,
    pub bytes_total: Option<u64>,
    pub was_truncated: Option<bool>,
    pub log_bundle_hash: Option<String>,
    /// Structured cache reuse decision (TCK-00626, REQ-0037).
    /// Present when a cache lookup was performed for this gate.
    pub cache_decision: Option<apm2_core::fac::gate_cache_v3::CacheDecision>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct StreamStats {
    bytes_written: u64,
    bytes_total: u64,
    was_truncated: bool,
}

/// Emit a gate-started progress event via the optional callback in
/// [`EvidenceGateOptions`].
fn emit_gate_started(opts: Option<&EvidenceGateOptions>, gate_name: &str) {
    if let Some(opts) = opts {
        if let Some(ref cb) = opts.on_gate_progress {
            cb(GateProgressEvent::Started {
                gate_name: gate_name.to_string(),
            });
        }
    }
}

/// Emit a gate-completed progress event via the optional callback in
/// [`EvidenceGateOptions`].
fn emit_gate_completed(opts: Option<&EvidenceGateOptions>, result: &EvidenceGateResult) {
    if let Some(opts) = opts {
        if let Some(ref cb) = opts.on_gate_progress {
            emit_gate_completed_via_cb(&**cb, result);
        }
    }
}

/// Emit a gate-started progress event via a bare callback reference.
fn emit_gate_started_cb(cb: Option<&dyn Fn(GateProgressEvent)>, gate_name: &str) {
    if let Some(cb) = cb {
        cb(GateProgressEvent::Started {
            gate_name: gate_name.to_string(),
        });
    }
}

/// Emit a gate-progress heartbeat event via a bare callback reference.
fn emit_gate_progress_cb(
    cb: Option<&dyn Fn(GateProgressEvent)>,
    gate_name: &str,
    elapsed_secs: u64,
    bytes_streamed: u64,
) {
    if let Some(cb) = cb {
        cb(GateProgressEvent::Progress {
            gate_name: gate_name.to_string(),
            elapsed_secs,
            bytes_streamed,
        });
    }
}

/// Emit a gate-completed progress event via a bare callback reference.
fn emit_gate_completed_cb(cb: Option<&dyn Fn(GateProgressEvent)>, result: &EvidenceGateResult) {
    if let Some(cb) = cb {
        emit_gate_completed_via_cb(cb, result);
    }
}

/// Shared implementation for emitting a gate-completed event.
fn emit_gate_completed_via_cb(cb: &dyn Fn(GateProgressEvent), result: &EvidenceGateResult) {
    let error_hint = if result.passed {
        None
    } else {
        result
            .log_path
            .as_deref()
            .and_then(super::jsonl::read_log_error_hint)
    };
    cb(GateProgressEvent::Completed {
        gate_name: result.gate_name.clone(),
        passed: result.passed,
        duration_secs: result.duration_secs,
        error_hint,
        cache_decision: result.cache_decision.clone(),
    });
}

/// Canonical list of lane-scoped evidence gate names used by the FAC pipeline.
///
/// Shared across evidence collection, log discovery, and push projection so
/// the gate list is defined in a single place.
pub const LANE_EVIDENCE_GATES: &[&str] = &[
    "merge_conflict_main",
    "review_artifact_lint",
    "rustfmt",
    "doc",
    "clippy",
    "test_safety_guard",
    "fac_review_machine_spec_snapshot",
    "test",
    "workspace_integrity",
];
const FRONTLOADED_NATIVE_EVIDENCE_GATES: &[&str] = &[
    "review_artifact_lint",
    "test_safety_guard",
    "fac_review_machine_spec_snapshot",
];

const SHORT_TEST_OUTPUT_HINT_THRESHOLD_BYTES: usize = 1024;
const LOG_STREAM_MAX_BYTES: u64 = 4 * 1024 * 1024;
const LOG_STREAM_CHUNK_BYTES: usize = 16 * 1024;
const LOG_BUNDLE_SCHEMA: &str = "apm2.fac.log_bundle.v1";
// Observability-only monotonic pulse cadence (not HTF authority time).
const MONOTONIC_HEARTBEAT_TICK_SECS: u64 = 10;
const GATE_WAIT_POLL_MILLIS: u64 = 250;
const MERGE_CONFLICT_GATE_NAME: &str = "merge_conflict_main";
const DEFAULT_TEST_PIDS_MAX: u64 = 1536;
const DEFAULT_TEST_KILL_AFTER_SECONDS: u64 = 20;

struct GateCommandOutput {
    status: ExitStatus,
    stream_stats: StreamStats,
}

fn sha256_file_hex(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(format!("{:x}", hasher.finalize()))
}

fn gate_attestation_digest(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    test_command_override: Option<&[String]>,
    policy: &GateResourcePolicy,
) -> Option<String> {
    let command = gate_command_for_attestation(workspace_root, gate_name, test_command_override)?;
    compute_gate_attestation(workspace_root, sha, gate_name, &command, policy)
        .ok()
        .map(|attestation| attestation.attestation_digest)
}

// NOTE: `reuse_decision_for_gate` (v2-only reuse path) was removed as part
// of the TCK-00541 MAJOR security fix. V2 entries lack RFC-0028/0029
// binding proof and cannot satisfy v3 compound-key continuity. All reuse
// decisions now flow through `reuse_decision_with_v3_fallback` which
// only allows v3-native entries to satisfy reuse.

// =============================================================================
// Gate Cache V3 helpers (TCK-00541)
// =============================================================================

/// Compute a toolchain fingerprint from `rustc --version --verbose` output.
///
/// Returns a BLAKE3 hex digest. Falls back to a hash of "unknown" if rustc
/// is not available (fail-closed: different key from any real toolchain).
pub(super) fn compute_toolchain_fingerprint() -> String {
    // Use CWD="/" to ensure rustup resolves the default toolchain regardless of
    // where the caller is invoked from.  Without this, rustup picks up the
    // nearest rust-toolchain.toml (e.g. nightly from the repo root) while the
    // worker process runs from $HOME and always gets the stable toolchain,
    // producing a different fingerprint and a V3 gate-cache lookup miss.
    let output = std::process::Command::new("rustc")
        .args(["--version", "--verbose"])
        .current_dir("/")
        .output();
    let version_bytes = match &output {
        Ok(o) if o.status.success() => &o.stdout[..],
        _ => b"unknown-toolchain",
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2.fac.toolchain_fingerprint:");
    hasher.update(version_bytes);
    format!("b3-256:{}", hasher.finalize().to_hex())
}

/// Compute a v3 compound key from the evidence pipeline context.
///
/// Uses the commit SHA as the workspace attestation digest (content
/// fingerprint), the FAC policy hash, a toolchain fingerprint, and
/// sandbox/network policy hashes for environment-binding cache isolation.
///
/// Note: RFC-0028/0029 receipt bindings are NOT part of the compound key
/// because receipts are produced AFTER gate execution. Instead, receipt
/// binding is enforced per-gate via `rfc0028_receipt_bound` /
/// `rfc0029_receipt_bound` flags on each `V3GateResult`, validated by
/// `check_reuse()`.
pub(super) fn compute_v3_compound_key(
    sha: &str,
    fac_policy: &FacPolicyV1,
    sandbox_hardening_hash: &str,
    network_policy_hash: &str,
) -> Option<V3CompoundKey> {
    let policy_hash = apm2_core::fac::compute_policy_hash(fac_policy).ok()?;
    let toolchain = compute_toolchain_fingerprint();
    V3CompoundKey::new(
        sha,
        &policy_hash,
        &toolchain,
        sandbox_hardening_hash,
        network_policy_hash,
    )
    .ok()
}

/// Cache directory paths for v3 and v2 under the FAC root.
pub(super) fn cache_v3_root() -> Option<std::path::PathBuf> {
    let apm2_home = apm2_core::github::resolve_apm2_home()?;
    Some(apm2_home.join("private/fac/gate_cache_v3"))
}

// cache_v2_root removed: v2 fallback loading disabled in evidence pipeline
// ([INV-GCV3-001] TCK-00541 MAJOR security fix round 4). V2 entries lack
// RFC-0028/0029 binding proof and cannot satisfy v3 compound-key continuity.

/// Try to reuse from v3 cache; v2 is structurally excluded.
///
/// Returns a unified `ReuseDecision` that can be used by the evidence flow.
/// When v3 hits, the v3 decision reason is used.
///
/// # Security: V2 structurally excluded (TCK-00541 MAJOR fix round 4)
///
/// [INV-GCV3-001] V2 entries lack RFC-0028/0029 binding proof and cannot
/// satisfy v3 compound-key continuity requirements. As of round 4, v2
/// entries are no longer loaded into `v3_cache_loaded` at all: the
/// evidence pipeline uses `GateCacheV3::load_from_dir` only (native v3).
/// The `_v2_cache` parameter is retained for the v2 fallback miss path
/// but v2 entries never reach `check_reuse`.
///
/// Defense-in-depth: even if a v2-sourced `GateCacheV3` were passed here,
/// `check_reuse` would deny via `v2_sourced_no_binding_proof`.
#[allow(clippy::too_many_arguments)]
fn reuse_decision_with_v3_fallback(
    v3_cache: Option<&GateCacheV3>,
    _v2_cache: Option<&GateCache>,
    gate_name: &str,
    attestation_digest: Option<&str>,
    verifying_key: Option<&apm2_core::crypto::VerifyingKey>,
    v3_cache_root: Option<&std::path::Path>,
    v3_compound_key: Option<&apm2_core::fac::gate_cache_v3::V3CompoundKey>,
    sha: Option<&str>,
) -> (
    ReuseDecision,
    Option<apm2_core::fac::gate_cache_v3::CacheDecision>,
) {
    // Try v3 first.
    //
    // TCK-00626 round 5: check_reuse now returns CacheDecision directly
    // (the old check_reuse_decision wrapper was eliminated). The single
    // check_reuse method performs all checks in the correct TCK-00626 S2
    // order (gate_miss -> signature -> receipt_binding -> drift -> TTL)
    // and returns a structured CacheDecision with first_mismatch_dimension.
    if let Some(v3) = v3_cache {
        let cache_decision = v3.check_reuse(gate_name, attestation_digest, true, verifying_key);
        if cache_decision.hit {
            return (ReuseDecision::hit_v3(), Some(cache_decision));
        }
        return (
            ReuseDecision::miss("v3_miss_v2_fallback_disabled"),
            Some(cache_decision),
        );
    }
    // No v3 cache loaded: diagnose compound-key drift if root and key are
    // available.
    if let (Some(root), Some(key), Some(sha_val)) = (v3_cache_root, v3_compound_key, sha) {
        let decision = apm2_core::fac::gate_cache_v3::diagnose_cache_miss(root, sha_val, key);
        return (
            ReuseDecision::miss("v3_miss_v2_fallback_disabled"),
            Some(decision),
        );
    }
    // [INV-GCV3-001] V2 fallback disabled for reuse. V2 entries do not
    // carry RFC-0028/0029 binding proof and cannot satisfy v3 compound-key
    // continuity. Returning miss ensures fail-closed behavior: gates that
    // only have v2 entries will be re-executed under v3 with full bindings.
    //
    // Fallback: no v3 context available.
    (
        ReuseDecision::miss("v3_miss_v2_fallback_disabled"),
        Some(apm2_core::fac::gate_cache_v3::CacheDecision::cache_miss(
            apm2_core::fac::gate_cache_v3::CacheReasonCode::ShaMiss,
            None,
        )),
    )
}

/// Unified cached payload fields extracted from either v2 or v3.
///
/// Used by the cache-hit path to avoid coupling the reuse sites to a
/// specific cache version.  The fields are the subset needed to emit
/// evidence results and propagate cache metadata.
struct CachedPayload {
    duration_secs: u64,
    evidence_log_digest: Option<String>,
    log_path: Option<String>,
}

/// Resolve the cached payload from the appropriate cache layer based on
/// the `ReuseDecision` source.
///
/// When `source == V3`, pulls from `v3_cache`; otherwise pulls from `v2_cache`.
/// Returns `None` if the indicated source does not contain the gate entry
/// (should not happen in a well-formed cache, but fail-closed).
fn resolve_cached_payload(
    reuse: &ReuseDecision,
    v3_cache: Option<&GateCacheV3>,
    v2_cache: Option<&GateCache>,
    gate_name: &str,
) -> Option<CachedPayload> {
    match reuse.source {
        CacheSource::V3 => {
            let v3 = v3_cache?;
            let entry = v3.get(gate_name)?;
            Some(CachedPayload {
                duration_secs: entry.duration_secs,
                evidence_log_digest: entry.evidence_log_digest.clone(),
                log_path: entry.log_path.clone(),
            })
        },
        #[cfg(test)]
        CacheSource::V2 => {
            let v2 = v2_cache?;
            let entry = v2.get(gate_name)?;
            Some(CachedPayload {
                duration_secs: entry.duration_secs,
                evidence_log_digest: entry.evidence_log_digest.clone(),
                log_path: entry.log_path.clone(),
            })
        },
        CacheSource::None => {
            let _ = (v2_cache, gate_name);
            None
        },
    }
}

fn stream_pipe_to_file<R: Read>(
    mut pipe: R,
    output_file: &Arc<Mutex<File>>,
    shared_bytes: &Arc<AtomicU64>,
    stream_prefix: &str,
) -> std::io::Result<StreamStats> {
    {
        let mut output = output_file
            .lock()
            .map_err(|_| std::io::Error::other("log file mutex poisoned"))?;
        output.write_all(stream_prefix.as_bytes())?;
        output.write_all(b"\n")?;
    }

    let mut stats = StreamStats::default();
    let mut buffer = [0_u8; LOG_STREAM_CHUNK_BYTES];
    loop {
        let bytes_read = pipe.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let chunk_bytes = u64::try_from(bytes_read).unwrap_or(u64::MAX);
        let total_before = shared_bytes.fetch_add(chunk_bytes, Ordering::SeqCst);
        stats.bytes_total += chunk_bytes;

        if total_before >= LOG_STREAM_MAX_BYTES {
            stats.was_truncated = true;
            continue;
        }

        let remaining_cap = LOG_STREAM_MAX_BYTES.saturating_sub(total_before);
        if remaining_cap == 0 {
            stats.was_truncated = true;
            continue;
        }

        let write_len = usize::try_from(
            remaining_cap
                .min(chunk_bytes)
                .min(LOG_STREAM_CHUNK_BYTES as u64),
        )
        .map_err(|_| std::io::Error::other("stream read chunk exceeds platform limit"))?;
        if write_len > 0 {
            let mut output = output_file
                .lock()
                .map_err(|_| std::io::Error::other("log file mutex poisoned"))?;
            output.write_all(&buffer[..write_len])?;
            stats.bytes_written += write_len as u64;
        }

        if write_len as u64 != chunk_bytes {
            stats.was_truncated = true;
        }
    }

    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn run_gate_command_with_heartbeat(
    workspace_root: &Path,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
    extra_env: Option<&[(String, String)]>,
    env_remove_keys: Option<&[String]>,
    emit_human_logs: bool,
    on_gate_progress: Option<&dyn Fn(GateProgressEvent)>,
) -> std::io::Result<GateCommandOutput> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .current_dir(workspace_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // TCK-00526: When a policy-filtered environment is provided, clear
    // the inherited environment first (default-deny) and then apply only
    // the policy-approved variables. Without env_clear(), Command::env()
    // adds to the inherited environment, leaking ambient secrets into
    // gate processes.
    if let Some(envs) = extra_env {
        command.env_clear();
        for (key, value) in envs {
            command.env(key, value);
        }
    }

    // Strip env vars that must not be inherited by the bounded test
    // process (e.g. RUSTC_WRAPPER, SCCACHE_* — TCK-00548).
    // When env_clear() is active this is defense-in-depth; when extra_env
    // is None (legacy callers) it prevents specific keys from leaking.
    if let Some(keys) = env_remove_keys {
        for key in keys {
            command.env_remove(key);
        }
    }

    let mut child = command.spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture child stdout for evidence gate"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture child stderr for evidence gate"))?;

    crate::commands::fac_permissions::write_fac_file_with_mode(log_path, b"").map_err(|err| {
        std::io::Error::other(format!(
            "failed to initialize evidence gate log {}: {err}",
            log_path.display()
        ))
    })?;

    let output_file = crate::commands::fac_permissions::append_fac_file_with_mode(log_path)
        .map_err(|err| {
            std::io::Error::other(format!(
                "failed to open evidence gate log {}: {err}",
                log_path.display()
            ))
        })?;
    let output_file = Arc::new(Mutex::new(output_file));
    let shared_bytes = Arc::new(AtomicU64::new(0));

    let stdout_handle = {
        let output_file = Arc::clone(&output_file);
        let shared_bytes = Arc::clone(&shared_bytes);
        thread::spawn(move || {
            stream_pipe_to_file(stdout, &output_file, &shared_bytes, "=== stdout ===")
        })
    };
    let stderr_handle = {
        let output_file = Arc::clone(&output_file);
        let shared_bytes = Arc::clone(&shared_bytes);
        thread::spawn(move || {
            stream_pipe_to_file(stderr, &output_file, &shared_bytes, "=== stderr ===")
        })
    };

    let started = Instant::now();
    let heartbeat_interval = Duration::from_secs(MONOTONIC_HEARTBEAT_TICK_SECS);
    let mut next_heartbeat = heartbeat_interval;

    let exit_status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }

        let elapsed = started.elapsed();
        if elapsed >= next_heartbeat {
            let elapsed_secs = elapsed.as_secs();
            let bytes_streamed = shared_bytes.load(Ordering::SeqCst);
            emit_gate_progress_cb(on_gate_progress, gate_name, elapsed_secs, bytes_streamed);
            if emit_human_logs {
                eprintln!(
                    "ts={} gate={} status=RUNNING tick={} elapsed_secs={}",
                    now_iso8601(),
                    gate_name,
                    elapsed_secs / MONOTONIC_HEARTBEAT_TICK_SECS,
                    elapsed_secs,
                );
            }
            // Keep heartbeat ticks aligned to fixed wall intervals.
            while elapsed >= next_heartbeat {
                next_heartbeat += heartbeat_interval;
            }
        }

        thread::sleep(Duration::from_millis(GATE_WAIT_POLL_MILLIS));
    };

    let stdout_stats = stdout_handle
        .join()
        .map_err(|_| std::io::Error::other("stdout stream thread panicked"))??;
    let stderr_stats = stderr_handle
        .join()
        .map_err(|_| std::io::Error::other("stderr stream thread panicked"))??;

    let mut stream_stats = StreamStats {
        bytes_written: stdout_stats.bytes_written + stderr_stats.bytes_written,
        bytes_total: stdout_stats.bytes_total + stderr_stats.bytes_total,
        was_truncated: stdout_stats.was_truncated || stderr_stats.was_truncated,
    };
    if stream_stats.bytes_written >= LOG_STREAM_MAX_BYTES {
        stream_stats.was_truncated = true;
    }

    Ok(GateCommandOutput {
        status: exit_status,
        stream_stats,
    })
}

/// Format and emit a single evidence line to stderr and an optional projection
/// log.
pub fn emit_evidence_line(
    sha: &str,
    gate: &str,
    status: &str,
    duration_secs: u64,
    log_path: &Path,
    projection_log: Option<&mut File>,
    emit_to_stderr: bool,
) {
    let ts = now_iso8601();
    let line = format!(
        "ts={ts} sha={sha} gate={gate} status={status} duration_secs={duration_secs} log={}",
        log_path.display()
    );
    if emit_to_stderr {
        eprintln!("{line}");
    }
    if let Some(file) = projection_log {
        let _ = writeln!(file, "{line}");
    }
}

fn append_short_test_failure_hint(log_path: &Path, combined_output_bytes: usize) {
    if combined_output_bytes >= SHORT_TEST_OUTPUT_HINT_THRESHOLD_BYTES {
        return;
    }

    let Ok(mut file) = crate::commands::fac_permissions::append_fac_file_with_mode(log_path) else {
        return;
    };

    let _ = writeln!(file);
    let _ = writeln!(file, "--- fac diagnostic ---");
    let _ = writeln!(
        file,
        "Test gate failed with minimal output ({combined_output_bytes} bytes). This usually indicates the process was killed by an OOM or timeout before tests could run."
    );
    let _ = writeln!(file, "{TEST_TIMEOUT_SLA_MESSAGE}");
    let _ = writeln!(file, "Check:");
    let _ = writeln!(file, "  journalctl --user --since '10 minutes ago'");
    let _ = writeln!(
        file,
        "  apm2 fac gates --memory-max 48G  # default is 48G; increase if needed"
    );
}

fn run_merge_conflict_gate(
    workspace_root: &Path,
    sha: &str,
    log_path: &Path,
    emit_human_logs: bool,
) -> (bool, u64, String, StreamStats) {
    let gate_name = MERGE_CONFLICT_GATE_NAME;
    let started = Instant::now();

    match check_merge_conflicts_against_main(workspace_root, sha) {
        Ok(report) => {
            let duration = started.elapsed().as_secs();
            let passed = !report.has_conflicts();
            let log = render_merge_conflict_log(&report);
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                log.as_bytes(),
            );
            let stats = StreamStats {
                bytes_written: log.len() as u64,
                bytes_total: log.len() as u64,
                was_truncated: false,
            };
            if emit_human_logs && !passed {
                eprintln!("{}", render_merge_conflict_summary(&report));
            }
            let gate_status = if passed { "PASS" } else { "FAIL" };
            emit_evidence_line(
                sha,
                gate_name,
                gate_status,
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            let ts = now_iso8601();
            (
                passed,
                duration,
                format!(
                    "ts={ts} sha={sha} gate={gate_name} status={gate_status} log={}",
                    log_path.display()
                ),
                stats,
            )
        },
        Err(err) => {
            let duration = started.elapsed().as_secs();
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                format!("merge conflict gate execution error: {err}\n").as_bytes(),
            );
            let message = format!("merge conflict gate execution error: {err}\n");
            let stats = StreamStats {
                bytes_written: message.len() as u64,
                bytes_total: message.len() as u64,
                was_truncated: false,
            };
            emit_evidence_line(
                sha,
                gate_name,
                "FAIL",
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            if emit_human_logs {
                eprintln!("merge_conflict_main: FAIL reason={err}");
            }
            let ts = now_iso8601();
            let sanitized_err = err.split_whitespace().collect::<Vec<_>>().join("_");
            (
                false,
                duration,
                format!(
                    "ts={ts} sha={sha} gate={gate_name} status=FAIL log={} error={}",
                    log_path.display(),
                    sanitized_err
                ),
                stats,
            )
        },
    }
}

/// Run a single evidence gate and emit the result.
///
/// NOTE: Production callers should prefer `run_single_evidence_gate_with_env`
/// with a policy-filtered environment. This wrapper passes `None` for env
/// (inheriting ambient) and is retained for test use.
#[cfg(test)]
pub fn run_single_evidence_gate(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
    emit_human_logs: bool,
) -> (bool, StreamStats) {
    run_single_evidence_gate_with_env(
        workspace_root,
        sha,
        gate_name,
        cmd,
        args,
        log_path,
        None,
        None,
        emit_human_logs,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn run_single_evidence_gate_with_env(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
    extra_env: Option<&[(String, String)]>,
    env_remove_keys: Option<&[String]>,
    emit_human_logs: bool,
) -> (bool, StreamStats) {
    run_single_evidence_gate_with_env_and_progress(
        workspace_root,
        sha,
        gate_name,
        cmd,
        args,
        log_path,
        extra_env,
        env_remove_keys,
        emit_human_logs,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_single_evidence_gate_with_env_and_progress(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    cmd: &str,
    args: &[&str],
    log_path: &Path,
    extra_env: Option<&[(String, String)]>,
    env_remove_keys: Option<&[String]>,
    emit_human_logs: bool,
    on_gate_progress: Option<&dyn Fn(GateProgressEvent)>,
) -> (bool, StreamStats) {
    let started = Instant::now();
    let mut output = run_gate_command_with_heartbeat(
        workspace_root,
        gate_name,
        cmd,
        args,
        log_path,
        extra_env,
        env_remove_keys,
        emit_human_logs,
        on_gate_progress,
    );

    // S8: retry once without parent binding when systemd reports parent unit
    // not found (e.g., stale session scope).
    if cmd == "systemd-run" {
        let stripped_args = strip_parent_binding_properties(args);
        if stripped_args.len() != args.len()
            && output.as_ref().is_ok_and(|out| !out.status.success())
            && is_systemd_unit_not_found_failure(log_path)
        {
            if emit_human_logs {
                eprintln!(
                    "ts={} gate={gate_name} retry=without_parent_binding reason=systemd_unit_not_found",
                    now_iso8601()
                );
            }
            let retry_args: Vec<&str> = stripped_args.iter().map(String::as_str).collect();
            output = run_gate_command_with_heartbeat(
                workspace_root,
                gate_name,
                cmd,
                &retry_args,
                log_path,
                extra_env,
                env_remove_keys,
                emit_human_logs,
                on_gate_progress,
            );
        }
    }

    let duration = started.elapsed().as_secs();
    match output {
        Ok(out) => {
            let passed = out.status.success();
            if !passed && gate_name == "test" {
                let combined_output_bytes =
                    usize::try_from(out.stream_stats.bytes_total).unwrap_or(usize::MAX);
                append_short_test_failure_hint(log_path, combined_output_bytes);
            }
            let status = if passed { "PASS" } else { "FAIL" };
            emit_evidence_line(
                sha,
                gate_name,
                status,
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            (passed, out.stream_stats)
        },
        Err(e) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                format!("execution error: {e}\n").as_bytes(),
            );
            emit_evidence_line(
                sha,
                gate_name,
                "FAIL",
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            (
                false,
                StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                },
            )
        },
    }
}

fn strip_parent_binding_properties(args: &[&str]) -> Vec<String> {
    let mut stripped = Vec::with_capacity(args.len());
    let mut idx = 0usize;
    while idx < args.len() {
        if args[idx] == "--property" {
            if let Some(value) = args.get(idx + 1) {
                if value.starts_with("PartOf=") || value.starts_with("BindsTo=") {
                    idx += 2;
                    continue;
                }
            }
        }
        stripped.push(args[idx].to_string());
        idx += 1;
    }
    stripped
}

fn is_systemd_unit_not_found_failure(log_path: &Path) -> bool {
    let Ok(mut file) = File::open(log_path) else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    let start = metadata
        .len()
        .saturating_sub(u64::try_from(RETRY_LOG_SCAN_MAX_BYTES).unwrap_or(u64::MAX));
    if file.seek(SeekFrom::Start(start)).is_err() {
        return false;
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return false;
    }
    let text = String::from_utf8_lossy(&bytes);
    text.contains(SYSTEMD_TRANSIENT_UNIT_NOT_FOUND_PREFIX) && text.contains(" not found.")
}

fn run_native_evidence_gate(
    workspace_root: &Path,
    sha: &str,
    gate_name: &str,
    log_path: &Path,
    emit_human_logs: bool,
) -> (bool, StreamStats) {
    let started = Instant::now();
    let execution = match gate_name {
        "test_safety_guard" => gate_checks::run_test_safety_guard(workspace_root),
        "fac_review_machine_spec_snapshot" => {
            gate_checks::run_fac_review_machine_spec_guard(workspace_root)
        },
        "review_artifact_lint" => gate_checks::run_review_artifact_lint(workspace_root),
        _ => Err(format!("unknown native evidence gate `{gate_name}`")),
    };
    let duration = started.elapsed().as_secs();

    match execution {
        Ok(check) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                check.output.as_bytes(),
            );
            let bytes = u64::try_from(check.output.len()).unwrap_or(u64::MAX);
            emit_evidence_line(
                sha,
                gate_name,
                if check.passed { "PASS" } else { "FAIL" },
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            (
                check.passed,
                StreamStats {
                    bytes_written: bytes,
                    bytes_total: bytes,
                    was_truncated: false,
                },
            )
        },
        Err(err) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                log_path,
                format!("execution error: {err}\n").as_bytes(),
            );
            emit_evidence_line(
                sha,
                gate_name,
                "FAIL",
                duration,
                log_path,
                None,
                emit_human_logs,
            );
            (
                false,
                StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                },
            )
        },
    }
}

/// Snapshot file path for workspace integrity (stored under target/ci/).
fn workspace_integrity_snapshot(workspace_root: &Path) -> PathBuf {
    workspace_root.join(gate_checks::WORKSPACE_INTEGRITY_SNAPSHOT_REL_PATH)
}

/// Take a baseline workspace integrity snapshot before test execution.
/// Returns `true` if snapshot was created successfully.
fn snapshot_workspace_integrity(workspace_root: &Path) -> bool {
    let snapshot = workspace_integrity_snapshot(workspace_root);
    gate_checks::snapshot_workspace_integrity(workspace_root, &snapshot).is_ok()
}

/// Verify workspace integrity against a previously captured snapshot.
fn verify_workspace_integrity_gate(
    workspace_root: &Path,
    sha: &str,
    log_path: &Path,
    emit_human_logs: bool,
) -> (bool, String, StreamStats) {
    let snapshot = workspace_integrity_snapshot(workspace_root);
    let log_path = log_path.to_path_buf();
    let gate_name = "workspace_integrity";
    let started = Instant::now();
    let execution = gate_checks::verify_workspace_integrity(workspace_root, &snapshot, None);
    let duration = started.elapsed().as_secs();

    let (passed, stream_stats) = match execution {
        Ok(check) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                &log_path,
                check.output.as_bytes(),
            );
            let bytes = u64::try_from(check.output.len()).unwrap_or(u64::MAX);
            emit_evidence_line(
                sha,
                gate_name,
                if check.passed { "PASS" } else { "FAIL" },
                duration,
                &log_path,
                None,
                emit_human_logs,
            );
            (
                check.passed,
                StreamStats {
                    bytes_written: bytes,
                    bytes_total: bytes,
                    was_truncated: false,
                },
            )
        },
        Err(err) => {
            let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
                &log_path,
                format!("execution error: {err}\n").as_bytes(),
            );
            emit_evidence_line(
                sha,
                gate_name,
                "FAIL",
                duration,
                &log_path,
                None,
                emit_human_logs,
            );
            (
                false,
                StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                },
            )
        },
    };

    let ts = now_iso8601();
    let status = if passed { "PASS" } else { "FAIL" };
    let line = format!(
        "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
        log_path.display()
    );
    (passed, line, stream_stats)
}

#[derive(Debug)]
struct PipelineTestCommand {
    command: Vec<String>,
    bounded_runner: bool,
    effective_timeout_seconds: u64,
    gate_profile: super::gates::GateThroughputProfile,
    effective_cpu_quota: String,
    effective_test_parallelism: u32,
    test_env: Vec<(String, String)>,
    /// Env var keys to remove from the spawned process environment.
    /// Prevents parent env inheritance of `sccache`/`RUSTC_WRAPPER` keys
    /// that could bypass the bounded test's cgroup containment (TCK-00548).
    env_remove_keys: Vec<String>,
    /// BLAKE3 hex hash of the effective `SandboxHardeningProfile` used for
    /// bounded test execution. Carried through so attestation binds to the
    /// actual policy-driven profile, not a default (TCK-00573 MAJOR-1 fix).
    sandbox_hardening_hash: String,
    /// BLAKE3 hex hash of the effective `NetworkPolicy` used for gate
    /// execution. Carried through so attestation binds to the actual
    /// policy-driven network posture, preventing cache reuse across
    /// policy drift (TCK-00574 MAJOR-1 fix).
    network_policy_hash: String,
}

/// Build the pipeline test command with policy-filtered environment.
///
/// # Arguments
///
/// * `workspace_root` - The workspace root directory.
/// * `lane_dir` - The lane directory from the actually-locked lane (returned by
///   `allocate_lane_job_logs_dir`). This MUST correspond to the lane protected
///   by the caller's `LaneLockGuard` to maintain lock/env coupling and prevent
///   concurrent access races.
fn build_pipeline_test_command(
    workspace_root: &Path,
    lane_dir: &Path,
) -> Result<PipelineTestCommand, String> {
    let memory_max_bytes = parse_memory_limit(DEFAULT_TEST_MEMORY_MAX)?;
    if memory_max_bytes > max_memory_bytes() {
        return Err(format!(
            "--memory-max {} exceeds FAC cap {}",
            DEFAULT_TEST_MEMORY_MAX,
            max_memory_bytes()
        ));
    }

    // Derive roots from the locked lane path to avoid ambient env races.
    let (apm2_home, fac_root) = resolve_pipeline_roots_from_lane_dir(lane_dir)?;
    let policy = load_or_create_pipeline_policy(&fac_root)?;

    // Ensure managed CARGO_HOME exists when policy denies ambient.
    if let Some(cargo_home) = policy.resolve_cargo_home(&apm2_home) {
        ensure_pipeline_managed_cargo_home(&cargo_home)?;
    }

    let timeout_decision =
        resolve_bounded_test_timeout(workspace_root, DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS);
    let gate_profile = super::gates::GateThroughputProfile::Throughput;
    // Throughput profile is intentionally host-aware and unconstrained by lane
    // count. Concurrency is controlled by queue admission rather than
    // per-lane CPU throttling so a single active pipeline can use full machine
    // capacity.
    let execution_profile = super::gates::resolve_gate_execution_profile(gate_profile);
    let effective_cpu_quota = format!("{}%", execution_profile.cpu_quota_percent);
    let lane_env = compute_test_env_for_parallelism(execution_profile.test_parallelism);

    // TCK-00526: Build policy-filtered environment.
    let ambient: Vec<(String, String)> = std::env::vars().collect();
    let mut policy_env = build_job_environment(&policy, &ambient, &apm2_home);

    // TCK-00575: Apply per-lane env isolation (HOME, TMPDIR, XDG_CACHE_HOME,
    // XDG_CONFIG_HOME). Uses the lane directory from the actually-locked lane
    // to maintain lock/env coupling (round 2 fix: was previously hardcoded
    // to lane-00).
    super::policy_loader::apply_review_lane_environment(&mut policy_env, lane_dir, &ambient)?;

    for (key, value) in &lane_env {
        policy_env.insert(key.clone(), value.clone());
    }
    let mut test_env: Vec<(String, String)> = policy_env.into_iter().collect();

    // TCK-00573 MAJOR-1 fix: compute the effective sandbox hardening hash
    // BEFORE the profile is moved into build_systemd_bounded_test_command,
    // so attestation binds to the actual policy-driven profile.
    let sandbox_hardening_hash = policy.sandbox_hardening.content_hash_hex();

    // TCK-00574: Resolve network policy for evidence gates with operator override.
    // Compute the hash BEFORE the policy is moved into the bounded test command
    // builder, so attestation binds to the actual policy-driven network posture
    // (MAJOR-1 fix: attestation digest must change when network policy changes).
    let evidence_network_policy =
        apm2_core::fac::resolve_network_policy("gates", policy.network_policy.as_ref());
    let network_policy_hash = evidence_network_policy.content_hash_hex();
    let bounded_spec = build_systemd_bounded_test_command(
        workspace_root,
        BoundedTestLimits {
            timeout_seconds: timeout_decision.effective_seconds,
            kill_after_seconds: DEFAULT_TEST_KILL_AFTER_SECONDS,
            memory_max: DEFAULT_TEST_MEMORY_MAX,
            pids_max: DEFAULT_TEST_PIDS_MAX,
            cpu_quota: &effective_cpu_quota,
        },
        &build_nextest_command(),
        None,
        &test_env,
        policy.sandbox_hardening,
        evidence_network_policy,
    )
    .map_err(|err| format!("bounded test runner unavailable for FAC pipeline: {err}"))?;
    test_env.extend(bounded_spec.environment);
    test_env.extend(bounded_spec.setenv_pairs);

    Ok(PipelineTestCommand {
        command: bounded_spec.command,
        bounded_runner: true,
        effective_timeout_seconds: timeout_decision.effective_seconds,
        gate_profile,
        effective_cpu_quota,
        effective_test_parallelism: execution_profile.test_parallelism,
        test_env,
        env_remove_keys: bounded_spec.env_remove_keys,
        sandbox_hardening_hash,
        network_policy_hash,
    })
}

fn resolve_pipeline_roots_from_lane_dir(lane_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let lane_parent = lane_dir.parent().ok_or_else(|| {
        format!(
            "invalid lane dir {}: missing parent lanes directory",
            lane_dir.display()
        )
    })?;
    if lane_parent.file_name() != Some(OsStr::new("lanes")) {
        return Err(format!(
            "invalid lane dir {}: expected parent directory named 'lanes'",
            lane_dir.display()
        ));
    }
    let fac_root = lane_parent.parent().ok_or_else(|| {
        format!(
            "invalid lane dir {}: missing FAC root ancestor",
            lane_dir.display()
        )
    })?;
    if fac_root.file_name() != Some(OsStr::new("fac")) {
        return Err(format!(
            "invalid lane dir {}: expected FAC root ancestor named 'fac'",
            lane_dir.display()
        ));
    }
    let private_dir = fac_root.parent().ok_or_else(|| {
        format!(
            "invalid lane dir {}: missing private directory ancestor",
            lane_dir.display()
        )
    })?;
    if private_dir.file_name() != Some(OsStr::new("private")) {
        return Err(format!(
            "invalid lane dir {}: expected private ancestor named 'private'",
            lane_dir.display()
        ));
    }
    let apm2_home = private_dir.parent().ok_or_else(|| {
        format!(
            "invalid lane dir {}: missing APM2 home ancestor",
            lane_dir.display()
        )
    })?;
    Ok((apm2_home.to_path_buf(), fac_root.to_path_buf()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CargoGateExecutionScope {
    FullWorkspace,
    ScopedPackages(Vec<String>),
    NoCargoImpact,
}

impl CargoGateExecutionScope {
    fn summary(&self) -> String {
        match self {
            Self::FullWorkspace => "full_workspace".to_string(),
            Self::ScopedPackages(packages) => {
                format!("scoped_packages({})", packages.join(","))
            },
            Self::NoCargoImpact => "no_cargo_impact".to_string(),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct CargoMetadataPackage {
    name: String,
    manifest_path: String,
}

#[derive(Debug, serde::Deserialize)]
struct CargoMetadataDocument {
    packages: Vec<CargoMetadataPackage>,
}

#[derive(Debug, Clone)]
struct Phase2GateSpec {
    gate_name: &'static str,
    command: Vec<String>,
    skip_reason: Option<&'static str>,
}

fn resolve_cargo_gate_execution_scope(workspace_root: &Path) -> CargoGateExecutionScope {
    resolve_cargo_gate_execution_scope_with(workspace_root)
        .unwrap_or(CargoGateExecutionScope::FullWorkspace)
}

fn resolve_cargo_gate_execution_scope_with(
    workspace_root: &Path,
) -> Result<CargoGateExecutionScope, String> {
    let package_dirs = resolve_workspace_package_dirs(workspace_root)?;
    let diff_range = resolve_cargo_scope_diff_range(workspace_root)?;
    let changed_paths = load_changed_paths(workspace_root, &diff_range)?;
    Ok(classify_cargo_gate_scope(&changed_paths, &package_dirs))
}

fn resolve_workspace_package_dirs(workspace_root: &Path) -> Result<Vec<(String, String)>, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(workspace_root)
        .output()
        .map_err(|err| format!("failed to execute cargo metadata: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "failed to resolve workspace package metadata: {}",
            if stderr.is_empty() {
                "cargo metadata returned non-zero status".to_string()
            } else {
                stderr
            }
        ));
    }
    let metadata: CargoMetadataDocument = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse cargo metadata output: {err}"))?;
    let canonical_workspace_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let mut dirs = metadata
        .packages
        .into_iter()
        .filter_map(|package| {
            let manifest = PathBuf::from(package.manifest_path);
            let relative_manifest = manifest
                .strip_prefix(&canonical_workspace_root)
                .ok()
                .or_else(|| manifest.strip_prefix(workspace_root).ok())?;
            let relative_dir = relative_manifest.parent()?;
            let dir = relative_dir.to_string_lossy().replace('\\', "/");
            if dir.is_empty() {
                return None;
            }
            Some((dir, package.name))
        })
        .collect::<Vec<_>>();
    dirs.sort_by(|left, right| {
        right
            .0
            .len()
            .cmp(&left.0.len())
            .then_with(|| left.0.cmp(&right.0))
    });
    Ok(dirs)
}

fn resolve_cargo_scope_diff_range(workspace_root: &Path) -> Result<String, String> {
    let mut base_ref = None;
    for candidate in ["origin/main", "main"] {
        let probe = Command::new("git")
            .args([
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("{candidate}^{{commit}}"),
            ])
            .current_dir(workspace_root)
            .output()
            .map_err(|err| format!("failed to execute git rev-parse: {err}"))?;
        if probe.status.success() {
            base_ref = Some(candidate.to_string());
            break;
        }
    }
    let resolved_base_ref = base_ref.unwrap_or_else(|| "HEAD^".to_string());
    let merge_base = Command::new("git")
        .args(["merge-base", "HEAD", &resolved_base_ref])
        .current_dir(workspace_root)
        .output()
        .map_err(|err| format!("failed to execute git merge-base: {err}"))?;
    if !merge_base.status.success() {
        return Err(format!(
            "failed to resolve merge-base against `{resolved_base_ref}`"
        ));
    }
    let base = String::from_utf8_lossy(&merge_base.stdout)
        .trim()
        .to_string();
    if base.is_empty() {
        return Err("git merge-base returned an empty base commit".to_string());
    }
    Ok(format!("{base}..HEAD"))
}

fn load_changed_paths(workspace_root: &Path, diff_range: &str) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=ACMR", diff_range])
        .current_dir(workspace_root)
        .output()
        .map_err(|err| format!("failed to execute git diff for cargo scope: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "failed to resolve changed files for cargo scope: {}",
            if stderr.is_empty() {
                "git diff returned non-zero status".to_string()
            } else {
                stderr
            }
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn classify_cargo_gate_scope(
    changed_paths: &[String],
    package_dirs: &[(String, String)],
) -> CargoGateExecutionScope {
    if changed_paths.is_empty() {
        return CargoGateExecutionScope::NoCargoImpact;
    }
    let mut packages = BTreeSet::new();
    for path in changed_paths {
        if path_requires_full_workspace(path) {
            return CargoGateExecutionScope::FullWorkspace;
        }
        if path_is_non_cargo_impact(path) {
            continue;
        }
        if let Some(package_name) = package_for_path(path, package_dirs) {
            packages.insert(package_name.to_string());
            continue;
        }
        return CargoGateExecutionScope::FullWorkspace;
    }
    if packages.is_empty() {
        CargoGateExecutionScope::NoCargoImpact
    } else {
        CargoGateExecutionScope::ScopedPackages(packages.into_iter().collect())
    }
}

fn path_requires_full_workspace(path: &str) -> bool {
    if matches!(
        path,
        "Cargo.toml"
            | "Cargo.lock"
            | "rust-toolchain.toml"
            | "rustfmt.toml"
            | ".config/nextest.toml"
    ) {
        return true;
    }
    path.starts_with(".cargo/") || path.starts_with("proto/") || path.ends_with("/Cargo.toml")
}

fn path_is_non_cargo_impact(path: &str) -> bool {
    if matches!(
        path,
        "AGENTS.md" | "README.md" | "SECURITY.md" | "DAEMON.md" | "LICENSE-APACHE" | "LICENSE-MIT"
    ) {
        return true;
    }
    path.starts_with("documents/")
        || path.starts_with("deploy/")
        || path.starts_with(".github/")
        || path.starts_with("contrib/")
        || path.starts_with("evidence/")
}

fn package_for_path<'a>(path: &str, package_dirs: &'a [(String, String)]) -> Option<&'a str> {
    let normalized = path.replace('\\', "/");
    for (dir, package_name) in package_dirs {
        if normalized == *dir || normalized.starts_with(&format!("{dir}/")) {
            return Some(package_name);
        }
    }
    None
}

fn append_scope_package_args(command: &mut Vec<String>, scope: &CargoGateExecutionScope) {
    match scope {
        CargoGateExecutionScope::ScopedPackages(packages) if !packages.is_empty() => {
            for package in packages {
                command.push("-p".to_string());
                command.push(package.clone());
            }
        },
        _ => command.push("--workspace".to_string()),
    }
}

fn build_doc_gate_command(scope: &CargoGateExecutionScope) -> Vec<String> {
    let mut command = vec!["cargo".to_string(), "doc".to_string()];
    append_scope_package_args(&mut command, scope);
    command.push("--no-deps".to_string());
    command
}

fn build_clippy_gate_command(scope: &CargoGateExecutionScope) -> Vec<String> {
    let mut command = vec!["cargo".to_string(), "clippy".to_string()];
    append_scope_package_args(&mut command, scope);
    command.extend([
        "--all-targets".to_string(),
        "--all-features".to_string(),
        "--".to_string(),
        "-D".to_string(),
        "warnings".to_string(),
    ]);
    command
}

fn should_force_doc_gate() -> bool {
    std::env::var("APM2_FAC_FORCE_DOC_GATE")
        .ok()
        .is_some_and(|value| {
            let value = value.trim();
            value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("on")
        })
}

const fn doc_gate_skip_reason(
    scope: &CargoGateExecutionScope,
    force_doc_gate: bool,
) -> Option<&'static str> {
    if force_doc_gate {
        return None;
    }
    match scope {
        CargoGateExecutionScope::FullWorkspace => None,
        CargoGateExecutionScope::ScopedPackages(_) => Some("scoped_latency_budget"),
        CargoGateExecutionScope::NoCargoImpact => Some("no_cargo_impact"),
    }
}

fn build_scoped_nextest_command(scope: &CargoGateExecutionScope) -> Vec<String> {
    let mut command = vec![
        "cargo".to_string(),
        "nextest".to_string(),
        "run".to_string(),
    ];
    append_scope_package_args(&mut command, scope);
    command.extend([
        "--all-features".to_string(),
        "--config-file".to_string(),
        ".config/nextest.toml".to_string(),
        "--profile".to_string(),
        "ci".to_string(),
    ]);
    command
}

fn resolve_evidence_test_command_with_scope(
    test_command_override: Option<&[String]>,
    scope: &CargoGateExecutionScope,
) -> Vec<String> {
    test_command_override.map_or_else(|| build_scoped_nextest_command(scope), <[_]>::to_vec)
}

fn resolve_evidence_test_command_environment(
    opts: Option<&EvidenceGateOptions>,
) -> Option<&[(String, String)]> {
    opts.and_then(|o| {
        (!o.test_command_environment.is_empty()).then_some(o.test_command_environment.as_slice())
    })
}

fn resolve_evidence_env_remove_keys(opts: Option<&EvidenceGateOptions>) -> Option<&[String]> {
    opts.and_then(|o| (!o.env_remove_keys.is_empty()).then_some(o.env_remove_keys.as_slice()))
}

fn resolve_evidence_gate_progress_callback(
    opts: Option<&EvidenceGateOptions>,
) -> Option<&dyn Fn(GateProgressEvent)> {
    opts.and_then(|o| {
        o.on_gate_progress
            .as_deref()
            .map(|cb| cb as &dyn Fn(GateProgressEvent))
    })
}

/// Build a policy-filtered environment for all evidence gates (not just
/// the test gate). Enforces default-deny by starting from an empty
/// environment and inheriting only allowlisted variables per
/// `FacPolicyV1`.
///
/// TCK-00526: Previously only the test gate received a policy-filtered
/// environment. This function is used by `run_evidence_gates` and
/// `run_evidence_gates_with_status` to apply the same policy to
/// fmt/clippy/doc and script gates.
///
/// TCK-00575: Applies per-lane env isolation (`HOME`, `TMPDIR`,
/// `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`) so every FAC gate phase runs with
/// deterministic lane-local values, preventing writes to ambient user
/// locations.
///
/// # Arguments
///
/// * `lane_dir` - The lane directory from the actually-locked lane (returned by
///   `allocate_lane_job_logs_dir`). This MUST correspond to the lane protected
///   by the caller's `LaneLockGuard` to maintain lock/env coupling and prevent
///   concurrent access races (e.g., with `apm2 fac doctor --fix` lane
///   remediation).
fn build_gate_policy_env(lane_dir: &Path) -> Result<Vec<(String, String)>, String> {
    let apm2_home = apm2_core::github::resolve_apm2_home()
        .ok_or_else(|| "cannot resolve APM2_HOME for gate env policy enforcement".to_string())?;
    let fac_root = apm2_home.join("private/fac");
    let policy = load_or_create_pipeline_policy(&fac_root)?;

    if let Some(cargo_home) = policy.resolve_cargo_home(&apm2_home) {
        ensure_pipeline_managed_cargo_home(&cargo_home)?;
    }

    let ambient: Vec<(String, String)> = std::env::vars().collect();
    let mut policy_env = build_job_environment(&policy, &ambient, &apm2_home);

    // TCK-00575: Apply per-lane env isolation for all evidence gate phases.
    // Uses the lane directory from the actually-locked lane to maintain
    // lock/env coupling (round 2 fix: was previously hardcoded to lane-00).
    super::policy_loader::apply_review_lane_environment(&mut policy_env, lane_dir, &ambient)?;

    Ok(policy_env.into_iter().collect())
}

/// Load or create FAC policy. Delegates to the shared `policy_loader` module
/// for bounded I/O and deduplication (TCK-00526).
fn load_or_create_pipeline_policy(fac_root: &Path) -> Result<FacPolicyV1, String> {
    super::policy_loader::load_or_create_fac_policy(fac_root)
}

/// Ensure managed `CARGO_HOME` directory exists. Delegates to the shared
/// `policy_loader` module (TCK-00526).
fn ensure_pipeline_managed_cargo_home(cargo_home: &Path) -> Result<(), String> {
    super::policy_loader::ensure_managed_cargo_home(cargo_home)
}

/// Result of lane allocation: logs directory, the lane's root directory,
/// and the lock guard that must be held for the lifetime of the job.
pub(super) struct EvidenceLaneContext {
    /// Path to the job-specific logs directory within the lane.
    logs_dir: PathBuf,
    /// Path to the lane's root directory
    /// (`$APM2_HOME/private/fac/lanes/<lane_id>`). Used to derive per-lane
    /// env isolation directories (`HOME`, `TMPDIR`, `XDG_CACHE_HOME`,
    /// `XDG_CONFIG_HOME`) via
    /// `policy_loader::apply_review_lane_environment`.
    ///
    /// SAFETY: This `lane_dir` corresponds to the lane protected by
    /// `_lane_guard`. Callers MUST use this `lane_dir` (not a hardcoded
    /// `lane-00`) for env overrides to maintain lock/env coupling.
    lane_dir: PathBuf,
    /// Exclusive lock guard for the allocated lane. Must be held for the
    /// entire duration of lane usage to prevent concurrent access (e.g.,
    /// doctor remediation racing with env dir creation).
    _lane_guard: LaneLockGuard,
}

pub(super) fn allocate_evidence_lane_context(
    lane_manager: &LaneManager,
    lane_id: &str,
    lane_lock: LaneLockGuard,
) -> Result<EvidenceLaneContext, String> {
    let lane_dir = lane_manager.lane_dir(lane_id);
    let logs_dir = lane_dir.join("logs").join(Uuid::new_v4().to_string());
    crate::commands::fac_permissions::ensure_dir_with_mode(&logs_dir)
        .map_err(|err| format!("failed to create job log dir {}: {err}", logs_dir.display()))?;
    Ok(EvidenceLaneContext {
        logs_dir,
        lane_dir,
        _lane_guard: lane_lock,
    })
}

fn allocate_lane_job_logs_dir() -> Result<EvidenceLaneContext, String> {
    let lane_manager = LaneManager::from_default_home()
        .map_err(|err| format!("failed to resolve lane manager: {err}"))?;
    lane_manager
        .ensure_directories()
        .map_err(|err| format!("failed to ensure FAC lane directories: {err}"))?;

    for lane_id in LaneManager::default_lane_ids() {
        match lane_manager.try_lock(&lane_id) {
            Ok(Some(guard)) => {
                return allocate_evidence_lane_context(&lane_manager, &lane_id, guard);
            },
            Ok(None) => {},
            Err(err) => {
                return Err(format!("failed to inspect lane {lane_id}: {err}"));
            },
        }
    }

    Err("no free FAC lane available for evidence gates".to_string())
}

fn build_evidence_gate_result(
    gate_name: &str,
    passed: bool,
    duration_secs: u64,
    log_path: Option<&Path>,
    stream_stats: Option<&StreamStats>,
) -> EvidenceGateResult {
    build_evidence_gate_result_with_cache_decision(
        gate_name,
        passed,
        duration_secs,
        log_path,
        stream_stats,
        None,
    )
}

fn build_evidence_gate_result_with_cache_decision(
    gate_name: &str,
    passed: bool,
    duration_secs: u64,
    log_path: Option<&Path>,
    stream_stats: Option<&StreamStats>,
    cache_decision: Option<apm2_core::fac::gate_cache_v3::CacheDecision>,
) -> EvidenceGateResult {
    EvidenceGateResult {
        gate_name: gate_name.to_string(),
        passed,
        duration_secs,
        log_path: log_path.map(PathBuf::from),
        bytes_written: stream_stats.map(|stats| stats.bytes_written),
        bytes_total: stream_stats.map(|stats| stats.bytes_total),
        was_truncated: stream_stats.map(|stats| stats.was_truncated),
        log_bundle_hash: None,
        cache_decision,
    }
}

fn write_cached_gate_log_marker(
    log_path: &Path,
    gate_name: &str,
    reuse_reason: &str,
    attestation_digest: Option<&str>,
) -> StreamStats {
    let marker = format!(
        "info: gate={gate_name} result reused from cache (reason={reuse_reason}) attestation_digest={}\n",
        attestation_digest.unwrap_or("unknown")
    );
    let _ = crate::commands::fac_permissions::write_fac_file_with_mode(log_path, marker.as_bytes());
    StreamStats {
        bytes_written: marker.len() as u64,
        bytes_total: marker.len() as u64,
        was_truncated: false,
    }
}

fn write_skipped_gate_log_marker(log_path: &Path, gate_name: &str, reason: &str) -> StreamStats {
    let marker = format!("info: gate={gate_name} skipped (reason={reason})\n");
    let _ = crate::commands::fac_permissions::write_fac_file_with_mode(log_path, marker.as_bytes());
    StreamStats {
        bytes_written: marker.len() as u64,
        bytes_total: marker.len() as u64,
        was_truncated: false,
    }
}

fn attach_log_bundle_hash(
    gate_results: &mut [EvidenceGateResult],
    logs_dir: &Path,
) -> Result<(), String> {
    let log_bundle_hash = compute_log_bundle_hash(logs_dir)?;
    for result in gate_results {
        result.log_bundle_hash = Some(log_bundle_hash.clone());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finalize_status_gate_run(
    projection_log: Option<&mut File>,
    evidence_lines: &[String],
    gate_results: &mut [EvidenceGateResult],
    logs_dir: &Path,
    gate_cache: &mut GateCache,
    updater: &PrBodyStatusUpdater,
    status: &CiStatus,
    signer: &apm2_core::crypto::Signer,
    v3_gate_cache: Option<&mut GateCacheV3>,
) -> Result<(), String> {
    attach_log_bundle_hash(gate_results, logs_dir)?;

    // Backfill truncation and log-bundle metadata into durable gate receipts
    // so the persisted cache carries the same observability data as the
    // in-memory EvidenceGateResult.
    for result in gate_results {
        gate_cache.backfill_evidence_metadata(
            &result.gate_name,
            result.log_bundle_hash.as_deref(),
            result.bytes_written,
            result.bytes_total,
            result.was_truncated,
            result.log_path.as_ref().and_then(|p| p.to_str()),
        );
    }

    // Force a final update to ensure all gate results are posted.
    updater.force_update(status);

    // TCK-00541: Persist v3 gate cache as the primary (receipt-indexed) store.
    // V3 is written first and treated as the authoritative cache. V2 follows
    // as backward-compatible fallback for push.rs / gates.rs callers that
    // have not yet been migrated to v3.
    if let Some(v3) = v3_gate_cache {
        // Populate v3 from the in-memory gate_cache entries (which contain
        // backfilled metadata from the step above). V3 entries are
        // independently signed below so they are self-contained — a v3 hit
        // does NOT require v2 to be present.
        for (gate_name, result) in &gate_cache.gates {
            let v3_result = apm2_core::fac::gate_cache_v3::V3GateResult {
                status: result.status.clone(),
                duration_secs: result.duration_secs,
                completed_at: result.completed_at.clone(),
                attestation_digest: result.attestation_digest.clone(),
                evidence_log_digest: result.evidence_log_digest.clone(),
                quick_mode: result.quick_mode,
                log_bundle_hash: result.log_bundle_hash.clone(),
                log_path: result.log_path.clone(),
                signature_hex: None, // Will be signed below.
                signer_id: None,
                // TCK-00541: Inherit receipt binding flags from v2 cache.
                // These are fail-closed (false) unless promoted by a durable
                // receipt lookup. The v3 check_reuse enforces both must be true.
                rfc0028_receipt_bound: result.rfc0028_receipt_bound,
                rfc0029_receipt_bound: result.rfc0029_receipt_bound,
            };
            // Best-effort: skip if we hit the gate limit.
            let _ = v3.set(gate_name, v3_result);
        }
        // Sign v3 entries (independent signatures, not derived from v2).
        v3.sign_all(signer);
        // Persist v3 cache (primary store).
        if let Some(root) = cache_v3_root() {
            if let Err(err) = v3.save_to_dir(&root) {
                eprintln!("warning: failed to persist v3 gate cache: {err}");
            }
        }
    }

    // TCK-00541: V2 writes removed from default evidence pipeline path.
    // The ticket requires "write only v3 in default mode". V2 read
    // compatibility is preserved (load_from_v2_dir exists for diagnostic/
    // migration tooling), but new gate results are only persisted to v3.
    // This eliminates the deprecated v2 cache surface from the default
    // admission flow.

    if let Some(file) = projection_log {
        for line in evidence_lines {
            let _ = writeln!(file, "{line}");
        }
    }

    Ok(())
}

/// Post-receipt v3 gate cache rebinding (TCK-00541 round-3 MAJOR fix).
///
/// After a receipt is committed, loads the persisted v3 cache from disk,
/// promotes `rfc0028_receipt_bound` and `rfc0029_receipt_bound` flags based
/// on verified receipt evidence, re-signs all entries, and saves back.
///
/// This is the v3 counterpart of
/// [`super::gate_cache::rebind_gate_cache_after_receipt`] (which only rebinds
/// v2 `GateCache`). Without this call, v3 entries persist with `false` defaults
/// and `check_reuse` never returns a hit.
///
/// # Arguments
///
/// * `sha` - The commit SHA whose v3 gate cache should be rebound.
/// * `policy_hash` - The FAC policy hash used to reconstruct the compound key.
/// * `sbx_hash` - Sandbox hardening hash for compound key reconstruction.
/// * `net_hash` - Network policy hash for compound key reconstruction.
/// * `receipts_dir` - Path to the receipt store
///   (`$APM2_HOME/private/fac/receipts`).
/// * `job_id` - The job ID whose receipt should be looked up.
/// * `signer` - The signing key for re-signing the cache after flag promotion.
pub(super) fn rebind_v3_gate_cache_after_receipt(
    sha: &str,
    policy_hash: &str,
    sbx_hash: &str,
    net_hash: &str,
    receipts_dir: &std::path::Path,
    job_id: &str,
    signer: &apm2_core::crypto::Signer,
) {
    let toolchain = compute_toolchain_fingerprint();
    let Ok(compound_key) = apm2_core::fac::gate_cache_v3::V3CompoundKey::new(
        sha,
        policy_hash,
        &toolchain,
        sbx_hash,
        net_hash,
    ) else {
        return; // Cannot reconstruct compound key — nothing to rebind.
    };
    let Some(root) = cache_v3_root() else {
        return; // No v3 cache root — nothing to rebind.
    };
    let Some(mut cache) =
        apm2_core::fac::gate_cache_v3::GateCacheV3::load_from_dir(&root, sha, &compound_key)
    else {
        return; // No v3 cache on disk — nothing to rebind.
    };

    cache.try_bind_receipt_from_store(receipts_dir, job_id);

    // Only re-sign and save if at least one gate was promoted.
    let any_bound = cache
        .gates
        .values()
        .any(|entry| entry.rfc0028_receipt_bound && entry.rfc0029_receipt_bound);
    if any_bound {
        cache.sign_all(signer);
        if let Err(err) = cache.save_to_dir(&root) {
            eprintln!("warning: failed to re-persist v3 gate cache after receipt rebind: {err}");
        }
    }
}

/// Maximum bytes to read from a single log file during bundle hashing.
/// Slightly larger than `LOG_STREAM_MAX_BYTES` to account for stream prefixes
/// (`=== stdout ===\n`, `=== stderr ===\n`) and any separator overhead that the
/// log writer prepends outside the payload byte counter.
const LOG_BUNDLE_PER_FILE_MAX_BYTES: u64 = LOG_STREAM_MAX_BYTES + 4096;

/// Open a file for reading with `O_NOFOLLOW` to atomically reject symlinks at
/// the kernel level. This eliminates TOCTOU races between metadata checks and
/// file opens — the kernel refuses to follow symlinks in a single syscall.
pub(super) fn open_nofollow(path: &Path) -> Result<fs::File, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    options
        .open(path)
        .map_err(|err| format!("failed to open {}: {err}", path.display()))
}

fn compute_log_bundle_hash(logs_dir: &Path) -> Result<String, String> {
    let mut log_paths: Vec<PathBuf> = fs::read_dir(logs_dir)
        .map_err(|err| {
            format!(
                "failed to read evidence log directory {}: {err}",
                logs_dir.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            // Pre-filter using symlink_metadata as defense-in-depth to avoid
            // attempting O_NOFOLLOW opens on entries that are obviously not
            // regular files (directories, sockets, etc.).  The actual open
            // below uses O_NOFOLLOW so even if the entry is swapped between
            // this check and the open the kernel will reject the symlink.
            fs::symlink_metadata(path).is_ok_and(|meta| {
                let ft = meta.file_type();
                ft.is_file() && !ft.is_symlink()
            })
        })
        .collect();

    log_paths.sort_by_key(|path| path.file_name().map(std::ffi::OsStr::to_owned));
    let bounded = log_paths.into_iter().take(128);

    let mut hasher = blake3::Hasher::new();
    hasher.update(LOG_BUNDLE_SCHEMA.as_bytes());
    hasher.update(b"\0");

    for path in bounded {
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");

        // Open with O_NOFOLLOW to atomically reject symlinks at the kernel
        // level, eliminating the TOCTOU window between the symlink_metadata
        // filter above and this open.
        let file = open_nofollow(&path)
            .map_err(|err| format!("failed to open evidence log file {}: {err}", path.display()))?;
        let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        if file_size > LOG_BUNDLE_PER_FILE_MAX_BYTES {
            return Err(format!(
                "evidence log file {} exceeds per-file cap ({} > {} bytes)",
                path.display(),
                file_size,
                LOG_BUNDLE_PER_FILE_MAX_BYTES,
            ));
        }
        let mut bytes = Vec::new();
        file.take(LOG_BUNDLE_PER_FILE_MAX_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|err| format!("failed to read evidence log file {}: {err}", path.display()))?;

        let filename_len = u32::try_from(filename.len())
            .map_err(|_| "log filename too long for serialization".to_string())?;
        let content_len = u32::try_from(bytes.len())
            .map_err(|_| "log content too long for serialization".to_string())?;
        hasher.update(&filename_len.to_be_bytes());
        hasher.update(filename.as_bytes());
        hasher.update(&content_len.to_be_bytes());
        hasher.update(&bytes);
    }

    let digest = hasher.finalize();
    Ok(format!("b3-256:{}", hex::encode(digest.as_bytes())))
}

pub(super) fn run_evidence_gates_with_lane_context(
    workspace_root: &Path,
    sha: &str,
    projection_log: Option<&mut File>,
    opts: Option<&EvidenceGateOptions>,
    lane_context: EvidenceLaneContext,
) -> Result<(bool, Vec<EvidenceGateResult>), String> {
    let emit_human_logs = opts.is_none_or(|o| o.emit_human_logs);
    let on_gate_progress = resolve_evidence_gate_progress_callback(opts);
    let logs_dir = lane_context.logs_dir;

    // TCK-00526: Build policy-filtered environment for ALL gates (not just
    // the test gate). This enforces default-deny on fmt, clippy, doc, and
    // native gate checks, preventing ambient secret leakage.
    // TCK-00575 round 2: Use the lane_dir from the actually-locked lane
    // (not hardcoded lane-00) to maintain lock/env coupling.
    let gate_env = build_gate_policy_env(&lane_context.lane_dir)?;

    // TCK-00526: Compute wrapper-stripping keys once for ALL gate phases.
    // build_job_environment already strips these at the policy level, but
    // env_remove on the spawned Command provides defense-in-depth against
    // parent process env inheritance. Pass the policy-filtered environment
    // so policy-introduced SCCACHE_* variables are also discovered.
    let gate_wrapper_strip = compute_gate_env_remove_keys(Some(&gate_env));
    let gate_wrapper_strip_ref: Option<&[String]> = if gate_wrapper_strip.is_empty() {
        None
    } else {
        Some(&gate_wrapper_strip)
    };

    // TCK-00540 fix round 3: Load the gate cache and signing material for
    // cache-reuse decisions in the `fac gates` path.
    //
    // Cache reuse is only active in full (non-quick) mode because quick mode
    // does not persist attested gate cache entries.
    let skip_test_gate = opts.is_some_and(|o| o.skip_test_gate);
    let cache_reuse_policy = opts.and_then(|o| o.gate_resource_policy.clone());
    let cache_reuse_active = !skip_test_gate && cache_reuse_policy.is_some();
    let (cached_gate_cache, fac_verifying_key) = if cache_reuse_active {
        let fac_signer_result = {
            let apm2_home = apm2_core::github::resolve_apm2_home()
                .ok_or_else(|| "cannot resolve APM2_HOME for gate cache signing".to_string())?;
            let fac_root = apm2_home.join("private/fac");
            crate::commands::fac_key_material::load_or_generate_persistent_signer(&fac_root)
                .map_err(|e| format!("cannot load signing key for gate cache: {e}"))
        };
        // If we cannot load the signer, cache reuse is not possible
        // (fail-closed: unsigned receipts are rejected).
        fac_signer_result.map_or((None, None), |signer| {
            let vk = signer.verifying_key();
            let cache = GateCache::load(sha);
            (cache, Some(vk))
        })
    } else {
        (None, None)
    };
    // TCK-00541: Non-status path now loads native v3 cache for reuse.
    // This closes the structural throughput gap where v3 persisted entries
    // were never considered and every gate re-executed.
    //
    // Fail-closed: if any v3 context material is unavailable (APM2_HOME,
    // policy load, sandbox/network hash, compound key parse), we simply skip
    // v3 loading and reuse decisions fall back to miss behavior.
    let (v3_cache_loaded, v3_compound_key_ns, v3_root_ns) = if cache_reuse_active {
        let result = cache_reuse_policy.as_ref().and_then(|reuse_policy| {
            let sandbox_hardening_hash = reuse_policy.sandbox_hardening.as_deref()?;
            let network_policy_hash = reuse_policy.network_policy_hash.as_deref()?;
            let apm2_home = apm2_core::github::resolve_apm2_home()?;
            let fac_root = apm2_home.join("private/fac");
            let fac_policy = load_or_create_pipeline_policy(&fac_root).ok()?;
            let compound_key = compute_v3_compound_key(
                sha,
                &fac_policy,
                sandbox_hardening_hash,
                network_policy_hash,
            )?;
            let root = cache_v3_root()?;
            let loaded = GateCacheV3::load_from_dir(&root, sha, &compound_key);
            Some((loaded, compound_key, root))
        });
        match result {
            Some((loaded, ck, root)) => (loaded, Some(ck), Some(root)),
            None => (None, None, None),
        }
    } else {
        (None, None, None)
    };

    let cargo_scope = resolve_cargo_gate_execution_scope(workspace_root);
    if emit_human_logs {
        eprintln!("fac gates: cargo execution scope={}", cargo_scope.summary());
    }
    let force_doc_gate = should_force_doc_gate();
    let doc_skip_reason = doc_gate_skip_reason(&cargo_scope, force_doc_gate);
    let skip_cargo_heavy_gates = matches!(cargo_scope, CargoGateExecutionScope::NoCargoImpact);

    // Fastest-first ordering for cargo-backed gates. We always keep rustfmt
    // active. doc is skipped for package-scoped pushes to stay within gate
    // latency SLO (override with APM2_FAC_FORCE_DOC_GATE=1).
    // clippy/test are scoped or skipped based on cargo impact.
    let phase2_gate_specs = vec![
        Phase2GateSpec {
            gate_name: "rustfmt",
            command: vec![
                "cargo".to_string(),
                "fmt".to_string(),
                "--all".to_string(),
                "--check".to_string(),
            ],
            skip_reason: None,
        },
        Phase2GateSpec {
            gate_name: "doc",
            command: build_doc_gate_command(&cargo_scope),
            skip_reason: doc_skip_reason,
        },
        Phase2GateSpec {
            gate_name: "clippy",
            command: build_clippy_gate_command(&cargo_scope),
            skip_reason: skip_cargo_heavy_gates.then_some("no_cargo_impact"),
        },
    ];

    let mut evidence_lines = Vec::new();
    let mut gate_results = Vec::new();

    let skip_merge_conflict_gate = opts.is_some_and(|o| o.skip_merge_conflict_gate);
    if !skip_merge_conflict_gate {
        // Phase 0: merge conflict gate (always first, including quick mode).
        let merge_log_path = logs_dir.join(format!("{MERGE_CONFLICT_GATE_NAME}.log"));
        emit_gate_started(opts, MERGE_CONFLICT_GATE_NAME);
        let (merge_passed, merge_duration, merge_line, merge_stats) =
            run_merge_conflict_gate(workspace_root, sha, &merge_log_path, emit_human_logs);
        let merge_result = build_evidence_gate_result(
            MERGE_CONFLICT_GATE_NAME,
            merge_passed,
            merge_duration,
            Some(&merge_log_path),
            Some(&merge_stats),
        );
        emit_gate_completed(opts, &merge_result);
        gate_results.push(merge_result);
        evidence_lines.push(merge_line);
        if !merge_passed {
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
            return Ok((false, gate_results));
        }
    }

    // Phase 1: fail-fast native gates.
    for gate_name in FRONTLOADED_NATIVE_EVIDENCE_GATES {
        let log_path = logs_dir.join(format!("{gate_name}.log"));

        let mut gate_cache_decision: Option<apm2_core::fac::gate_cache_v3::CacheDecision> = None;

        if cache_reuse_active {
            let reuse_grp = cache_reuse_policy
                .as_ref()
                .expect("guarded by cache_reuse_active");
            let attestation_digest =
                gate_attestation_digest(workspace_root, sha, gate_name, None, reuse_grp);
            let (reuse, cache_decision_local) = reuse_decision_with_v3_fallback(
                v3_cache_loaded.as_ref(),
                cached_gate_cache.as_ref(),
                gate_name,
                attestation_digest.as_deref(),
                fac_verifying_key.as_ref(),
                v3_root_ns.as_deref(),
                v3_compound_key_ns.as_ref(),
                Some(sha),
            );
            gate_cache_decision.clone_from(&cache_decision_local);
            if reuse.reusable {
                if let Some(cached) = resolve_cached_payload(
                    &reuse,
                    v3_cache_loaded.as_ref(),
                    cached_gate_cache.as_ref(),
                    gate_name,
                ) {
                    emit_gate_started(opts, gate_name);
                    let stream_stats = write_cached_gate_log_marker(
                        &log_path,
                        gate_name,
                        reuse.reason,
                        attestation_digest.as_deref(),
                    );
                    let cached_result = build_evidence_gate_result_with_cache_decision(
                        gate_name,
                        true,
                        cached.duration_secs,
                        Some(&log_path),
                        Some(&stream_stats),
                        cache_decision_local,
                    );
                    emit_gate_completed(opts, &cached_result);
                    gate_results.push(cached_result);
                    if emit_human_logs {
                        eprintln!(
                            "ts={} sha={sha} gate={gate_name} status=PASS cached=true reuse_reason={}",
                            now_iso8601(),
                            reuse.reason,
                        );
                    }
                    evidence_lines.push(format!(
                        "ts={} sha={sha} gate={gate_name} status=PASS cached=true reuse_reason={}",
                        now_iso8601(),
                        reuse.reason,
                    ));
                    continue;
                }
            }
            if emit_human_logs {
                eprintln!(
                    "ts={} sha={sha} gate={gate_name} reuse_status=miss reuse_reason={}",
                    now_iso8601(),
                    reuse.reason,
                );
            }
        }

        emit_gate_started(opts, gate_name);
        let started = Instant::now();
        let (passed, stream_stats) =
            run_native_evidence_gate(workspace_root, sha, gate_name, &log_path, emit_human_logs);
        let duration = started.elapsed().as_secs();
        let result = build_evidence_gate_result_with_cache_decision(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
            gate_cache_decision.take(),
        );
        emit_gate_completed(opts, &result);
        gate_results.push(result);
        let ts = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
            log_path.display()
        ));
        if !passed {
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
            return Ok((false, gate_results));
        }
    }

    // Phase 2: cargo fmt/doc/clippy — all receive the policy-filtered env
    // and wrapper-stripping keys (TCK-00526: defense-in-depth for all gates).
    //
    // TCK-00574 BLOCKER fix: In full (non-quick) mode, wrap non-test gates
    // in systemd-run with network policy isolation directives to enforce
    // default-deny network posture for ALL evidence gate phases (not just test).
    // Quick mode skips network isolation (development shortcut, same as test skip).
    #[allow(clippy::type_complexity)]
    let bounded_gate_specs: Option<Vec<(&str, Vec<String>, Vec<(String, String)>)>> =
        if skip_test_gate {
            None
        } else {
            // Load the policy to resolve network policy and sandbox hardening
            // for non-test gate phases (TCK-00574 BLOCKER fix).
            let apm2_home = apm2_core::github::resolve_apm2_home().ok_or_else(|| {
                "cannot resolve APM2_HOME for gate network policy enforcement".to_string()
            })?;
            let fac_root = apm2_home.join("private/fac");
            let policy = load_or_create_pipeline_policy(&fac_root)?;
            let gate_network_policy =
                apm2_core::fac::resolve_network_policy("gates", policy.network_policy.as_ref());
            let mut specs = Vec::new();
            for spec in phase2_gate_specs
                .iter()
                .filter(|phase2| phase2.skip_reason.is_none())
            {
                let gate_name = spec.gate_name;
                let gate_cmd = spec.command.clone();
                let gate_unit_name = opts
                    .and_then(|options| options.bounded_gate_unit_base.as_ref())
                    .map(|base| format!("{base}-{gate_name}"));
                let bounded = build_systemd_bounded_gate_command(
                    workspace_root,
                    BoundedTestLimits {
                        timeout_seconds: DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS,
                        kill_after_seconds: DEFAULT_TEST_KILL_AFTER_SECONDS,
                        memory_max: DEFAULT_TEST_MEMORY_MAX,
                        pids_max: DEFAULT_TEST_PIDS_MAX,
                        cpu_quota: "200%",
                    },
                    &gate_cmd,
                    gate_unit_name.as_deref(),
                    &gate_env,
                    policy.sandbox_hardening.clone(),
                    gate_network_policy.clone(),
                )
                .map_err(|err| {
                    format!(
                        "bounded gate runner unavailable for {gate_name} \
                         (network deny enforcement requires systemd-run): {err}"
                    )
                })?;
                specs.push((gate_name, bounded.command, bounded.environment));
            }
            Some(specs)
        };

    for spec in &phase2_gate_specs {
        let gate_name = spec.gate_name;
        let log_path = logs_dir.join(format!("{gate_name}.log"));

        if let Some(skip_reason) = spec.skip_reason {
            emit_gate_started(opts, gate_name);
            let stream_stats = write_skipped_gate_log_marker(&log_path, gate_name, skip_reason);
            let skipped_result = build_evidence_gate_result(
                gate_name,
                true,
                0,
                Some(&log_path),
                Some(&stream_stats),
            );
            emit_gate_completed(opts, &skipped_result);
            gate_results.push(skipped_result);
            let ts = now_iso8601();
            if emit_human_logs {
                eprintln!(
                    "ts={ts} sha={sha} gate={gate_name} status=SKIP reason={skip_reason} log={}",
                    log_path.display()
                );
            }
            evidence_lines.push(format!(
                "ts={ts} sha={sha} gate={gate_name} status=SKIP reason={skip_reason} log={}",
                log_path.display()
            ));
            continue;
        }

        // TCK-00626 round 4: Hoist cache_decision so it is available on both
        // hit and miss paths — gate_finished must always carry the decision.
        let mut gate_cache_decision: Option<apm2_core::fac::gate_cache_v3::CacheDecision> = None;

        // TCK-00540 fix round 3: Check gate cache for reuse before execution.
        if cache_reuse_active {
            // SAFETY: `cache_reuse_policy` is guaranteed `Some` here because
            // `cache_reuse_active` is gated on `cache_reuse_policy.is_some()`.
            let reuse_grp = cache_reuse_policy
                .as_ref()
                .expect("guarded by cache_reuse_active");
            let attestation_digest =
                gate_attestation_digest(workspace_root, sha, gate_name, None, reuse_grp);
            let (reuse, cache_decision_local) = reuse_decision_with_v3_fallback(
                v3_cache_loaded.as_ref(),
                cached_gate_cache.as_ref(),
                gate_name,
                attestation_digest.as_deref(),
                fac_verifying_key.as_ref(),
                v3_root_ns.as_deref(),
                v3_compound_key_ns.as_ref(),
                Some(sha),
            );
            // TCK-00626 round 4: propagate cache decision to outer scope so
            // both hit and miss paths include it in gate_finished.
            gate_cache_decision.clone_from(&cache_decision_local);
            if reuse.reusable {
                if let Some(cached) = resolve_cached_payload(
                    &reuse,
                    v3_cache_loaded.as_ref(),
                    cached_gate_cache.as_ref(),
                    gate_name,
                ) {
                    emit_gate_started(opts, gate_name);
                    let stream_stats = write_cached_gate_log_marker(
                        &log_path,
                        gate_name,
                        reuse.reason,
                        attestation_digest.as_deref(),
                    );
                    let cached_result = build_evidence_gate_result_with_cache_decision(
                        gate_name,
                        true,
                        cached.duration_secs,
                        Some(&log_path),
                        Some(&stream_stats),
                        cache_decision_local,
                    );
                    emit_gate_completed(opts, &cached_result);
                    gate_results.push(cached_result);
                    if emit_human_logs {
                        eprintln!(
                            "ts={} sha={sha} gate={gate_name} status=PASS cached=true reuse_reason={}",
                            now_iso8601(),
                            reuse.reason,
                        );
                    }
                    evidence_lines.push(format!(
                        "ts={} sha={sha} gate={gate_name} status=PASS cached=true reuse_reason={}",
                        now_iso8601(),
                        reuse.reason,
                    ));
                    continue;
                }
            }
            if emit_human_logs {
                eprintln!(
                    "ts={} sha={sha} gate={gate_name} reuse_status=miss reuse_reason={}",
                    now_iso8601(),
                    reuse.reason,
                );
            }
        }

        emit_gate_started(opts, gate_name);
        let started = Instant::now();

        // TCK-00574: Use bounded gate command (with network isolation) in
        // full mode; fall back to bare command in quick mode.
        let (passed, stream_stats) = if let Some(ref specs) = bounded_gate_specs {
            if let Some((_, bounded_cmd, bounded_env)) =
                specs.iter().find(|(name, _, _)| *name == gate_name)
            {
                let (bcmd, bargs) = bounded_cmd
                    .split_first()
                    .ok_or_else(|| format!("bounded gate command is empty for {gate_name}"))?;
                // The outer env includes D-Bus runtime variables needed by
                // systemd-run; the inner unit gets env via --setenv.
                let mut outer_env = gate_env.clone();
                outer_env.extend(bounded_env.iter().cloned());
                run_single_evidence_gate_with_env_and_progress(
                    workspace_root,
                    sha,
                    gate_name,
                    bcmd,
                    &bargs.iter().map(String::as_str).collect::<Vec<_>>(),
                    &log_path,
                    Some(&outer_env),
                    gate_wrapper_strip_ref,
                    emit_human_logs,
                    on_gate_progress,
                )
            } else {
                let (command, args) = spec
                    .command
                    .split_first()
                    .ok_or_else(|| format!("gate command is empty for {gate_name}"))?;
                run_single_evidence_gate_with_env_and_progress(
                    workspace_root,
                    sha,
                    gate_name,
                    command,
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                    &log_path,
                    Some(&gate_env),
                    gate_wrapper_strip_ref,
                    emit_human_logs,
                    on_gate_progress,
                )
            }
        } else {
            let (command, args) = spec
                .command
                .split_first()
                .ok_or_else(|| format!("gate command is empty for {gate_name}"))?;
            run_single_evidence_gate_with_env_and_progress(
                workspace_root,
                sha,
                gate_name,
                command,
                &args.iter().map(String::as_str).collect::<Vec<_>>(),
                &log_path,
                Some(&gate_env),
                gate_wrapper_strip_ref,
                emit_human_logs,
                on_gate_progress,
            )
        };

        let duration = started.elapsed().as_secs();
        let result = build_evidence_gate_result_with_cache_decision(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
            gate_cache_decision.take(),
        );
        emit_gate_completed(opts, &result);
        gate_results.push(result);
        let ts = now_iso8601();
        let status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate={gate_name} status={status} log={}",
            log_path.display()
        ));
        if !passed {
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
            return Ok((false, gate_results));
        }
    }

    // Phase 3: workspace integrity snapshot → test (optional) → verify.
    snapshot_workspace_integrity(workspace_root);

    let test_log = logs_dir.join("test.log");
    let skip_test_for_scope =
        skip_cargo_heavy_gates && opts.and_then(|o| o.test_command.as_ref()).is_none();
    if skip_test_gate || skip_test_for_scope {
        let skip_reason = if skip_test_gate {
            "quick_mode"
        } else {
            "no_cargo_impact"
        };
        let skip_msg = format!("scope={skip_reason}: skipped heavyweight test gate\n");
        let _ = crate::commands::fac_permissions::write_fac_file_with_mode(
            &test_log,
            skip_msg.as_bytes(),
        );
        let ts = now_iso8601();
        if emit_human_logs {
            eprintln!(
                "ts={ts} sha={sha} gate=test status=SKIP reason={skip_reason} log={}",
                test_log.display()
            );
        }
        evidence_lines.push(format!(
            "ts={ts} sha={sha} gate=test status=SKIP reason={skip_reason} log={}",
            test_log.display()
        ));
        let test_result = build_evidence_gate_result(
            "test",
            true,
            0,
            Some(&test_log),
            Some(&StreamStats {
                bytes_written: skip_msg.len() as u64,
                bytes_total: skip_msg.len() as u64,
                was_truncated: false,
            }),
        );
        emit_gate_completed(opts, &test_result);
        gate_results.push(test_result);
    } else {
        // TCK-00540 fix round 3: Cache reuse for the test gate.
        let test_command_override = resolve_evidence_test_command_with_scope(
            opts.and_then(|o| o.test_command.as_deref()),
            &cargo_scope,
        );
        let mut test_cache_hit = false;
        // TCK-00626 round 4: Hoist cache_decision for miss path.
        let mut test_cache_decision: Option<apm2_core::fac::gate_cache_v3::CacheDecision> = None;
        if cache_reuse_active {
            let reuse_grp = cache_reuse_policy
                .as_ref()
                .expect("guarded by cache_reuse_active");
            let attestation_digest = gate_attestation_digest(
                workspace_root,
                sha,
                "test",
                Some(&test_command_override),
                reuse_grp,
            );
            let (reuse, cache_decision_local) = reuse_decision_with_v3_fallback(
                v3_cache_loaded.as_ref(),
                cached_gate_cache.as_ref(),
                "test",
                attestation_digest.as_deref(),
                fac_verifying_key.as_ref(),
                v3_root_ns.as_deref(),
                v3_compound_key_ns.as_ref(),
                Some(sha),
            );
            // TCK-00626 round 4: propagate cache decision to outer scope.
            test_cache_decision.clone_from(&cache_decision_local);
            if reuse.reusable {
                if let Some(cached) = resolve_cached_payload(
                    &reuse,
                    v3_cache_loaded.as_ref(),
                    cached_gate_cache.as_ref(),
                    "test",
                ) {
                    emit_gate_started(opts, "test");
                    let stream_stats = write_cached_gate_log_marker(
                        &test_log,
                        "test",
                        reuse.reason,
                        attestation_digest.as_deref(),
                    );
                    let cached_result = build_evidence_gate_result_with_cache_decision(
                        "test",
                        true,
                        cached.duration_secs,
                        Some(&test_log),
                        Some(&stream_stats),
                        cache_decision_local,
                    );
                    emit_gate_completed(opts, &cached_result);
                    gate_results.push(cached_result);
                    if emit_human_logs {
                        eprintln!(
                            "ts={} sha={sha} gate=test status=PASS cached=true reuse_reason={}",
                            now_iso8601(),
                            reuse.reason,
                        );
                    }
                    evidence_lines.push(format!(
                        "ts={} sha={sha} gate=test status=PASS cached=true reuse_reason={}",
                        now_iso8601(),
                        reuse.reason,
                    ));
                    test_cache_hit = true;
                }
            }
            if !test_cache_hit && emit_human_logs {
                eprintln!(
                    "ts={} sha={sha} gate=test reuse_status=miss reuse_reason={}",
                    now_iso8601(),
                    reuse.reason,
                );
            }
        }

        if !test_cache_hit {
            emit_gate_started(opts, "test");
            let test_started = Instant::now();
            // TCK-00526: Use caller-provided test env if available (gates.rs
            // pre-computes policy env + bounded runner env), otherwise fall
            // back to the policy-filtered gate env.
            let caller_test_env = resolve_evidence_test_command_environment(opts);
            let test_env: Option<&[(String, String)]> = caller_test_env.or(Some(&gate_env));
            // TCK-00526: Use caller-provided env_remove_keys if available
            // (bounded test runner computes these), otherwise fall back to the
            // gate-level wrapper strip keys for defense-in-depth.
            let env_remove = resolve_evidence_env_remove_keys(opts).or(gate_wrapper_strip_ref);
            let (test_cmd, test_args) = test_command_override
                .split_first()
                .ok_or_else(|| "test command is empty".to_string())?;
            let (passed, stream_stats) = run_single_evidence_gate_with_env_and_progress(
                workspace_root,
                sha,
                "test",
                test_cmd,
                &test_args.iter().map(String::as_str).collect::<Vec<_>>(),
                &test_log,
                test_env,
                env_remove,
                emit_human_logs,
                on_gate_progress,
            );
            let test_duration = test_started.elapsed().as_secs();
            let test_result = build_evidence_gate_result_with_cache_decision(
                "test",
                passed,
                test_duration,
                Some(&test_log),
                Some(&stream_stats),
                test_cache_decision.take(),
            );
            emit_gate_completed(opts, &test_result);
            gate_results.push(test_result);
            let ts = now_iso8601();
            let status = if passed { "PASS" } else { "FAIL" };
            evidence_lines.push(format!(
                "ts={ts} sha={sha} gate=test status={status} log={}",
                test_log.display()
            ));
            if !passed {
                if let Some(file) = projection_log {
                    for line in &evidence_lines {
                        let _ = writeln!(file, "{line}");
                    }
                }
                attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
                return Ok((false, gate_results));
            }
        }
    }

    let wi_log_path = logs_dir.join("workspace_integrity.log");
    let mut wi_cache_hit = false;
    // TCK-00626 round 4: Hoist cache_decision for miss path.
    let mut wi_cache_decision: Option<apm2_core::fac::gate_cache_v3::CacheDecision> = None;
    if cache_reuse_active {
        let reuse_grp = cache_reuse_policy
            .as_ref()
            .expect("guarded by cache_reuse_active");
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, "workspace_integrity", None, reuse_grp);
        let (reuse, cache_decision_local) = reuse_decision_with_v3_fallback(
            v3_cache_loaded.as_ref(),
            cached_gate_cache.as_ref(),
            "workspace_integrity",
            attestation_digest.as_deref(),
            fac_verifying_key.as_ref(),
            v3_root_ns.as_deref(),
            v3_compound_key_ns.as_ref(),
            Some(sha),
        );
        // TCK-00626 round 4: propagate cache decision to outer scope.
        wi_cache_decision.clone_from(&cache_decision_local);
        if reuse.reusable {
            if let Some(cached) = resolve_cached_payload(
                &reuse,
                v3_cache_loaded.as_ref(),
                cached_gate_cache.as_ref(),
                "workspace_integrity",
            ) {
                emit_gate_started(opts, "workspace_integrity");
                let stream_stats = write_cached_gate_log_marker(
                    &wi_log_path,
                    "workspace_integrity",
                    reuse.reason,
                    attestation_digest.as_deref(),
                );
                let cached_result = build_evidence_gate_result_with_cache_decision(
                    "workspace_integrity",
                    true,
                    cached.duration_secs,
                    Some(&wi_log_path),
                    Some(&stream_stats),
                    cache_decision_local,
                );
                emit_gate_completed(opts, &cached_result);
                gate_results.push(cached_result);
                if emit_human_logs {
                    eprintln!(
                        "ts={} sha={sha} gate=workspace_integrity status=PASS cached=true reuse_reason={}",
                        now_iso8601(),
                        reuse.reason,
                    );
                }
                evidence_lines.push(format!(
                    "ts={} sha={sha} gate=workspace_integrity status=PASS cached=true reuse_reason={}",
                    now_iso8601(),
                    reuse.reason,
                ));
                wi_cache_hit = true;
            }
        }
        if !wi_cache_hit && emit_human_logs {
            eprintln!(
                "ts={} sha={sha} gate=workspace_integrity reuse_status=miss reuse_reason={}",
                now_iso8601(),
                reuse.reason,
            );
        }
    }

    if !wi_cache_hit {
        emit_gate_started(opts, "workspace_integrity");
        let wi_started = Instant::now();
        let (wi_passed, wi_line, wi_stream_stats) =
            verify_workspace_integrity_gate(workspace_root, sha, &wi_log_path, emit_human_logs);
        let wi_duration = wi_started.elapsed().as_secs();
        let wi_result = build_evidence_gate_result_with_cache_decision(
            "workspace_integrity",
            wi_passed,
            wi_duration,
            Some(&wi_log_path),
            Some(&wi_stream_stats),
            wi_cache_decision.take(),
        );
        emit_gate_completed(opts, &wi_result);
        gate_results.push(wi_result);
        evidence_lines.push(wi_line);
        if !wi_passed {
            if let Some(file) = projection_log {
                for line in &evidence_lines {
                    let _ = writeln!(file, "{line}");
                }
            }
            attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
            return Ok((false, gate_results));
        }
    }

    if let Some(file) = projection_log {
        for line in &evidence_lines {
            let _ = writeln!(file, "{line}");
        }
    }

    attach_log_bundle_hash(&mut gate_results, &logs_dir)?;
    Ok((true, gate_results))
}

/// Run evidence gates with PR-body gate status updates.
///
/// Same as [`run_evidence_gates_with_lane_context`] but also updates the PR
/// body gate section after each gate completes. Checks the per-SHA gate cache
/// before each gate and skips execution if the gate already passed for this
/// SHA.
#[allow(clippy::too_many_arguments)]
pub fn run_evidence_gates_with_status(
    workspace_root: &Path,
    sha: &str,
    owner_repo: &str,
    pr_number: u32,
    projection_log: Option<&mut File>,
    emit_human_logs: bool,
    on_gate_progress: Option<&dyn Fn(GateProgressEvent)>,
) -> Result<(bool, Vec<EvidenceGateResult>), String> {
    let lane_context = allocate_lane_job_logs_dir()?;
    run_evidence_gates_with_status_with_lane_context(
        workspace_root,
        sha,
        owner_repo,
        pr_number,
        projection_log,
        emit_human_logs,
        on_gate_progress,
        lane_context,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_evidence_gates_with_status_with_lane_context(
    workspace_root: &Path,
    sha: &str,
    owner_repo: &str,
    pr_number: u32,
    projection_log: Option<&mut File>,
    emit_human_logs: bool,
    on_gate_progress: Option<&dyn Fn(GateProgressEvent)>,
    lane_context: EvidenceLaneContext,
) -> Result<(bool, Vec<EvidenceGateResult>), String> {
    let logs_dir = lane_context.logs_dir;
    // Pipeline path enforces fail-closed cache reuse decisions.

    // TCK-00526: Build policy-filtered environment for ALL gates.
    // TCK-00575 round 2: Use the lane_dir from the actually-locked lane
    // (not hardcoded lane-00) to maintain lock/env coupling.
    let gate_env = build_gate_policy_env(&lane_context.lane_dir)?;

    // TCK-00526: Compute wrapper-stripping keys once for ALL gate phases.
    // Pass the policy-filtered environment so policy-introduced SCCACHE_*
    // variables are also discovered for defense-in-depth stripping.
    let gate_wrapper_strip = compute_gate_env_remove_keys(Some(&gate_env));
    let gate_wrapper_strip_ref: Option<&[String]> = if gate_wrapper_strip.is_empty() {
        None
    } else {
        Some(&gate_wrapper_strip)
    };

    let mut status = CiStatus::new(sha, pr_number);
    let updater = PrBodyStatusUpdater::new(owner_repo, pr_number);

    // TCK-00576: Load the persistent signer for gate cache signature
    // verification (reuse decisions) and signing (new cache entries).
    let fac_signer = {
        let apm2_home = apm2_core::github::resolve_apm2_home()
            .ok_or_else(|| "cannot resolve APM2_HOME for gate cache signing".to_string())?;
        let fac_root = apm2_home.join("private/fac");
        crate::commands::fac_key_material::load_or_generate_persistent_signer(&fac_root)
            .map_err(|e| format!("cannot load signing key for gate cache: {e}"))?
    };
    let fac_verifying_key = fac_signer.verifying_key();

    // Load attested gate cache for this SHA (typically populated by `fac gates`).
    let cache = GateCache::load(sha);
    let mut gate_cache = GateCache::new(sha);
    let pipeline_test_command =
        build_pipeline_test_command(workspace_root, &lane_context.lane_dir)?;

    // TCK-00541: Build v3 compound key and load v3 cache (with v2 fallback).
    let v3_compound_key = compute_v3_compound_key(
        sha,
        &load_or_create_pipeline_policy(
            &apm2_core::github::resolve_apm2_home()
                .ok_or_else(|| "cannot resolve APM2_HOME for v3 cache".to_string())?
                .join("private/fac"),
        )?,
        &pipeline_test_command.sandbox_hardening_hash,
        &pipeline_test_command.network_policy_hash,
    );
    let v3_root = cache_v3_root();
    // [INV-GCV3-001] V2 fallback loading removed from evidence pipeline.
    // V2 entries lack RFC-0028/0029 binding proof and cannot satisfy v3
    // compound-key continuity. Loading v2 entries into a GateCacheV3
    // assigned the current compound key without cryptographic binding,
    // creating a structural gap even though check_reuse denied reuse.
    // The evidence pipeline now only loads native v3 entries.
    let v3_cache_loaded = v3_compound_key.as_ref().and_then(|ck| {
        let root = v3_root.as_deref()?;
        GateCacheV3::load_from_dir(root, sha, ck)
    });
    // Create a mutable v3 cache for new gate results (writes only to v3).
    let mut v3_gate_cache = v3_compound_key
        .as_ref()
        .and_then(|ck| GateCacheV3::new(sha, ck.clone()).ok());
    // TCK-00573 MAJOR-3: Include sandbox hardening hash in gate attestation
    // to prevent stale gate results from insecure environments being reused.
    // Uses the effective policy-driven profile carried through
    // PipelineTestCommand (MAJOR-1 fix: was previously default()).
    let sandbox_hardening_hash = &pipeline_test_command.sandbox_hardening_hash;
    // TCK-00574 MAJOR-1: Include network policy hash in gate attestation
    // to prevent cache reuse across network policy drift.
    let network_policy_hash = &pipeline_test_command.network_policy_hash;
    let policy = GateResourcePolicy::from_cli(
        false,
        pipeline_test_command.effective_timeout_seconds,
        DEFAULT_TEST_MEMORY_MAX,
        DEFAULT_TEST_PIDS_MAX,
        &pipeline_test_command.effective_cpu_quota,
        pipeline_test_command.bounded_runner,
        Some(pipeline_test_command.gate_profile.as_str()),
        Some(pipeline_test_command.effective_test_parallelism),
        Some(sandbox_hardening_hash.as_str()),
        Some(network_policy_hash.as_str()),
    );
    if emit_human_logs {
        eprintln!(
            "FAC pipeline test throughput: profile={} cpu_quota={} test_parallelism={}",
            pipeline_test_command.gate_profile.as_str(),
            pipeline_test_command.effective_cpu_quota,
            pipeline_test_command.effective_test_parallelism
        );
    }

    // Fastest-first ordering for expensive cargo gates. Keep cheap checks
    // ahead of heavier analysis to minimize wasted compute on early failure.
    let gates: &[(&str, &[&str])] = &[
        ("rustfmt", &["cargo", "fmt", "--all", "--check"]),
        ("doc", &["cargo", "doc", "--workspace", "--no-deps"]),
        (
            "clippy",
            &[
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
    ];

    let mut evidence_lines = Vec::new();
    let mut gate_results = Vec::new();

    // Phase 0: merge conflict gate (always first, always recomputed).
    {
        let gate_name = MERGE_CONFLICT_GATE_NAME;
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);

        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let (passed, duration, line, stream_stats) =
            run_merge_conflict_gate(workspace_root, sha, &log_path, emit_human_logs);
        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        let merge_result = build_evidence_gate_result(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
        );
        emit_gate_completed_cb(on_gate_progress, &merge_result);
        gate_results.push(merge_result);
        evidence_lines.push(line);
        let merge_digest = sha256_file_hex(&log_path);
        let merge_attestation =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        gate_cache.set_with_attestation(
            gate_name,
            passed,
            duration,
            merge_attestation,
            false,
            merge_digest,
            log_path.to_str().map(str::to_string),
        );
        if !passed {
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
                v3_gate_cache.as_mut(),
            )?;
            return Ok((false, gate_results));
        }
    }

    // Phase 1: front-loaded native gates.
    for gate_name in FRONTLOADED_NATIVE_EVIDENCE_GATES {
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let (reuse, cache_decision_local) = reuse_decision_with_v3_fallback(
            v3_cache_loaded.as_ref(),
            cache.as_ref(),
            gate_name,
            attestation_digest.as_deref(),
            Some(&fac_verifying_key),
            v3_root.as_deref(),
            v3_compound_key.as_ref(),
            Some(sha),
        );
        if reuse.reusable {
            if let Some(cached) =
                resolve_cached_payload(&reuse, v3_cache_loaded.as_ref(), cache.as_ref(), gate_name)
            {
                emit_gate_started_cb(on_gate_progress, gate_name);
                status.set_running(gate_name);
                updater.update(&status);
                let stream_stats = write_cached_gate_log_marker(
                    &log_path,
                    gate_name,
                    reuse.reason,
                    attestation_digest.as_deref(),
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let cached_result = build_evidence_gate_result_with_cache_decision(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                    cache_decision_local,
                );
                emit_gate_completed_cb(on_gate_progress, &cached_result);
                gate_results.push(cached_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest,
                    cached.log_path,
                );
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                        .map_or_else(|| "unknown".to_string(), short_digest),
                ));
                continue;
            }
            emit_gate_started_cb(on_gate_progress, gate_name);
            status.set_running(gate_name);
            updater.update(&status);
            status.set_result(gate_name, false, 0);
            updater.update(&status);
            let fail_result = build_evidence_gate_result_with_cache_decision(
                gate_name,
                false,
                0,
                Some(&log_path),
                Some(&StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                }),
                cache_decision_local,
            );
            emit_gate_completed_cb(on_gate_progress, &fail_result);
            gate_results.push(fail_result);
            gate_cache.set_with_attestation(
                gate_name,
                false,
                0,
                attestation_digest,
                false,
                None,
                log_path.to_str().map(str::to_string),
            );
            evidence_lines.push(format!(
                "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                now_iso8601(),
                sha,
                gate_name
            ));
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
                v3_gate_cache.as_mut(),
            )?;
            return Ok((false, gate_results));
        }

        if emit_human_logs {
            eprintln!(
                "ts={} sha={} gate={} reuse_status=miss reuse_reason={} attestation_digest={}",
                now_iso8601(),
                sha,
                gate_name,
                reuse.reason,
                attestation_digest
                    .as_deref()
                    .map_or_else(|| "unknown".to_string(), short_digest),
            );
        }
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);
        let started = Instant::now();
        let (passed, stream_stats) =
            run_native_evidence_gate(workspace_root, sha, gate_name, &log_path, emit_human_logs);
        let duration = started.elapsed().as_secs();

        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        let exec_result = build_evidence_gate_result_with_cache_decision(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
            cache_decision_local.clone(),
        );
        emit_gate_completed_cb(on_gate_progress, &exec_result);
        gate_results.push(exec_result);
        gate_cache.set_with_attestation(
            gate_name,
            passed,
            duration,
            attestation_digest.clone(),
            false,
            sha256_file_hex(&log_path),
            log_path.to_str().map(str::to_string),
        );
        let gate_status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
            now_iso8601(),
            sha,
            gate_name,
            gate_status,
            log_path.display(),
            reuse.reason,
        ));
        if !passed {
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
                v3_gate_cache.as_mut(),
            )?;
            return Ok((false, gate_results));
        }
    }

    // TCK-00574 BLOCKER fix: Build bounded gate commands for non-test gates
    // to enforce network-deny in the pipeline path (always full mode).
    #[allow(clippy::type_complexity)]
    let pipeline_bounded_gate_specs: Vec<(&str, Vec<String>, Vec<(String, String)>)> = {
        let apm2_home = apm2_core::github::resolve_apm2_home().ok_or_else(|| {
            "cannot resolve APM2_HOME for pipeline gate network policy enforcement".to_string()
        })?;
        let fac_root = apm2_home.join("private/fac");
        let fac_policy = load_or_create_pipeline_policy(&fac_root)?;
        let gate_network_policy =
            apm2_core::fac::resolve_network_policy("gates", fac_policy.network_policy.as_ref());
        let mut specs = Vec::new();
        for &(gate_name, cmd_args) in gates {
            let gate_cmd: Vec<String> = cmd_args.iter().map(|s| (*s).to_string()).collect();
            let bounded = build_systemd_bounded_gate_command(
                workspace_root,
                BoundedTestLimits {
                    timeout_seconds: DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS,
                    kill_after_seconds: DEFAULT_TEST_KILL_AFTER_SECONDS,
                    memory_max: DEFAULT_TEST_MEMORY_MAX,
                    pids_max: DEFAULT_TEST_PIDS_MAX,
                    cpu_quota: "200%",
                },
                &gate_cmd,
                None,
                &gate_env,
                fac_policy.sandbox_hardening.clone(),
                gate_network_policy.clone(),
            )
            .map_err(|err| {
                format!(
                    "bounded gate runner unavailable for {gate_name} \
                     (network deny enforcement requires systemd-run): {err}"
                )
            })?;
            specs.push((gate_name, bounded.command, bounded.environment));
        }
        specs
    };

    // Phase 2: cargo fmt/doc/clippy.
    for (idx, &(gate_name, _cmd_args)) in gates.iter().enumerate() {
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let log_path = logs_dir.join(format!("{gate_name}.log"));
        let (reuse, cache_decision_local) = reuse_decision_with_v3_fallback(
            v3_cache_loaded.as_ref(),
            cache.as_ref(),
            gate_name,
            attestation_digest.as_deref(),
            Some(&fac_verifying_key),
            v3_root.as_deref(),
            v3_compound_key.as_ref(),
            Some(sha),
        );
        if reuse.reusable {
            if let Some(cached) =
                resolve_cached_payload(&reuse, v3_cache_loaded.as_ref(), cache.as_ref(), gate_name)
            {
                emit_gate_started_cb(on_gate_progress, gate_name);
                status.set_running(gate_name);
                updater.update(&status);
                let stream_stats = write_cached_gate_log_marker(
                    &log_path,
                    gate_name,
                    reuse.reason,
                    attestation_digest.as_deref(),
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let cached_result = build_evidence_gate_result_with_cache_decision(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                    cache_decision_local,
                );
                emit_gate_completed_cb(on_gate_progress, &cached_result);
                gate_results.push(cached_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest,
                    cached.log_path,
                );
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                    .map_or_else(|| "unknown".to_string(), short_digest),
                ));
                continue;
            }
            emit_gate_started_cb(on_gate_progress, gate_name);
            status.set_running(gate_name);
            updater.update(&status);
            status.set_result(gate_name, false, 0);
            updater.update(&status);
            let fail_result = build_evidence_gate_result_with_cache_decision(
                gate_name,
                false,
                0,
                Some(&log_path),
                Some(&StreamStats {
                    bytes_written: 0,
                    bytes_total: 0,
                    was_truncated: false,
                }),
                cache_decision_local,
            );
            emit_gate_completed_cb(on_gate_progress, &fail_result);
            gate_results.push(fail_result);
            gate_cache.set_with_attestation(
                gate_name,
                false,
                0,
                attestation_digest,
                false,
                None,
                log_path.to_str().map(str::to_string),
            );
            evidence_lines.push(format!(
                "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                now_iso8601(),
                sha,
                gate_name
            ));
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
                v3_gate_cache.as_mut(),
            )?;
            return Ok((false, gate_results));
        }

        if emit_human_logs {
            eprintln!(
                "ts={} sha={} gate={} reuse_status=miss reuse_reason={} attestation_digest={}",
                now_iso8601(),
                sha,
                gate_name,
                reuse.reason,
                attestation_digest
                    .as_deref()
                    .map_or_else(|| "unknown".to_string(), short_digest),
            );
        }
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);
        let started = Instant::now();
        // TCK-00574: Use bounded gate command with network isolation.
        let (_bounded_name, bounded_cmd, bounded_env) = &pipeline_bounded_gate_specs[idx];
        let (bcmd, bargs) = bounded_cmd
            .split_first()
            .ok_or_else(|| format!("bounded gate command is empty for {gate_name}"))?;
        let mut outer_env = gate_env.clone();
        outer_env.extend(bounded_env.iter().cloned());
        let (passed, stream_stats) = run_single_evidence_gate_with_env_and_progress(
            workspace_root,
            sha,
            gate_name,
            bcmd,
            &bargs.iter().map(String::as_str).collect::<Vec<_>>(),
            &log_path,
            Some(&outer_env),
            gate_wrapper_strip_ref,
            emit_human_logs,
            on_gate_progress,
        );
        let duration = started.elapsed().as_secs();

        status.set_result(gate_name, passed, duration);
        updater.update(&status);
        let exec_result = build_evidence_gate_result_with_cache_decision(
            gate_name,
            passed,
            duration,
            Some(&log_path),
            Some(&stream_stats),
            cache_decision_local.clone(),
        );
        emit_gate_completed_cb(on_gate_progress, &exec_result);
        gate_results.push(exec_result);
        gate_cache.set_with_attestation(
            gate_name,
            passed,
            duration,
            attestation_digest.clone(),
            false,
            sha256_file_hex(&log_path),
            log_path.to_str().map(str::to_string),
        );
        let gate_status = if passed { "PASS" } else { "FAIL" };
        evidence_lines.push(format!(
            "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
            now_iso8601(),
            sha,
            gate_name,
            gate_status,
            log_path.display(),
            reuse.reason,
        ));
        if !passed {
            finalize_status_gate_run(
                projection_log,
                &evidence_lines,
                &mut gate_results,
                &logs_dir,
                &mut gate_cache,
                &updater,
                &status,
                &fac_signer,
                v3_gate_cache.as_mut(),
            )?;
            return Ok((false, gate_results));
        }
    }

    // Phase 3: workspace integrity snapshot → test → verify.
    snapshot_workspace_integrity(workspace_root);

    {
        let gate_name = "test";
        let attestation_digest = gate_attestation_digest(
            workspace_root,
            sha,
            gate_name,
            Some(pipeline_test_command.command.as_slice()),
            &policy,
        );
        let (reuse, cache_decision_local) = reuse_decision_with_v3_fallback(
            v3_cache_loaded.as_ref(),
            cache.as_ref(),
            gate_name,
            attestation_digest.as_deref(),
            Some(&fac_verifying_key),
            v3_root.as_deref(),
            v3_compound_key.as_ref(),
            Some(sha),
        );
        let log_path = logs_dir.join("test.log");
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);
        if reuse.reusable {
            if let Some(cached) =
                resolve_cached_payload(&reuse, v3_cache_loaded.as_ref(), cache.as_ref(), gate_name)
            {
                let stream_stats = write_cached_gate_log_marker(
                    &log_path,
                    gate_name,
                    reuse.reason,
                    attestation_digest.as_deref(),
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let cached_result = build_evidence_gate_result_with_cache_decision(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                    cache_decision_local,
                );
                emit_gate_completed_cb(on_gate_progress, &cached_result);
                gate_results.push(cached_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest,
                    cached.log_path,
                );
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                        .map_or_else(|| "unknown".to_string(), short_digest),
                ));
            } else {
                status.set_result(gate_name, false, 0);
                updater.update(&status);
                let fail_result = build_evidence_gate_result_with_cache_decision(
                    gate_name,
                    false,
                    0,
                    Some(&log_path),
                    Some(&StreamStats {
                        bytes_written: 0,
                        bytes_total: 0,
                        was_truncated: false,
                    }),
                    cache_decision_local,
                );
                emit_gate_completed_cb(on_gate_progress, &fail_result);
                gate_results.push(fail_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    false,
                    0,
                    attestation_digest,
                    false,
                    None,
                    log_path.to_str().map(str::to_string),
                );
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                    now_iso8601(),
                    sha,
                    gate_name
                ));
                finalize_status_gate_run(
                    projection_log,
                    &evidence_lines,
                    &mut gate_results,
                    &logs_dir,
                    &mut gate_cache,
                    &updater,
                    &status,
                    &fac_signer,
                    v3_gate_cache.as_mut(),
                )?;
                return Ok((false, gate_results));
            }
        } else {
            if emit_human_logs {
                eprintln!(
                    "ts={} sha={} gate={} reuse_status=miss reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                        .map_or_else(|| "unknown".to_string(), short_digest),
                );
            }
            let started = Instant::now();
            let (test_cmd, test_args) = pipeline_test_command
                .command
                .split_first()
                .ok_or_else(|| "pipeline test command is empty".to_string())?;
            let pipeline_env_remove = if pipeline_test_command.env_remove_keys.is_empty() {
                None
            } else {
                Some(pipeline_test_command.env_remove_keys.as_slice())
            };
            let (passed, stream_stats) = run_single_evidence_gate_with_env_and_progress(
                workspace_root,
                sha,
                gate_name,
                test_cmd,
                &test_args.iter().map(String::as_str).collect::<Vec<_>>(),
                &log_path,
                Some(&pipeline_test_command.test_env),
                pipeline_env_remove,
                emit_human_logs,
                on_gate_progress,
            );
            let duration = started.elapsed().as_secs();
            status.set_result(gate_name, passed, duration);
            updater.update(&status);
            let test_result = build_evidence_gate_result_with_cache_decision(
                gate_name,
                passed,
                duration,
                Some(&log_path),
                Some(&stream_stats),
                cache_decision_local,
            );
            emit_gate_completed_cb(on_gate_progress, &test_result);
            gate_results.push(test_result);
            gate_cache.set_with_attestation(
                gate_name,
                passed,
                duration,
                attestation_digest,
                false,
                sha256_file_hex(&log_path),
                log_path.to_str().map(str::to_string),
            );
            let gate_status = if passed { "PASS" } else { "FAIL" };
            evidence_lines.push(format!(
                "ts={} sha={} gate={} status={} log={} reuse_status=miss reuse_reason={}",
                now_iso8601(),
                sha,
                gate_name,
                gate_status,
                log_path.display(),
                reuse.reason,
            ));
            if !passed {
                finalize_status_gate_run(
                    projection_log,
                    &evidence_lines,
                    &mut gate_results,
                    &logs_dir,
                    &mut gate_cache,
                    &updater,
                    &status,
                    &fac_signer,
                    v3_gate_cache.as_mut(),
                )?;
                return Ok((false, gate_results));
            }
        }
    }

    {
        let gate_name = "workspace_integrity";
        let attestation_digest =
            gate_attestation_digest(workspace_root, sha, gate_name, None, &policy);
        let (reuse, cache_decision_local) = reuse_decision_with_v3_fallback(
            v3_cache_loaded.as_ref(),
            cache.as_ref(),
            gate_name,
            attestation_digest.as_deref(),
            Some(&fac_verifying_key),
            v3_root.as_deref(),
            v3_compound_key.as_ref(),
            Some(sha),
        );
        let log_path = logs_dir.join("workspace_integrity.log");
        emit_gate_started_cb(on_gate_progress, gate_name);
        status.set_running(gate_name);
        updater.update(&status);
        if reuse.reusable {
            if let Some(cached) =
                resolve_cached_payload(&reuse, v3_cache_loaded.as_ref(), cache.as_ref(), gate_name)
            {
                let stream_stats = write_cached_gate_log_marker(
                    &log_path,
                    gate_name,
                    reuse.reason,
                    attestation_digest.as_deref(),
                );
                status.set_result(gate_name, true, cached.duration_secs);
                updater.update(&status);
                let cached_result = build_evidence_gate_result_with_cache_decision(
                    gate_name,
                    true,
                    cached.duration_secs,
                    Some(&log_path),
                    Some(&stream_stats),
                    cache_decision_local,
                );
                emit_gate_completed_cb(on_gate_progress, &cached_result);
                gate_results.push(cached_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    true,
                    cached.duration_secs,
                    attestation_digest.clone(),
                    false,
                    cached.evidence_log_digest,
                    cached.log_path,
                );
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=PASS cached=true reuse_status=hit reuse_reason={} attestation_digest={}",
                    now_iso8601(),
                    sha,
                    gate_name,
                    reuse.reason,
                    attestation_digest
                        .as_deref()
                        .map_or_else(|| "unknown".to_string(), short_digest),
                ));
            } else {
                status.set_result(gate_name, false, 0);
                updater.update(&status);
                let fail_result = build_evidence_gate_result_with_cache_decision(
                    gate_name,
                    false,
                    0,
                    Some(&log_path),
                    Some(&StreamStats {
                        bytes_written: 0,
                        bytes_total: 0,
                        was_truncated: false,
                    }),
                    cache_decision_local,
                );
                emit_gate_completed_cb(on_gate_progress, &fail_result);
                gate_results.push(fail_result);
                gate_cache.set_with_attestation(
                    gate_name,
                    false,
                    0,
                    attestation_digest,
                    false,
                    None,
                    log_path.to_str().map(str::to_string),
                );
                evidence_lines.push(format!(
                    "ts={} sha={} gate={} status=FAIL reuse_status=miss reuse_reason=inconsistent_cache_entry",
                    now_iso8601(),
                    sha,
                    gate_name
                ));
                finalize_status_gate_run(
                    projection_log,
                    &evidence_lines,
                    &mut gate_results,
                    &logs_dir,
                    &mut gate_cache,
                    &updater,
                    &status,
                    &fac_signer,
                    v3_gate_cache.as_mut(),
                )?;
                return Ok((false, gate_results));
            }
        } else {
            let started = Instant::now();
            let (passed, line, stream_stats) =
                verify_workspace_integrity_gate(workspace_root, sha, &log_path, emit_human_logs);
            let duration = started.elapsed().as_secs();
            status.set_result(gate_name, passed, duration);
            updater.update(&status);
            let wi_result = build_evidence_gate_result_with_cache_decision(
                gate_name,
                passed,
                duration,
                Some(&log_path),
                Some(&stream_stats),
                cache_decision_local,
            );
            emit_gate_completed_cb(on_gate_progress, &wi_result);
            gate_results.push(wi_result);
            gate_cache.set_with_attestation(
                gate_name,
                passed,
                duration,
                attestation_digest,
                false,
                sha256_file_hex(&log_path),
                log_path.to_str().map(str::to_string),
            );
            evidence_lines.push(format!(
                "{} reuse_status=miss reuse_reason={}",
                line, reuse.reason
            ));
            if !passed {
                finalize_status_gate_run(
                    projection_log,
                    &evidence_lines,
                    &mut gate_results,
                    &logs_dir,
                    &mut gate_cache,
                    &updater,
                    &status,
                    &fac_signer,
                    v3_gate_cache.as_mut(),
                )?;
                return Ok((false, gate_results));
            }
        }
    }

    finalize_status_gate_run(
        projection_log,
        &evidence_lines,
        &mut gate_results,
        &logs_dir,
        &mut gate_cache,
        &updater,
        &status,
        &fac_signer,
        v3_gate_cache.as_mut(),
    )?;
    Ok((true, gate_results))
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_log_path(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "apm2-evidence-tests-{test_name}-{}-{nonce}",
            std::process::id()
        ));
        crate::commands::fac_permissions::ensure_dir_with_mode(&dir).expect("create temp dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .expect("set temp dir permissions");
        }
        dir.join("test.log")
    }

    #[test]
    fn short_test_failure_hint_is_appended() {
        let log_path = temp_log_path("short");
        fs::write(&log_path, "=== stdout ===\n\n=== stderr ===\n\n").expect("write seed log");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))
                .expect("set log file mode");
        }

        append_short_test_failure_hint(&log_path, 128);

        let content = fs::read_to_string(&log_path).expect("read updated log");
        assert!(content.contains("--- fac diagnostic ---"));
        assert!(content.contains("minimal output (128 bytes)"));
    }

    #[test]
    fn short_test_failure_hint_is_skipped_for_large_output() {
        let log_path = temp_log_path("large");
        fs::write(&log_path, "=== stdout ===\n\n=== stderr ===\n\n").expect("write seed log");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))
                .expect("set log file mode");
        }

        append_short_test_failure_hint(&log_path, SHORT_TEST_OUTPUT_HINT_THRESHOLD_BYTES);

        let content = fs::read_to_string(&log_path).expect("read updated log");
        assert!(!content.contains("--- fac diagnostic ---"));
    }

    #[test]
    fn default_evidence_test_command_uses_nextest() {
        let command =
            resolve_evidence_test_command_with_scope(None, &CargoGateExecutionScope::FullWorkspace);
        let joined = command.join(" ");
        assert!(joined.contains("cargo nextest run --workspace"));
        assert!(!joined.contains("cargo test --workspace"));
    }

    #[test]
    fn cargo_scope_classifies_docs_only_changes_as_no_cargo_impact() {
        let scope = classify_cargo_gate_scope(
            &["documents/strategy/ROADMAP.json".to_string()],
            &[("crates/apm2-cli".to_string(), "apm2-cli".to_string())],
        );
        assert_eq!(scope, CargoGateExecutionScope::NoCargoImpact);
    }

    #[test]
    fn cargo_scope_classifies_crate_changes_as_scoped_packages() {
        let scope = classify_cargo_gate_scope(
            &[
                "crates/apm2-cli/src/main.rs".to_string(),
                "crates/apm2-cli/src/lib.rs".to_string(),
            ],
            &[
                ("crates/apm2-cli".to_string(), "apm2-cli".to_string()),
                ("crates/apm2-core".to_string(), "apm2-core".to_string()),
            ],
        );
        assert_eq!(
            scope,
            CargoGateExecutionScope::ScopedPackages(vec!["apm2-cli".to_string()])
        );
    }

    #[test]
    fn cargo_scope_escalates_lockfile_changes_to_full_workspace() {
        let scope = classify_cargo_gate_scope(
            &["Cargo.lock".to_string()],
            &[("crates/apm2-cli".to_string(), "apm2-cli".to_string())],
        );
        assert_eq!(scope, CargoGateExecutionScope::FullWorkspace);
    }

    #[test]
    fn scoped_commands_emit_package_flags_without_workspace_flag() {
        let scope = CargoGateExecutionScope::ScopedPackages(vec!["apm2-cli".to_string()]);
        let nextest = build_scoped_nextest_command(&scope).join(" ");
        let doc = build_doc_gate_command(&scope).join(" ");
        let clippy = build_clippy_gate_command(&scope).join(" ");

        assert!(nextest.contains("cargo nextest run -p apm2-cli"));
        assert!(!nextest.contains("--workspace"));
        assert!(doc.contains("cargo doc -p apm2-cli --no-deps"));
        assert!(!doc.contains("--workspace"));
        assert!(clippy.contains("cargo clippy -p apm2-cli"));
        assert!(!clippy.contains("--workspace"));
    }

    #[test]
    fn doc_gate_skip_reason_defaults_to_skip_for_scoped_packages() {
        let scope = CargoGateExecutionScope::ScopedPackages(vec!["apm2-cli".to_string()]);
        assert_eq!(
            doc_gate_skip_reason(&scope, false),
            Some("scoped_latency_budget")
        );
        assert_eq!(doc_gate_skip_reason(&scope, true), None);
    }

    #[test]
    fn doc_gate_skip_reason_respects_scope_transitions() {
        assert_eq!(
            doc_gate_skip_reason(&CargoGateExecutionScope::FullWorkspace, false),
            None
        );
        assert_eq!(
            doc_gate_skip_reason(&CargoGateExecutionScope::NoCargoImpact, false),
            Some("no_cargo_impact")
        );
    }

    #[test]
    fn pipeline_test_command_uses_rust_bounded_runner_or_surfaces_preflight_error() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let lane_dir = temp_dir
            .path()
            .join("apm2-home/private/fac/lanes/lane-test");
        std::fs::create_dir_all(&lane_dir).expect("create lane dir");
        match build_pipeline_test_command(temp_dir.path(), &lane_dir) {
            Ok(command) => {
                let joined = command.command.join(" ");
                assert!(joined.contains("systemd-run"));
                assert!(joined.contains("cargo nextest run --workspace"));
                assert!(!joined.contains(".sh"));
                assert_eq!(
                    command.gate_profile,
                    crate::commands::fac_review::GateThroughputProfile::Throughput
                );
                let host_parallelism = apm2_core::fac::resolve_host_test_parallelism();
                assert!(command.effective_test_parallelism >= 1);
                assert!(command.effective_cpu_quota.ends_with('%'));
                assert_eq!(command.effective_test_parallelism, host_parallelism);
                assert_eq!(
                    command.effective_cpu_quota,
                    format!("{}%", host_parallelism.saturating_mul(100).max(100))
                );
                let threads = command
                    .test_env
                    .iter()
                    .find(|(k, _)| k == "NEXTEST_TEST_THREADS")
                    .and_then(|(_, v)| v.parse::<u32>().ok())
                    .unwrap_or(0);
                let build_jobs = command
                    .test_env
                    .iter()
                    .find(|(k, _)| k == "CARGO_BUILD_JOBS")
                    .and_then(|(_, v)| v.parse::<u32>().ok())
                    .unwrap_or(0);
                assert_eq!(threads, command.effective_test_parallelism);
                assert_eq!(threads, build_jobs);
            },
            Err(err) => {
                assert!(
                    err.contains("bounded test runner unavailable")
                        || err.contains("systemd-run not found")
                        || err.contains("cgroup v2")
                        || err.contains("D-Bus socket")
                        || err.contains("lane env dir")
                        || err.contains("too-permissive mode"),
                    "unexpected error: {err}"
                );
            },
        }
    }

    #[test]
    fn pipeline_test_command_carries_env_remove_keys() {
        // BLOCKER-2 regression: build_pipeline_test_command must propagate
        // env_remove_keys from bounded_spec so the pipeline/doctor-fix path
        // strips sccache env vars.
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let lane_dir = temp_dir
            .path()
            .join("apm2-home/private/fac/lanes/lane-test");
        std::fs::create_dir_all(&lane_dir).expect("create lane dir");
        if let Ok(command) = build_pipeline_test_command(temp_dir.path(), &lane_dir) {
            // The bounded test runner always strips at least RUSTC_WRAPPER.
            assert!(
                command
                    .env_remove_keys
                    .contains(&"RUSTC_WRAPPER".to_string()),
                "pipeline test command must carry RUSTC_WRAPPER in env_remove_keys, got: {:?}",
                command.env_remove_keys
            );
        }
        // If the bounded runner is unavailable (Err), the test cannot
        // verify this assertion — skip gracefully.
    }

    /// Helper: create a temporary directory with 0o700 permissions for test
    /// isolation, returning the directory path itself (not a file inside it).
    fn temp_test_dir(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "apm2-evidence-tests-{test_name}-{}-{nonce}",
            std::process::id()
        ));
        crate::commands::fac_permissions::ensure_dir_with_mode(&dir).expect("create temp dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .expect("set temp dir permissions");
        }
        dir
    }

    /// BLOCKER 1: Prove that >=3 concurrent evidence gate runs produce unique,
    /// non-overlapping log files via lane-scoped namespacing.
    ///
    /// Each thread runs `run_single_evidence_gate` with a trivially-fast
    /// command (`echo`), writing to a unique log path. The test asserts:
    ///   - All 3 runs succeed.
    ///   - Each produces a distinct log file path.
    ///   - No log file content is empty or duplicated across runs.
    #[test]
    fn concurrent_evidence_runs_produce_unique_logs() {
        let workspace_root = temp_test_dir("concurrent");
        let num_concurrent = 3;
        let sha = "deadbeef_concurrent_test";

        let handles: Vec<_> = (0..num_concurrent)
            .map(|idx| {
                let ws = workspace_root.clone();
                thread::spawn(move || {
                    let gate_name = format!("echo_gate_{idx}");
                    let log_dir = ws.join(format!("lane-{idx}"));
                    crate::commands::fac_permissions::ensure_dir_with_mode(&log_dir)
                        .expect("create lane dir");
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;

                        fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700))
                            .expect("set lane dir permissions");
                    }
                    let log_path = log_dir.join(format!("{gate_name}.log"));

                    let (passed, _stream_stats) = run_single_evidence_gate(
                        &ws,
                        sha,
                        &gate_name,
                        "echo",
                        &[&format!("hello from lane {idx}")],
                        &log_path,
                        true,
                    );
                    (passed, log_path)
                })
            })
            .collect();

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().expect("thread should not panic"));
        }

        // All runs must succeed.
        for (idx, (passed, _)) in results.iter().enumerate() {
            assert!(passed, "concurrent run {idx} should pass");
        }

        // All log paths must be unique.
        let paths: Vec<String> = results
            .iter()
            .map(|(_, p)| p.display().to_string())
            .collect();
        let unique_paths: std::collections::HashSet<&String> = paths.iter().collect();
        assert_eq!(
            unique_paths.len(),
            num_concurrent,
            "each concurrent run must produce a unique log path"
        );

        // No log file content should be empty or identical to another.
        let contents: Vec<String> = results
            .iter()
            .map(|(_, p)| fs::read_to_string(p).expect("log file should be readable"))
            .collect();
        for (idx, content) in contents.iter().enumerate() {
            assert!(!content.is_empty(), "log {idx} should not be empty");
        }
        let unique_contents: std::collections::HashSet<&String> = contents.iter().collect();
        assert_eq!(
            unique_contents.len(),
            num_concurrent,
            "log file contents must be unique across concurrent runs"
        );
    }

    /// BLOCKER 2: Prove that log caps prevent disk blowup without deadlocking
    /// child processes.
    ///
    /// Launches a child that emits well beyond the 4 MB cap on both stdout
    /// and stderr. Asserts:
    ///   - The child process completes (no deadlock).
    ///   - `bytes_written` is bounded (<= 4 MB + chunk overhead).
    ///   - `was_truncated` metadata is `true`.
    #[test]
    fn log_cap_prevents_blowup_without_deadlock() {
        let workspace_root = temp_test_dir("log_cap");
        let sha = "deadbeef_logcap_test";
        let gate_name = "logcap_gate";
        let log_path = workspace_root.join(format!("{gate_name}.log"));

        // Generate ~8 MB on stdout and ~8 MB on stderr (well beyond 4 MB cap).
        // Use a bash one-liner that writes to both streams.
        let emit_bytes = 8 * 1024 * 1024; // 8 MB per stream
        let script = format!(
            "dd if=/dev/zero bs=4096 count={stdout_blocks} 2>/dev/null; \
             dd if=/dev/zero bs=4096 count={stderr_blocks} >&2 2>/dev/null",
            stdout_blocks = emit_bytes / 4096,
            stderr_blocks = emit_bytes / 4096,
        );

        let (passed, stream_stats) = run_single_evidence_gate(
            &workspace_root,
            sha,
            gate_name,
            "bash",
            &["-c", &script],
            &log_path,
            true,
        );

        // The command itself succeeds (dd returns 0).
        assert!(passed, "log cap gate should pass (child exited 0)");

        // bytes_written must be bounded by LOG_STREAM_MAX_BYTES + chunk overhead.
        // We allow one extra chunk per stream thread (2 * chunk size) as
        // overhead since the atomic counter is checked after the fetch_add.
        let max_expected = LOG_STREAM_MAX_BYTES + 2 * LOG_STREAM_CHUNK_BYTES as u64;
        assert!(
            stream_stats.bytes_written <= max_expected,
            "bytes_written ({}) should be bounded by {} (4 MB + 2 chunks)",
            stream_stats.bytes_written,
            max_expected,
        );

        // Total bytes emitted should exceed the cap (proving truncation occurred).
        assert!(
            stream_stats.bytes_total > LOG_STREAM_MAX_BYTES,
            "bytes_total ({}) should exceed 4 MB cap to prove truncation",
            stream_stats.bytes_total,
        );

        // was_truncated must be true.
        assert!(
            stream_stats.was_truncated,
            "was_truncated should be true when output exceeds cap"
        );

        // The log file on disk should also be bounded.
        let log_size = fs::metadata(&log_path)
            .expect("log file should exist")
            .len();
        assert!(
            log_size <= max_expected,
            "on-disk log size ({log_size}) should be bounded by {max_expected}"
        );
    }

    // =========================================================================
    // TCK-00541 BLOCKER regression: v3-only cache hits must succeed without v2
    // =========================================================================

    /// Prove that when v3 has a valid signed entry but v2 is absent,
    /// `reuse_decision_with_v3_fallback` returns a hit with `CacheSource::V3`,
    /// and `resolve_cached_payload` successfully extracts the cached payload
    /// from v3 alone (no v2 fallback needed).
    #[test]
    fn v3_only_cache_hit_succeeds_without_v2() {
        use apm2_core::crypto::Signer;
        use apm2_core::fac::gate_cache_v3::{GateCacheV3, V3CompoundKey, V3GateResult};

        let signer = Signer::generate();
        let vk = signer.verifying_key();

        // Build a v3 cache with a signed gate result.
        let compound_key = V3CompoundKey::new(
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "b3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "b3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "b3-256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "b3-256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        )
        .expect("valid compound key");

        let mut v3_cache = GateCacheV3::new("test-sha-123", compound_key).expect("new v3 cache");
        let v3_result = V3GateResult {
            status: "PASS".to_string(),
            duration_secs: 42,
            completed_at: "2026-02-17T00:00:00Z".to_string(),
            attestation_digest: Some(
                "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            evidence_log_digest: Some("log-digest-v3-only".to_string()),
            quick_mode: Some(false),
            log_bundle_hash: None,
            log_path: Some("/tmp/v3-only-test.log".to_string()),
            signature_hex: None,
            signer_id: None,
            rfc0028_receipt_bound: true,
            rfc0029_receipt_bound: true,
        };
        v3_cache.set("rustfmt", v3_result).expect("set");
        v3_cache.sign_all(&signer);

        let gate_name = "rustfmt";
        let attestation_digest =
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // Step 1: v3 exists, v2 is None — reuse decision must be a v3 hit.
        let (reuse, _cache_decision_local) = reuse_decision_with_v3_fallback(
            Some(&v3_cache),
            None, // v2 is absent
            gate_name,
            Some(attestation_digest),
            Some(&vk),
            None,
            None,
            None,
        );
        assert!(reuse.reusable, "v3-only cache hit must be reusable");
        assert_eq!(
            reuse.source,
            CacheSource::V3,
            "hit source must be V3 when v2 is absent"
        );
        assert_eq!(reuse.reason, "v3_compound_key_match");

        // Step 2: resolve_cached_payload must succeed from v3 alone.
        let payload = resolve_cached_payload(
            &reuse,
            Some(&v3_cache),
            None, // v2 is absent
            gate_name,
        );
        let payload = payload.expect("v3-only payload must resolve");
        assert_eq!(payload.duration_secs, 42);
        assert_eq!(
            payload.evidence_log_digest.as_deref(),
            Some("log-digest-v3-only")
        );
        assert_eq!(payload.log_path.as_deref(), Some("/tmp/v3-only-test.log"));
    }

    /// Prove that when both v3 and v2 exist, v3 is preferred.
    #[test]
    fn v3_preferred_over_v2_when_both_present() {
        use apm2_core::crypto::Signer;
        use apm2_core::fac::gate_cache_v3::{GateCacheV3, V3CompoundKey, V3GateResult};

        let signer = Signer::generate();
        let vk = signer.verifying_key();

        let compound_key = V3CompoundKey::new(
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "b3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "b3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "b3-256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "b3-256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        )
        .expect("valid compound key");

        // Build v3 with duration 42.
        let mut v3_cache = GateCacheV3::new("test-sha-456", compound_key).expect("new v3 cache");
        let v3_result = V3GateResult {
            status: "PASS".to_string(),
            duration_secs: 42,
            completed_at: "2026-02-17T00:00:00Z".to_string(),
            attestation_digest: Some(
                "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            evidence_log_digest: Some("v3-digest".to_string()),
            quick_mode: Some(false),
            log_bundle_hash: None,
            log_path: Some("/tmp/v3-path.log".to_string()),
            signature_hex: None,
            signer_id: None,
            rfc0028_receipt_bound: true,
            rfc0029_receipt_bound: true,
        };
        v3_cache.set("clippy", v3_result).expect("set");
        v3_cache.sign_all(&signer);

        // Build v2 with duration 99 (different to detect which source is used).
        let mut v2_cache = GateCache {
            sha: "test-sha-456".to_string(),
            gates: std::collections::BTreeMap::new(),
        };
        v2_cache.gates.insert(
            "clippy".to_string(),
            super::super::gate_cache::CachedGateResult {
                status: "PASS".to_string(),
                duration_secs: 99,
                completed_at: "2026-02-17T00:00:00Z".to_string(),
                attestation_digest: Some(
                    "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ),
                evidence_log_digest: Some("v2-digest".to_string()),
                quick_mode: Some(false),
                log_bundle_hash: None,
                bytes_written: None,
                bytes_total: None,
                was_truncated: None,
                log_path: Some("/tmp/v2-path.log".to_string()),
                signature_hex: None,
                signer_id: None,
                rfc0028_receipt_bound: false,
                rfc0029_receipt_bound: false,
            },
        );

        let gate_name = "clippy";
        let attestation_digest =
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // Reuse decision should prefer v3.
        let (reuse, _cache_decision_local) = reuse_decision_with_v3_fallback(
            Some(&v3_cache),
            Some(&v2_cache),
            gate_name,
            Some(attestation_digest),
            Some(&vk),
            None,
            None,
            None,
        );
        assert!(reuse.reusable);
        assert_eq!(reuse.source, CacheSource::V3);

        // Payload must come from v3 (duration 42), not v2 (duration 99).
        let payload = resolve_cached_payload(&reuse, Some(&v3_cache), Some(&v2_cache), gate_name);
        let payload = payload.expect("payload must resolve");
        assert_eq!(
            payload.duration_secs, 42,
            "payload must come from v3 (42), not v2 (99)"
        );
        assert_eq!(payload.evidence_log_digest.as_deref(), Some("v3-digest"));
        assert_eq!(payload.log_path.as_deref(), Some("/tmp/v3-path.log"));
    }

    /// [INV-GCV3-001] Prove that when v3 misses and v2 has a signed entry,
    /// v2 fallback is denied for reuse (security: no binding continuity proof).
    ///
    /// TCK-00541 MAJOR fix: v2 entries lack RFC-0028/0029 binding proof and
    /// cannot satisfy v3 compound-key continuity requirements. The gate
    /// must be re-executed under v3 with full bindings.
    #[test]
    fn v2_fallback_denied_when_v3_misses() {
        use apm2_core::crypto::Signer;
        use apm2_core::fac::gate_cache_v3::{GateCacheV3, V3CompoundKey};

        let signer = Signer::generate();
        let vk = signer.verifying_key();

        let compound_key = V3CompoundKey::new(
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "b3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "b3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "b3-256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "b3-256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        )
        .expect("valid compound key");

        // v3 is empty (no gates).
        let v3_cache = GateCacheV3::new("test-sha-789", compound_key).expect("new v3 cache");

        // v2 has a signed entry.
        let mut v2_cache = GateCache {
            sha: "test-sha-789".to_string(),
            gates: std::collections::BTreeMap::new(),
        };
        let mut v2_result = super::super::gate_cache::CachedGateResult {
            status: "PASS".to_string(),
            duration_secs: 77,
            completed_at: "2026-02-17T00:00:00Z".to_string(),
            attestation_digest: Some(
                "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            evidence_log_digest: Some("v2-fallback-digest".to_string()),
            quick_mode: Some(false),
            log_bundle_hash: None,
            bytes_written: None,
            bytes_total: None,
            was_truncated: None,
            log_path: Some("/tmp/v2-fallback.log".to_string()),
            signature_hex: None,
            signer_id: None,
            rfc0028_receipt_bound: false,
            rfc0029_receipt_bound: false,
        };
        v2_result.sign(&signer, "test-sha-789", "doc");
        v2_cache.gates.insert("doc".to_string(), v2_result);

        let gate_name = "doc";
        let attestation_digest =
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // [INV-GCV3-001] v3 cache exists but has no "doc" entry. V2 fallback
        // MUST be denied — v2 entries lack binding continuity proof.
        let (reuse, _cache_decision_local) = reuse_decision_with_v3_fallback(
            Some(&v3_cache),
            Some(&v2_cache),
            gate_name,
            Some(attestation_digest),
            Some(&vk),
            None,
            None,
            None,
        );
        assert!(
            !reuse.reusable,
            "v2 fallback must be denied: v2 entries lack RFC-0028/0029 binding proof"
        );
        assert_eq!(
            reuse.reason, "v3_miss_v2_fallback_disabled",
            "reason must indicate v2 fallback was disabled"
        );
    }

    /// Regression integration test: non-status evidence execution
    /// (`run_evidence_gates_with_lane_context`) must reuse persisted v3
    /// entries instead of re-executing all gates.
    #[test]
    #[allow(unsafe_code)]
    fn non_status_evidence_path_reuses_v3_cache_entries() {
        use std::collections::BTreeMap;
        use std::ffi::OsString;

        use apm2_core::fac::LaneManager;
        use apm2_core::fac::gate_cache_v3::{GateCacheV3, V3GateResult};

        struct EnvGuard {
            original_apm2_home: Option<OsString>,
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                if let Some(value) = self.original_apm2_home.take() {
                    // SAFETY: environment mutation is serialized by env_var_test_lock.
                    unsafe { std::env::set_var("APM2_HOME", value) };
                } else {
                    // SAFETY: environment mutation is serialized by env_var_test_lock.
                    unsafe { std::env::remove_var("APM2_HOME") };
                }
            }
        }

        let _env_lock = crate::commands::env_var_test_lock()
            .lock()
            .expect("serialize APM2_HOME test env");

        let temp = tempfile::tempdir().expect("tempdir");
        let apm2_home = temp.path().join("apm2-home");
        let workspace_root = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace_root).expect("create workspace");

        let original_apm2_home = std::env::var_os("APM2_HOME");
        // SAFETY: environment mutation is serialized by env_var_test_lock.
        unsafe { std::env::set_var("APM2_HOME", &apm2_home) };
        let _env_guard = EnvGuard { original_apm2_home };

        let lane_manager = LaneManager::from_default_home().expect("lane manager");
        lane_manager
            .ensure_directories()
            .expect("ensure lane directories");
        let lane_lock = lane_manager
            .try_lock("lane-00")
            .expect("probe lane lock")
            .expect("acquire lane lock");
        let lane_context = allocate_evidence_lane_context(&lane_manager, "lane-00", lane_lock)
            .expect("allocate lane context");

        let fac_root = apm2_home.join("private/fac");
        let v3_root = fac_root.join("gate_cache_v3");
        let fac_policy = load_or_create_pipeline_policy(&fac_root).expect("load policy");
        std::fs::create_dir_all(&v3_root).expect("create v3 cache root");

        let sha = "test-sha-v3-non-status-reuse";
        let sandbox_hardening_hash =
            "b3-256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let network_policy_hash =
            "b3-256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let resource_policy = GateResourcePolicy::from_cli(
            false,
            60,
            "256M",
            256,
            "200%",
            true,
            Some("balanced"),
            Some(2),
            Some(sandbox_hardening_hash),
            Some(network_policy_hash),
        );

        let compound_key = compute_v3_compound_key(
            sha,
            &fac_policy,
            sandbox_hardening_hash,
            network_policy_hash,
        )
        .expect("compute v3 compound key");
        let mut cache = GateCacheV3::new(sha, compound_key).expect("new v3 cache");
        let signer =
            crate::commands::fac_key_material::load_or_generate_persistent_signer(&fac_root)
                .expect("persistent signer");
        let test_command = vec!["true".to_string()];
        let expected_durations = [
            ("rustfmt", 11_u64),
            ("clippy", 12_u64),
            ("doc", 13_u64),
            ("test_safety_guard", 14_u64),
            ("fac_review_machine_spec_snapshot", 15_u64),
            ("test", 16_u64),
            ("workspace_integrity", 17_u64),
            ("review_artifact_lint", 18_u64),
        ];
        for (gate_name, duration_secs) in expected_durations {
            let attestation_digest = if gate_name == "test" {
                gate_attestation_digest(
                    &workspace_root,
                    sha,
                    gate_name,
                    Some(test_command.as_slice()),
                    &resource_policy,
                )
            } else {
                gate_attestation_digest(&workspace_root, sha, gate_name, None, &resource_policy)
            }
            .expect("attestation digest");
            cache
                .set(
                    gate_name,
                    V3GateResult {
                        status: "PASS".to_string(),
                        duration_secs,
                        completed_at: "2026-02-18T00:00:00Z".to_string(),
                        attestation_digest: Some(attestation_digest),
                        evidence_log_digest: Some(format!("digest-{gate_name}")),
                        quick_mode: Some(false),
                        log_bundle_hash: None,
                        log_path: Some(format!("/tmp/{gate_name}.log")),
                        signature_hex: None,
                        signer_id: None,
                        rfc0028_receipt_bound: true,
                        rfc0029_receipt_bound: true,
                    },
                )
                .expect("set v3 cache entry");
        }
        cache.sign_all(&signer);
        cache.save_to_dir(&v3_root).expect("save v3 cache");

        let opts = EvidenceGateOptions {
            test_command: Some(test_command),
            test_command_environment: Vec::new(),
            env_remove_keys: Vec::new(),
            bounded_gate_unit_base: None,
            skip_test_gate: false,
            skip_merge_conflict_gate: true,
            emit_human_logs: false,
            on_gate_progress: None,
            gate_resource_policy: Some(resource_policy),
        };
        let (passed, gate_results) = run_evidence_gates_with_lane_context(
            &workspace_root,
            sha,
            None,
            Some(&opts),
            lane_context,
        )
        .expect("run evidence gates");

        assert!(
            passed,
            "all gates should pass when every phase is reused from v3 cache; gate_results={gate_results:?}"
        );
        assert_eq!(
            gate_results.len(),
            expected_durations.len(),
            "all non-merge gate phases must be present"
        );

        let observed_durations: BTreeMap<String, u64> = gate_results
            .iter()
            .map(|result| (result.gate_name.clone(), result.duration_secs))
            .collect();
        for (gate_name, expected_duration) in expected_durations {
            let observed = observed_durations
                .get(gate_name)
                .copied()
                .unwrap_or_default();
            assert_eq!(
                observed, expected_duration,
                "gate {gate_name} should use cached v3 duration"
            );
        }

        for result in &gate_results {
            assert!(result.passed, "reused gate should remain PASS");
            let log_path = result
                .log_path
                .as_ref()
                .expect("cached gate result should include log path");
            let log = std::fs::read_to_string(log_path).expect("read cached marker log");
            assert!(
                log.contains("result reused from cache"),
                "gate {} should emit cached marker",
                result.gate_name
            );
        }
    }

    /// Regression integration test: the evidence-layer v3 rebind wrapper must
    /// find the on-disk v3 cache via `APM2_HOME`, promote receipt bindings from
    /// a durable receipt, re-sign, and make the entry reusable.
    #[test]
    #[allow(unsafe_code)]
    fn rebind_v3_gate_cache_after_receipt_promotes_flags_via_wrapper() {
        use std::ffi::OsString;

        use apm2_core::crypto::Signer;
        use apm2_core::fac::gate_cache_v3::{GateCacheV3, V3CompoundKey, V3GateResult};
        use apm2_core::fac::{
            ChannelBoundaryTrace, FacJobOutcome, FacJobReceiptV1, FacPolicyV1, QueueAdmissionTrace,
            compute_job_receipt_content_hash_v2, compute_policy_hash,
        };

        struct EnvGuard {
            original_apm2_home: Option<OsString>,
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                if let Some(value) = self.original_apm2_home.take() {
                    // SAFETY: environment mutation is serialized by env_var_test_lock.
                    unsafe { std::env::set_var("APM2_HOME", value) };
                } else {
                    // SAFETY: environment mutation is serialized by env_var_test_lock.
                    unsafe { std::env::remove_var("APM2_HOME") };
                }
            }
        }

        let _env_lock = crate::commands::env_var_test_lock()
            .lock()
            .expect("serialize APM2_HOME test env");

        let temp = tempfile::tempdir().expect("tempdir");
        let apm2_home = temp.path().join("apm2-home");
        let fac_root = apm2_home.join("private/fac");
        let v3_root = fac_root.join("gate_cache_v3");
        let receipts_dir = fac_root.join("receipts");
        std::fs::create_dir_all(&v3_root).expect("create v3 root");
        std::fs::create_dir_all(&receipts_dir).expect("create receipts root");

        let original_apm2_home = std::env::var_os("APM2_HOME");
        // SAFETY: environment mutation is serialized by env_var_test_lock.
        unsafe { std::env::set_var("APM2_HOME", &apm2_home) };
        let _env_guard = EnvGuard { original_apm2_home };

        let signer = Signer::generate();
        let vk = signer.verifying_key();

        let sha = "test-sha-wrapper-rebind";
        let policy_hash = compute_policy_hash(&FacPolicyV1::default_policy()).expect("policy hash");
        let sbx_hash = "b3-256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let net_hash = "b3-256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let attestation_digest =
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let compound_key = V3CompoundKey::new(
            sha,
            &policy_hash,
            &compute_toolchain_fingerprint(),
            sbx_hash,
            net_hash,
        )
        .expect("valid compound key");

        let mut cache = GateCacheV3::new(sha, compound_key.clone()).expect("new v3 cache");
        cache
            .set(
                "rustfmt",
                V3GateResult {
                    status: "PASS".to_string(),
                    duration_secs: 11,
                    completed_at: "2026-02-18T00:00:00Z".to_string(),
                    attestation_digest: Some(attestation_digest.to_string()),
                    evidence_log_digest: Some("log-digest".to_string()),
                    quick_mode: Some(false),
                    log_bundle_hash: None,
                    log_path: Some("/tmp/rebind-wrapper.log".to_string()),
                    signature_hex: None,
                    signer_id: None,
                    rfc0028_receipt_bound: false,
                    rfc0029_receipt_bound: false,
                },
            )
            .expect("set gate");
        cache.sign_all(&signer);
        cache.save_to_dir(&v3_root).expect("persist unbound cache");

        let pre = GateCacheV3::load_from_dir(&v3_root, sha, &compound_key).expect("load pre");
        let pre_decision = pre.check_reuse("rustfmt", Some(attestation_digest), true, Some(&vk));
        assert!(!pre_decision.hit, "must deny before receipt rebind");
        assert_eq!(
            pre_decision.reason_code,
            apm2_core::fac::gate_cache_v3::CacheReasonCode::ReceiptBindingMissing
        );

        let job_id = "job-wrapper-rebind";
        let receipt = FacJobReceiptV1 {
            schema: "apm2.fac.receipt.v1".to_string(),
            receipt_id: "receipt-wrapper-rebind".to_string(),
            job_id: job_id.to_string(),
            job_spec_digest: "spec-digest-wrapper".to_string(),
            outcome: FacJobOutcome::Completed,
            reason: "test".to_string(),
            rfc0028_channel_boundary: Some(ChannelBoundaryTrace {
                passed: true,
                defect_count: 0,
                defect_classes: vec![],
                token_fac_policy_hash: None,
                token_canonicalizer_tuple_digest: None,
                token_boundary_id: None,
                token_issued_at_tick: None,
                token_expiry_tick: None,
            }),
            eio29_queue_admission: Some(QueueAdmissionTrace {
                verdict: "allow".to_string(),
                queue_lane: "consume".to_string(),
                defect_reason: None,
                cost_estimate_ticks: None,
            }),
            ..Default::default()
        };
        let receipt_digest = compute_job_receipt_content_hash_v2(&receipt);
        let receipt_path = receipts_dir.join(format!("{receipt_digest}.json"));
        std::fs::write(
            &receipt_path,
            serde_json::to_string(&receipt).expect("serialize receipt"),
        )
        .expect("write receipt");

        rebind_v3_gate_cache_after_receipt(
            sha,
            &policy_hash,
            sbx_hash,
            net_hash,
            &receipts_dir,
            job_id,
            &signer,
        );

        let rebound = GateCacheV3::load_from_dir(&v3_root, sha, &compound_key).expect("load post");
        let entry = rebound.get("rustfmt").expect("rustfmt entry");
        assert!(entry.rfc0028_receipt_bound, "rfc0028 flag must be promoted");
        assert!(entry.rfc0029_receipt_bound, "rfc0029 flag must be promoted");
        let post_decision =
            rebound.check_reuse("rustfmt", Some(attestation_digest), true, Some(&vk));
        assert!(
            post_decision.hit,
            "entry must be reusable after wrapper rebind"
        );
        assert_eq!(
            post_decision.reason_code,
            apm2_core::fac::gate_cache_v3::CacheReasonCode::CacheHit
        );
    }
}
