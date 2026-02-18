// AGENT-AUTHORED
//! Toolchain fingerprint derivation, caching, and verification (TCK-00538).
//!
//! Computes a stable `b3-256:` BLAKE3 fingerprint of the build toolchain
//! installed on this node: `rustc -Vv`, `cargo -V`, `cargo nextest --version`,
//! and `systemd-run --version`. The fingerprint changes when any underlying
//! tool changes (different binary, different version, different host triple).
//!
//! # Design
//!
//! The fingerprint is computed once at worker startup. Fresh probes are always
//! executed to collect current tool versions (4 fast process spawns). If a
//! valid cache exists under
//! `$APM2_HOME/private/fac/toolchain/fingerprint.v1.json`, the cached
//! `raw_versions` are compared against the fresh probe outputs. If they match,
//! the cached fingerprint is reused (skipping the hash derivation
//! step). If they differ — indicating a toolchain change between startups —
//! the fingerprint is recomputed and the cache is overwritten atomically with
//! restricted permissions (dir 0o700, file 0o600, O_NOFOLLOW).
//!
//! # Security Model
//!
//! - Domain-separated BLAKE3 hash prevents cross-domain preimage collisions.
//! - Length-prefixed encoding of each tool's output prevents concatenation
//!   ambiguity.
//! - Bounded I/O on tool output prevents OOM from malicious tool wrappers.
//! - Bounded process reaping prevents indefinite hangs on misbehaving tools.
//! - Required probes (rustc, cargo) propagate errors to enforce fail-closed
//!   startup semantics.
//!
//! # Invariants
//!
//! - [INV-TC-001] Fingerprint changes when any toolchain component changes.
//! - [INV-TC-002] Fingerprint is consistent across processes on the same node
//!   (deterministic hash over deterministic inputs).
//! - [INV-TC-003] Required probes (rustc, cargo) must succeed or the worker
//!   refuses to start (fail-closed).
//! - [INV-TC-004] Cache is validated by re-deriving the fingerprint from stored
//!   raw versions before use.
//! - [INV-TC-005] Tool version probes are bounded by `MAX_VERSION_OUTPUT_BYTES`
//!   and `VERSION_PROBE_TIMEOUT` to prevent OOM and hang.
//! - [INV-TC-006] Process reaping is bounded to prevent indefinite blocking.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Domain separator for the toolchain fingerprint hash.
const HASH_DOMAIN: &str = "apm2.fac.toolchain_fingerprint.v1";

/// Maximum size of a tool's version output (bytes). Prevents OOM from
/// malicious tool wrappers (INV-TC-005).
const MAX_VERSION_OUTPUT_BYTES: u64 = 8192;

/// Timeout for each version probe command (INV-TC-005).
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time to wait for a child process to exit after killing it
/// (INV-TC-006). Prevents indefinite blocking on misbehaving tools.
const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time to wait for the reader thread to join after the child
/// process has been killed and reaped. Prevents indefinite blocking if
/// a descendant process holds stdout open (INV-TC-006).
const THREAD_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum length of the fingerprint string (`b3-256:` + 64 hex = 71).
pub const FINGERPRINT_STRING_LENGTH: usize = 71;

/// Maximum size of the cache file (bytes). Prevents memory-DoS from a
/// tampered or corrupted cache file.
pub const MAX_CACHE_FILE_BYTES: usize = 65536;

/// Cache file name within the toolchain cache directory.
pub const CACHE_FILE_NAME: &str = "fingerprint.v1.json";

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from toolchain fingerprint operations.
#[derive(Debug, Error)]
pub enum ToolchainFingerprintError {
    /// I/O failure during version probe.
    #[error("toolchain fingerprint I/O failure while {context}: {source}")]
    Io {
        /// Operation context.
        context: &'static str,
        /// Source error.
        source: std::io::Error,
    },

    /// A required toolchain probe failed (rustc or cargo).
    #[error("required toolchain probe '{tool}' failed: {reason}")]
    RequiredProbeFailed {
        /// Tool name.
        tool: &'static str,
        /// Failure reason.
        reason: String,
    },

    /// Process could not be reaped within the bounded timeout (INV-TC-006).
    #[error("toolchain probe '{tool}' could not be reaped within {timeout_secs}s")]
    ReapTimeout {
        /// Tool name.
        tool: &'static str,
        /// Timeout in seconds.
        timeout_secs: u64,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Raw tool version outputs collected from the local toolchain.
///
/// Each field holds the stdout output of the corresponding version command,
/// or `None` if the tool is not available. Fields are hashed in declaration
/// order for deterministic fingerprint derivation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolchainVersions {
    /// `rustc -Vv` output.
    pub rustc: Option<String>,
    /// `cargo -V` output.
    pub cargo: Option<String>,
    /// `cargo nextest --version` output.
    pub nextest: Option<String>,
    /// `systemd-run --version` output.
    pub systemd_run: Option<String>,
}

/// Cached toolchain fingerprint stored on disk.
///
/// Contains both the derived fingerprint and the raw version strings used to
/// compute it. On load, the fingerprint is re-derived from `raw_versions` and
/// compared against `fingerprint` to detect tampering or corruption
/// (INV-TC-004).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedFingerprint {
    /// The `b3-256:<hex>` fingerprint string.
    pub fingerprint: String,
    /// The raw version outputs used to derive the fingerprint.
    pub raw_versions: ToolchainVersions,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve the toolchain fingerprint by collecting version probes and
/// deriving the hash.
///
/// Spawns subprocesses to probe tool versions, then computes a
/// domain-separated BLAKE3 hash. Called once at worker startup.
///
/// Required probes (rustc, cargo) MUST succeed or the function returns an
/// error, preserving fail-closed startup semantics (INV-TC-003).
/// Optional probes (nextest, systemd-run) produce `None` if not available.
///
/// Returns a `b3-256:<hex>` string that changes when any toolchain component
/// changes.
///
/// # Errors
///
/// Returns `ToolchainFingerprintError::RequiredProbeFailed` if rustc or cargo
/// probes fail. Returns `ToolchainFingerprintError::ReapTimeout` if a process
/// cannot be reaped within the bounded timeout.
pub fn resolve_fingerprint(
    hardened_env: &BTreeMap<String, String>,
) -> Result<String, ToolchainFingerprintError> {
    let versions = collect_toolchain_versions(hardened_env)?;
    let fingerprint = derive_fingerprint(&versions);
    Ok(fingerprint)
}

/// Compute the toolchain fingerprint without caching (pure derivation).
///
/// Useful for testing and environments where version probes have already
/// been collected.
#[must_use]
pub fn derive_from_versions(versions: &ToolchainVersions) -> String {
    derive_fingerprint(versions)
}

/// Collect tool version outputs from the local system.
///
/// Uses the provided hardened environment for process spawning
/// (INV-WARM-009 defense-in-depth).
///
/// Required probes (rustc, cargo) must succeed with exit code 0 and
/// produce non-empty output. Optional probes (nextest, systemd-run)
/// produce `None` on failure or non-zero exit.
///
/// # Errors
///
/// Returns an error if a required probe (rustc, cargo) fails.
pub fn collect_toolchain_versions(
    hardened_env: &BTreeMap<String, String>,
) -> Result<ToolchainVersions, ToolchainFingerprintError> {
    let rustc = required_probe("rustc", &["-Vv"], hardened_env)?;
    let cargo = required_probe("cargo", &["-V"], hardened_env)?;

    // Optional probes: nextest and systemd-run. Errors and non-zero exits
    // are swallowed to produce None (these tools are not required for
    // fingerprint validity).
    let nextest = optional_probe("cargo", &["nextest", "--version"], hardened_env);
    let systemd_run = optional_probe("systemd-run", &["--version"], hardened_env);

    Ok(ToolchainVersions {
        rustc: Some(rustc),
        cargo: Some(cargo),
        nextest,
        systemd_run,
    })
}

/// Execute a required probe and enforce exit status + non-empty output.
///
/// Returns the trimmed stdout string on success (exit code 0, non-empty
/// output). Returns an error if the tool is not found, exits non-zero,
/// times out, or produces empty output.
fn required_probe(
    program: &str,
    args: &[&str],
    hardened_env: &BTreeMap<String, String>,
) -> Result<String, ToolchainFingerprintError> {
    let tool_static: &'static str = match program {
        "rustc" => "rustc",
        "cargo" => "cargo",
        _ => "unknown",
    };

    let result = version_output(program, args, hardened_env).map_err(|e| {
        ToolchainFingerprintError::RequiredProbeFailed {
            tool: tool_static,
            reason: e.to_string(),
        }
    })?;

    match result {
        Some((output, Some(status))) if status.success() => {
            if output.is_empty() {
                Err(ToolchainFingerprintError::RequiredProbeFailed {
                    tool: tool_static,
                    reason: "probe returned empty output".to_string(),
                })
            } else {
                Ok(output)
            }
        },
        Some((_, Some(status))) => Err(ToolchainFingerprintError::RequiredProbeFailed {
            tool: tool_static,
            reason: format!("probe exited with non-zero status: {status}"),
        }),
        Some((_, None)) => Err(ToolchainFingerprintError::RequiredProbeFailed {
            tool: tool_static,
            reason: "probe timed out".to_string(),
        }),
        None => Err(ToolchainFingerprintError::RequiredProbeFailed {
            tool: tool_static,
            reason: "tool not found".to_string(),
        }),
    }
}

/// Execute an optional probe. Non-zero exit, timeout, missing tool, and
/// errors all produce `None`.
fn optional_probe(
    program: &str,
    args: &[&str],
    hardened_env: &BTreeMap<String, String>,
) -> Option<String> {
    let result = version_output(program, args, hardened_env).ok()??;
    let (output, status) = result;
    // Only accept output from a successful exit.
    if status.is_some_and(|s| s.success()) && !output.is_empty() {
        Some(output)
    } else {
        None
    }
}

/// Validate a toolchain fingerprint string format.
///
/// Returns `true` if the string matches `b3-256:<64 hex chars>`.
#[must_use]
pub fn is_valid_fingerprint(fingerprint: &str) -> bool {
    if !fingerprint.starts_with("b3-256:") {
        return false;
    }
    let hex_part = &fingerprint["b3-256:".len()..];
    hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

/// Extract the short hex prefix from a fingerprint string.
///
/// Returns the first 16 hex characters of the fingerprint hash, suitable for
/// use as a directory name suffix. Returns `None` if the fingerprint is
/// invalid.
#[must_use]
pub fn fingerprint_short_hex(fingerprint: &str) -> Option<&str> {
    if !fingerprint.starts_with("b3-256:") {
        return None;
    }
    let hex_part = &fingerprint["b3-256:".len()..];
    if hex_part.len() >= 16 && hex_part[..16].chars().all(|c| c.is_ascii_hexdigit()) {
        Some(&hex_part[..16])
    } else {
        None
    }
}

/// Try to load and validate a cached fingerprint from disk.
///
/// Returns `Ok(Some(fingerprint))` if a valid cache exists, `Ok(None)` if
/// the cache is missing, corrupt, or fails integrity validation.
///
/// # Integrity Validation (INV-TC-004)
///
/// The cached fingerprint is re-derived from `cached.raw_versions` using
/// `derive_fingerprint`. If the result does not match `cached.fingerprint`,
/// the cache is considered invalid and `None` is returned.
///
/// # Arguments
///
/// * `cache_bytes` - Raw bytes read from the cache file (bounded by caller).
#[must_use]
pub fn validate_cached_fingerprint(cache_bytes: &[u8]) -> Option<String> {
    let cached: CachedFingerprint = serde_json::from_slice(cache_bytes).ok()?;

    // Validate format.
    if !is_valid_fingerprint(&cached.fingerprint) {
        return None;
    }

    // Re-derive from stored raw versions and compare (INV-TC-004).
    let rederived = derive_fingerprint(&cached.raw_versions);
    if rederived != cached.fingerprint {
        return None;
    }

    Some(cached.fingerprint)
}

/// Serialize a fingerprint and its raw versions for cache persistence.
///
/// Returns the JSON bytes to be written atomically to the cache file.
///
/// # Errors
///
/// Returns `ToolchainFingerprintError::Io` if JSON serialization fails.
pub fn serialize_cache(
    fingerprint: &str,
    versions: &ToolchainVersions,
) -> Result<Vec<u8>, ToolchainFingerprintError> {
    let cached = CachedFingerprint {
        fingerprint: fingerprint.to_string(),
        raw_versions: versions.clone(),
    };
    serde_json::to_vec_pretty(&cached).map_err(|e| ToolchainFingerprintError::Io {
        context: "serializing cache",
        source: std::io::Error::other(e.to_string()),
    })
}

/// Resolve the toolchain fingerprint with cache support.
///
/// Always probes fresh toolchain versions from the host to detect
/// toolchain changes between startups (INV-TC-001). The cache is used
/// as an optimization to skip the BLAKE3 hash derivation step when
/// the fresh probe outputs match the cached `raw_versions`.
///
/// 1. Collect fresh probe outputs (always — never skip probes).
/// 2. If `cache_bytes` is `Some`, validate the cache and compare its
///    `raw_versions` against fresh outputs. If they match, reuse the cached
///    fingerprint.
/// 3. If cache is missing, invalid, or stale (versions differ), recompute the
///    fingerprint from fresh outputs.
/// 4. Returns the fingerprint string AND the raw versions (for cache
///    persistence by the caller).
///
/// The caller is responsible for reading/writing the cache file with
/// appropriate permissions and bounded reads.
///
/// # Errors
///
/// Returns an error if required probes (rustc, cargo) fail.
pub fn resolve_fingerprint_cached(
    hardened_env: &BTreeMap<String, String>,
    cache_bytes: Option<&[u8]>,
) -> Result<(String, ToolchainVersions), ToolchainFingerprintError> {
    // Step 1: Always probe fresh toolchain versions to detect changes.
    let fresh_versions = collect_toolchain_versions(hardened_env)?;

    // Step 2: If cache exists and its raw_versions match fresh probes,
    // reuse the cached fingerprint (skip hash derivation).
    if let Some(bytes) = cache_bytes {
        if let Some(cached) = validate_cached_fingerprint_full(bytes) {
            if cached.raw_versions == fresh_versions {
                return Ok((cached.fingerprint, fresh_versions));
            }
            // Cache is stale — versions differ, recompute below.
        }
    }

    // Step 3: Cache miss, invalid, or stale — compute fresh fingerprint.
    let fingerprint = derive_fingerprint(&fresh_versions);
    Ok((fingerprint, fresh_versions))
}

/// Validate a cached fingerprint and return the full struct if valid.
///
/// Checks structural integrity (valid format) and hash integrity
/// (re-derives fingerprint from `raw_versions` and compares).
fn validate_cached_fingerprint_full(cache_bytes: &[u8]) -> Option<CachedFingerprint> {
    let cached: CachedFingerprint = serde_json::from_slice(cache_bytes).ok()?;

    if !is_valid_fingerprint(&cached.fingerprint) {
        return None;
    }

    let rederived = derive_fingerprint(&cached.raw_versions);
    if rederived != cached.fingerprint {
        return None;
    }

    Some(cached)
}

/// Return the cache subdirectory path relative to `fac_root`.
///
/// The full path is `<fac_root>/toolchain/`.
#[must_use]
pub fn cache_dir(fac_root: &Path) -> std::path::PathBuf {
    fac_root.join("toolchain")
}

/// Return the cache file path relative to `fac_root`.
///
/// The full path is `<fac_root>/toolchain/fingerprint.v1.json`.
#[must_use]
pub fn cache_file_path(fac_root: &Path) -> std::path::PathBuf {
    cache_dir(fac_root).join(CACHE_FILE_NAME)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: fingerprint derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a `b3-256:<hex>` fingerprint from tool versions.
///
/// Uses domain-separated BLAKE3 with length-prefixed encoding of each tool's
/// output to prevent concatenation ambiguity (`GATE_HASH_PREIMAGE_FRAMING`).
fn derive_fingerprint(versions: &ToolchainVersions) -> String {
    let mut hasher = blake3::Hasher::new();

    // Domain separation.
    hasher.update(HASH_DOMAIN.as_bytes());
    hasher.update(b"\0");

    // Each tool's output is length-prefixed with a presence marker.
    push_optional_versioned(&mut hasher, versions.rustc.as_deref());
    push_optional_versioned(&mut hasher, versions.cargo.as_deref());
    push_optional_versioned(&mut hasher, versions.nextest.as_deref());
    push_optional_versioned(&mut hasher, versions.systemd_run.as_deref());

    let digest = hasher.finalize();
    format!("b3-256:{}", digest.to_hex())
}

/// Push an optional string into the hasher with presence marker and length
/// prefix.
fn push_optional_versioned(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(s) => {
            hasher.update(&[1u8]); // present
            hasher.update(&(s.len() as u64).to_le_bytes());
            hasher.update(s.as_bytes());
        },
        None => {
            hasher.update(&[0u8]); // absent
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: version probe
// ─────────────────────────────────────────────────────────────────────────────

/// Collect version output from a tool command with bounded stdout reads and
/// bounded execution time.
///
/// Returns `Ok(None)` if the tool is not found (command-not-found).
/// Returns `Ok(Some((output, Some(exit_status))))` on normal completion.
/// Returns `Ok(Some((output, None)))` on timeout (exit status unknown).
///
/// [INV-TC-005] Uses `Read::take(MAX_VERSION_OUTPUT_BYTES)` to prevent OOM
/// from a malicious or verbose tool wrapper producing unbounded stdout.
///
/// [INV-TC-006] Uses bounded process reaping: after the read thread
/// completes, `try_wait()` is used first, and if the process is still
/// running, `kill()` + bounded `try_wait()` loop ensures the function
/// never blocks indefinitely.
///
/// # Deadlock-free design
///
/// Same pattern as `warm.rs::version_output()` -- the calling thread retains
/// direct ownership of the `Child` process handle (no mutex). The helper thread
/// receives only the `ChildStdout` pipe and performs the bounded `read_to_end`.
///
/// Synchronization protocol (mutex-free):
/// - The calling thread owns `Child` directly. It can call `kill()` and
///   `wait()` at any time without acquiring a lock.
/// - The helper thread owns `ChildStdout` (taken from `Child` before spawn).
///   When the calling thread kills the child, the pipe closes, which unblocks
///   `read_to_end`.
/// - On timeout, the calling thread kills the child directly, drops the child
///   handle (closing its end of the pipe), then joins the helper thread with a
///   bounded timeout to prevent indefinite blocking from descendant processes
///   holding stdout open.
///
/// Happens-before edges:
///   H1: helper `read_to_end` completes -> helper thread returns (program
///       order)
///   H2: calling thread `child.kill()` -> pipe close -> helper `read_to_end`
///       unblocks (OS pipe semantics)
///   H3: calling thread drops `Child` -> OS closes child's pipe fd ->
///       supplemental EOF guarantee for reader thread
///   H4: helper thread terminates -> `handle.join()` returns (thread join
///       synchronizes-with)
///
/// # Errors
///
/// Returns `ToolchainFingerprintError::Io` on spawn failure.
/// Returns `ToolchainFingerprintError::ReapTimeout` if the process cannot
/// be reaped within the bounded timeout after read completion.
fn version_output(
    program: &str,
    args: &[&str],
    hardened_env: &BTreeMap<String, String>,
) -> Result<Option<(String, Option<ExitStatus>)>, ToolchainFingerprintError> {
    let mut child = match Command::new(program)
        .args(args)
        .env_clear()
        .envs(hardened_env)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Tool not found — not an error, just absent.
            return Ok(None);
        },
        Err(e) => {
            return Err(ToolchainFingerprintError::Io {
                context: "spawning version probe",
                source: e,
            });
        },
    };

    // Take stdout pipe before spawning the helper thread.
    let Some(stdout) = child.stdout.take() else {
        let _ = bounded_reap(&mut child, program);
        return Ok(Some((String::new(), None)));
    };

    // Spawn helper thread for bounded read.
    let handle = std::thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout
            .take(MAX_VERSION_OUTPUT_BYTES)
            .read_to_end(&mut output);
        result.ok().map(|_| output)
    });

    // Poll with timeout.
    let deadline = Instant::now() + VERSION_PROBE_TIMEOUT;
    loop {
        if handle.is_finished() {
            break;
        }
        if Instant::now() >= deadline {
            // Timeout: kill child, reap, then drop to close pipe fds.
            let _ = child.kill();
            let _ = bounded_reap(&mut child, program);
            // Drop the child handle to close our end of any inherited
            // pipe file descriptors. This ensures the reader thread
            // gets EOF even if a descendant process holds stdout open,
            // preventing indefinite blocking on handle.join().
            drop(child);

            // Join the reader thread with a bounded timeout.
            let join_deadline = Instant::now() + THREAD_JOIN_TIMEOUT;
            loop {
                if handle.is_finished() {
                    let _ = handle.join();
                    break;
                }
                if Instant::now() >= join_deadline {
                    // Reader thread is stuck — abandon it. The thread
                    // will eventually terminate when the pipe closes.
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            return Ok(Some((String::new(), None)));
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Normal read completion: bounded reap of the child process (INV-TC-006).
    // Capture exit status to let callers enforce exit code checks.
    let exit_status = bounded_reap(&mut child, program)?;

    let Ok(Some(output_bytes)) = handle.join() else {
        return Ok(Some((String::new(), exit_status)));
    };
    let raw = String::from_utf8_lossy(&output_bytes);
    let trimmed = raw.trim().to_string();
    Ok(Some((trimmed, exit_status)))
}

/// Bounded process reaping (INV-TC-006).
///
/// After the read thread completes, the child process may still be running
/// (e.g., it produced bounded output but continues executing). This function
/// ensures the process is reaped within a bounded timeout:
///
/// 1. `try_wait()` — if already exited, return its `ExitStatus`.
/// 2. If still running, `kill()` then poll `try_wait()` with bounded timeout.
/// 3. If process cannot be reaped within the bound, return error.
///
/// Returns `Ok(Some(ExitStatus))` if the process exited normally or after
/// being killed. Returns `Ok(None)` if the process handle was invalid.
fn bounded_reap(
    child: &mut std::process::Child,
    tool_name: &str,
) -> Result<Option<ExitStatus>, ToolchainFingerprintError> {
    // Fast path: already exited.
    match child.try_wait() {
        Ok(None) => {},
        Ok(Some(status)) => return Ok(Some(status)),
        // Process handle invalid — nothing more to reap.
        Err(_) => return Ok(None),
    }

    // Still running: kill and wait with bounded timeout.
    let _ = child.kill();

    let reap_deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(None) => {},
            Ok(Some(status)) => return Ok(Some(status)),
            Err(_) => return Ok(None),
        }
        if Instant::now() >= reap_deadline {
            // Determine the &'static str for the tool name.
            // Since we cannot coerce a &str to &'static str at runtime,
            // leak a small allocation. This path is only hit in extreme
            // edge cases (process cannot be killed).
            let tool_static: &'static str = match tool_name {
                "rustc" => "rustc",
                "cargo" => "cargo",
                "systemd-run" => "systemd-run",
                _ => "unknown",
            };
            return Err(ToolchainFingerprintError::ReapTimeout {
                tool: tool_static,
                timeout_secs: PROCESS_REAP_TIMEOUT.as_secs(),
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hardened_env() -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        if let Ok(path) = std::env::var("PATH") {
            env.insert("PATH".to_string(), path);
        }
        if let Ok(home) = std::env::var("HOME") {
            env.insert("HOME".to_string(), home);
        }
        env
    }

    #[test]
    fn test_derive_fingerprint_deterministic() {
        let versions = ToolchainVersions {
            rustc: Some("rustc 1.85.0 (4d91de4e4 2025-02-17)\nbinary: rustc\nhost: x86_64-unknown-linux-gnu\nrelease: 1.85.0".to_string()),
            cargo: Some("cargo 1.85.0 (d73d2caf9 2025-02-17)".to_string()),
            nextest: Some("cargo-nextest 0.9.72".to_string()),
            systemd_run: None,
        };

        let fp1 = derive_fingerprint(&versions);
        let fp2 = derive_fingerprint(&versions);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
        assert!(
            is_valid_fingerprint(&fp1),
            "fingerprint must be valid format"
        );
    }

    #[test]
    fn test_fingerprint_changes_on_version_change() {
        let v1 = ToolchainVersions {
            rustc: Some("rustc 1.85.0".to_string()),
            cargo: Some("cargo 1.85.0".to_string()),
            nextest: None,
            systemd_run: None,
        };
        let v2 = ToolchainVersions {
            rustc: Some("rustc 1.86.0".to_string()),
            cargo: Some("cargo 1.86.0".to_string()),
            nextest: None,
            systemd_run: None,
        };

        let fp1 = derive_fingerprint(&v1);
        let fp2 = derive_fingerprint(&v2);
        assert_ne!(fp1, fp2, "fingerprint must change when toolchain changes");
    }

    #[test]
    fn test_fingerprint_changes_on_tool_presence() {
        let v1 = ToolchainVersions {
            rustc: Some("rustc 1.85.0".to_string()),
            cargo: Some("cargo 1.85.0".to_string()),
            nextest: None,
            systemd_run: None,
        };
        let v2 = ToolchainVersions {
            rustc: Some("rustc 1.85.0".to_string()),
            cargo: Some("cargo 1.85.0".to_string()),
            nextest: Some("cargo-nextest 0.9.72".to_string()),
            systemd_run: None,
        };

        let fp1 = derive_fingerprint(&v1);
        let fp2 = derive_fingerprint(&v2);
        assert_ne!(
            fp1, fp2,
            "fingerprint must change when a tool becomes available"
        );
    }

    #[test]
    fn test_fingerprint_all_none() {
        let versions = ToolchainVersions::default();
        let fp = derive_fingerprint(&versions);
        assert!(
            is_valid_fingerprint(&fp),
            "fingerprint valid even with no tools"
        );
    }

    #[test]
    fn test_is_valid_fingerprint() {
        assert!(is_valid_fingerprint(
            "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ));
        assert!(!is_valid_fingerprint("sha256:abc"));
        assert!(!is_valid_fingerprint("b3-256:tooshort"));
        assert!(!is_valid_fingerprint(""));
        assert!(!is_valid_fingerprint(
            "b3-256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
    }

    #[test]
    fn test_resolve_fingerprint_returns_valid() {
        let env = test_hardened_env();
        let fp = resolve_fingerprint(&env).expect("resolve_fingerprint");
        assert!(
            is_valid_fingerprint(&fp),
            "resolved fingerprint must be valid"
        );
    }

    #[test]
    fn test_resolve_fingerprint_deterministic() {
        let env = test_hardened_env();
        let fp1 = resolve_fingerprint(&env).expect("first resolve");
        let fp2 = resolve_fingerprint(&env).expect("second resolve");
        assert_eq!(fp1, fp2, "successive resolves must be identical");
    }

    #[test]
    fn test_collect_toolchain_versions_returns_required() {
        let env = test_hardened_env();
        let versions = collect_toolchain_versions(&env).expect("collect should succeed");
        assert!(
            versions.rustc.is_some(),
            "rustc must be present in test env"
        );
        assert!(
            versions.cargo.is_some(),
            "cargo must be present in test env"
        );
    }

    #[test]
    fn test_collect_toolchain_versions_fails_on_missing_rustc() {
        // Empty env — rustc/cargo not found on PATH.
        let empty_env = BTreeMap::new();
        let result = collect_toolchain_versions(&empty_env);
        assert!(
            result.is_err(),
            "must fail when required probes cannot find tools"
        );
    }

    #[test]
    fn test_domain_separation_prevents_collision() {
        let v1 = ToolchainVersions {
            rustc: Some("1.85.0".to_string()),
            cargo: None,
            nextest: None,
            systemd_run: None,
        };
        let v2 = ToolchainVersions {
            rustc: None,
            cargo: Some("1.85.0".to_string()),
            nextest: None,
            systemd_run: None,
        };
        let fp1 = derive_fingerprint(&v1);
        let fp2 = derive_fingerprint(&v2);
        assert_ne!(
            fp1, fp2,
            "different tool slots with same string must produce different fingerprints"
        );
    }

    #[test]
    fn test_fingerprint_short_hex_valid() {
        let fp = "b3-256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert_eq!(fingerprint_short_hex(fp), Some("abcdef0123456789"));
    }

    #[test]
    fn test_fingerprint_short_hex_invalid() {
        assert_eq!(fingerprint_short_hex("sha256:abc"), None);
        assert_eq!(fingerprint_short_hex("b3-256:short"), None);
        assert_eq!(fingerprint_short_hex(""), None);
    }

    #[test]
    fn test_fingerprint_short_hex_from_resolved() {
        let env = test_hardened_env();
        let fp = resolve_fingerprint(&env).expect("resolve");
        let short = fingerprint_short_hex(&fp);
        assert!(
            short.is_some(),
            "resolved fingerprint must have valid short hex"
        );
        assert_eq!(short.unwrap().len(), 16);
    }

    // ── Cache tests ──────────────────────────────────────────────────────

    #[test]
    fn test_cache_round_trip() {
        let versions = ToolchainVersions {
            rustc: Some("rustc 1.85.0".to_string()),
            cargo: Some("cargo 1.85.0".to_string()),
            nextest: None,
            systemd_run: None,
        };
        let fp = derive_fingerprint(&versions);
        let bytes = serialize_cache(&fp, &versions).expect("serialize");
        let validated = validate_cached_fingerprint(&bytes);
        assert_eq!(validated, Some(fp));
    }

    #[test]
    fn test_cache_rejects_tampered_fingerprint() {
        let versions = ToolchainVersions {
            rustc: Some("rustc 1.85.0".to_string()),
            cargo: Some("cargo 1.85.0".to_string()),
            nextest: None,
            systemd_run: None,
        };
        let mut cached = CachedFingerprint {
            fingerprint: derive_fingerprint(&versions),
            raw_versions: versions,
        };
        // Tamper with fingerprint.
        cached.fingerprint =
            "b3-256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let bytes = serde_json::to_vec(&cached).unwrap();
        assert_eq!(
            validate_cached_fingerprint(&bytes),
            None,
            "tampered fingerprint must be rejected"
        );
    }

    #[test]
    fn test_cache_rejects_tampered_versions() {
        let versions = ToolchainVersions {
            rustc: Some("rustc 1.85.0".to_string()),
            cargo: Some("cargo 1.85.0".to_string()),
            nextest: None,
            systemd_run: None,
        };
        let fp = derive_fingerprint(&versions);
        let mut cached = CachedFingerprint {
            fingerprint: fp,
            raw_versions: versions,
        };
        // Tamper with versions.
        cached.raw_versions.rustc = Some("rustc 1.99.0".to_string());
        let bytes = serde_json::to_vec(&cached).unwrap();
        assert_eq!(
            validate_cached_fingerprint(&bytes),
            None,
            "tampered versions must be rejected"
        );
    }

    #[test]
    fn test_cache_rejects_corrupt_json() {
        assert_eq!(
            validate_cached_fingerprint(b"not json at all"),
            None,
            "corrupt JSON must be rejected"
        );
    }

    #[test]
    fn test_cache_rejects_invalid_fingerprint_format() {
        let cached = CachedFingerprint {
            fingerprint: "invalid-format".to_string(),
            raw_versions: ToolchainVersions::default(),
        };
        let bytes = serde_json::to_vec(&cached).unwrap();
        assert_eq!(
            validate_cached_fingerprint(&bytes),
            None,
            "invalid fingerprint format must be rejected"
        );
    }

    #[test]
    fn test_resolve_fingerprint_cached_uses_valid_cache() {
        let env = test_hardened_env();
        let versions = collect_toolchain_versions(&env).expect("collect");
        let fp = derive_fingerprint(&versions);
        let cache_bytes = serialize_cache(&fp, &versions).expect("serialize");

        // Resolve with cache should return cached fingerprint (versions match fresh).
        let (resolved_fp, resolved_versions) =
            resolve_fingerprint_cached(&env, Some(&cache_bytes)).expect("resolve cached");
        assert_eq!(resolved_fp, fp);
        assert_eq!(resolved_versions, versions);
    }

    #[test]
    fn test_resolve_fingerprint_cached_falls_through_on_invalid_cache() {
        let env = test_hardened_env();
        let corrupt_cache = b"not valid json";

        // Should fall through to fresh computation.
        let (fp, _versions) =
            resolve_fingerprint_cached(&env, Some(corrupt_cache)).expect("resolve fresh");
        assert!(is_valid_fingerprint(&fp));
    }

    #[test]
    fn test_resolve_fingerprint_cached_falls_through_on_none() {
        let env = test_hardened_env();

        // No cache: should compute fresh.
        let (fp, _versions) = resolve_fingerprint_cached(&env, None).expect("resolve fresh");
        assert!(is_valid_fingerprint(&fp));
    }

    // ── Regression: stale cache after toolchain upgrade ─────────────────

    #[test]
    fn test_resolve_fingerprint_cached_detects_stale_cache() {
        // Regression test for BLOCKER-1: cache-first fingerprint reuse
        // staying stale across toolchain changes.
        //
        // Simulates: worker starts with rustc 1.85.0, cache is written.
        // Then rustc is upgraded to 1.86.0, worker restarts. The cache
        // must be invalidated because fresh probe outputs differ.
        let env = test_hardened_env();

        // Build a cache with OLD (synthetic) versions that differ from
        // the real toolchain on this host.
        let old_versions = ToolchainVersions {
            rustc: Some("rustc 1.85.0-FAKE-OLD".to_string()),
            cargo: Some("cargo 1.85.0-FAKE-OLD".to_string()),
            nextest: None,
            systemd_run: None,
        };
        let old_fp = derive_fingerprint(&old_versions);
        let stale_cache = serialize_cache(&old_fp, &old_versions).expect("serialize");

        // resolve_fingerprint_cached MUST detect the stale cache because
        // fresh probes will produce different version strings.
        let (resolved_fp, resolved_versions) =
            resolve_fingerprint_cached(&env, Some(&stale_cache)).expect("resolve");

        // The resolved fingerprint must NOT be the old cached one.
        assert_ne!(
            resolved_fp, old_fp,
            "stale cache must be invalidated when fresh probes differ"
        );

        // The resolved versions must match what the host actually reports.
        assert_ne!(
            resolved_versions, old_versions,
            "resolved versions must come from fresh probes, not stale cache"
        );

        // Verify the resolved fingerprint is valid and matches fresh derivation.
        let expected_fp = derive_fingerprint(&resolved_versions);
        assert_eq!(
            resolved_fp, expected_fp,
            "resolved fingerprint must match derivation from fresh versions"
        );
    }

    // ── Regression: exit status enforcement ─────────────────────────────

    #[test]
    fn test_version_output_captures_exit_status_success() {
        // Verify that version_output returns exit status for a known-good command.
        let env = test_hardened_env();
        let result = version_output("rustc", &["-Vv"], &env).expect("version_output");
        let (output, status) = result.expect("rustc must be found");
        assert!(
            !output.is_empty(),
            "rustc -Vv must produce non-empty output"
        );
        assert!(
            status.expect("exit status must be present").success(),
            "rustc -Vv must exit with status 0"
        );
    }

    #[test]
    fn test_version_output_captures_nonzero_exit() {
        // Use a command that will exit non-zero. `rustc --this-flag-does-not-exist`
        // should fail with a non-zero exit code but may produce some output.
        let env = test_hardened_env();
        // `false` is a standard Unix command that always exits 1 with no output.
        let result = version_output("false", &[], &env);
        if let Ok(Some((_, Some(status)))) = result {
            assert!(!status.success(), "`false` must exit with non-zero status");
        }
        // `false` not found, timeout, or spawn error — all acceptable.
    }

    #[test]
    fn test_required_probe_rejects_nonzero_exit() {
        // Verify that required_probe rejects a command that exits non-zero.
        // We use `false` which always exits 1.
        let env = test_hardened_env();
        let result = required_probe("false", &[], &env);
        match &result {
            Err(ToolchainFingerprintError::RequiredProbeFailed { reason, .. }) => {
                // Either "non-zero status" or "empty output" or "not found" is acceptable.
                assert!(
                    reason.contains("non-zero")
                        || reason.contains("empty")
                        || reason.contains("not found"),
                    "expected rejection reason, got: {reason}"
                );
            },
            _ => {
                // `false` not found on PATH is also acceptable.
                assert!(
                    result.is_err(),
                    "required_probe should have rejected `false`"
                );
            },
        }
    }

    #[test]
    fn test_optional_probe_returns_none_on_nonzero_exit() {
        // Verify that optional_probe returns None for a command that exits non-zero.
        let env = test_hardened_env();
        let result = optional_probe("false", &[], &env);
        assert_eq!(
            result, None,
            "optional_probe must return None for non-zero exit"
        );
    }

    // ── Path and cache utilities ────────────────────────────────────────

    #[test]
    fn test_cache_dir_and_file_path() {
        let fac_root = std::path::Path::new("/home/test/.apm2/private/fac");
        let dir = cache_dir(fac_root);
        assert_eq!(dir, fac_root.join("toolchain"));
        let file = cache_file_path(fac_root);
        assert_eq!(file, fac_root.join("toolchain").join("fingerprint.v1.json"));
    }
}
