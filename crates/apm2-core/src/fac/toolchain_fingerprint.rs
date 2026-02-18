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
//! The fingerprint is computed once at worker startup. If a valid cache exists
//! under `$APM2_HOME/private/fac/toolchain/fingerprint.v1.json`, it is loaded
//! first and validated by recomputing `derive_fingerprint(cached.raw_versions)`
//! and comparing against `cached.fingerprint`. If validation passes, process
//! spawning is skipped entirely. Otherwise, fresh probes are executed and the
//! result is persisted atomically with restricted permissions (dir 0o700,
//! file 0o600, O_NOFOLLOW).
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
use std::process::{Command, Stdio};
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
/// Required probes (rustc, cargo) must succeed. Optional probes (nextest,
/// systemd-run) produce `None` on failure.
///
/// # Errors
///
/// Returns an error if a required probe (rustc, cargo) fails.
pub fn collect_toolchain_versions(
    hardened_env: &BTreeMap<String, String>,
) -> Result<ToolchainVersions, ToolchainFingerprintError> {
    let rustc = version_output("rustc", &["-Vv"], hardened_env).map_err(|e| {
        ToolchainFingerprintError::RequiredProbeFailed {
            tool: "rustc",
            reason: e.to_string(),
        }
    })?;
    if rustc.is_none() {
        return Err(ToolchainFingerprintError::RequiredProbeFailed {
            tool: "rustc",
            reason: "probe returned empty output".to_string(),
        });
    }

    let cargo = version_output("cargo", &["-V"], hardened_env).map_err(|e| {
        ToolchainFingerprintError::RequiredProbeFailed {
            tool: "cargo",
            reason: e.to_string(),
        }
    })?;
    if cargo.is_none() {
        return Err(ToolchainFingerprintError::RequiredProbeFailed {
            tool: "cargo",
            reason: "probe returned empty output".to_string(),
        });
    }

    // Optional probes: nextest and systemd-run. Errors are swallowed to
    // produce None (these tools are not required for fingerprint validity).
    let nextest = version_output("cargo", &["nextest", "--version"], hardened_env).unwrap_or(None);
    let systemd_run = version_output("systemd-run", &["--version"], hardened_env).unwrap_or(None);

    Ok(ToolchainVersions {
        rustc,
        cargo,
        nextest,
        systemd_run,
    })
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
/// 1. If `cache_bytes` is `Some`, attempt to validate and use the cached
///    fingerprint (skip probes).
/// 2. If cache is missing/invalid, compute fresh via probes.
/// 3. Returns the fingerprint string AND the raw versions (for cache
///    persistence by the caller).
///
/// The caller is responsible for reading/writing the cache file with
/// appropriate permissions and bounded reads.
///
/// # Errors
///
/// Returns an error if required probes (rustc, cargo) fail and no valid
/// cache exists.
pub fn resolve_fingerprint_cached(
    hardened_env: &BTreeMap<String, String>,
    cache_bytes: Option<&[u8]>,
) -> Result<(String, ToolchainVersions), ToolchainFingerprintError> {
    // Step 1: Try cache first.
    if let Some(bytes) = cache_bytes {
        if let Some(cached) = validate_cached_fingerprint_full(bytes) {
            return Ok((cached.fingerprint, cached.raw_versions));
        }
    }

    // Step 2: Cache miss/invalid — compute fresh.
    let versions = collect_toolchain_versions(hardened_env)?;
    let fingerprint = derive_fingerprint(&versions);
    Ok((fingerprint, versions))
}

/// Validate a cached fingerprint and return the full struct if valid.
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
/// - On timeout, the calling thread kills the child directly, waits for exit,
///   then joins the helper thread.
///
/// Happens-before edges:
///   H1: helper `read_to_end` completes -> helper thread returns (program
///       order)
///   H2: calling thread `child.kill()` -> pipe close -> helper `read_to_end`
///       unblocks (OS pipe semantics)
///   H3: helper thread terminates -> `handle.join()` returns (thread join
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
) -> Result<Option<String>, ToolchainFingerprintError> {
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
        return Ok(None);
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
            // Timeout: kill child and reap.
            let _ = child.kill();
            let _ = bounded_reap(&mut child, program);
            let _ = handle.join();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Normal read completion: bounded reap of the child process (INV-TC-006).
    bounded_reap(&mut child, program)?;

    let Ok(Some(output_bytes)) = handle.join() else {
        return Ok(None);
    };
    let raw = String::from_utf8_lossy(&output_bytes);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

/// Bounded process reaping (INV-TC-006).
///
/// After the read thread completes, the child process may still be running
/// (e.g., it produced bounded output but continues executing). This function
/// ensures the process is reaped within a bounded timeout:
///
/// 1. `try_wait()` — if already exited, done.
/// 2. If still running, `kill()` then poll `try_wait()` with bounded timeout.
/// 3. If process cannot be reaped within the bound, return error.
fn bounded_reap(
    child: &mut std::process::Child,
    tool_name: &str,
) -> Result<(), ToolchainFingerprintError> {
    // Fast path: already exited.
    match child.try_wait() {
        Ok(None) => {},
        // Exited or process handle invalid — nothing more to reap.
        Ok(Some(_)) | Err(_) => return Ok(()),
    }

    // Still running: kill and wait with bounded timeout.
    let _ = child.kill();

    let reap_deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(None) => {},
            Ok(Some(_)) | Err(_) => return Ok(()),
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

        // Resolve with cache should return cached fingerprint without probing.
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

    #[test]
    fn test_cache_dir_and_file_path() {
        let fac_root = std::path::Path::new("/home/test/.apm2/private/fac");
        let dir = cache_dir(fac_root);
        assert_eq!(dir, fac_root.join("toolchain"));
        let file = cache_file_path(fac_root);
        assert_eq!(file, fac_root.join("toolchain").join("fingerprint.v1.json"));
    }
}
