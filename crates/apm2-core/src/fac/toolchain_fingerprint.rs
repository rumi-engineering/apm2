// AGENT-AUTHORED
//! Toolchain fingerprint derivation and verification (TCK-00538).
//!
//! Computes a stable `b3-256:` BLAKE3 fingerprint of the build toolchain
//! installed on this node: `rustc -Vv`, `cargo -V`, `cargo nextest --version`,
//! and `systemd-run --version`. The fingerprint changes when any underlying
//! tool changes (different binary, different version, different host triple).
//!
//! # Design
//!
//! The fingerprint is computed once at worker startup by spawning 4 version-
//! probe subprocesses and hashing their output. Since this runs exactly once
//! per worker lifecycle, no caching is needed -- the cost of 4 process spawns
//! is negligible at startup.
//!
//! # Security Model
//!
//! - Domain-separated BLAKE3 hash prevents cross-domain preimage collisions.
//! - Length-prefixed encoding of each tool's output prevents concatenation
//!   ambiguity.
//! - Bounded I/O on tool output prevents OOM from malicious tool wrappers.
//!
//! # Invariants
//!
//! - [INV-TC-001] Fingerprint changes when any toolchain component changes.
//! - [INV-TC-002] Fingerprint is consistent across processes on the same node
//!   (deterministic hash over deterministic inputs).
//! - [INV-TC-005] Tool version probes are bounded by `MAX_VERSION_OUTPUT_BYTES`
//!   and `VERSION_PROBE_TIMEOUT` to prevent OOM and hang.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

/// Maximum length of the fingerprint string (`b3-256:` + 64 hex = 71).
pub const FINGERPRINT_STRING_LENGTH: usize = 71;

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
}

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Raw tool version outputs collected from the local toolchain.
///
/// Each field holds the stdout output of the corresponding version command,
/// or `None` if the tool is not available. Fields are hashed in declaration
/// order for deterministic fingerprint derivation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve the toolchain fingerprint by collecting version probes and
/// deriving the hash.
///
/// Spawns 4 subprocesses to probe tool versions, then computes a
/// domain-separated BLAKE3 hash. Called once at worker startup.
///
/// Returns a `b3-256:<hex>` string that changes when any toolchain component
/// changes.
///
/// # Errors
///
/// This function is infallible with respect to individual tool probes
/// (missing tools produce `None` in the version struct). It always returns
/// `Ok(fingerprint)`.
pub fn resolve_fingerprint(
    hardened_env: &BTreeMap<String, String>,
) -> Result<String, ToolchainFingerprintError> {
    let versions = collect_toolchain_versions(hardened_env);
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
#[must_use]
pub fn collect_toolchain_versions(hardened_env: &BTreeMap<String, String>) -> ToolchainVersions {
    ToolchainVersions {
        rustc: version_output("rustc", &["-Vv"], hardened_env),
        cargo: version_output("cargo", &["-V"], hardened_env),
        nextest: version_output("cargo", &["nextest", "--version"], hardened_env),
        systemd_run: version_output("systemd-run", &["--version"], hardened_env),
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
/// order)   H2: calling thread `child.kill()` -> pipe close -> helper
/// `read_to_end`       unblocks (OS pipe semantics)
///   H3: helper thread terminates -> `handle.join()` returns (thread join
///       synchronizes-with)
fn version_output(
    program: &str,
    args: &[&str],
    hardened_env: &BTreeMap<String, String>,
) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(hardened_env)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Take stdout pipe before spawning the helper thread.
    let stdout = child.stdout.take()?;

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
            let _ = child.wait();
            let _ = handle.join();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Normal completion: wait for child exit and join helper.
    let _ = child.wait();
    let output_bytes = handle.join().ok()??;
    let raw = String::from_utf8_lossy(&output_bytes);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
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
    fn test_collect_toolchain_versions_does_not_panic() {
        let env = test_hardened_env();
        let _ = collect_toolchain_versions(&env);
    }

    #[test]
    fn test_domain_separation_prevents_collision() {
        // Ensure that the hash domain prevents collisions between
        // different tools with the same version string.
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
}
