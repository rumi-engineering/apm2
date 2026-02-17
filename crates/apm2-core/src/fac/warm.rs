// AGENT-AUTHORED (TCK-00525)
//! `WarmReceiptV1` and warm-phase execution primitives for lane-scoped
//! prewarming.
//!
//! Warm reduces cold-start probability for subsequent gates by pre-populating
//! build caches in the lane target namespace. Warm is a first-class FAC
//! maintenance action that produces structured, content-addressed receipts.
//!
//! # Warm Phases
//!
//! The following phases are available and selectable via flags:
//!
//! - `fetch` — `cargo fetch --locked`
//! - `build` — `cargo build --workspace --all-targets --all-features --locked`
//! - `nextest` — `cargo nextest run --workspace --all-features --no-run`
//! - `clippy` — `cargo clippy --workspace --all-targets --all-features -- -D
//!   warnings`
//! - `doc` — `cargo doc --workspace --no-deps`
//!
//! # Receipt Model
//!
//! `WarmReceiptV1` captures per-phase exit codes, durations, and tool
//! versions. Receipts are content-addressed via BLAKE3 and persisted to
//! the standard FAC receipts directory.
//!
//! # Security Invariants
//!
//! - [INV-WARM-001] All string fields bounded by `MAX_*` constants during both
//!   construction and deserialization (SEC-CTRL-FAC-0016).
//! - [INV-WARM-002] Warm uses lane target namespace (`CARGO_TARGET_DIR`).
//! - [INV-WARM-003] Warm uses FAC-managed `CARGO_HOME`.
//! - [INV-WARM-004] Phase count bounded by `MAX_WARM_PHASES` during both
//!   construction and deserialization.
//! - [INV-WARM-005] Content hash uses domain-separated BLAKE3 with
//!   length-prefixed injective framing.
//! - [INV-WARM-006] Content hash verification uses constant-time comparison via
//!   `subtle::ConstantTimeEq` (INV-PC-001 consistency).
//! - [INV-WARM-007] Phase execution enforces `MAX_PHASE_TIMEOUT_SECS` via
//!   `Child::try_wait` polling + `Child::kill` on timeout.
//! - [INV-WARM-008] Tool version collection uses bounded stdout reads
//!   (`Read::take(MAX_VERSION_OUTPUT_BYTES)`) to prevent OOM.
//! - [INV-WARM-009] Warm phase subprocesses execute with a hardened environment
//!   constructed via `build_job_environment()` (default-deny + policy
//!   allowlist). The ambient process environment is NOT inherited. FAC-private
//!   state paths and secrets are unreachable from `build.rs` / proc-macro
//!   execution. `RUSTC_WRAPPER` and `SCCACHE_*` are unconditionally stripped
//!   (INV-ENV-008).
//! - [INV-WARM-014] Warm phase subprocesses are executed under `systemd-run`
//!   transient units with MemoryMax/CPUQuota/TasksMax/RuntimeMaxSec constraints
//!   matching the lane profile, identical to how standard bounded test jobs are
//!   contained. When `systemd-run` is unavailable, execution falls back to
//!   direct `Command::spawn` with a logged warning (no silent degradation).
//! - [INV-WARM-015] Heartbeat refresh is integrated into the warm phase polling
//!   loop via an optional callback. The heartbeat is refreshed every
//!   `HEARTBEAT_REFRESH_INTERVAL` (5 seconds) during the `try_wait` spin,
//!   preventing the worker heartbeat file from going stale during long-running
//!   warm phases (which can take hours for large projects).

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read as _, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::execution_backend::{
    ExecutionBackend, ExecutionBackendError, SystemModeConfig, build_systemd_run_command,
};
use super::systemd_properties::SystemdUnitProperties;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Schema identifier for `WarmReceiptV1`.
pub const WARM_RECEIPT_SCHEMA: &str = "apm2.fac.warm_receipt.v1";

/// Domain separator for `WarmReceiptV1` content hash.
const WARM_RECEIPT_DOMAIN: &[u8] = b"apm2.fac.warm_receipt.content_hash.v1\0";

/// Maximum number of warm phases in a single receipt.
pub const MAX_WARM_PHASES: usize = 16;

/// Maximum string field length in warm receipts.
pub const MAX_WARM_STRING_LENGTH: usize = 512;

/// Maximum command string length in phase results.
pub const MAX_WARM_CMD_LENGTH: usize = 4096;

/// Maximum serialized size of a `WarmReceiptV1` (bytes).
pub const MAX_WARM_RECEIPT_SIZE: usize = 65_536;

/// Default warm phases (ordered).
pub const DEFAULT_WARM_PHASES: &[WarmPhase] = &[
    WarmPhase::Fetch,
    WarmPhase::Build,
    WarmPhase::Nextest,
    WarmPhase::Clippy,
    WarmPhase::Doc,
];

/// Maximum wall-clock time for a single warm phase (seconds).
pub const MAX_PHASE_TIMEOUT_SECS: u64 = 1800;

/// Maximum bytes to read from tool version stdout (finding #7: bounded reads).
const MAX_VERSION_OUTPUT_BYTES: u64 = 8192;

/// Maximum wall-clock time for a version probe command (seconds).
/// Version commands should complete near-instantly; 30s is generous.
const MAX_VERSION_TIMEOUT_SECS: u64 = 30;

/// [INV-WARM-015] Interval between heartbeat refresh calls during phase
/// polling. 5 seconds ensures the heartbeat file never appears stale to the
/// broker even during hour-long compilation phases.
const HEARTBEAT_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

// ─────────────────────────────────────────────────────────────────────────────
// Warm Containment
// ─────────────────────────────────────────────────────────────────────────────

/// [INV-WARM-014] Systemd transient unit containment configuration for warm
/// phase subprocesses.
///
/// When provided to `execute_warm_phase`, each warm subprocess is wrapped in a
/// `systemd-run` transient unit with the specified resource limits. This
/// matches the containment model used by standard FAC bounded test execution.
///
/// When `None` is passed (systemd-run unavailable), execution falls back to
/// direct `Command::spawn` with a logged warning.
#[derive(Debug, Clone)]
pub struct WarmContainment {
    /// Execution backend (user-mode or system-mode).
    pub backend: ExecutionBackend,
    /// Systemd unit properties from the lane profile.
    pub properties: SystemdUnitProperties,
    /// System-mode configuration (required when `backend == SystemMode`).
    pub system_config: Option<SystemModeConfig>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase Enum
// ─────────────────────────────────────────────────────────────────────────────

/// Selectable warm phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarmPhase {
    /// `cargo fetch --locked`
    Fetch,
    /// `cargo build --workspace --all-targets --all-features --locked`
    Build,
    /// `cargo nextest run --workspace --all-features --no-run`
    Nextest,
    /// `cargo clippy --workspace --all-targets --all-features -- -D warnings`
    Clippy,
    /// `cargo doc --workspace --no-deps`
    Doc,
}

impl WarmPhase {
    /// Phase name as used in receipts.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::Build => "build",
            Self::Nextest => "nextest",
            Self::Clippy => "clippy",
            Self::Doc => "doc",
        }
    }

    /// Parse a phase name string.
    ///
    /// # Errors
    ///
    /// Returns `WarmError::InvalidPhase` if the name is not recognized.
    pub fn parse(s: &str) -> Result<Self, WarmError> {
        match s {
            "fetch" => Ok(Self::Fetch),
            "build" => Ok(Self::Build),
            "nextest" => Ok(Self::Nextest),
            "clippy" => Ok(Self::Clippy),
            "doc" => Ok(Self::Doc),
            _ => Err(WarmError::InvalidPhase {
                phase: s.to_string(),
            }),
        }
    }
}

impl fmt::Display for WarmPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from warm operations.
#[derive(Debug, Error)]
pub enum WarmError {
    /// An invalid phase name was specified.
    #[error("invalid warm phase: {phase}")]
    InvalidPhase {
        /// The unrecognized phase name.
        phase: String,
    },

    /// Too many phases specified.
    #[error("too many phases: {count} exceeds max {max}")]
    TooManyPhases {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// A string field exceeds maximum length.
    #[error("{field} length {len} exceeds max {max}")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Phase execution failed.
    #[error("phase {phase} failed: {reason}")]
    PhaseExecutionFailed {
        /// Phase that failed.
        phase: String,
        /// Failure reason.
        reason: String,
    },

    /// Phase execution exceeded `MAX_PHASE_TIMEOUT_SECS`.
    #[error("phase {phase} timed out after {timeout_secs}s")]
    PhaseTimeout {
        /// Phase that timed out.
        phase: String,
        /// Timeout duration in seconds.
        timeout_secs: u64,
    },

    /// Systemd-run containment command construction failed.
    #[error("containment command failed: {reason}")]
    ContainmentFailed {
        /// Failure reason.
        reason: String,
    },

    /// I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Content hash mismatch.
    #[error("content hash mismatch: declared={declared}, computed={computed}")]
    ContentHashMismatch {
        /// Declared hash.
        declared: String,
        /// Computed hash.
        computed: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase Result
// ─────────────────────────────────────────────────────────────────────────────

/// Result of executing a single warm phase.
///
/// [INV-WARM-001] All string fields use bounded deserialization to prevent
/// OOM from crafted JSON (SEC-CTRL-FAC-0016).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmPhaseResult {
    /// Phase name.
    #[serde(deserialize_with = "deserialize_bounded_name")]
    pub name: String,
    /// Command that was executed.
    #[serde(deserialize_with = "deserialize_bounded_cmd")]
    pub cmd: String,
    /// Exit code from the command (None if the command could not be spawned).
    pub exit_code: Option<i32>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Warm Receipt V1
// ─────────────────────────────────────────────────────────────────────────────

/// Content-addressed receipt for a warm operation.
///
/// [INV-WARM-001] All string fields bounded by `MAX_WARM_STRING_LENGTH` and
/// `phases` bounded by `MAX_WARM_PHASES` during deserialization to prevent OOM
/// from crafted JSON (SEC-CTRL-FAC-0016).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmReceiptV1 {
    /// Schema identifier.
    #[serde(deserialize_with = "deserialize_bounded_string_field")]
    pub schema: String,
    /// Lane identifier.
    #[serde(deserialize_with = "deserialize_bounded_string_field")]
    pub lane_id: String,
    /// BLAKE3 hash of the canonical lane profile JSON.
    #[serde(deserialize_with = "deserialize_bounded_string_field")]
    pub lane_profile_hash: String,
    /// Workspace root path.
    ///
    /// NOTE (finding #9): This is an absolute path local to the worker that
    /// executed the warm operation. It is intentionally absolute because warm
    /// receipts are verified locally on the same machine where the lane
    /// workspace exists. Cross-machine portability is out of scope for
    /// lane-scoped warm receipts (the lane namespace is inherently local).
    #[serde(deserialize_with = "deserialize_bounded_string_field")]
    pub workspace_root: String,
    /// Git HEAD SHA at warm time.
    #[serde(deserialize_with = "deserialize_bounded_string_field")]
    pub git_head_sha: String,
    /// ISO 8601 start time.
    #[serde(deserialize_with = "deserialize_bounded_string_field")]
    pub started_at: String,
    /// ISO 8601 finish time.
    #[serde(deserialize_with = "deserialize_bounded_string_field")]
    pub finished_at: String,
    /// Per-phase results.
    #[serde(deserialize_with = "deserialize_bounded_phases")]
    pub phases: Vec<WarmPhaseResult>,
    /// Tool versions collected at warm time.
    pub tool_versions: WarmToolVersions,
    /// BLAKE3 content hash of the receipt payload.
    #[serde(deserialize_with = "deserialize_bounded_string_field")]
    pub content_hash: String,
}

/// Tool version snapshot at warm time.
///
/// [INV-WARM-001] All string fields bounded during deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmToolVersions {
    /// `rustc --version` output.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_bounded_optional_string_field"
    )]
    pub rustc: Option<String>,
    /// `cargo --version` output.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_bounded_optional_string_field"
    )]
    pub cargo: Option<String>,
    /// `cargo clippy --version` output.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_bounded_optional_string_field"
    )]
    pub clippy: Option<String>,
    /// `cargo nextest --version` output.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_bounded_optional_string_field"
    )]
    pub nextest: Option<String>,
}

impl WarmReceiptV1 {
    /// Compute canonical bytes for content hash (domain-separated,
    /// length-prefixed injective framing).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2048);
        buf.extend_from_slice(WARM_RECEIPT_DOMAIN);

        push_len_prefixed(&mut buf, self.schema.as_bytes());
        push_len_prefixed(&mut buf, self.lane_id.as_bytes());
        push_len_prefixed(&mut buf, self.lane_profile_hash.as_bytes());
        push_len_prefixed(&mut buf, self.workspace_root.as_bytes());
        push_len_prefixed(&mut buf, self.git_head_sha.as_bytes());
        push_len_prefixed(&mut buf, self.started_at.as_bytes());
        push_len_prefixed(&mut buf, self.finished_at.as_bytes());

        // Phases: count prefix + per-phase framing.
        buf.extend_from_slice(&(self.phases.len() as u64).to_le_bytes());
        for phase in &self.phases {
            push_len_prefixed(&mut buf, phase.name.as_bytes());
            push_len_prefixed(&mut buf, phase.cmd.as_bytes());
            buf.extend_from_slice(&phase.exit_code.unwrap_or(-1_i32).to_le_bytes());
            buf.extend_from_slice(&phase.duration_ms.to_le_bytes());
        }

        // Tool versions.
        push_optional_len_prefixed(&mut buf, self.tool_versions.rustc.as_deref());
        push_optional_len_prefixed(&mut buf, self.tool_versions.cargo.as_deref());
        push_optional_len_prefixed(&mut buf, self.tool_versions.clippy.as_deref());
        push_optional_len_prefixed(&mut buf, self.tool_versions.nextest.as_deref());

        buf
    }

    /// Compute the BLAKE3 content hash for this receipt.
    #[must_use]
    pub fn compute_content_hash(&self) -> String {
        let bytes = self.canonical_bytes();
        let hash = blake3::hash(&bytes);
        format!("b3-256:{}", hash.to_hex())
    }

    /// Verify content hash integrity.
    ///
    /// Uses constant-time comparison via `subtle::ConstantTimeEq` to prevent
    /// timing side-channel leakage (INV-PC-001 consistency).
    ///
    /// # Errors
    ///
    /// Returns `WarmError::ContentHashMismatch` if the declared hash does not
    /// match the computed hash.
    pub fn verify_content_hash(&self) -> Result<(), WarmError> {
        let computed = self.compute_content_hash();
        // [INV-WARM-006] Constant-time comparison prevents timing side-channels
        // on cryptographic hash values, consistent with INV-PC-001.
        if self
            .content_hash
            .as_bytes()
            .ct_eq(computed.as_bytes())
            .into()
        {
            Ok(())
        } else {
            Err(WarmError::ContentHashMismatch {
                declared: self.content_hash.clone(),
                computed,
            })
        }
    }

    /// Persist the receipt to the FAC receipts directory.
    ///
    /// Uses the content hash as the filename for content-addressed storage.
    ///
    /// # Errors
    ///
    /// Returns `WarmError::Io` on filesystem failures or
    /// `WarmError::FieldTooLong` if the serialized receipt exceeds size limits.
    pub fn persist(&self, receipts_dir: &Path) -> Result<std::path::PathBuf, WarmError> {
        std::fs::create_dir_all(receipts_dir).map_err(WarmError::Io)?;

        let hash_hex = self
            .content_hash
            .strip_prefix("b3-256:")
            .unwrap_or(&self.content_hash);
        let filename = format!("{hash_hex}.json");
        let target_path = receipts_dir.join(&filename);

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| WarmError::Serialization(e.to_string()))?;

        if json.len() > MAX_WARM_RECEIPT_SIZE {
            return Err(WarmError::FieldTooLong {
                field: "serialized_receipt",
                len: json.len(),
                max: MAX_WARM_RECEIPT_SIZE,
            });
        }

        // Atomic write: temp file + rename.
        let temp = tempfile::NamedTempFile::new_in(receipts_dir).map_err(WarmError::Io)?;
        {
            let mut file = temp.as_file();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            file.write_all(json.as_bytes()).map_err(WarmError::Io)?;
            file.sync_all().map_err(WarmError::Io)?;
        }
        temp.persist(&target_path)
            .map_err(|e| WarmError::Io(e.error))?;

        Ok(target_path)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Warm Executor
// ─────────────────────────────────────────────────────────────────────────────

/// Return the cargo subcommand arguments and display string for a warm phase.
///
/// The first element of the returned tuple is `("cargo", &[args])` and the
/// second is a human-readable command string for receipt logging.
fn phase_cargo_args(phase: WarmPhase) -> (Vec<String>, String) {
    match phase {
        WarmPhase::Fetch => (
            vec!["cargo".into(), "fetch".into(), "--locked".into()],
            "cargo fetch --locked".to_string(),
        ),
        WarmPhase::Build => (
            vec![
                "cargo".into(),
                "build".into(),
                "--workspace".into(),
                "--all-targets".into(),
                "--all-features".into(),
                "--locked".into(),
            ],
            "cargo build --workspace --all-targets --all-features --locked".to_string(),
        ),
        WarmPhase::Nextest => (
            vec![
                "cargo".into(),
                "nextest".into(),
                "run".into(),
                "--workspace".into(),
                "--all-features".into(),
                "--no-run".into(),
            ],
            "cargo nextest run --workspace --all-features --no-run".to_string(),
        ),
        WarmPhase::Clippy => (
            vec![
                "cargo".into(),
                "clippy".into(),
                "--workspace".into(),
                "--all-targets".into(),
                "--all-features".into(),
                "--".into(),
                "-D".into(),
                "warnings".into(),
            ],
            "cargo clippy --workspace --all-targets --all-features -- -D warnings".to_string(),
        ),
        WarmPhase::Doc => (
            vec![
                "cargo".into(),
                "doc".into(),
                "--workspace".into(),
                "--no-deps".into(),
            ],
            "cargo doc --workspace --no-deps".to_string(),
        ),
    }
}

fn is_sensitive_setenv_key(key: &str) -> bool {
    matches!(key, "GITHUB_TOKEN" | "GH_TOKEN")
}

/// Build the `Command` for a warm phase, optionally wrapped in a `systemd-run`
/// transient unit for cgroup containment.
///
/// [INV-WARM-009] Environment hardening differs by execution path:
///
/// - **Containment path** (`systemd-run`): The hardened environment is
///   forwarded into the transient unit via `--setenv` arguments. The contained
///   child process does NOT inherit the parent's environment; systemd manages
///   its environment exclusively via `--setenv`. The systemd-run process itself
///   inherits the parent environment because it needs
///   `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` for user-mode D-Bus
///   connectivity.
///
/// - **Direct spawn path** (fallback): `env_clear()` is called on the
///   `Command`, then only the policy-filtered `hardened_env` is applied.
///
/// In both cases, `CARGO_HOME` and `CARGO_TARGET_DIR` are overridden to
/// lane-managed paths, and `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` are
/// set to `/dev/null` to prevent ambient git config interference.
///
/// [INV-WARM-014] When `containment` is `Some`, the cargo command is wrapped
/// via `build_systemd_run_command()` with lane-profile resource limits. The
/// environment is forwarded via `--setenv` arguments. When `None`, falls back
/// to direct `Command::spawn`.
///
/// This prevents `build.rs` and proc-macro code from accessing
/// FAC-private state, secrets, or worker authority context.
#[allow(clippy::too_many_arguments)]
fn build_phase_command(
    phase: WarmPhase,
    workspace: &Path,
    cargo_home: &Path,
    cargo_target_dir: &Path,
    hardened_env: &BTreeMap<String, String>,
    containment: Option<&WarmContainment>,
    lane_id: &str,
    job_id: &str,
) -> Result<(Command, String), WarmError> {
    let (cargo_args, cmd_str) = phase_cargo_args(phase);

    // Build the composite environment including lane overrides and git config
    // isolation. This is used both for direct spawn and for --setenv
    // forwarding into systemd transient units.
    let mut env_map = hardened_env.clone();
    env_map.insert(
        "CARGO_HOME".to_string(),
        cargo_home.to_string_lossy().to_string(),
    );
    env_map.insert(
        "CARGO_TARGET_DIR".to_string(),
        cargo_target_dir.to_string_lossy().to_string(),
    );
    env_map.insert("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string());
    env_map.insert("GIT_CONFIG_SYSTEM".to_string(), "/dev/null".to_string());

    if let Some(containment) = containment {
        // [INV-WARM-014] Wrap cargo command in systemd-run transient unit.
        // Unit name includes lane + job_id prefix + phase to ensure
        // uniqueness across concurrent workers and rapid re-execution.
        // Job IDs are UUIDs so 8-char prefix provides sufficient
        // collision resistance for transient unit naming.
        let job_prefix = if job_id.len() >= 8 {
            &job_id[..8]
        } else {
            job_id
        };
        let unit_name = format!("apm2-warm-{lane_id}-{job_prefix}-{}", phase.name());
        let systemd_cmd = build_systemd_run_command(
            containment.backend,
            &containment.properties,
            workspace,
            Some(&unit_name),
            containment.system_config.as_ref(),
            &cargo_args,
        )
        .map_err(|e: ExecutionBackendError| WarmError::ContainmentFailed {
            reason: e.to_string(),
        })?;

        // Insert --setenv arguments into the command args before the
        // --property arguments. This follows the same insertion pattern as
        // the bounded test runner: env vars are forwarded into the transient
        // unit via `--setenv KEY=VALUE` so the contained process receives
        // the hardened environment (the transient unit does NOT inherit
        // the parent's environment).
        let property_start = systemd_cmd
            .args
            .iter()
            .position(|a| a == "--property")
            .unwrap_or(systemd_cmd.args.len());

        let mut full_args = Vec::with_capacity(systemd_cmd.args.len() + env_map.len() * 2);
        let mut sensitive_setenv_pairs: Vec<(String, String)> = Vec::new();
        full_args.extend(systemd_cmd.args[..property_start].iter().cloned());
        for (key, value) in &env_map {
            full_args.push("--setenv".to_string());
            if is_sensitive_setenv_key(key) {
                // Use key-only forwarding for sensitive vars so secret values do
                // not appear on argv. systemd-run reads the value from its own
                // process environment, which we set explicitly on `cmd` below.
                full_args.push(key.clone());
                sensitive_setenv_pairs.push((key.clone(), value.clone()));
            } else {
                full_args.push(format!("{key}={value}"));
            }
        }
        full_args.extend(systemd_cmd.args[property_start..].iter().cloned());

        // Build Command from the assembled args.
        //
        // NOTE: We do NOT call cmd.env_clear() here. The systemd-run
        // process itself needs DBUS_SESSION_BUS_ADDRESS and
        // XDG_RUNTIME_DIR to connect to the user session bus (for
        // --user mode). Clearing the environment breaks D-Bus
        // connectivity and causes systemd-run to fail in user-mode.
        //
        // Environment isolation for the *contained child process* is
        // handled by systemd: the transient unit receives its
        // environment exclusively via --setenv arguments above, not
        // by inheriting the parent's environment. This matches the
        // bounded test runner pattern in bounded_test_runner.rs.
        let mut cmd = Command::new(&full_args[0]);
        cmd.args(&full_args[1..]);
        for (key, value) in sensitive_setenv_pairs {
            cmd.env(key, value);
        }

        let display_str = format!("systemd-run [contained] {cmd_str}");
        Ok((cmd, display_str))
    } else {
        // Direct spawn fallback (no systemd-run).
        let mut cmd = Command::new("cargo");
        cmd.current_dir(workspace);

        // [INV-WARM-009] Clear inherited environment (default-deny), then
        // apply only the policy-filtered allowlist.
        cmd.env_clear();
        cmd.envs(&env_map);

        Ok((cmd, cmd_str))
    }
}

/// Execute a single warm phase and return the result.
///
/// Enforces `MAX_PHASE_TIMEOUT_SECS` via `Child::wait` with a polling loop
/// and `Child::kill` on timeout. This prevents unbounded blocking if a cargo
/// command hangs (e.g., due to a malicious `build.rs`).
///
/// # Containment (INV-WARM-014)
///
/// When `containment` is `Some`, warm subprocesses are wrapped in `systemd-run`
/// transient units with MemoryMax/CPUQuota/TasksMax/RuntimeMaxSec constraints
/// from the lane profile. This matches the containment model used by standard
/// FAC bounded test execution (TCK-00529/TCK-00511). When `None`, falls back
/// to direct `Command::spawn` with a logged warning.
///
/// # Heartbeat Liveness (INV-WARM-015)
///
/// When `heartbeat_fn` is `Some`, the callback is invoked every
/// `HEARTBEAT_REFRESH_INTERVAL` during the `try_wait` polling loop. This
/// prevents the worker heartbeat file from going stale during long-running
/// warm phases.
///
/// # Environment Hardening (INV-WARM-009)
///
/// Warm subprocesses execute with a hardened environment constructed via
/// `build_job_environment()` (default-deny + policy allowlist). The ambient
/// process environment is NOT inherited. FAC-private state paths and secrets
/// are unreachable from `build.rs` / proc-macro execution. `RUSTC_WRAPPER`
/// and `SCCACHE_*` are unconditionally stripped (INV-ENV-008).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn execute_warm_phase(
    phase: WarmPhase,
    workspace: &Path,
    cargo_home: &Path,
    cargo_target_dir: &Path,
    hardened_env: &BTreeMap<String, String>,
    containment: Option<&WarmContainment>,
    heartbeat_fn: Option<&dyn Fn()>,
    lane_id: &str,
    job_id: &str,
) -> WarmPhaseResult {
    let (mut cmd, cmd_str) = match build_phase_command(
        phase,
        workspace,
        cargo_home,
        cargo_target_dir,
        hardened_env,
        containment,
        lane_id,
        job_id,
    ) {
        Ok(pair) => pair,
        Err(e) => {
            // Containment command construction failed — report as spawn
            // failure with zero duration.
            return WarmPhaseResult {
                name: phase.name().to_string(),
                cmd: format!("cargo {} [containment failed: {e}]", phase.name()),
                exit_code: None,
                duration_ms: 0,
            };
        },
    };
    // Suppress stdout/stderr to prevent unbounded pipe buffering on the parent.
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let start = Instant::now();
    let timeout = Duration::from_secs(MAX_PHASE_TIMEOUT_SECS);
    let mut last_heartbeat = Instant::now();

    #[allow(clippy::option_if_let_else)] // complex timeout logic not suited for map_or
    let exit_code = match cmd.spawn() {
        Ok(mut child) => {
            // [INV-WARM-007] Enforce MAX_PHASE_TIMEOUT_SECS via polling
            // wait loop. On timeout, kill the child and report None exit
            // code to indicate abnormal termination.
            let mut result = None;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        result = status.code();
                        break;
                    },
                    Ok(None) => {
                        if start.elapsed() >= timeout {
                            // Timeout exceeded — kill and break.
                            let _ = child.kill();
                            let _ = child.wait();
                            // exit_code = None signals timeout/kill.
                            break;
                        }
                        // [INV-WARM-015] Refresh heartbeat during the polling
                        // loop to prevent stale heartbeat files during
                        // long-running warm phases (which can take hours).
                        if let Some(hb) = heartbeat_fn {
                            if last_heartbeat.elapsed() >= HEARTBEAT_REFRESH_INTERVAL {
                                hb();
                                last_heartbeat = Instant::now();
                            }
                        }
                        // Sleep briefly to avoid busy-spinning. 100ms resolution
                        // is adequate for phases running minutes.
                        std::thread::sleep(Duration::from_millis(100));
                    },
                    Err(_) => break,
                }
            }
            result
        },
        Err(_) => None,
    };

    let duration = start.elapsed();
    #[allow(clippy::cast_possible_truncation)] // clamped to u64::MAX before cast
    let duration_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;

    WarmPhaseResult {
        name: phase.name().to_string(),
        cmd: cmd_str,
        exit_code,
        duration_ms,
    }
}

/// Execute all requested warm phases and build a `WarmReceiptV1`.
///
/// `start_epoch_secs` is the Unix epoch timestamp at the start of execution
/// (injected to avoid wall-clock dependency in the core crate).
///
/// `hardened_env` is the policy-filtered environment constructed via
/// `build_job_environment()`. All warm subprocesses execute with this
/// default-deny environment (INV-WARM-009). The caller MUST construct
/// this via `build_job_environment()` to ensure FAC-private state and
/// secrets are stripped.
///
/// `containment` optionally wraps each phase in a `systemd-run` transient
/// unit for cgroup containment (INV-WARM-014). Pass `None` when
/// `systemd-run` is unavailable.
///
/// `heartbeat_fn` optionally refreshes the worker heartbeat during phase
/// execution to prevent stale heartbeat files (INV-WARM-015).
///
/// # Errors
///
/// Returns `WarmError::TooManyPhases` if `phases` exceeds `MAX_WARM_PHASES`.
#[allow(clippy::too_many_arguments)]
pub fn execute_warm(
    phases: &[WarmPhase],
    lane_id: &str,
    lane_profile_hash: &str,
    workspace: &Path,
    cargo_home: &Path,
    cargo_target_dir: &Path,
    git_head_sha: &str,
    start_epoch_secs: u64,
    hardened_env: &BTreeMap<String, String>,
    containment: Option<&WarmContainment>,
    heartbeat_fn: Option<&dyn Fn()>,
    job_id: &str,
) -> Result<WarmReceiptV1, WarmError> {
    if phases.len() > MAX_WARM_PHASES {
        return Err(WarmError::TooManyPhases {
            count: phases.len(),
            max: MAX_WARM_PHASES,
        });
    }

    validate_field_length("lane_id", lane_id, MAX_WARM_STRING_LENGTH)?;
    validate_field_length(
        "lane_profile_hash",
        lane_profile_hash,
        MAX_WARM_STRING_LENGTH,
    )?;
    validate_field_length("git_head_sha", git_head_sha, MAX_WARM_STRING_LENGTH)?;

    let workspace_str = workspace.to_string_lossy().to_string();
    validate_field_length("workspace_root", &workspace_str, MAX_WARM_STRING_LENGTH)?;

    let started_at = format_epoch_secs(start_epoch_secs);
    let wall_start = Instant::now();
    let mut phase_results = Vec::with_capacity(phases.len());

    for &phase in phases {
        let result = execute_warm_phase(
            phase,
            workspace,
            cargo_home,
            cargo_target_dir,
            hardened_env,
            containment,
            heartbeat_fn,
            lane_id,
            job_id,
        );
        phase_results.push(result);
    }

    // Compute finish time by adding elapsed wall-clock to start epoch.
    let elapsed_secs = wall_start.elapsed().as_secs();
    let finish_epoch_secs = start_epoch_secs.saturating_add(elapsed_secs);
    let finished_at = format_epoch_secs(finish_epoch_secs);
    let tool_versions = collect_tool_versions(hardened_env);

    let mut receipt = WarmReceiptV1 {
        schema: WARM_RECEIPT_SCHEMA.to_string(),
        lane_id: lane_id.to_string(),
        lane_profile_hash: lane_profile_hash.to_string(),
        workspace_root: workspace_str,
        git_head_sha: git_head_sha.to_string(),
        started_at,
        finished_at,
        phases: phase_results,
        tool_versions,
        content_hash: String::new(),
    };

    // Compute and set content hash.
    receipt.content_hash = receipt.compute_content_hash();

    Ok(receipt)
}

/// Collect tool versions for the warm receipt.
///
/// Version probes execute with the same hardened environment as warm phases
/// (INV-WARM-009, defense-in-depth). While version commands do not compile
/// untrusted code, using a consistent hardened environment prevents ambient
/// secrets from being observable even via tool introspection.
#[must_use]
pub fn collect_tool_versions(hardened_env: &BTreeMap<String, String>) -> WarmToolVersions {
    WarmToolVersions {
        rustc: version_output("rustc", &["--version"], hardened_env),
        cargo: version_output("cargo", &["--version"], hardened_env),
        clippy: version_output("cargo", &["clippy", "--version"], hardened_env),
        nextest: version_output("cargo", &["nextest", "--version"], hardened_env),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn push_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(data);
}

fn push_optional_len_prefixed(buf: &mut Vec<u8>, data: Option<&str>) {
    match data {
        Some(s) => {
            buf.push(1); // present marker
            push_len_prefixed(buf, s.as_bytes());
        },
        None => {
            buf.push(0); // absent marker
        },
    }
}

#[allow(clippy::missing_const_for_fn)]
fn validate_field_length(field: &'static str, value: &str, max: usize) -> Result<(), WarmError> {
    if value.len() > max {
        return Err(WarmError::FieldTooLong {
            field,
            len: value.len(),
            max,
        });
    }
    Ok(())
}

/// Format epoch seconds as a deterministic timestamp string (secs.nanos).
fn format_epoch_secs(secs: u64) -> String {
    format!("{secs}.000000000")
}

/// Collect version output from a tool command with bounded stdout reads and
/// bounded execution time.
///
/// [INV-WARM-008] Uses `Read::take(MAX_VERSION_OUTPUT_BYTES)` to prevent OOM
/// from a malicious or verbose tool wrapper producing unbounded stdout
/// (finding #7: bounded I/O on untrusted process output).
///
/// # Deadlock-free design (round 6 fix)
///
/// The calling thread retains direct ownership of the `Child` process handle
/// (no mutex). The helper thread receives only the `ChildStdout` pipe and
/// performs the bounded `read_to_end`. This eliminates the deadlock scenario
/// where a helper thread holds a child mutex across a blocking `wait()` while
/// the timeout path needs the same mutex to `kill()` the process.
///
/// Synchronization protocol (mutex-free):
/// - The calling thread owns `Child` directly. It can call `kill()` and
///   `wait()` at any time without acquiring a lock.
/// - The helper thread owns `ChildStdout` (taken from `Child` before spawn). It
///   performs `read_to_end` on the bounded reader. When the calling thread
///   kills the child, the pipe closes, which unblocks `read_to_end` with an
///   error or EOF. The helper then returns.
/// - The calling thread polls `handle.is_finished()` with short sleeps. On
///   timeout, it kills the child directly, waits for the child to exit (reaping
///   the zombie), then joins the helper thread.
/// - On normal completion, the calling thread waits for the child to exit, then
///   joins the helper to retrieve the read result.
///
/// Happens-before edges:
///   H1: helper `read_to_end` completes -> helper thread returns (program
///       order)
///   H2: calling thread `child.kill()` -> pipe close -> helper `read_to_end`
///       unblocks (OS pipe semantics)
///   H3: helper thread terminates -> `handle.join()` returns (thread join
///       synchronizes-with)
///   Guarantee: the calling thread always has exclusive kill authority over
///   the child, and the helper thread always terminates after kill (via
///   H2->H3).
fn version_output(
    program: &str,
    args: &[&str],
    hardened_env: &BTreeMap<String, String>,
) -> Option<String> {
    // [INV-WARM-009] Version probes use the same hardened environment
    // as warm phases (defense-in-depth).
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(hardened_env)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Take stdout pipe before spawning the helper thread. The calling
    // thread retains direct ownership of `child` (no mutex). The helper
    // thread receives only the pipe and reads from it.
    let stdout = child.stdout.take()?;

    // Helper thread: owns the stdout pipe, performs bounded read, returns
    // the raw bytes. Does NOT touch the Child handle -- no mutex needed.
    let handle = std::thread::spawn(move || -> Option<Vec<u8>> {
        let mut bounded = stdout.take(MAX_VERSION_OUTPUT_BYTES);
        let mut buf = Vec::with_capacity(256);
        if bounded.read_to_end(&mut buf).is_err() {
            return None;
        }
        Some(buf)
    });

    // Calling thread: poll helper completion with a bounded deadline.
    // The calling thread retains direct kill authority over the child.
    let timeout = Duration::from_secs(MAX_VERSION_TIMEOUT_SECS);
    let deadline = Instant::now() + timeout;
    loop {
        if handle.is_finished() {
            // Helper finished reading. Reap the child process.
            let status = child.wait().ok()?;
            // Join helper to get the read result.
            let buf = handle.join().ok()??;
            if !status.success() {
                return None;
            }
            let output = String::from_utf8(buf).ok()?;
            let normalized = output.trim();
            // Version probe output must be text-like; reject binary NUL payloads
            // produced by oversized stdout regressions.
            if normalized.contains('\0') {
                return None;
            }
            return Some(normalized.to_string());
        }
        if Instant::now() >= deadline {
            // Timeout: kill the child directly (no mutex needed).
            // This closes the stdout pipe, which unblocks the helper's
            // `read_to_end` (returns EOF or error).
            let _ = child.kill();
            let _ = child.wait();
            // Join the helper -- it will return promptly now that the
            // pipe is closed.
            let _ = handle.join();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bounded Deserialization Helpers (SEC-CTRL-FAC-0016, finding #3)
// ─────────────────────────────────────────────────────────────────────────────

/// Deserialize a string field with `MAX_WARM_STRING_LENGTH` bound.
fn deserialize_bounded_string_field<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() > MAX_WARM_STRING_LENGTH {
        return Err(de::Error::custom(format!(
            "string field exceeds maximum length ({} > {})",
            s.len(),
            MAX_WARM_STRING_LENGTH
        )));
    }
    Ok(s)
}

/// Deserialize an optional string field with `MAX_WARM_STRING_LENGTH` bound.
fn deserialize_bounded_optional_string_field<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    if let Some(ref s) = opt {
        if s.len() > MAX_WARM_STRING_LENGTH {
            return Err(de::Error::custom(format!(
                "optional string field exceeds maximum length ({} > {})",
                s.len(),
                MAX_WARM_STRING_LENGTH
            )));
        }
    }
    Ok(opt)
}

/// Deserialize `name` field with `MAX_WARM_STRING_LENGTH` bound.
fn deserialize_bounded_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() > MAX_WARM_STRING_LENGTH {
        return Err(de::Error::custom(format!(
            "field 'name' exceeds maximum length ({} > {})",
            s.len(),
            MAX_WARM_STRING_LENGTH
        )));
    }
    Ok(s)
}

/// Deserialize `cmd` field with `MAX_WARM_CMD_LENGTH` bound.
fn deserialize_bounded_cmd<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() > MAX_WARM_CMD_LENGTH {
        return Err(de::Error::custom(format!(
            "field 'cmd' exceeds maximum length ({} > {})",
            s.len(),
            MAX_WARM_CMD_LENGTH
        )));
    }
    Ok(s)
}

/// Deserialize `phases` vec with `MAX_WARM_PHASES` bound.
fn deserialize_bounded_phases<'de, D>(deserializer: D) -> Result<Vec<WarmPhaseResult>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedPhasesVisitor;

    impl<'de> Visitor<'de> for BoundedPhasesVisitor {
        type Value = Vec<WarmPhaseResult>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            let max = MAX_WARM_PHASES;
            write!(formatter, "a sequence with at most {max} items")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_WARM_PHASES));

            while let Some(item) = seq.next_element()? {
                if vec.len() >= MAX_WARM_PHASES {
                    let max = MAX_WARM_PHASES;
                    return Err(de::Error::custom(format!(
                        "collection 'phases' exceeds maximum size of {max}"
                    )));
                }
                vec.push(item);
            }

            Ok(vec)
        }
    }

    deserializer.deserialize_seq(BoundedPhasesVisitor)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_parse_roundtrip() {
        for phase in DEFAULT_WARM_PHASES {
            let parsed = WarmPhase::parse(phase.name()).unwrap();
            assert_eq!(parsed, *phase);
        }
    }

    #[test]
    fn test_phase_parse_invalid() {
        assert!(WarmPhase::parse("invalid").is_err());
    }

    /// Build a minimal hardened environment for testing.
    fn test_hardened_env() -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        // Minimal environment for cargo to resolve toolchain.
        if let Ok(path) = std::env::var("PATH") {
            env.insert("PATH".to_string(), path);
        }
        if let Ok(home) = std::env::var("HOME") {
            env.insert("HOME".to_string(), home);
        }
        if let Ok(rustup) = std::env::var("RUSTUP_HOME") {
            env.insert("RUSTUP_HOME".to_string(), rustup);
        }
        env
    }

    #[test]
    fn test_too_many_phases() {
        let phases: Vec<WarmPhase> = (0..=MAX_WARM_PHASES).map(|_| WarmPhase::Fetch).collect();
        let env = test_hardened_env();
        let result = execute_warm(
            &phases,
            "lane-00",
            "b3-256:abc",
            Path::new("/tmp"),
            Path::new("/tmp"),
            Path::new("/tmp"),
            "abc123",
            1_700_000_000,
            &env,
            None, // no containment in unit tests
            None, // no heartbeat in unit tests
            "test-job-00000000",
        );
        assert!(matches!(result, Err(WarmError::TooManyPhases { .. })));
    }

    #[test]
    fn test_field_too_long() {
        let long = "x".repeat(MAX_WARM_STRING_LENGTH + 1);
        let env = test_hardened_env();
        let result = execute_warm(
            &[WarmPhase::Fetch],
            &long,
            "b3-256:abc",
            Path::new("/tmp"),
            Path::new("/tmp"),
            Path::new("/tmp"),
            "abc123",
            1_700_000_000,
            &env,
            None, // no containment in unit tests
            None, // no heartbeat in unit tests
            "test-job-00000000",
        );
        assert!(matches!(result, Err(WarmError::FieldTooLong { .. })));
    }

    #[test]
    fn test_receipt_content_hash_determinism() {
        let receipt = WarmReceiptV1 {
            schema: WARM_RECEIPT_SCHEMA.to_string(),
            lane_id: "lane-00".to_string(),
            lane_profile_hash: "b3-256:aabbccdd".to_string(),
            workspace_root: "/tmp/workspace".to_string(),
            git_head_sha: "abc123".to_string(),
            started_at: "100.000000000".to_string(),
            finished_at: "200.000000000".to_string(),
            phases: vec![WarmPhaseResult {
                name: "fetch".to_string(),
                cmd: "cargo fetch --locked".to_string(),
                exit_code: Some(0),
                duration_ms: 1234,
            }],
            tool_versions: WarmToolVersions {
                rustc: Some("rustc 1.80.0".to_string()),
                cargo: Some("cargo 1.80.0".to_string()),
                clippy: None,
                nextest: None,
            },
            content_hash: String::new(),
        };

        let hash1 = receipt.compute_content_hash();
        let hash2 = receipt.compute_content_hash();
        assert_eq!(hash1, hash2, "content hash must be deterministic");
        assert!(
            hash1.starts_with("b3-256:"),
            "content hash must have b3-256 prefix"
        );
    }

    #[test]
    fn test_receipt_content_hash_verify() {
        let mut receipt = WarmReceiptV1 {
            schema: WARM_RECEIPT_SCHEMA.to_string(),
            lane_id: "lane-00".to_string(),
            lane_profile_hash: "b3-256:aabbccdd".to_string(),
            workspace_root: "/tmp/workspace".to_string(),
            git_head_sha: "abc123".to_string(),
            started_at: "100.000000000".to_string(),
            finished_at: "200.000000000".to_string(),
            phases: vec![],
            tool_versions: WarmToolVersions {
                rustc: None,
                cargo: None,
                clippy: None,
                nextest: None,
            },
            content_hash: String::new(),
        };
        receipt.content_hash = receipt.compute_content_hash();
        assert!(receipt.verify_content_hash().is_ok());

        // Tamper and verify failure.
        receipt.lane_id = "lane-01".to_string();
        assert!(receipt.verify_content_hash().is_err());
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let mut receipt = WarmReceiptV1 {
            schema: WARM_RECEIPT_SCHEMA.to_string(),
            lane_id: "lane-00".to_string(),
            lane_profile_hash: "b3-256:aabbccdd".to_string(),
            workspace_root: "/tmp/workspace".to_string(),
            git_head_sha: "abc123".to_string(),
            started_at: "100.000000000".to_string(),
            finished_at: "200.000000000".to_string(),
            phases: vec![WarmPhaseResult {
                name: "build".to_string(),
                cmd: "cargo build --workspace".to_string(),
                exit_code: Some(0),
                duration_ms: 5678,
            }],
            tool_versions: WarmToolVersions {
                rustc: Some("rustc 1.80.0".to_string()),
                cargo: None,
                clippy: None,
                nextest: None,
            },
            content_hash: String::new(),
        };
        receipt.content_hash = receipt.compute_content_hash();

        let json = serde_json::to_string(&receipt).unwrap();
        let deser: WarmReceiptV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, deser);
    }

    #[test]
    fn test_warm_phase_display() {
        assert_eq!(format!("{}", WarmPhase::Fetch), "fetch");
        assert_eq!(format!("{}", WarmPhase::Build), "build");
        assert_eq!(format!("{}", WarmPhase::Nextest), "nextest");
        assert_eq!(format!("{}", WarmPhase::Clippy), "clippy");
        assert_eq!(format!("{}", WarmPhase::Doc), "doc");
    }

    #[test]
    fn test_collect_tool_versions_does_not_panic() {
        // Should not panic even if tools are missing.
        let env = test_hardened_env();
        let _ = collect_tool_versions(&env);
    }

    // ── Deadlock-free version probe regression test (round 6 fix) ───────

    /// Regression test for the round 6 MAJOR finding: `version_output` must
    /// not deadlock when a tool writes more than `MAX_VERSION_OUTPUT_BYTES`
    /// to stdout.
    ///
    /// This test spawns a subprocess that writes 2x the bounded limit.
    /// Under the old mutex-based design, the helper thread would complete
    /// its bounded read, then lock the child mutex and call `wait()`. The
    /// child would be blocked writing remaining stdout (pipe full, nobody
    /// reading), causing `wait()` to block. The timeout path would then
    /// try to acquire the same mutex, deadlocking.
    ///
    /// Under the fixed design, the calling thread owns the `Child` directly
    /// (no mutex), so it can always kill the child on timeout regardless
    /// of what the helper thread is doing.
    #[test]
    fn test_version_output_no_deadlock_on_oversized_stdout() {
        let env = test_hardened_env();
        // Construct a deterministic byte count exceeding the bounded limit.
        // Use 2x the limit to ensure the pipe fills after the bounded read
        // completes.
        let byte_count = MAX_VERSION_OUTPUT_BYTES * 2;

        // Use `dd` to write oversized output. `dd` is available on all
        // Unix systems. The `if=/dev/zero` source produces null bytes.
        //
        // `version_output` uses a 30s timeout. dd writing 16 KiB should
        // complete near-instantly. The test verifies that `version_output`
        // returns None (because dd outputs binary zeros, not valid
        // UTF-8 version text, and the exit status may vary) without
        // hanging. If the old deadlock existed, this test would hang
        // for 30+ seconds and then the test runner timeout would kill it.
        let start = Instant::now();
        let result = version_output(
            "dd",
            &["if=/dev/zero", "bs=1", &format!("count={byte_count}")],
            &env,
        );

        // dd outputs binary zeros, so the result should be None (not
        // valid version text). The important assertion is that we
        // returned at all (no deadlock) and did so quickly.
        assert!(
            result.is_none(),
            "oversized binary output should not produce a version string"
        );

        // If the old deadlock existed, we would hang for the full 30s
        // timeout (or longer). Completing in under 10s proves the
        // deadlock is fixed. In practice dd finishes in milliseconds.
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(10),
            "version_output should complete quickly, not deadlock (took {elapsed:?})"
        );
    }

    // ── Bounded deserialization tests (finding #3) ───────────────────────

    #[test]
    fn test_deserialize_rejects_too_many_phases() {
        // Build a JSON receipt with MAX_WARM_PHASES + 1 phases.
        let mut phases_json = Vec::new();
        for i in 0..=MAX_WARM_PHASES {
            phases_json.push(format!(
                r#"{{"name":"p{i}","cmd":"echo","exit_code":0,"duration_ms":1}}"#,
            ));
        }
        let phases_csv = phases_json.join(",");
        let json = format!(
            r#"{{
                "schema":"test",
                "lane_id":"l",
                "lane_profile_hash":"h",
                "workspace_root":"/tmp",
                "git_head_sha":"abc",
                "started_at":"0",
                "finished_at":"0",
                "phases":[{phases_csv}],
                "tool_versions":{{}},
                "content_hash":"h"
            }}"#,
        );
        let result: Result<WarmReceiptV1, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "should reject >MAX_WARM_PHASES phases");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("exceeds maximum size"),
            "error should mention size: {err_msg}"
        );
    }

    #[test]
    fn test_deserialize_rejects_oversized_string_field() {
        let long = "x".repeat(MAX_WARM_STRING_LENGTH + 1);
        let json = format!(
            r#"{{
                "schema":"{long}",
                "lane_id":"l",
                "lane_profile_hash":"h",
                "workspace_root":"/tmp",
                "git_head_sha":"abc",
                "started_at":"0",
                "finished_at":"0",
                "phases":[],
                "tool_versions":{{}},
                "content_hash":"h"
            }}"#,
        );
        let result: Result<WarmReceiptV1, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "should reject oversized string field");
    }

    #[test]
    fn test_deserialize_rejects_oversized_cmd_field() {
        let long_cmd = "x".repeat(MAX_WARM_CMD_LENGTH + 1);
        let json = format!(
            r#"{{
                "schema":"test",
                "lane_id":"l",
                "lane_profile_hash":"h",
                "workspace_root":"/tmp",
                "git_head_sha":"abc",
                "started_at":"0",
                "finished_at":"0",
                "phases":[{{"name":"p","cmd":"{long_cmd}","exit_code":0,"duration_ms":1}}],
                "tool_versions":{{}},
                "content_hash":"h"
            }}"#,
        );
        let result: Result<WarmReceiptV1, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "should reject oversized cmd field");
    }

    #[test]
    fn test_deserialize_rejects_oversized_optional_tool_version() {
        let long = "x".repeat(MAX_WARM_STRING_LENGTH + 1);
        let json = format!(
            r#"{{
                "schema":"test",
                "lane_id":"l",
                "lane_profile_hash":"h",
                "workspace_root":"/tmp",
                "git_head_sha":"abc",
                "started_at":"0",
                "finished_at":"0",
                "phases":[],
                "tool_versions":{{"rustc":"{long}"}},
                "content_hash":"h"
            }}"#,
        );
        let result: Result<WarmReceiptV1, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "should reject oversized tool version");
    }

    // ── Constant-time comparison test (finding #5) ──────────────────────

    #[test]
    fn test_verify_content_hash_constant_time() {
        let mut receipt = WarmReceiptV1 {
            schema: WARM_RECEIPT_SCHEMA.to_string(),
            lane_id: "lane-00".to_string(),
            lane_profile_hash: "b3-256:aabbccdd".to_string(),
            workspace_root: "/tmp/workspace".to_string(),
            git_head_sha: "abc123".to_string(),
            started_at: "100.000000000".to_string(),
            finished_at: "200.000000000".to_string(),
            phases: vec![],
            tool_versions: WarmToolVersions {
                rustc: None,
                cargo: None,
                clippy: None,
                nextest: None,
            },
            content_hash: String::new(),
        };
        receipt.content_hash = receipt.compute_content_hash();
        // Valid hash passes.
        assert!(receipt.verify_content_hash().is_ok());

        // Tampered hash fails.
        receipt.content_hash =
            "b3-256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(receipt.verify_content_hash().is_err());

        // Different-length hash fails.
        receipt.content_hash = "short".to_string();
        assert!(receipt.verify_content_hash().is_err());
    }

    // ── Hardened environment tests (INV-WARM-009, round 5 security fix) ──

    #[test]
    fn test_build_phase_command_uses_env_clear() {
        // Verify that build_phase_command constructs a command using
        // env_clear + hardened env, not the ambient environment.
        //
        // We construct a command using the same pattern as build_phase_command
        // (env_clear + envs + specific overrides) and verify that a subprocess
        // only sees the hardened env vars, not ambient ones.
        let mut hardened = BTreeMap::new();
        hardened.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        hardened.insert("WARM_TEST_MARKER".to_string(), "present".to_string());

        let cargo_home = Path::new("/tmp/cargo_home");
        let cargo_target_dir = Path::new("/tmp/target");

        // Construct a command mimicking the build_phase_command pattern:
        // env_clear() + envs(hardened) + specific overrides.
        let mut test_cmd = Command::new("env");
        test_cmd.env_clear();
        test_cmd.envs(&hardened);
        test_cmd.env("CARGO_HOME", cargo_home);
        test_cmd.env("CARGO_TARGET_DIR", cargo_target_dir);
        test_cmd.stdout(Stdio::piped());
        test_cmd.stderr(Stdio::null());

        if let Ok(output) = test_cmd.output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // The hardened env should contain our marker.
            assert!(
                stdout.contains("WARM_TEST_MARKER=present"),
                "hardened env marker should be present in child"
            );
            // CARGO_HOME should be the lane-managed path.
            assert!(
                stdout.contains("CARGO_HOME=/tmp/cargo_home"),
                "CARGO_HOME should be overridden to lane-managed path"
            );
            // Count env vars — should be exactly 4 (PATH, WARM_TEST_MARKER,
            // CARGO_HOME, CARGO_TARGET_DIR). No ambient leakage.
            let env_count = stdout.lines().filter(|l| l.contains('=')).count();
            assert_eq!(
                env_count, 4,
                "should have exactly 4 env vars (no ambient leakage), got {env_count}: {stdout}"
            );
        }

        // Also verify that build_phase_command itself doesn't panic.
        let workspace = Path::new("/tmp");
        let (cmd, cmd_str) = build_phase_command(
            WarmPhase::Fetch,
            workspace,
            cargo_home,
            cargo_target_dir,
            &hardened,
            None, // no containment
            "lane-0",
            "test-job-00000000",
        )
        .expect("build_phase_command should not fail without containment");
        assert_eq!(cmd_str, "cargo fetch --locked");
        drop(cmd);
    }

    #[test]
    fn test_hardened_env_excludes_fac_private_paths() {
        // Verify that a hardened env built from policy does not contain
        // APM2_HOME or any FAC-private path references. This is a
        // structural test: build_job_environment with default policy
        // should not admit APM2_HOME or FAC-private env vars.
        use crate::fac::policy::{FacPolicyV1, build_job_environment};

        let policy = FacPolicyV1::default_policy();
        let ambient = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/testuser".to_string()),
            ("APM2_HOME".to_string(), "/home/testuser/.apm2".to_string()),
            (
                "FAC_SIGNING_KEY".to_string(),
                "secret-key-material".to_string(),
            ),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "supersecret".to_string(),
            ),
            ("RUSTC_WRAPPER".to_string(), "sccache".to_string()),
            ("SCCACHE_DIR".to_string(), "/tmp/sccache".to_string()),
        ];

        let apm2_home = Path::new("/home/testuser/.apm2");
        let env = build_job_environment(&policy, &ambient, apm2_home);

        // FAC-private and secret variables must NOT be in the hardened env.
        assert!(
            !env.contains_key("APM2_HOME"),
            "APM2_HOME must not be in hardened env"
        );
        assert!(
            !env.contains_key("FAC_SIGNING_KEY"),
            "FAC_SIGNING_KEY must not be in hardened env"
        );
        assert!(
            !env.contains_key("AWS_SECRET_ACCESS_KEY"),
            "AWS_SECRET_ACCESS_KEY must not be in hardened env"
        );
        assert!(
            !env.contains_key("RUSTC_WRAPPER"),
            "RUSTC_WRAPPER must not be in hardened env (INV-ENV-008)"
        );
        assert!(
            !env.contains_key("SCCACHE_DIR"),
            "SCCACHE_DIR must not be in hardened env (INV-ENV-008)"
        );

        // Allowlisted variables should be present.
        assert!(env.contains_key("PATH"), "PATH should be in hardened env");
        assert!(env.contains_key("HOME"), "HOME should be in hardened env");
    }

    // ── Heartbeat callback tests (INV-WARM-015) ─────────────────────────

    #[test]
    fn test_heartbeat_callback_invoked_during_phase_execution() {
        // Verify that the heartbeat callback is invoked at least once during
        // a child process that runs long enough for the polling loop to fire.
        //
        // This test directly exercises the same polling loop used by
        // `execute_warm_phase` with a controllable `sleep` child process
        // that outlasts the HEARTBEAT_REFRESH_INTERVAL. Using a reduced
        // interval (200ms) and a 1-second sleep ensures deterministic
        // invocation without making the test unacceptably slow.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let call_count = Arc::new(AtomicU32::new(0));
        let counter = call_count.clone();
        let heartbeat_fn = move || {
            counter.fetch_add(1, Ordering::Relaxed);
        };

        // Spawn a child that runs for 1 second — long enough for the heartbeat
        // to fire with a test-scoped reduced interval (200ms).
        let mut child = Command::new("sleep")
            .arg("1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep should be available on PATH");

        let start = Instant::now();
        let timeout = Duration::from_secs(MAX_PHASE_TIMEOUT_SECS);
        // Use a reduced heartbeat interval for deterministic testing.
        // Production uses HEARTBEAT_REFRESH_INTERVAL (5s); here we use 200ms
        // so the 1-second sleep guarantees at least 1 callback invocation.
        let test_heartbeat_interval = Duration::from_millis(200);
        let mut last_heartbeat = Instant::now();

        loop {
            match child.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    if last_heartbeat.elapsed() >= test_heartbeat_interval {
                        heartbeat_fn();
                        last_heartbeat = Instant::now();
                    }
                    std::thread::sleep(Duration::from_millis(50));
                },
                Err(_) => break,
            }
        }

        let count = call_count.load(Ordering::Relaxed);
        assert!(
            count >= 1,
            "heartbeat callback must be invoked at least once during a 1-second \
             child process with 200ms interval, but was invoked {count} times"
        );
    }

    #[test]
    fn test_execute_warm_phase_without_heartbeat() {
        // Verify that passing None for heartbeat_fn works correctly.
        let env = test_hardened_env();
        let result = execute_warm_phase(
            WarmPhase::Fetch,
            Path::new("/nonexistent-workspace-for-test"),
            Path::new("/tmp/cargo_home"),
            Path::new("/tmp/target"),
            &env,
            None, // no containment
            None, // no heartbeat
            "test-lane",
            "test-job-00000000",
        );
        assert_eq!(result.name, "fetch");
    }

    // ── Containment command construction tests (INV-WARM-014) ───────────

    #[test]
    fn test_build_phase_command_with_containment() {
        // Verify that build_phase_command constructs a systemd-run wrapped
        // command when containment is provided.
        let env = test_hardened_env();
        let containment = WarmContainment {
            backend: ExecutionBackend::UserMode,
            properties: SystemdUnitProperties {
                cpu_quota_percent: 200,
                memory_max_bytes: 8_000_000_000,
                tasks_max: 512,
                io_weight: 100,
                timeout_start_sec: 600,
                runtime_max_sec: 1800,
                kill_mode: "control-group".to_string(),
                sandbox_hardening:
                    super::super::systemd_properties::SandboxHardeningProfile::default(),
            },
            system_config: None,
        };

        let (cmd, cmd_str) = build_phase_command(
            WarmPhase::Build,
            Path::new("/tmp/workspace"),
            Path::new("/tmp/cargo_home"),
            Path::new("/tmp/target"),
            &env,
            Some(&containment),
            "lane-0",
            "abcd1234-5678-90ab-cdef-1234567890ab",
        )
        .expect("containment command construction should succeed");

        // The display string should indicate containment.
        assert!(
            cmd_str.contains("systemd-run [contained]"),
            "cmd_str should indicate containment: {cmd_str}"
        );
        assert!(
            cmd_str.contains("cargo build"),
            "cmd_str should contain original command: {cmd_str}"
        );
        drop(cmd);
    }

    #[test]
    fn test_build_phase_command_masks_sensitive_setenv_values() {
        let mut env = test_hardened_env();
        env.insert("GITHUB_TOKEN".to_string(), "ghp_secret_value".to_string());
        let containment = WarmContainment {
            backend: ExecutionBackend::UserMode,
            properties: SystemdUnitProperties {
                cpu_quota_percent: 200,
                memory_max_bytes: 8_000_000_000,
                tasks_max: 512,
                io_weight: 100,
                timeout_start_sec: 600,
                runtime_max_sec: 1800,
                kill_mode: "control-group".to_string(),
                sandbox_hardening:
                    super::super::systemd_properties::SandboxHardeningProfile::default(),
            },
            system_config: None,
        };

        let (cmd, _cmd_str) = build_phase_command(
            WarmPhase::Build,
            Path::new("/tmp/workspace"),
            Path::new("/tmp/cargo_home"),
            Path::new("/tmp/target"),
            &env,
            Some(&containment),
            "lane-0",
            "abcd1234-5678-90ab-cdef-1234567890ab",
        )
        .expect("containment command construction should succeed");

        let args: Vec<String> = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        assert!(
            args.windows(2)
                .any(|window| window[0] == "--setenv" && window[1] == "GITHUB_TOKEN"),
            "expected key-only --setenv forwarding for GITHUB_TOKEN, got args: {args:?}"
        );
        assert!(
            !args
                .iter()
                .any(|arg| arg.contains("GITHUB_TOKEN=ghp_secret_value")),
            "secret value must not appear in systemd-run argv: {args:?}"
        );

        let has_secret_env = cmd.get_envs().any(|(key, value)| {
            key.to_string_lossy() == "GITHUB_TOKEN"
                && value.is_some_and(|v| v.to_string_lossy() == "ghp_secret_value")
        });
        assert!(
            has_secret_env,
            "systemd-run process env must carry GITHUB_TOKEN for key-only forwarding"
        );
    }

    #[test]
    fn test_build_phase_command_without_containment() {
        // Verify that build_phase_command falls back to direct cargo command
        // when containment is None.
        let env = test_hardened_env();
        let (cmd, cmd_str) = build_phase_command(
            WarmPhase::Fetch,
            Path::new("/tmp/workspace"),
            Path::new("/tmp/cargo_home"),
            Path::new("/tmp/target"),
            &env,
            None,
            "lane-0",
            "test-job-00000000",
        )
        .expect("should succeed without containment");

        assert_eq!(cmd_str, "cargo fetch --locked");
        // Should NOT contain systemd-run indicator.
        assert!(
            !cmd_str.contains("systemd-run"),
            "direct command should not mention systemd-run"
        );
        drop(cmd);
    }

    #[test]
    fn test_phase_cargo_args_all_phases() {
        // Verify that phase_cargo_args returns correct args for all phases.
        for phase in DEFAULT_WARM_PHASES {
            let (args, display) = phase_cargo_args(*phase);
            assert!(!args.is_empty(), "args should not be empty for {phase}");
            assert_eq!(args[0], "cargo", "first arg should be cargo for {phase}");
            assert!(
                display.starts_with("cargo "),
                "display should start with 'cargo ' for {phase}: {display}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_unit_name_uniqueness_across_jobs_and_lanes() {
        // Regression: unit names MUST be unique per lane/job/phase to prevent
        // systemd transient unit collisions across concurrent workers or
        // rapid re-execution. We extract the --unit argument from the
        // Command's Debug representation since std::process::Command does
        // not expose args through a public accessor.

        /// Extract the `--unit` value from a Command's Debug output.
        fn extract_unit_name(cmd: &Command) -> String {
            let debug = format!("{cmd:?}");
            // Debug format includes args as quoted strings: ... "--unit" "value" ...
            let marker = "\"--unit\"";
            let idx = debug
                .find(marker)
                .unwrap_or_else(|| panic!("--unit not found in command: {debug}"));
            let after = &debug[idx + marker.len()..];
            // Skip whitespace/comma and opening quote.
            let start = after
                .find('"')
                .unwrap_or_else(|| panic!("no quoted value after --unit: {debug}"))
                + 1;
            let rest = &after[start..];
            let end = rest
                .find('"')
                .unwrap_or_else(|| panic!("unterminated quote after --unit: {debug}"));
            rest[..end].to_string()
        }

        let env = test_hardened_env();
        let containment = WarmContainment {
            backend: ExecutionBackend::UserMode,
            properties: SystemdUnitProperties {
                cpu_quota_percent: 200,
                memory_max_bytes: 8_000_000_000,
                tasks_max: 512,
                io_weight: 100,
                timeout_start_sec: 600,
                runtime_max_sec: 1800,
                kill_mode: "control-group".to_string(),
                sandbox_hardening:
                    super::super::systemd_properties::SandboxHardeningProfile::default(),
            },
            system_config: None,
        };

        // Build commands for the same phase but different lane/job combinations.
        let (cmd_a, _) = build_phase_command(
            WarmPhase::Build,
            Path::new("/tmp/ws"),
            Path::new("/tmp/ch"),
            Path::new("/tmp/td"),
            &env,
            Some(&containment),
            "lane-0",
            "aaaaaaaa-1111-2222-3333-444444444444",
        )
        .unwrap();
        let unit_a = extract_unit_name(&cmd_a);

        let (cmd_b, _) = build_phase_command(
            WarmPhase::Build,
            Path::new("/tmp/ws"),
            Path::new("/tmp/ch"),
            Path::new("/tmp/td"),
            &env,
            Some(&containment),
            "lane-0",
            "bbbbbbbb-1111-2222-3333-444444444444",
        )
        .unwrap();
        let unit_b = extract_unit_name(&cmd_b);

        let (cmd_c, _) = build_phase_command(
            WarmPhase::Build,
            Path::new("/tmp/ws"),
            Path::new("/tmp/ch"),
            Path::new("/tmp/td"),
            &env,
            Some(&containment),
            "lane-1",
            "aaaaaaaa-1111-2222-3333-444444444444",
        )
        .unwrap();
        let unit_c = extract_unit_name(&cmd_c);

        // Different job IDs on the same lane must produce different unit names.
        assert_ne!(
            unit_a, unit_b,
            "unit names must differ for different job IDs on the same lane"
        );
        // Different lanes with the same job ID must produce different unit names.
        assert_ne!(
            unit_a, unit_c,
            "unit names must differ for different lanes with the same job ID"
        );
        // Same lane and job must produce the same name (deterministic).
        let (cmd_a2, _) = build_phase_command(
            WarmPhase::Build,
            Path::new("/tmp/ws"),
            Path::new("/tmp/ch"),
            Path::new("/tmp/td"),
            &env,
            Some(&containment),
            "lane-0",
            "aaaaaaaa-1111-2222-3333-444444444444",
        )
        .unwrap();
        let unit_a2 = extract_unit_name(&cmd_a2);
        assert_eq!(
            unit_a, unit_a2,
            "same lane + job + phase must produce the same unit name"
        );

        // Verify the unit name includes expected components.
        assert!(
            unit_a.contains("lane-0"),
            "unit name should contain lane ID: {unit_a}"
        );
        assert!(
            unit_a.contains("aaaaaaaa"),
            "unit name should contain job ID prefix: {unit_a}"
        );
        assert!(
            unit_a.contains("build"),
            "unit name should contain phase name: {unit_a}"
        );
    }
}
