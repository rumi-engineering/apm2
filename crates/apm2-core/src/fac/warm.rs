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

use std::fmt;
use std::io::{Read as _, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

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

/// Build the cargo command for a warm phase.
///
/// `workspace` is the directory containing `Cargo.toml`.
/// `cargo_home` is the FAC-managed `CARGO_HOME` directory.
/// `cargo_target_dir` is the lane target directory.
fn build_phase_command(
    phase: WarmPhase,
    workspace: &Path,
    cargo_home: &Path,
    cargo_target_dir: &Path,
) -> (Command, String) {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace);
    cmd.env("CARGO_HOME", cargo_home);
    cmd.env("CARGO_TARGET_DIR", cargo_target_dir);
    // Prevent ambient config interference.
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");

    let cmd_str = match phase {
        WarmPhase::Fetch => {
            cmd.args(["fetch", "--locked"]);
            "cargo fetch --locked".to_string()
        },
        WarmPhase::Build => {
            cmd.args([
                "build",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
            ]);
            "cargo build --workspace --all-targets --all-features --locked".to_string()
        },
        WarmPhase::Nextest => {
            cmd.args([
                "nextest",
                "run",
                "--workspace",
                "--all-features",
                "--no-run",
            ]);
            "cargo nextest run --workspace --all-features --no-run".to_string()
        },
        WarmPhase::Clippy => {
            cmd.args([
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ]);
            "cargo clippy --workspace --all-targets --all-features -- -D warnings".to_string()
        },
        WarmPhase::Doc => {
            cmd.args(["doc", "--workspace", "--no-deps"]);
            "cargo doc --workspace --no-deps".to_string()
        },
    };

    (cmd, cmd_str)
}

/// Execute a single warm phase and return the result.
///
/// Enforces `MAX_PHASE_TIMEOUT_SECS` via `Child::wait` with a polling loop
/// and `Child::kill` on timeout. This prevents unbounded blocking if a cargo
/// command hangs (e.g., due to a malicious `build.rs`).
///
/// # Containment Note (finding #6)
///
/// Warm execution runs within the FAC worker's systemd transient unit,
/// inheriting cgroup + namespace isolation from TCK-00529/TCK-00511.
/// The worker executes jobs as systemd transient units with
/// `MemoryMax`, `CPUQuota`, `TasksMax`, `RuntimeMaxSec`, and
/// `KillMode=control-group` properties. `build.rs` scripts from
/// untrusted repos execute within this containment boundary. Explicit
/// bubblewrap wrapping is not added here because the systemd unit
/// boundary already provides process, resource, and filesystem
/// isolation at the job level.
#[must_use]
pub fn execute_warm_phase(
    phase: WarmPhase,
    workspace: &Path,
    cargo_home: &Path,
    cargo_target_dir: &Path,
) -> WarmPhaseResult {
    let (mut cmd, cmd_str) = build_phase_command(phase, workspace, cargo_home, cargo_target_dir);
    // Suppress stdout/stderr to prevent unbounded pipe buffering on the parent.
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let start = Instant::now();
    let timeout = Duration::from_secs(MAX_PHASE_TIMEOUT_SECS);

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
/// `finish_epoch_secs_fn` is called after all phases complete to capture end
/// time.
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
        let result = execute_warm_phase(phase, workspace, cargo_home, cargo_target_dir);
        phase_results.push(result);
    }

    // Compute finish time by adding elapsed wall-clock to start epoch.
    let elapsed_secs = wall_start.elapsed().as_secs();
    let finish_epoch_secs = start_epoch_secs.saturating_add(elapsed_secs);
    let finished_at = format_epoch_secs(finish_epoch_secs);
    let tool_versions = collect_tool_versions();

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
#[must_use]
pub fn collect_tool_versions() -> WarmToolVersions {
    WarmToolVersions {
        rustc: version_output("rustc", &["--version"]),
        cargo: version_output("cargo", &["--version"]),
        clippy: version_output("cargo", &["clippy", "--version"]),
        nextest: version_output("cargo", &["nextest", "--version"]),
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

/// Collect version output from a tool command with bounded stdout reads.
///
/// [INV-WARM-008] Uses `Read::take(MAX_VERSION_OUTPUT_BYTES)` to prevent OOM
/// from a malicious or verbose tool wrapper producing unbounded stdout
/// (finding #7: bounded I/O on untrusted process output).
fn version_output(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let stdout = child.stdout.take()?;
    let mut bounded = stdout.take(MAX_VERSION_OUTPUT_BYTES);
    let mut buf = Vec::with_capacity(256);
    if bounded.read_to_end(&mut buf).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }

    let status = child.wait().ok()?;
    if !status.success() {
        return None;
    }

    String::from_utf8(buf).ok().map(|s| s.trim().to_string())
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

    #[test]
    fn test_too_many_phases() {
        let phases: Vec<WarmPhase> = (0..=MAX_WARM_PHASES).map(|_| WarmPhase::Fetch).collect();
        let result = execute_warm(
            &phases,
            "lane-00",
            "b3-256:abc",
            Path::new("/tmp"),
            Path::new("/tmp"),
            Path::new("/tmp"),
            "abc123",
            1_700_000_000,
        );
        assert!(matches!(result, Err(WarmError::TooManyPhases { .. })));
    }

    #[test]
    fn test_field_too_long() {
        let long = "x".repeat(MAX_WARM_STRING_LENGTH + 1);
        let result = execute_warm(
            &[WarmPhase::Fetch],
            &long,
            "b3-256:abc",
            Path::new("/tmp"),
            Path::new("/tmp"),
            Path::new("/tmp"),
            "abc123",
            1_700_000_000,
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
        let _ = collect_tool_versions();
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
}
