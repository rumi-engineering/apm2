//! Shared utilities for xtask commands.
//!
//! This module provides common functions used across multiple commands:
//! - Branch validation and parsing
//! - Worktree path finding
//! - Ticket YAML path construction
//! - Non-authoritative banner display
//! - Internal receipt/event emission (TCK-00295)

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use xshell::{Shell, cmd};

// =============================================================================
// Internal Receipt Emission Feature Flag (TCK-00295)
// =============================================================================

/// Name of the environment variable enabling optional internal receipt
/// emission.
pub const EMIT_INTERNAL_ENV: &str = "XTASK_EMIT_INTERNAL";

/// Checks if internal receipt emission is enabled via environment variable.
///
/// Returns `true` if the `XTASK_EMIT_INTERNAL` environment variable is set to
/// "true" (case-insensitive).
///
/// Per TCK-00295, this flag defaults to `false`. When `true`, xtask will
/// attempt to emit internal receipts/events to the daemon. If the daemon is
/// unavailable, xtask continues without blocking.
///
/// # Important
///
/// Internal emission is NON-AUTHORITATIVE and is additive scaffolding only.
/// It does not elevate xtask authority. Per RFC-0018 REQ-HEF-0001, these
/// events are hints only and must never be used for admission decisions
/// without ledger+CAS verification.
pub fn emit_internal_from_env() -> bool {
    std::env::var(EMIT_INTERNAL_ENV)
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Attempts to emit an internal receipt/event to the daemon.
///
/// This function is NON-BLOCKING: if the daemon is unavailable, it logs a
/// warning and returns `Ok(())`. Per TCK-00295, daemon unavailability must
/// not block xtask runs.
///
/// # Arguments
///
/// * `event_type` - Event type identifier (e.g., "aat.evidence.published",
///   "review.completed")
/// * `payload` - Serialized event payload (JSON)
/// * `correlation_id` - Correlation ID for event tracing
///
/// # Returns
///
/// * `Ok(Some(event_id))` if the event was successfully emitted
/// * `Ok(None)` if the daemon is unavailable (non-blocking)
/// * `Err(_)` only for non-recoverable errors (should be rare)
///
/// # NON-AUTHORITATIVE
///
/// Events emitted via this function are NON-AUTHORITATIVE scaffolding.
/// Per RFC-0018, consumers must verify via ledger+CAS before acting on
/// any gate, admission, or authorization decision.
pub fn try_emit_internal_receipt(
    event_type: &str,
    payload: &[u8],
    correlation_id: &str,
) -> Result<Option<String>> {
    // Per TCK-00295: Daemon unavailability does not block xtask runs.
    // This is a best-effort emission; we log and continue on failure.

    // Get daemon socket path from environment or default
    let socket_path = std::env::var("APM2_SESSION_SOCKET")
        .unwrap_or_else(|_| "/var/run/apm2d/session.sock".to_string());

    let socket = Path::new(&socket_path);

    // Quick check: if socket doesn't exist, daemon is not running
    if !socket.exists() {
        eprintln!("  [EMIT_INTERNAL] Daemon not running (socket not found: {socket_path})");
        eprintln!("  [EMIT_INTERNAL] Continuing without internal receipt emission.");
        return Ok(None);
    }

    // Per TCK-00295: Internal emission requires a session token.
    // For xtask scaffolding, we use an environment variable for the token.
    // In future stages, this would be obtained via proper capability flow.
    let Ok(session_token) = std::env::var("APM2_SESSION_TOKEN") else {
        eprintln!("  [EMIT_INTERNAL] No session token available (APM2_SESSION_TOKEN not set)");
        eprintln!("  [EMIT_INTERNAL] Continuing without internal receipt emission.");
        return Ok(None);
    };

    // Attempt to emit the event using synchronous subprocess call.
    // We use apm2 CLI to avoid pulling async runtime dependencies into xtask.
    // This is a best-effort call; timeout after 5 seconds.
    let sh = Shell::new().context("Failed to create shell for internal emission")?;

    // Build the command using apm2 CLI (if available)
    let event_type_arg = event_type;
    let correlation_id_arg = correlation_id;

    // SECURITY (CWE-214): We do NOT pass the session token via --session-token
    // flag, as command-line arguments are visible in process listings (ps,
    // /proc). Instead, we rely on the APM2_SESSION_TOKEN environment variable
    // which is automatically inherited by the subprocess and read by the apm2
    // CLI.
    //
    // The session_token variable is used here ONLY to verify it's available;
    // the actual authentication happens via env var inheritance.
    let _ = &session_token; // Acknowledge availability check

    // Convert payload bytes to string for the CLI --payload argument
    let payload_str = String::from_utf8_lossy(payload).to_string();

    let result = cmd!(
        sh,
        "timeout 5 apm2 event emit --event-type {event_type_arg} --payload {payload_str} --correlation-id {correlation_id_arg}"
    )
    .ignore_status()
    .read();

    match result {
        Ok(output) => {
            if output.contains("event_id") || output.contains("success") {
                // Try to extract event_id from output (best effort)
                let event_id = output
                    .lines()
                    .find(|line| line.contains("event_id"))
                    .map(|line| line.trim().to_string());
                eprintln!(
                    "  [EMIT_INTERNAL] Internal receipt emitted: {}",
                    event_id.as_deref().unwrap_or("OK")
                );
                Ok(event_id)
            } else if output.contains("not found")
                || output.contains("No such file")
                || output.is_empty()
            {
                // apm2 CLI not available
                eprintln!("  [EMIT_INTERNAL] apm2 CLI not available for internal emission");
                eprintln!("  [EMIT_INTERNAL] Continuing without internal receipt emission.");
                Ok(None)
            } else {
                // Other output - log and continue
                eprintln!(
                    "  [EMIT_INTERNAL] Internal emission returned: {}",
                    output.trim()
                );
                Ok(None)
            }
        },
        Err(e) => {
            // Command execution failed (timeout, etc.)
            eprintln!("  [EMIT_INTERNAL] Internal emission failed: {e}");
            eprintln!("  [EMIT_INTERNAL] Continuing without internal receipt emission.");
            Ok(None)
        },
    }
}

// =============================================================================
// HEF Projection Feature Flag (TCK-00309)
// =============================================================================

/// Name of the environment variable gating HEF projection logic.
pub const USE_HEF_PROJECTION_ENV: &str = "USE_HEF_PROJECTION";

/// Checks if HEF projection logic is enabled.
///
/// Returns `true` if the `USE_HEF_PROJECTION` environment variable is set to
/// "true" (case-insensitive).
///
/// Per TCK-00309, this flag defaults to `false`. When `true`, xtask must NOT
/// write status checks directly to GitHub, as these should be handled by the
/// daemon's projection logic.
pub fn use_hef_projection() -> bool {
    std::env::var(USE_HEF_PROJECTION_ENV)
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

// =============================================================================
// Status Write Gating (TCK-00296 + TCK-00324)
// =============================================================================

/// Name of the environment variable enabling strict mode.
///
/// Per TCK-00296, strict mode enforces fail-closed behavior for GitHub status
/// writes. When enabled, status writes require explicit opt-in via
/// `XTASK_ALLOW_STATUS_WRITES=true`.
pub const XTASK_STRICT_MODE_ENV: &str = "XTASK_STRICT_MODE";

/// Name of the environment variable allowing status writes in strict mode.
///
/// Per TCK-00296, this flag must be explicitly set to "true" to allow GitHub
/// status writes when `XTASK_STRICT_MODE=true`. This is the "dev flag" that
/// enables development workflows while maintaining fail-closed security
/// posture.
pub const XTASK_ALLOW_STATUS_WRITES_ENV: &str = "XTASK_ALLOW_STATUS_WRITES";

// =============================================================================
// Cutover Policy Propagation (TCK-00408)
// =============================================================================

/// Name of the environment variable propagating cutover policy to child
/// processes.
///
/// Per TCK-00408, when emit-only cutover is active, ALL spawned child processes
/// (reviewers, executors) MUST inherit the same cutover policy. This
/// environment variable is set by the parent process and read by child
/// processes to enforce consistent behavior.
///
/// Value: `"emit_only"` | `"legacy"` (default: `"legacy"`)
pub const XTASK_CUTOVER_POLICY_ENV: &str = "XTASK_CUTOVER_POLICY";

/// Returns the effective cutover policy from environment.
///
/// Per TCK-00408, this checks both the explicit policy env var and the
/// emit-receipt-only flag. If either indicates emit-only mode, the policy
/// is emit-only.
///
/// Note: This reads environment variables only. Prefer
/// [`effective_cutover_policy_with_flag`] when a CLI `--emit-receipt-only`
/// flag is available, so the CLI flag is also honoured.
pub fn effective_cutover_policy() -> CutoverPolicy {
    effective_cutover_policy_with_flag(false)
}

/// Returns the effective cutover policy, also considering a CLI flag.
///
/// Per TCK-00408, the CLI `--emit-receipt-only` flag MUST have the same
/// effect as the `XTASK_EMIT_RECEIPT_ONLY` environment variable. This
/// function merges both sources so that callers which have the CLI flag
/// available can thread it through to every enforcement point.
pub fn effective_cutover_policy_with_flag(cli_emit_receipt_only: bool) -> CutoverPolicy {
    // Explicit policy propagation takes precedence
    if let Ok(policy) = std::env::var(XTASK_CUTOVER_POLICY_ENV) {
        if policy == "emit_only" {
            return CutoverPolicy::EmitOnly;
        }
    }
    // CLI flag has the same semantics as the env var
    if cli_emit_receipt_only {
        return CutoverPolicy::EmitOnly;
    }
    // Fall back to legacy emit-receipt-only env var
    if emit_receipt_only_from_env() {
        return CutoverPolicy::EmitOnly;
    }
    CutoverPolicy::Legacy
}

/// Cutover policy governing side-effect behavior.
///
/// Per TCK-00408, this enum determines whether xtask commands perform direct
/// GitHub writes or emit receipts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutoverPolicy {
    /// Legacy mode: direct writes allowed (being phased out).
    Legacy,
    /// Emit-only mode: no direct GitHub writes; emit receipts only.
    /// Child processes MUST inherit this policy.
    EmitOnly,
}

impl CutoverPolicy {
    /// Returns true if direct GitHub writes are forbidden under this policy.
    #[must_use]
    pub const fn is_emit_only(self) -> bool {
        matches!(self, Self::EmitOnly)
    }

    /// Returns the environment variable value to propagate this policy to
    /// child processes.
    #[must_use]
    pub const fn env_value(self) -> &'static str {
        match self {
            Self::EmitOnly => "emit_only",
            Self::Legacy => "legacy",
        }
    }
}

// =============================================================================
// Cutover Stage 1 Feature Flags (TCK-00324)
// =============================================================================

/// Name of the environment variable enabling emit-receipt-only mode.
///
/// Per TCK-00324 (REQ-0007), when set to "true", xtask will NOT perform direct
/// GitHub writes. Instead, it will emit internal receipts and rely on the
/// projection worker to perform the actual writes.
///
/// This is Stage 1 of the xtask authority reduction, implementing the principle
/// of least authority.
pub const XTASK_EMIT_RECEIPT_ONLY_ENV: &str = "XTASK_EMIT_RECEIPT_ONLY";

/// Name of the environment variable allowing direct GitHub writes.
///
/// Per TCK-00324 (REQ-0007), this flag must be explicitly set to "true" to
/// allow direct GitHub writes when emit-receipt-only mode is enabled (which
/// is the new default in cutover stage 1).
///
/// This provides an explicit opt-in for development/debugging scenarios where
/// the projection worker is not available.
pub const XTASK_ALLOW_GITHUB_WRITE_ENV: &str = "XTASK_ALLOW_GITHUB_WRITE";

/// Checks if emit-receipt-only mode is enabled via environment variable.
///
/// Returns `true` if the `XTASK_EMIT_RECEIPT_ONLY` environment variable is set
/// to "true" (case-insensitive).
///
/// Per TCK-00324 (REQ-0007), this flag defaults to `false` for backward
/// compatibility during the Stage 1 rollout. In Stage 2, this will become
/// `true` by default.
///
/// When `true`, xtask will emit internal receipts and NOT perform direct
/// GitHub writes, relying on the projection worker instead.
pub fn emit_receipt_only_from_env() -> bool {
    std::env::var(XTASK_EMIT_RECEIPT_ONLY_ENV)
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Checks if direct GitHub writes are allowed via environment variable.
///
/// Returns `true` if the `XTASK_ALLOW_GITHUB_WRITE` environment variable is set
/// to "true" (case-insensitive).
///
/// Per TCK-00324 (REQ-0007), this flag provides explicit opt-in for direct
/// GitHub writes when emit-receipt-only mode is active. It allows development
/// and debugging workflows when the projection worker is not available.
pub fn allow_github_write_from_env() -> bool {
    std::env::var(XTASK_ALLOW_GITHUB_WRITE_ENV)
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Checks if strict mode is enabled.
///
/// Returns `true` if the `XTASK_STRICT_MODE` environment variable is set to
/// "true" (case-insensitive).
///
/// Per TCK-00296:
/// - Default is `false` (non-strict mode) to preserve existing dev workflows.
/// - When `true`, status writes are blocked unless `XTASK_ALLOW_STATUS_WRITES`
///   is explicitly set.
pub fn is_strict_mode() -> bool {
    std::env::var(XTASK_STRICT_MODE_ENV)
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Checks if status writes are explicitly allowed.
///
/// Returns `true` if the `XTASK_ALLOW_STATUS_WRITES` environment variable is
/// set to "true" (case-insensitive).
///
/// Per TCK-00296, this flag is only meaningful in strict mode. It provides
/// explicit opt-in for development workflows.
pub fn allow_status_writes() -> bool {
    std::env::var(XTASK_ALLOW_STATUS_WRITES_ENV)
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Result of checking whether status writes should proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusWriteDecision {
    /// Proceed with the status write (may include warning).
    Proceed,
    /// Skip the status write (`USE_HEF_PROJECTION=true`).
    SkipHefProjection,
    /// Block the status write (strict mode without allow flag).
    BlockStrictMode,
    /// Emit receipt only, do NOT write directly to GitHub (TCK-00324).
    ///
    /// When this is returned, xtask should emit an internal receipt and
    /// return without performing the direct GitHub API call. The projection
    /// worker will handle the actual write.
    EmitReceiptOnly,
    /// Status writes permanently removed (TCK-00297, Stage X3).
    ///
    /// Per RFC-0018, direct GitHub status writes from xtask have been removed.
    /// Replacement paths (daemon projection, FAC v0 harness) are now live.
    /// Callers must log what the status would have been and return Ok(()).
    Removed,
}

/// Determines whether a GitHub status write should proceed.
///
/// # TCK-00297 (Stage X3): Status writes permanently removed
///
/// As of TCK-00297, direct GitHub status writes from xtask are **permanently
/// disabled**. This function always returns `StatusWriteDecision::Removed`.
///
/// Replacement paths (daemon projection via HEF, FAC v0 harness) are now the
/// authoritative mechanisms for status management. Per RFC-0018, xtask is
/// non-authoritative development scaffolding and must not write GitHub
/// statuses.
///
/// The previous gating logic (TCK-00296 strict mode, TCK-00309 HEF projection,
/// TCK-00324 cutover stage 1) is superseded by this unconditional removal.
///
/// # Returns
///
/// Always returns `StatusWriteDecision::Removed`.
///
/// # Example
///
/// ```ignore
/// use crate::util::{check_status_write_allowed, StatusWriteDecision};
///
/// match check_status_write_allowed() {
///     StatusWriteDecision::Removed => {
///         println!("[TCK-00297] Status writes removed. Would have been: {state}");
///         return Ok(());
///     }
///     // Legacy variants preserved for backwards compatibility but never returned.
///     _ => unreachable!("TCK-00297: status writes are permanently removed"),
/// }
/// ```
pub const fn check_status_write_allowed() -> StatusWriteDecision {
    // TCK-00297 (Stage X3): Direct GitHub status writes are permanently removed.
    // Replacement paths (daemon projection, FAC v0 harness) are live.
    // All previous gating logic (strict mode, HEF projection flag, cutover) is
    // superseded.
    StatusWriteDecision::Removed
}

/// Extended check for GitHub writes with CLI flag override.
///
/// # TCK-00297 (Stage X3): Status writes permanently removed
///
/// As of TCK-00297, this function always returns
/// `StatusWriteDecision::Removed`, regardless of CLI flags. The
/// `emit_receipt_only_flag` and `allow_github_write_flag` parameters are
/// retained for call-site compatibility with TCK-00324 callers but are ignored.
///
/// # Arguments
///
/// * `_emit_receipt_only_flag` - CLI --emit-receipt-only flag (ignored,
///   TCK-00297)
/// * `_allow_github_write_flag` - CLI --allow-github-write flag (ignored,
///   TCK-00297)
///
/// # Returns
///
/// Always returns `StatusWriteDecision::Removed`.
pub const fn check_status_write_with_flags(
    _emit_receipt_only_flag: bool,
    _allow_github_write_flag: bool,
) -> StatusWriteDecision {
    // TCK-00297 (Stage X3): Direct GitHub status writes are permanently removed.
    // All previous gating logic (HEF projection, cutover, strict mode) is
    // superseded.
    StatusWriteDecision::Removed
}

/// Warning message printed when status writes are attempted.
///
/// Per TCK-00297 (Stage X3), direct GitHub status writes are permanently
/// removed. This message replaces the previous non-strict mode warning
/// from TCK-00296.
pub const STATUS_WRITES_REMOVED_NOTICE: &str = r"
  [TCK-00297] Direct GitHub status writes have been permanently removed.
  Replacement paths: daemon projection (HEF), FAC v0 harness.
  The previous XTASK_STRICT_MODE / XTASK_ALLOW_STATUS_WRITES flags are no longer used.
";

/// Prints notice that status writes have been removed.
///
/// Per TCK-00297 (Stage X3), direct GitHub status writes from xtask are
/// permanently disabled. This function replaces the previous
/// `print_non_strict_mode_warning()` and informs operators that replacement
/// paths are now live.
pub fn print_status_writes_removed_notice() {
    eprintln!("{STATUS_WRITES_REMOVED_NOTICE}");
}

// =============================================================================
// Emit-Receipt-Only Mode Messages (TCK-00324)
// =============================================================================

/// Message printed when emit-receipt-only mode is active.
///
/// Per TCK-00324, this message informs the operator that direct GitHub writes
/// are disabled and the projection worker will handle the actual writes.
pub const EMIT_RECEIPT_ONLY_MESSAGE: &str = r"
================================================================================
                         EMIT-RECEIPT-ONLY MODE (TCK-00324)
================================================================================
  Direct GitHub writes are DISABLED. Emitting projection request receipt only.

  The projection worker will perform the actual GitHub API write.
  To force direct writes, use --allow-github-write or set XTASK_ALLOW_GITHUB_WRITE=true.

  This is Stage 1 of the xtask authority reduction per RFC-0019 REQ-0007.
================================================================================
";

/// Prints the emit-receipt-only mode message.
///
/// Call this function when emit-receipt-only mode is active to inform the
/// operator that direct GitHub writes are disabled.
pub fn print_emit_receipt_only_message() {
    eprintln!("{EMIT_RECEIPT_ONLY_MESSAGE}");
}

/// Emits a projection request receipt for GitHub status/comment writes.
///
/// Per TCK-00324, when emit-receipt-only mode is active, xtask emits a receipt
/// that requests the projection worker to perform the actual GitHub write.
///
/// # Arguments
///
/// * `operation` - Description of the requested operation (e.g.,
///   `status_write`, `comment_post`)
/// * `owner_repo` - GitHub owner/repo (e.g., "owner/repo")
/// * `target_ref` - Target reference (SHA or PR number)
/// * `payload` - Operation-specific payload (JSON)
/// * `correlation_id` - Correlation ID for event tracing
///
/// # Returns
///
/// * `Ok(Some(receipt_id))` if the receipt was successfully emitted
/// * `Ok(None)` if the daemon is unavailable (non-blocking)
/// * `Err(_)` only for non-recoverable errors
pub fn emit_projection_request_receipt(
    operation: &str,
    owner_repo: &str,
    target_ref: &str,
    payload: &str,
    correlation_id: &str,
) -> Result<Option<String>> {
    print_emit_receipt_only_message();

    let event_payload = serde_json::json!({
        "type": "projection_request",
        "operation": operation,
        "owner_repo": owner_repo,
        "target_ref": target_ref,
        "payload": payload,
        "cutover_stage": 1,
        "source": "xtask",
        "non_authoritative": true,
    });

    eprintln!(
        "  [CUTOVER] Emitting projection request receipt: {operation} for {owner_repo}/{target_ref}"
    );

    try_emit_internal_receipt(
        "projection.request.created",
        event_payload.to_string().as_bytes(),
        correlation_id,
    )
}

// =============================================================================
// Durable Projection Acknowledgement (TCK-00408)
// =============================================================================

/// Emits a projection request receipt and requires a durable acknowledgement.
///
/// Per TCK-00408, emit-only mode operations MUST NOT report success unless
/// the projection layer returns a durable receipt/event ID. This function
/// wraps `emit_projection_request_receipt` and fails closed when no
/// acknowledgement is returned.
///
/// # Errors
///
/// Returns an error if:
/// - The receipt emission itself fails
/// - No durable acknowledgement (event ID) is returned from the projection
///   layer
pub fn emit_projection_receipt_with_ack(
    operation: &str,
    owner_repo: &str,
    target_ref: &str,
    payload: &str,
    correlation_id: &str,
) -> Result<String> {
    match emit_projection_request_receipt(
        operation,
        owner_repo,
        target_ref,
        payload,
        correlation_id,
    ) {
        Ok(Some(event_id)) => {
            eprintln!("  [TCK-00408] Durable projection acknowledgement received: {event_id}");
            Ok(event_id)
        },
        Ok(None) => {
            // TCK-00408: Fail closed — emit-only mode requires durable ack
            bail!(
                "TCK-00408: emit-only mode requires durable projection acknowledgement, \
                 but the projection layer returned no event ID for operation '{operation}'. \
                 The side-effect has NOT been confirmed."
            )
        },
        Err(e) => Err(e),
    }
}

// =============================================================================
// Non-Authoritative Banner
// =============================================================================

/// NON-AUTHORITATIVE banner text for xtask operations.
///
/// Per RFC-0018 REQ-HEF-0001: "Pulse plane is non-authoritative" - xtask
/// outputs are development scaffolding hints only and must never be used as
/// authoritative admission, gate, lease, or secret-backed decision signals.
///
/// As of TCK-00297 (Stage X3), direct GitHub status writes from xtask have been
/// permanently removed. This banner is retained for any remaining xtask output
/// that might be consumed by operators or automation.
///
/// See: TCK-00294 (Stage X0), TCK-00297 (Stage X3)
pub const NON_AUTHORITATIVE_BANNER: &str = r"
================================================================================
                          NON-AUTHORITATIVE OUTPUT
================================================================================
  This xtask command is DEVELOPMENT SCAFFOLDING only.
  Per TCK-00297 (Stage X3): Direct GitHub status writes have been REMOVED.

  Per RFC-0018: Pulse-plane signals are lossy hints only. Consumers must verify
  via ledger+CAS before acting on any gate, admission, or authorization decision.

  For authoritative evidence, use the daemon's projection system.
================================================================================
";

/// Print the NON-AUTHORITATIVE banner to stderr.
///
/// Per TCK-00297 (Stage X3), this banner now reflects that direct GitHub
/// status writes have been removed. It is printed when xtask operations
/// produce output that operators or automation might consume.
pub fn print_non_authoritative_banner() {
    eprintln!("{NON_AUTHORITATIVE_BANNER}");
}

/// Regex pattern for validating ticket branch names.
///
/// Valid formats:
/// - `ticket/RFC-XXXX/TCK-XXXXX` (with RFC)
/// - `ticket/TCK-XXXXX` (standalone ticket)
///
/// Where XXXX is 4 digits and XXXXX is 5 digits.
static TICKET_BRANCH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Two separate patterns:
    // 1. ticket/ branches require strict TCK-XXXXX format (with optional RFC-XXXX/)
    // 2. feat/ branches allow any word/hyphen characters
    Regex::new(r"^(?:ticket/(?:(RFC-\d{4})/)?(TCK-\d{5})|feat/([\w\-]+))$")
        .expect("Invalid regex pattern for ticket branch")
});

/// Parsed ticket branch information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketBranch {
    /// The RFC ID (e.g., "RFC-0002"), if present.
    /// None for standalone tickets without an RFC.
    pub rfc_id: Option<String>,
    /// The ticket ID (e.g., "TCK-00027")
    pub ticket_id: String,
}

/// Validates a branch name and extracts RFC and ticket IDs.
///
/// # Arguments
///
/// * `branch_name` - The git branch name to validate
///
/// # Returns
///
/// Returns `Ok(TicketBranch)` with the parsed IDs if the branch name matches
/// one of the expected formats:
/// - `ticket/RFC-XXXX/TCK-XXXXX` (with RFC)
/// - `ticket/TCK-XXXXX` (standalone ticket)
///
/// # Errors
///
/// Returns an error if the branch name does not match the expected format.
///
/// # Examples
///
/// ```
/// # use xtask::util::validate_ticket_branch;
/// // With RFC
/// let result = validate_ticket_branch("ticket/RFC-0002/TCK-00027");
/// assert!(result.is_ok());
/// let branch = result.unwrap();
/// assert_eq!(branch.rfc_id, Some("RFC-0002".to_string()));
/// assert_eq!(branch.ticket_id, "TCK-00027");
///
/// // Standalone ticket (no RFC)
/// let result = validate_ticket_branch("ticket/TCK-00049");
/// assert!(result.is_ok());
/// let branch = result.unwrap();
/// assert_eq!(branch.rfc_id, None);
/// assert_eq!(branch.ticket_id, "TCK-00049");
/// ```
pub fn validate_ticket_branch(branch_name: &str) -> Result<TicketBranch> {
    let captures = TICKET_BRANCH_REGEX.captures(branch_name).with_context(|| {
        format!(
            "Invalid branch name: '{branch_name}'\n\
                 Expected format: ticket/RFC-XXXX/TCK-XXXXX or ticket/TCK-XXXXX\n\
                 Examples: ticket/RFC-0002/TCK-00027, ticket/TCK-00049"
        )
    })?;

    Ok(TicketBranch {
        rfc_id: captures.get(1).map(|m| m.as_str().to_string()),
        // Group 2 captures TCK-XXXXX for ticket/ branches
        // Group 3 captures the name for feat/ branches
        ticket_id: captures
            .get(2)
            .or_else(|| captures.get(3))
            .expect("Ticket ID capture group missing")
            .as_str()
            .to_string(),
    })
}

/// Finds the path to the main worktree from any worktree.
///
/// Uses `git worktree list` to find all worktrees and returns the path
/// to the main (bare) worktree, which is always listed first.
///
/// # Arguments
///
/// * `sh` - The xshell Shell instance
///
/// # Returns
///
/// Returns the absolute path to the main worktree.
///
/// # Errors
///
/// Returns an error if:
/// - Not in a git repository
/// - Cannot parse the output of `git worktree list`
pub fn main_worktree(sh: &Shell) -> Result<PathBuf> {
    let output = cmd!(sh, "git worktree list --porcelain")
        .read()
        .context("Failed to list git worktrees")?;

    // The first "worktree" line in porcelain output is the main worktree
    for line in output.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            return Ok(PathBuf::from(path));
        }
    }

    bail!("Could not find main worktree in git worktree list output")
}

/// Constructs the path to a ticket's YAML metadata file.
///
/// # Arguments
///
/// * `main_worktree_path` - Path to the main worktree
/// * `ticket_id` - The ticket ID (e.g., "TCK-00027")
///
/// # Returns
///
/// Returns the path to the ticket YAML file.
///
/// # Examples
///
/// ```
/// # use std::path::Path;
/// # use xtask::util::ticket_yaml_path;
/// let main = Path::new("/home/user/project");
/// let path = ticket_yaml_path(main, "TCK-00027");
/// assert_eq!(
///     path.to_str().unwrap(),
///     "/home/user/project/documents/work/tickets/TCK-00027.yaml"
/// );
/// ```
#[must_use]
pub fn ticket_yaml_path(main_worktree_path: &Path, ticket_id: &str) -> PathBuf {
    main_worktree_path
        .join("documents")
        .join("work")
        .join("tickets")
        .join(format!("{ticket_id}.yaml"))
}

/// Gets the current git branch name.
///
/// # Arguments
///
/// * `sh` - The xshell Shell instance
///
/// # Returns
///
/// Returns the name of the current branch.
///
/// # Errors
///
/// Returns an error if not on a branch (e.g., detached HEAD) or not in a git
/// repo.
pub fn current_branch(sh: &Shell) -> Result<String> {
    let branch = cmd!(sh, "git rev-parse --abbrev-ref HEAD")
        .read()
        .context("Failed to get current branch name")?;

    if branch == "HEAD" {
        bail!("Not on a branch (detached HEAD state)");
    }

    Ok(branch)
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    #[test]
    fn test_validate_ticket_branch_valid_with_rfc() {
        let result = validate_ticket_branch("ticket/RFC-0002/TCK-00027");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, Some("RFC-0002".to_string()));
        assert_eq!(branch.ticket_id, "TCK-00027");
    }

    #[test]
    fn test_validate_ticket_branch_valid_standalone() {
        let result = validate_ticket_branch("ticket/TCK-00049");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, None);
        assert_eq!(branch.ticket_id, "TCK-00049");
    }

    #[test]
    fn test_validate_ticket_branch_valid_different_ids() {
        let result = validate_ticket_branch("ticket/RFC-0001/TCK-00001");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, Some("RFC-0001".to_string()));
        assert_eq!(branch.ticket_id, "TCK-00001");
    }

    #[test]
    fn test_validate_ticket_branch_valid_high_numbers() {
        let result = validate_ticket_branch("ticket/RFC-9999/TCK-99999");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, Some("RFC-9999".to_string()));
        assert_eq!(branch.ticket_id, "TCK-99999");
    }

    #[test]
    fn test_validate_ticket_branch_invalid_missing_prefix() {
        let result = validate_ticket_branch("RFC-0002/TCK-00027");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid branch name"));
    }

    #[test]
    fn test_validate_ticket_branch_invalid_wrong_rfc_format() {
        let result = validate_ticket_branch("ticket/RFC-02/TCK-00027");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_invalid_wrong_ticket_format() {
        let result = validate_ticket_branch("ticket/RFC-0002/TCK-027");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_invalid_main_branch() {
        let result = validate_ticket_branch("main");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_invalid_feature_branch() {
        let result = validate_ticket_branch("feature/add-logging");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_invalid_extra_suffix() {
        let result = validate_ticket_branch("ticket/RFC-0002/TCK-00027/extra");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_invalid_lowercase() {
        let result = validate_ticket_branch("ticket/rfc-0002/tck-00027");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ticket_branch_standalone_high_number() {
        let result = validate_ticket_branch("ticket/TCK-99999");
        assert!(result.is_ok());
        let branch = result.unwrap();
        assert_eq!(branch.rfc_id, None);
        assert_eq!(branch.ticket_id, "TCK-99999");
    }

    #[test]
    fn test_ticket_yaml_path() {
        let main = PathBuf::from("/home/user/project");
        let path = ticket_yaml_path(&main, "TCK-00027");
        assert_eq!(
            path,
            PathBuf::from("/home/user/project/documents/work/tickets/TCK-00027.yaml")
        );
    }

    #[test]
    fn test_ticket_yaml_path_different_ticket() {
        let main = PathBuf::from("/opt/apm2");
        let path = ticket_yaml_path(&main, "TCK-00001");
        assert_eq!(
            path,
            PathBuf::from("/opt/apm2/documents/work/tickets/TCK-00001.yaml")
        );
    }

    // =============================================================================
    // HEF Projection Feature Flag Tests (TCK-00309)
    // =============================================================================

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_use_hef_projection_env_var() {
        // SERIAL TEST: Modifies environment variables, must be single test

        // 1. Default (unset) -> false
        unsafe { std::env::remove_var(USE_HEF_PROJECTION_ENV) };
        assert!(!use_hef_projection(), "Default should be false");

        // 2. "TRUE" -> true
        unsafe { std::env::set_var(USE_HEF_PROJECTION_ENV, "TRUE") };
        assert!(use_hef_projection(), "TRUE should be true");

        // 3. "true" -> true
        unsafe { std::env::set_var(USE_HEF_PROJECTION_ENV, "true") };
        assert!(use_hef_projection(), "true should be true");

        // 4. "false" -> false
        unsafe { std::env::set_var(USE_HEF_PROJECTION_ENV, "false") };
        assert!(!use_hef_projection(), "false should be false");

        // 5. "0" -> false
        unsafe { std::env::set_var(USE_HEF_PROJECTION_ENV, "0") };
        assert!(!use_hef_projection(), "0 should be false");

        // Cleanup
        unsafe { std::env::remove_var(USE_HEF_PROJECTION_ENV) };
    }

    // =============================================================================
    // Status Write Gating Tests (TCK-00296)
    // =============================================================================

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_is_strict_mode_env_var() {
        // SERIAL TEST: Modifies environment variables

        // 1. Default (unset) -> false
        unsafe { std::env::remove_var(XTASK_STRICT_MODE_ENV) };
        assert!(!is_strict_mode(), "Default should be false");

        // 2. "TRUE" -> true
        unsafe { std::env::set_var(XTASK_STRICT_MODE_ENV, "TRUE") };
        assert!(is_strict_mode(), "TRUE should be true");

        // 3. "true" -> true
        unsafe { std::env::set_var(XTASK_STRICT_MODE_ENV, "true") };
        assert!(is_strict_mode(), "true should be true");

        // 4. "false" -> false
        unsafe { std::env::set_var(XTASK_STRICT_MODE_ENV, "false") };
        assert!(!is_strict_mode(), "false should be false");

        // Cleanup
        unsafe { std::env::remove_var(XTASK_STRICT_MODE_ENV) };
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_allow_status_writes_env_var() {
        // SERIAL TEST: Modifies environment variables

        // 1. Default (unset) -> false
        unsafe { std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV) };
        assert!(!allow_status_writes(), "Default should be false");

        // 2. "TRUE" -> true
        unsafe { std::env::set_var(XTASK_ALLOW_STATUS_WRITES_ENV, "TRUE") };
        assert!(allow_status_writes(), "TRUE should be true");

        // 3. "true" -> true
        unsafe { std::env::set_var(XTASK_ALLOW_STATUS_WRITES_ENV, "true") };
        assert!(allow_status_writes(), "true should be true");

        // 4. "false" -> false
        unsafe { std::env::set_var(XTASK_ALLOW_STATUS_WRITES_ENV, "false") };
        assert!(!allow_status_writes(), "false should be false");

        // Cleanup
        unsafe { std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV) };
    }

    // =============================================================================
    // Status Write Removal Tests (TCK-00297, Stage X3)
    // =============================================================================

    /// IT-00297-01: Verify that direct GitHub status writes are removed.
    ///
    /// Per TCK-00297 (Stage X3), `check_status_write_allowed()` must
    /// unconditionally return `StatusWriteDecision::Removed`, regardless of
    /// any environment variable configuration. This test verifies that status
    /// writes cannot be re-enabled by any combination of flags.
    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn xtask_status_removed() {
        // 1. Default (no env vars set) -> Removed
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV);
        }
        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Removed,
            "Default state must return Removed (TCK-00297)"
        );

        // 2. HEF projection enabled -> still Removed (not SkipHefProjection)
        unsafe {
            std::env::set_var(USE_HEF_PROJECTION_ENV, "true");
        }
        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Removed,
            "HEF projection flag must not override Removed (TCK-00297)"
        );

        // 3. Strict mode enabled -> still Removed (not BlockStrictMode)
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::set_var(XTASK_STRICT_MODE_ENV, "true");
            std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV);
        }
        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Removed,
            "Strict mode must not override Removed (TCK-00297)"
        );

        // 4. Strict mode + allow flag -> still Removed (not Proceed)
        unsafe {
            std::env::set_var(XTASK_STRICT_MODE_ENV, "true");
            std::env::set_var(XTASK_ALLOW_STATUS_WRITES_ENV, "true");
        }
        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Removed,
            "Strict mode + allow flag must not override Removed (TCK-00297)"
        );

        // 5. Non-strict mode + allow flag -> still Removed (not Proceed)
        unsafe {
            std::env::set_var(XTASK_STRICT_MODE_ENV, "false");
            std::env::set_var(XTASK_ALLOW_STATUS_WRITES_ENV, "true");
        }
        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Removed,
            "Non-strict mode + allow must not override Removed (TCK-00297)"
        );

        // 6. All flags set -> still Removed
        unsafe {
            std::env::set_var(USE_HEF_PROJECTION_ENV, "true");
            std::env::set_var(XTASK_STRICT_MODE_ENV, "true");
            std::env::set_var(XTASK_ALLOW_STATUS_WRITES_ENV, "true");
        }
        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Removed,
            "All flags set must still return Removed (TCK-00297)"
        );

        // Cleanup
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV);
        }
    }

    #[test]
    fn test_status_writes_removed_notice_contains_key_phrases() {
        // Verify the removal notice contains all required guidance
        assert!(
            STATUS_WRITES_REMOVED_NOTICE.contains("TCK-00297"),
            "Notice must reference TCK-00297"
        );
        assert!(
            STATUS_WRITES_REMOVED_NOTICE.contains("permanently removed"),
            "Notice must state writes are permanently removed"
        );
        assert!(
            STATUS_WRITES_REMOVED_NOTICE.contains("daemon projection"),
            "Notice must mention daemon projection as replacement"
        );
    }

    // Integration tests that require a real git repo
    #[test]
    fn test_main_worktree_in_git_repo() {
        let sh = Shell::new().expect("Failed to create shell");
        // This test assumes we're running in a git repo
        // Should succeed in the xtask crate directory
        if let Ok(path) = main_worktree(&sh) {
            assert!(path.exists(), "Main worktree path should exist");
        }
        // If not in a git repo, the test passes (CI might not have a repo)
    }

    #[test]
    fn test_current_branch_in_git_repo() {
        let sh = Shell::new().expect("Failed to create shell");
        // Should succeed if we're in a git repo on a branch
        if let Ok(branch) = current_branch(&sh) {
            assert!(!branch.is_empty(), "Branch name should not be empty");
        }
    }

    // =============================================================================
    // Internal Receipt Emission Tests (TCK-00295)
    // =============================================================================

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_emit_internal_from_env() {
        // SERIAL TEST: Modifies environment variables, must be single test

        // 1. Default (unset) -> false
        unsafe { std::env::remove_var(EMIT_INTERNAL_ENV) };
        assert!(
            !emit_internal_from_env(),
            "Default should be false (opt-in)"
        );

        // 2. "TRUE" -> true
        unsafe { std::env::set_var(EMIT_INTERNAL_ENV, "TRUE") };
        assert!(emit_internal_from_env(), "TRUE should be true");

        // 3. "true" -> true
        unsafe { std::env::set_var(EMIT_INTERNAL_ENV, "true") };
        assert!(emit_internal_from_env(), "true should be true");

        // 4. "false" -> false
        unsafe { std::env::set_var(EMIT_INTERNAL_ENV, "false") };
        assert!(!emit_internal_from_env(), "false should be false");

        // 5. "1" -> false (only "true" is accepted)
        unsafe { std::env::set_var(EMIT_INTERNAL_ENV, "1") };
        assert!(
            !emit_internal_from_env(),
            "1 should be false (only 'true' accepted)"
        );

        // Cleanup
        unsafe { std::env::remove_var(EMIT_INTERNAL_ENV) };
    }

    #[test]
    fn test_try_emit_internal_receipt_daemon_not_running() {
        // Test that emission continues gracefully when daemon is not running
        // This tests the non-blocking requirement of TCK-00295
        let result = try_emit_internal_receipt("test.event", b"{}", "test-correlation-id");

        // Should succeed with None (not an error)
        assert!(
            result.is_ok(),
            "Emission should not fail when daemon is unavailable"
        );
        assert!(
            result.unwrap().is_none(),
            "Should return None when daemon is not running"
        );
    }

    // =============================================================================
    // NON-AUTHORITATIVE Banner Tests (TCK-00294)
    // =============================================================================

    #[test]
    fn test_non_authoritative_banner_contains_key_phrases() {
        // Verify the banner contains all required warning phrases
        assert!(
            NON_AUTHORITATIVE_BANNER.contains("NON-AUTHORITATIVE"),
            "Banner must contain 'NON-AUTHORITATIVE'"
        );
        assert!(
            NON_AUTHORITATIVE_BANNER.contains("DEVELOPMENT SCAFFOLDING"),
            "Banner must mention 'DEVELOPMENT SCAFFOLDING'"
        );
        assert!(
            NON_AUTHORITATIVE_BANNER.contains("RFC-0018"),
            "Banner must reference RFC-0018"
        );
        assert!(
            NON_AUTHORITATIVE_BANNER.contains("ledger+CAS"),
            "Banner must mention ledger+CAS verification"
        );
        // TCK-00297: Banner must mention status write removal
        assert!(
            NON_AUTHORITATIVE_BANNER.contains("TCK-00297"),
            "Banner must reference TCK-00297 status write removal"
        );
        assert!(
            NON_AUTHORITATIVE_BANNER.contains("REMOVED"),
            "Banner must state status writes are REMOVED"
        );
    }

    #[test]
    fn test_non_authoritative_banner_is_not_empty() {
        assert!(
            !NON_AUTHORITATIVE_BANNER.is_empty(),
            "Banner must not be empty"
        );
        // Should be a substantial warning, at least 200 characters
        assert!(
            NON_AUTHORITATIVE_BANNER.len() > 200,
            "Banner should be a substantial warning"
        );
    }

    // =============================================================================
    // TCK-00324 Cutover Stage 1 Tests
    // =============================================================================

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_emit_receipt_only_from_env() {
        // SERIAL TEST: Modifies environment variables

        // 1. Default (unset) -> false
        unsafe { std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV) };
        assert!(
            !emit_receipt_only_from_env(),
            "Default should be false (backward compatible)"
        );

        // 2. "TRUE" -> true
        unsafe { std::env::set_var(XTASK_EMIT_RECEIPT_ONLY_ENV, "TRUE") };
        assert!(emit_receipt_only_from_env(), "TRUE should be true");

        // 3. "true" -> true
        unsafe { std::env::set_var(XTASK_EMIT_RECEIPT_ONLY_ENV, "true") };
        assert!(emit_receipt_only_from_env(), "true should be true");

        // 4. "false" -> false
        unsafe { std::env::set_var(XTASK_EMIT_RECEIPT_ONLY_ENV, "false") };
        assert!(!emit_receipt_only_from_env(), "false should be false");

        // Cleanup
        unsafe { std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV) };
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_allow_github_write_from_env() {
        // SERIAL TEST: Modifies environment variables

        // 1. Default (unset) -> false
        unsafe { std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV) };
        assert!(!allow_github_write_from_env(), "Default should be false");

        // 2. "TRUE" -> true
        unsafe { std::env::set_var(XTASK_ALLOW_GITHUB_WRITE_ENV, "TRUE") };
        assert!(allow_github_write_from_env(), "TRUE should be true");

        // 3. "true" -> true
        unsafe { std::env::set_var(XTASK_ALLOW_GITHUB_WRITE_ENV, "true") };
        assert!(allow_github_write_from_env(), "true should be true");

        // 4. "false" -> false
        unsafe { std::env::set_var(XTASK_ALLOW_GITHUB_WRITE_ENV, "false") };
        assert!(!allow_github_write_from_env(), "false should be false");

        // Cleanup
        unsafe { std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV) };
    }

    /// IT-00297-02: Verify that TCK-00324 cutover flags do not override
    /// removal.
    ///
    /// Per TCK-00297 (Stage X3), `check_status_write_allowed()` and
    /// `check_status_write_with_flags()` must unconditionally return
    /// `StatusWriteDecision::Removed`, even when TCK-00324 cutover flags are
    /// set. This test verifies that the cutover flags are superseded.
    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_check_status_write_allowed_emit_receipt_only_superseded() {
        // TCK-00324 emit-receipt-only mode -> still Removed (TCK-00297)
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::set_var(XTASK_EMIT_RECEIPT_ONLY_ENV, "true");
            std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV);
        }

        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Removed,
            "TCK-00324 emit-receipt-only must not override Removed (TCK-00297)"
        );

        // Cleanup
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
            std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV);
        }
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_check_status_write_allowed_emit_receipt_only_with_override_superseded() {
        // TCK-00324 allow-github-write override -> still Removed (TCK-00297)
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::set_var(XTASK_EMIT_RECEIPT_ONLY_ENV, "true");
            std::env::set_var(XTASK_ALLOW_GITHUB_WRITE_ENV, "true");
        }

        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Removed,
            "TCK-00324 allow-github-write must not override Removed (TCK-00297)"
        );

        // Cleanup
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
            std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV);
        }
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_check_status_write_with_flags_all_return_removed() {
        // TCK-00297: CLI flags must not override Removed
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
            std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV);
        }

        // CLI flag emit_receipt_only=true -> still Removed
        assert_eq!(
            check_status_write_with_flags(true, false),
            StatusWriteDecision::Removed,
            "CLI emit_receipt_only=true must not override Removed (TCK-00297)"
        );

        // CLI flag allow_github_write=true -> still Removed
        assert_eq!(
            check_status_write_with_flags(true, true),
            StatusWriteDecision::Removed,
            "CLI allow_github_write=true must not override Removed (TCK-00297)"
        );

        // Both flags false -> still Removed
        assert_eq!(
            check_status_write_with_flags(false, false),
            StatusWriteDecision::Removed,
            "Both flags false must still return Removed (TCK-00297)"
        );

        // Cleanup
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
            std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV);
        }
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_hef_projection_superseded_by_removal() {
        // TCK-00297: HEF projection flag must not override Removed
        unsafe {
            std::env::set_var(USE_HEF_PROJECTION_ENV, "true");
            std::env::set_var(XTASK_EMIT_RECEIPT_ONLY_ENV, "true");
            std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV);
        }

        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Removed,
            "HEF projection must not override Removed (TCK-00297)"
        );

        // HEF projection via CLI flags -> still Removed
        assert_eq!(
            check_status_write_with_flags(true, false),
            StatusWriteDecision::Removed,
            "HEF projection with CLI flags must not override Removed (TCK-00297)"
        );

        // Cleanup
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
            std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV);
        }
    }

    #[test]
    fn test_emit_receipt_only_message_contains_key_phrases() {
        // Verify the emit-receipt-only message contains all required info
        assert!(
            EMIT_RECEIPT_ONLY_MESSAGE.contains("TCK-00324"),
            "Message must mention TCK-00324"
        );
        assert!(
            EMIT_RECEIPT_ONLY_MESSAGE.contains("EMIT-RECEIPT-ONLY"),
            "Message must mention EMIT-RECEIPT-ONLY"
        );
        assert!(
            EMIT_RECEIPT_ONLY_MESSAGE.contains("projection worker"),
            "Message must mention projection worker"
        );
        assert!(
            EMIT_RECEIPT_ONLY_MESSAGE.contains("allow-github-write"),
            "Message must mention allow-github-write override"
        );
    }

    // =============================================================================
    // Cutover Policy Tests (TCK-00408)
    // =============================================================================

    #[test]
    fn test_cutover_policy_is_emit_only() {
        assert!(CutoverPolicy::EmitOnly.is_emit_only());
        assert!(!CutoverPolicy::Legacy.is_emit_only());
    }

    #[test]
    fn test_cutover_policy_env_value() {
        assert_eq!(CutoverPolicy::EmitOnly.env_value(), "emit_only");
        assert_eq!(CutoverPolicy::Legacy.env_value(), "legacy");
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_effective_cutover_policy_default_is_legacy() {
        unsafe {
            std::env::remove_var(XTASK_CUTOVER_POLICY_ENV);
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
        }
        assert_eq!(
            effective_cutover_policy(),
            CutoverPolicy::Legacy,
            "Default cutover policy should be Legacy"
        );
        unsafe {
            std::env::remove_var(XTASK_CUTOVER_POLICY_ENV);
        }
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_effective_cutover_policy_explicit_emit_only() {
        unsafe {
            std::env::set_var(XTASK_CUTOVER_POLICY_ENV, "emit_only");
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
        }
        assert_eq!(
            effective_cutover_policy(),
            CutoverPolicy::EmitOnly,
            "Explicit emit_only policy should be EmitOnly"
        );
        unsafe {
            std::env::remove_var(XTASK_CUTOVER_POLICY_ENV);
        }
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_effective_cutover_policy_inherit_from_receipt_only() {
        unsafe {
            std::env::remove_var(XTASK_CUTOVER_POLICY_ENV);
            std::env::set_var(XTASK_EMIT_RECEIPT_ONLY_ENV, "true");
        }
        assert_eq!(
            effective_cutover_policy(),
            CutoverPolicy::EmitOnly,
            "XTASK_EMIT_RECEIPT_ONLY=true should infer EmitOnly policy"
        );
        unsafe {
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
        }
    }

    /// TCK-00408: CLI --emit-receipt-only flag triggers `EmitOnly` cutover
    /// policy.
    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_effective_cutover_policy_with_cli_flag() {
        unsafe {
            std::env::remove_var(XTASK_CUTOVER_POLICY_ENV);
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
        }
        // CLI flag false, no env vars -> Legacy
        assert_eq!(
            effective_cutover_policy_with_flag(false),
            CutoverPolicy::Legacy,
            "CLI flag false with no env vars should be Legacy"
        );
        // CLI flag true, no env vars -> EmitOnly
        assert_eq!(
            effective_cutover_policy_with_flag(true),
            CutoverPolicy::EmitOnly,
            "CLI flag true should trigger EmitOnly even without env vars"
        );
        // Explicit env var takes precedence over CLI flag=false
        unsafe {
            std::env::set_var(XTASK_CUTOVER_POLICY_ENV, "emit_only");
        }
        assert_eq!(
            effective_cutover_policy_with_flag(false),
            CutoverPolicy::EmitOnly,
            "Explicit env var should override CLI flag=false"
        );
        // Cleanup
        unsafe {
            std::env::remove_var(XTASK_CUTOVER_POLICY_ENV);
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
        }
    }

    /// TCK-00408: Durable acknowledgement fails closed when daemon unavailable.
    #[test]
    fn test_emit_projection_receipt_with_ack_fails_closed() {
        let result = emit_projection_receipt_with_ack(
            "test_op",
            "owner/repo",
            "abc123",
            r#"{"test": true}"#,
            "test-correlation",
        );
        assert!(
            result.is_err(),
            "emit_projection_receipt_with_ack must fail closed when no durable ack is returned"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("TCK-00408"),
            "Error must reference TCK-00408"
        );
    }
}
