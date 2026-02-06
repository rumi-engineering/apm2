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
}

/// Determines whether a GitHub status write should proceed.
///
/// Per TCK-00296, TCK-00309, and TCK-00324, this function implements the
/// decision logic for GitHub status writes:
///
/// 1. If `USE_HEF_PROJECTION=true`: Skip (daemon handles projection).
/// 2. If `XTASK_EMIT_RECEIPT_ONLY=true` and `XTASK_ALLOW_GITHUB_WRITE!=true`:
///    Emit receipt only (TCK-00324 cutover stage 1).
/// 3. If `XTASK_STRICT_MODE=true` and `XTASK_ALLOW_STATUS_WRITES!=true`: Block.
/// 4. Otherwise: Proceed (non-strict mode preserves existing behavior).
///
/// # Returns
///
/// - `StatusWriteDecision::SkipHefProjection` - Status write should be skipped
///   (HEF projection is enabled).
/// - `StatusWriteDecision::EmitReceiptOnly` - Emit receipt only, do NOT write
///   directly (TCK-00324 cutover).
/// - `StatusWriteDecision::BlockStrictMode` - Status write is blocked (strict
///   mode without explicit allow).
/// - `StatusWriteDecision::Proceed` - Status write may proceed.
///
/// # Example
///
/// ```ignore
/// use crate::util::{check_status_write_allowed, StatusWriteDecision};
///
/// match check_status_write_allowed() {
///     StatusWriteDecision::SkipHefProjection => {
///         println!("[HEF] Skipping status write");
///         return Ok(());
///     }
///     StatusWriteDecision::EmitReceiptOnly => {
///         println!("[CUTOVER] Emitting receipt only, no direct write");
///         emit_projection_request_receipt(...)?;
///         return Ok(());
///     }
///     StatusWriteDecision::BlockStrictMode => {
///         return Err(anyhow::anyhow!(
///             "Status writes blocked in strict mode. Set XTASK_ALLOW_STATUS_WRITES=true to allow."
///         ));
///     }
///     StatusWriteDecision::Proceed => {
///         // Continue with status write
///     }
/// }
/// ```
pub fn check_status_write_allowed() -> StatusWriteDecision {
    // TCK-00309: HEF projection takes precedence
    if use_hef_projection() {
        return StatusWriteDecision::SkipHefProjection;
    }

    // TCK-00324: Emit-receipt-only mode (cutover stage 1)
    // If enabled AND allow-github-write is NOT set, emit receipt only
    if emit_receipt_only_from_env() && !allow_github_write_from_env() {
        return StatusWriteDecision::EmitReceiptOnly;
    }

    // TCK-00296: Strict mode blocks without explicit allow
    if is_strict_mode() && !allow_status_writes() {
        return StatusWriteDecision::BlockStrictMode;
    }

    StatusWriteDecision::Proceed
}

/// Extended check for GitHub writes with CLI flag override.
///
/// This function extends `check_status_write_allowed` with CLI flag support
/// for the TCK-00324 cutover flags.
///
/// # Arguments
///
/// * `emit_receipt_only_flag` - CLI --emit-receipt-only flag
/// * `allow_github_write_flag` - CLI --allow-github-write flag
///
/// # Returns
///
/// Same as `check_status_write_allowed`, but CLI flags take precedence over
/// environment variables.
pub fn check_status_write_with_flags(
    emit_receipt_only_flag: bool,
    allow_github_write_flag: bool,
) -> StatusWriteDecision {
    // TCK-00309: HEF projection takes precedence over everything
    if use_hef_projection() {
        return StatusWriteDecision::SkipHefProjection;
    }

    // TCK-00324: CLI flags take precedence over env vars
    let emit_receipt_only = emit_receipt_only_flag || emit_receipt_only_from_env();
    let allow_github_write = allow_github_write_flag || allow_github_write_from_env();

    // If emit-receipt-only is active AND allow-github-write is NOT set
    if emit_receipt_only && !allow_github_write {
        return StatusWriteDecision::EmitReceiptOnly;
    }

    // TCK-00296: Strict mode blocks without explicit allow
    if is_strict_mode() && !allow_status_writes() {
        return StatusWriteDecision::BlockStrictMode;
    }

    StatusWriteDecision::Proceed
}

/// Warning message printed in non-strict mode before status writes.
///
/// Per TCK-00296, non-strict mode preserves existing behavior but prints a
/// warning to remind operators that status writes are development scaffolding.
pub const NON_STRICT_MODE_WARNING: &str = r"
  [WARNING] Status writes enabled in non-strict mode.
  For fail-closed behavior, set XTASK_STRICT_MODE=true.
  Then, explicitly allow writes with XTASK_ALLOW_STATUS_WRITES=true.
";

/// Prints warning message for non-strict mode status writes.
///
/// Per TCK-00296, this function prints a warning to stderr when status writes
/// proceed in non-strict mode. This reminds operators that:
/// - Status writes are development scaffolding
/// - Strict mode provides fail-closed security
/// - Explicit opt-in is available via `XTASK_ALLOW_STATUS_WRITES`
pub fn print_non_strict_mode_warning() {
    // Only print warning if NOT in strict mode (strict mode has explicit allow)
    if !is_strict_mode() {
        eprintln!("{NON_STRICT_MODE_WARNING}");
    }
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
// Non-Authoritative Banner
// =============================================================================

/// NON-AUTHORITATIVE banner text for xtask status-writing operations.
///
/// This banner must be printed before any GitHub status check writes to make
/// clear that xtask outputs are development scaffolding, NOT the source of
/// truth for the HEF (Holonic Evidence Framework) pipeline.
///
/// Per RFC-0018 REQ-HEF-0001: "Pulse plane is non-authoritative" - status
/// writes from xtask are hints only and must never be used as authoritative
/// admission, gate, lease, or secret-backed decision signals.
///
/// See: TCK-00294 (Stage X0 of xtask authority reduction)
pub const NON_AUTHORITATIVE_BANNER: &str = r"
================================================================================
                          NON-AUTHORITATIVE OUTPUT
================================================================================
  This xtask command writes GitHub status checks as DEVELOPMENT SCAFFOLDING.
  These statuses are NOT the source of truth for the HEF evidence pipeline.

  Per RFC-0018: Pulse-plane signals are lossy hints only. Consumers must verify
  via ledger+CAS before acting on any gate, admission, or authorization decision.

  For authoritative evidence, use the daemon's projection system (when available).
================================================================================
";

/// Print the NON-AUTHORITATIVE banner to stdout.
///
/// Call this function before any GitHub status check API writes to ensure
/// operators understand that xtask outputs are non-authoritative scaffolding.
///
/// # Example
///
/// ```ignore
/// use crate::util::print_non_authoritative_banner;
///
/// // Before writing status checks
/// print_non_authoritative_banner();
/// set_status_check(&sh, &pr_info, &sha, "success", "All checks passed", None)?;
/// ```
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

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_check_status_write_allowed_hef_projection() {
        // HEF projection takes precedence over all other flags
        unsafe {
            std::env::set_var(USE_HEF_PROJECTION_ENV, "true");
            std::env::set_var(XTASK_STRICT_MODE_ENV, "false");
            std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV);
        }

        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::SkipHefProjection,
            "HEF projection should skip status writes"
        );

        // Even with strict mode enabled, HEF projection takes precedence
        unsafe {
            std::env::set_var(USE_HEF_PROJECTION_ENV, "true");
            std::env::set_var(XTASK_STRICT_MODE_ENV, "true");
        }
        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::SkipHefProjection,
            "HEF projection should take precedence over strict mode"
        );

        // Cleanup
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV);
        }
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_check_status_write_allowed_strict_mode_blocked() {
        // Strict mode without allow flag should block
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::set_var(XTASK_STRICT_MODE_ENV, "true");
            std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV);
        }

        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::BlockStrictMode,
            "Strict mode without allow flag should block"
        );

        // Strict mode with allow flag explicitly false should still block
        unsafe {
            std::env::set_var(XTASK_ALLOW_STATUS_WRITES_ENV, "false");
        }
        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::BlockStrictMode,
            "Strict mode with allow=false should block"
        );

        // Cleanup
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV);
        }
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_check_status_write_allowed_strict_mode_with_allow() {
        // Strict mode with allow flag should proceed
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::set_var(XTASK_STRICT_MODE_ENV, "true");
            std::env::set_var(XTASK_ALLOW_STATUS_WRITES_ENV, "true");
        }

        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Proceed,
            "Strict mode with allow flag should proceed"
        );

        // Cleanup
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV);
        }
    }

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_check_status_write_allowed_non_strict_mode() {
        // Non-strict mode (default) should always proceed
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV);
        }

        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Proceed,
            "Non-strict mode should proceed"
        );

        // Non-strict mode should proceed even without allow flag
        unsafe {
            std::env::set_var(XTASK_STRICT_MODE_ENV, "false");
        }
        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Proceed,
            "Explicit non-strict mode should proceed"
        );

        // Cleanup
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_ALLOW_STATUS_WRITES_ENV);
        }
    }

    #[test]
    fn test_non_strict_mode_warning_contains_key_phrases() {
        // Verify the warning contains all required guidance
        assert!(
            NON_STRICT_MODE_WARNING.contains("XTASK_STRICT_MODE"),
            "Warning must mention XTASK_STRICT_MODE"
        );
        assert!(
            NON_STRICT_MODE_WARNING.contains("XTASK_ALLOW_STATUS_WRITES"),
            "Warning must mention XTASK_ALLOW_STATUS_WRITES"
        );
        assert!(
            NON_STRICT_MODE_WARNING.contains("fail-closed"),
            "Warning must mention fail-closed behavior"
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

    #[test]
    #[serial]
    #[allow(unsafe_code)]
    fn test_check_status_write_allowed_emit_receipt_only() {
        // Test emit-receipt-only mode (TCK-00324)
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::set_var(XTASK_EMIT_RECEIPT_ONLY_ENV, "true");
            std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV);
        }

        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::EmitReceiptOnly,
            "Emit-receipt-only mode should return EmitReceiptOnly"
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
    fn test_check_status_write_allowed_emit_receipt_only_with_override() {
        // Test that allow-github-write overrides emit-receipt-only
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::set_var(XTASK_EMIT_RECEIPT_ONLY_ENV, "true");
            std::env::set_var(XTASK_ALLOW_GITHUB_WRITE_ENV, "true");
        }

        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::Proceed,
            "Allow-github-write should override emit-receipt-only"
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
    fn test_check_status_write_with_flags_cli_overrides_env() {
        // Test that CLI flags take precedence over env vars
        unsafe {
            std::env::remove_var(USE_HEF_PROJECTION_ENV);
            std::env::remove_var(XTASK_STRICT_MODE_ENV);
            std::env::remove_var(XTASK_EMIT_RECEIPT_ONLY_ENV);
            std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV);
        }

        // CLI flag emit_receipt_only=true should activate emit-receipt-only mode
        assert_eq!(
            check_status_write_with_flags(true, false),
            StatusWriteDecision::EmitReceiptOnly,
            "CLI emit_receipt_only=true should return EmitReceiptOnly"
        );

        // CLI flag allow_github_write=true should override emit-receipt-only
        assert_eq!(
            check_status_write_with_flags(true, true),
            StatusWriteDecision::Proceed,
            "CLI allow_github_write=true should override emit-receipt-only"
        );

        // Both flags false should proceed (default behavior)
        assert_eq!(
            check_status_write_with_flags(false, false),
            StatusWriteDecision::Proceed,
            "Both flags false should proceed (default)"
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
    fn test_hef_projection_takes_precedence_over_cutover() {
        // HEF projection should take precedence over emit-receipt-only
        unsafe {
            std::env::set_var(USE_HEF_PROJECTION_ENV, "true");
            std::env::set_var(XTASK_EMIT_RECEIPT_ONLY_ENV, "true");
            std::env::remove_var(XTASK_ALLOW_GITHUB_WRITE_ENV);
        }

        assert_eq!(
            check_status_write_allowed(),
            StatusWriteDecision::SkipHefProjection,
            "HEF projection should take precedence over emit-receipt-only"
        );

        // HEF projection should also take precedence via CLI flags
        assert_eq!(
            check_status_write_with_flags(true, false),
            StatusWriteDecision::SkipHefProjection,
            "HEF projection should take precedence over CLI flags"
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
}
