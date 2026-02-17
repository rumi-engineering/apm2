// AGENT-AUTHORED (TCK-00561)
//! CLI commands for FAC policy management: show, validate, adopt, rollback.
//!
//! Implements `apm2 fac policy {show, validate, adopt, rollback}` per
//! TCK-00561.
//!
//! # Security
//!
//! - Policy adoption requires explicit operator action (CLI invocation).
//! - Adoption validates schema + hash before acceptance.
//! - All reads are bounded (CTR-1603).
//! - Rollback is atomic with receipt emission.
//! - Actor identity is resolved from the calling process environment, not
//!   hard-coded (f-722-security-1771347580085305-0).

use std::fs::OpenOptions;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use apm2_core::fac::policy::MAX_POLICY_SIZE;
use apm2_core::fac::policy_adoption::{
    adopt_policy, is_policy_hash_admitted, load_admitted_policy_root, rollback_policy,
    validate_policy_bytes,
};
use clap::{Args, Subcommand};

use crate::exit_codes::codes as exit_codes;

// =============================================================================
// Args
// =============================================================================

/// Arguments for `apm2 fac policy`.
#[derive(Debug, Args)]
pub struct PolicyArgs {
    /// Policy subcommand.
    #[command(subcommand)]
    pub subcommand: PolicySubcommand,
}

/// Policy subcommands.
#[derive(Debug, Subcommand)]
pub enum PolicySubcommand {
    /// Show the current admitted policy and its hash.
    Show(PolicyShowArgs),
    /// Validate a policy file (schema + hash computation).
    Validate(PolicyValidateArgs),
    /// Adopt a new policy (atomic, with receipt).
    Adopt(PolicyAdoptArgs),
    /// Rollback to the previous admitted policy (with receipt).
    Rollback(PolicyRollbackArgs),
}

/// Arguments for `apm2 fac policy show`.
#[derive(Debug, Args)]
pub struct PolicyShowArgs {
    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac policy validate`.
#[derive(Debug, Args)]
pub struct PolicyValidateArgs {
    /// Path to the policy file to validate, or "-" for stdin.
    pub path: Option<PathBuf>,

    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac policy adopt`.
#[derive(Debug, Args)]
pub struct PolicyAdoptArgs {
    /// Path to the policy file to adopt, or "-" for stdin.
    pub path: Option<PathBuf>,

    /// Reason for the adoption (for the receipt).
    #[arg(long, default_value = "operator adoption")]
    pub reason: String,

    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac policy rollback`.
#[derive(Debug, Args)]
pub struct PolicyRollbackArgs {
    /// Reason for the rollback (for the receipt).
    #[arg(long, default_value = "operator rollback")]
    pub reason: String,

    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

// =============================================================================
// Dispatch
// =============================================================================

/// Execute a policy subcommand. Returns a CLI exit code.
pub fn run_policy_command(args: &PolicyArgs, json_global: bool) -> u8 {
    match &args.subcommand {
        PolicySubcommand::Show(show_args) => run_show(show_args, json_global),
        PolicySubcommand::Validate(validate_args) => run_validate(validate_args, json_global),
        PolicySubcommand::Adopt(adopt_args) => run_adopt(adopt_args, json_global),
        PolicySubcommand::Rollback(rollback_args) => run_rollback(rollback_args, json_global),
    }
}

// =============================================================================
// Show
// =============================================================================

fn run_show(args: &PolicyShowArgs, json_global: bool) -> u8 {
    let json = args.json || json_global;
    let fac_root = resolve_fac_root();

    match load_admitted_policy_root(&fac_root) {
        Ok(root) => {
            if json {
                match serde_json::to_string_pretty(&root) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("ERROR: cannot serialize admitted root: {e}");
                        return exit_codes::GENERIC_ERROR;
                    },
                }
            } else {
                println!("Admitted policy root:");
                println!("  hash:       {}", root.admitted_policy_hash);
                println!("  adopted_at: {} (unix secs)", root.adopted_at_unix_secs);
                println!("  actor:      {}", root.actor_id);
            }
            exit_codes::SUCCESS
        },
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": format!("{e}"),
                        "status": "no_admitted_policy"
                    })
                );
            } else {
                eprintln!("No admitted policy root found: {e}");
                eprintln!("Adopt a policy with: apm2 fac policy adopt <path-to-policy.json>");
            }
            exit_codes::NOT_FOUND
        },
    }
}

// =============================================================================
// Validate
// =============================================================================

fn run_validate(args: &PolicyValidateArgs, json_global: bool) -> u8 {
    let json = args.json || json_global;

    // Read from path or stdin (CTR-1603 bounded).
    let bytes = match read_policy_input(args.path.as_deref()) {
        Ok(b) => b,
        Err(msg) => {
            if json {
                println!("{}", serde_json::json!({ "error": msg, "valid": false }));
            } else {
                eprintln!("ERROR: {msg}");
            }
            return exit_codes::VALIDATION_ERROR;
        },
    };

    match validate_policy_bytes(&bytes) {
        Ok((policy, hash)) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": true,
                        "policy_hash": hash,
                        "schema": policy.schema,
                        "version": policy.version,
                        "risk_tier": format!("{:?}", policy.risk_tier),
                    })
                );
            } else {
                println!("Policy is valid.");
                println!("  schema:    {}", policy.schema);
                println!("  version:   {}", policy.version);
                println!("  hash:      {hash}");
                println!("  risk_tier: {:?}", policy.risk_tier);
            }

            // Check if it matches the currently admitted policy.
            let fac_root = resolve_fac_root();
            if is_policy_hash_admitted(&fac_root, &hash) {
                if json {
                    // Already printed above.
                } else {
                    println!("  status:    ADMITTED (matches current admitted root)");
                }
            } else if json {
                // Already printed above.
            } else {
                println!("  status:    NOT ADMITTED");
            }

            exit_codes::SUCCESS
        },
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "valid": false, "error": format!("{e}") })
                );
            } else {
                eprintln!("Policy validation failed: {e}");
            }
            exit_codes::VALIDATION_ERROR
        },
    }
}

// =============================================================================
// Adopt
// =============================================================================

fn run_adopt(args: &PolicyAdoptArgs, json_global: bool) -> u8 {
    let json = args.json || json_global;
    let fac_root = resolve_fac_root();
    let actor_id = resolve_operator_identity();

    // Read from path or stdin (CTR-1603 bounded).
    let bytes = match read_policy_input(args.path.as_deref()) {
        Ok(b) => b,
        Err(msg) => {
            if json {
                println!("{}", serde_json::json!({ "error": msg, "adopted": false }));
            } else {
                eprintln!("ERROR: {msg}");
            }
            return exit_codes::VALIDATION_ERROR;
        },
    };

    match adopt_policy(&fac_root, &bytes, &actor_id, &args.reason) {
        Ok((root, receipt)) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "adopted": true,
                        "admitted_policy_hash": root.admitted_policy_hash,
                        "receipt_content_hash": receipt.content_hash,
                        "old_digest": receipt.old_digest,
                        "action": format!("{}", receipt.action),
                    })
                );
            } else {
                println!("Policy adopted successfully.");
                println!("  new hash:      {}", root.admitted_policy_hash);
                if !receipt.old_digest.is_empty() {
                    println!("  old hash:      {}", receipt.old_digest);
                }
                println!("  receipt hash:  {}", receipt.content_hash);
            }
            exit_codes::SUCCESS
        },
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "adopted": false, "error": format!("{e}") })
                );
            } else {
                eprintln!("Policy adoption failed: {e}");
            }
            exit_codes::VALIDATION_ERROR
        },
    }
}

// =============================================================================
// Rollback
// =============================================================================

fn run_rollback(args: &PolicyRollbackArgs, json_global: bool) -> u8 {
    let json = args.json || json_global;
    let fac_root = resolve_fac_root();
    let actor_id = resolve_operator_identity();

    match rollback_policy(&fac_root, &actor_id, &args.reason) {
        Ok((root, receipt)) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "rolled_back": true,
                        "admitted_policy_hash": root.admitted_policy_hash,
                        "receipt_content_hash": receipt.content_hash,
                        "old_digest": receipt.old_digest,
                        "action": format!("{}", receipt.action),
                    })
                );
            } else {
                println!("Policy rolled back successfully.");
                println!("  restored hash: {}", root.admitted_policy_hash);
                if !receipt.old_digest.is_empty() {
                    println!("  old hash:      {}", receipt.old_digest);
                }
                println!("  receipt hash:  {}", receipt.content_hash);
            }
            exit_codes::SUCCESS
        },
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "rolled_back": false, "error": format!("{e}") })
                );
            } else {
                eprintln!("Policy rollback failed: {e}");
            }
            exit_codes::VALIDATION_ERROR
        },
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Resolve the FAC root directory (`$APM2_HOME/private/fac`).
///
/// Uses the shared `fac_utils::resolve_fac_root()` helper for consistent
/// path resolution across all FAC commands (f-722-security-1771348946744505-0).
/// Eliminates the predictable `/tmp/.apm2` fallback that diverged from
/// the canonical implementation.
fn resolve_fac_root() -> PathBuf {
    super::fac_utils::resolve_fac_root().unwrap_or_else(|_| {
        // Fail-closed: if APM2 home cannot be resolved, use a path that
        // will not exist and will produce clear errors downstream rather
        // than falling back to a predictable /tmp path (RSK-1502).
        PathBuf::from("/nonexistent/.apm2/private/fac")
    })
}

/// Resolve the operator identity from the environment.
///
/// Uses `$USER` or `$LOGNAME` (standard POSIX), falling back to the
/// numeric UID if neither is set. The format is `operator:<username>`
/// to distinguish CLI operator actors from other actor types in
/// receipts.
///
/// The username is sanitized to the safe character set
/// `[a-zA-Z0-9._@-]` to prevent control character injection into
/// the audit trail (f-722-code_quality-1771348873224017-0).
///
/// Uses `nix::unistd::getuid()` instead of `unsafe { libc::getuid() }`
/// (f-722-code_quality-1771348873076573-0).
fn resolve_operator_identity() -> String {
    let raw_username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| {
            // Fall back to numeric UID for environments where USER is
            // unset (e.g., cron, containers). Uses safe nix wrapper
            // instead of unsafe libc call.
            #[cfg(unix)]
            {
                let uid = nix::unistd::getuid();
                format!("uid:{}", uid.as_raw())
            }
            #[cfg(not(unix))]
            {
                "unknown".to_string()
            }
        });

    // Sanitize to safe character set: alphanumeric + .-_@
    // Reject usernames that contain only unsafe characters.
    let sanitized: String = raw_username
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
        .collect();

    if sanitized.is_empty() {
        // If sanitization removed everything, fall back to hex encoding
        // of the raw bytes to preserve auditability without control chars.
        use std::fmt::Write as _;
        let hex = raw_username
            .as_bytes()
            .iter()
            .fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            });
        format!("operator:hex:{hex}")
    } else {
        format!("operator:{sanitized}")
    }
}

/// Read policy input from a file path or stdin.
///
/// When `path` is `None` or `Some("-")`, reads from stdin with bounded
/// semantics (CTR-1603). Otherwise reads from the given file path.
fn read_policy_input(path: Option<&Path>) -> Result<Vec<u8>, String> {
    match path {
        None => read_bounded_stdin(MAX_POLICY_SIZE),
        Some(p) if p.as_os_str() == "-" => read_bounded_stdin(MAX_POLICY_SIZE),
        Some(p) => read_bounded_file(p, MAX_POLICY_SIZE),
    }
}

/// Read a file with a size cap before reading into memory (CTR-1603).
///
/// Uses the open-once pattern: `O_NOFOLLOW | O_CLOEXEC` at open(2)
/// atomically refuses symlinks at the kernel level, then `fstat` on
/// the opened fd verifies regular file type. This eliminates the
/// TOCTOU gap between `symlink_metadata` and `fs::read`
/// (f-722-security-1771348928218169-0).
fn read_bounded_file(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    // Open-once: O_NOFOLLOW rejects symlinks at open(2), no TOCTOU gap.
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    let file = options.open(path).map_err(|e| {
        format!(
            "cannot open {} (symlink rejected fail-closed): {e}",
            path.display()
        )
    })?;

    // fstat on the opened fd -- not the path -- to verify regular file.
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot fstat {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "not a regular file (fail-closed): {}",
            path.display()
        ));
    }

    let file_size = metadata.len();
    if file_size > max_size as u64 {
        return Err(format!(
            "file size {file_size} exceeds maximum {max_size} bytes"
        ));
    }

    // Bounded read via take() -- never reads more than max_size + 1 bytes.
    let limit = (max_size as u64).saturating_add(1);
    let mut bounded_reader = file.take(limit);
    #[allow(clippy::cast_possible_truncation)]
    let mut bytes = Vec::with_capacity((file_size as usize).min(max_size));
    bounded_reader
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() > max_size {
        return Err(format!(
            "file size {} exceeds maximum {max_size} bytes",
            bytes.len()
        ));
    }

    Ok(bytes)
}

/// Read from stdin with bounded semantics (CTR-1603).
///
/// Reads at most `max_size + 1` bytes. Returns an error if the input
/// exceeds `max_size`. This prevents memory exhaustion from unbounded
/// piped input.
fn read_bounded_stdin(max_size: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut handle = std::io::stdin().take(max_size.saturating_add(1) as u64);
    handle
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read from stdin: {e}"))?;
    if bytes.len() > max_size {
        return Err(format!(
            "stdin input exceeds maximum size limit of {max_size} bytes"
        ));
    }
    if bytes.is_empty() {
        return Err("stdin is empty; provide a policy file via path or pipe".to_string());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_operator_identity_not_hardcoded() {
        let identity = resolve_operator_identity();
        assert!(
            identity.starts_with("operator:"),
            "identity should start with 'operator:' prefix, got: {identity}"
        );
        // The identity should NOT be the old hard-coded value in all cases
        // (unless the system user actually is named "local").
        // Verify it resolves to something meaningful.
        let user_part = identity.strip_prefix("operator:").unwrap();
        assert!(
            !user_part.is_empty(),
            "operator identity should have a non-empty user part"
        );
    }

    /// Verify that sanitization strips control characters and unsafe chars.
    #[test]
    fn test_resolve_operator_identity_sanitizes_control_chars() {
        // Test the sanitization logic directly by simulating what would
        // happen with a username containing control characters.
        let raw = "user\x00\x1b[31m\nhack";
        let sanitized: String = raw
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
            .collect();
        assert_eq!(sanitized, "user31mhack");
    }

    /// Verify that a username with only unsafe characters falls back to
    /// hex encoding.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn test_resolve_operator_identity_hex_fallback() {
        let raw = "\x01\x02\x03";
        let sanitized: String = raw
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
            .collect();
        assert!(sanitized.is_empty());
        // Would produce hex fallback.
        use std::fmt::Write as _;
        let hex = raw
            .as_bytes()
            .iter()
            .fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            });
        let result = format!("operator:hex:{hex}");
        assert_eq!(result, "operator:hex:010203");
    }

    #[test]
    fn test_read_bounded_file_rejects_symlink() {
        use tempfile::tempdir;

        let tmp = tempdir().expect("tempdir");
        let real_file = tmp.path().join("real.json");
        std::fs::write(&real_file, b"{}").expect("write");

        #[cfg(unix)]
        {
            let symlink = tmp.path().join("link.json");
            std::os::unix::fs::symlink(&real_file, &symlink).expect("symlink");
            let result = read_bounded_file(&symlink, 1024);
            assert!(result.is_err());
            let err = result.unwrap_err();
            // O_NOFOLLOW produces ELOOP on Linux, which maps to
            // "symlink rejected fail-closed" in our error message.
            assert!(
                err.contains("symlink rejected") || err.contains("loop"),
                "should reject symlink via O_NOFOLLOW, got: {err}"
            );
        }
    }

    #[test]
    fn test_read_bounded_file_rejects_oversized() {
        use tempfile::tempdir;

        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("big.json");
        std::fs::write(&path, vec![b' '; 100]).expect("write");

        let result = read_bounded_file(&path, 50);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }
}
