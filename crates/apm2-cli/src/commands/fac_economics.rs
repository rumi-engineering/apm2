// AGENT-AUTHORED (TCK-00584)
//! CLI commands for FAC economics profile management: show, adopt, rollback.
//!
//! Implements `apm2 fac economics {show, adopt, rollback}` per TCK-00584.
//!
//! # Security
//!
//! - Economics profile adoption requires explicit operator action (CLI
//!   invocation).
//! - Adoption validates schema + hash before acceptance.
//! - All reads are bounded (CTR-1603).
//! - Rollback is atomic with receipt emission.
//! - Actor identity is resolved from the calling process environment, not
//!   hard-coded.

use std::io::Read;
use std::path::{Path, PathBuf};

use apm2_core::fac::economics_adoption::{
    MAX_ECONOMICS_PROFILE_SIZE, adopt_economics_profile, adopt_economics_profile_by_hash,
    is_economics_profile_hash_admitted, load_admitted_economics_profile_root, looks_like_digest,
    read_bounded_file, rollback_economics_profile, validate_digest_string,
    validate_economics_profile_bytes,
};
use clap::{Args, Subcommand};

use crate::exit_codes::codes as exit_codes;

// =============================================================================
// Args
// =============================================================================

/// Arguments for `apm2 fac economics`.
#[derive(Debug, Args)]
pub struct EconomicsArgs {
    /// Economics subcommand.
    #[command(subcommand)]
    pub subcommand: EconomicsSubcommand,
}

/// Economics subcommands.
#[derive(Debug, Subcommand)]
pub enum EconomicsSubcommand {
    /// Show the current admitted economics profile and its hash.
    Show(EconomicsShowArgs),
    /// Adopt a new economics profile (atomic, with receipt).
    Adopt(EconomicsAdoptArgs),
    /// Rollback to the previous admitted economics profile (with receipt).
    Rollback(EconomicsRollbackArgs),
}

/// Arguments for `apm2 fac economics show`.
#[derive(Debug, Args)]
pub struct EconomicsShowArgs {
    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac economics adopt`.
#[derive(Debug, Args)]
pub struct EconomicsAdoptArgs {
    /// Hash digest or path to the economics profile file to adopt.
    ///
    /// Accepts one of:
    /// - A `b3-256:<64-hex>` digest string (hash-only adoption).
    /// - A file path to an economics profile (framed or raw JSON).
    /// - `"-"` to read from stdin.
    /// - Omitted to read from stdin.
    pub hash_or_path: Option<String>,

    /// Reason for the adoption (for the receipt).
    #[arg(long, default_value = "operator adoption")]
    pub reason: String,

    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac economics rollback`.
#[derive(Debug, Args)]
pub struct EconomicsRollbackArgs {
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

/// Execute an economics subcommand. Returns a CLI exit code.
pub fn run_economics_command(args: &EconomicsArgs, json_global: bool) -> u8 {
    match &args.subcommand {
        EconomicsSubcommand::Show(show_args) => run_show(show_args, json_global),
        EconomicsSubcommand::Adopt(adopt_args) => run_adopt(adopt_args, json_global),
        EconomicsSubcommand::Rollback(rollback_args) => run_rollback(rollback_args, json_global),
    }
}

// =============================================================================
// Show
// =============================================================================

fn run_show(args: &EconomicsShowArgs, json_global: bool) -> u8 {
    let json = args.json || json_global;
    let fac_root = resolve_fac_root();

    match load_admitted_economics_profile_root(&fac_root) {
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
                println!("Admitted economics profile root:");
                println!("  hash:       {}", root.admitted_profile_hash);
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
                        "status": "no_admitted_economics_profile"
                    })
                );
            } else {
                eprintln!("No admitted economics profile root found: {e}");
                eprintln!(
                    "Adopt a profile with: \
                     apm2 fac economics adopt <path-to-profile>"
                );
            }
            exit_codes::NOT_FOUND
        },
    }
}

// =============================================================================
// Adopt
// =============================================================================

fn run_adopt(args: &EconomicsAdoptArgs, json_global: bool) -> u8 {
    let json = args.json || json_global;
    let fac_root = resolve_fac_root();
    let actor_id = resolve_operator_identity();

    // Route: if the positional argument looks like a `b3-256:` digest,
    // use hash-only adoption. Otherwise, treat as file path / stdin.
    if let Some(ref input) = args.hash_or_path {
        if looks_like_digest(input) {
            return run_adopt_by_hash(input, &fac_root, &actor_id, &args.reason, json);
        }
    }

    // File / stdin path: convert hash_or_path to a Path reference.
    let path_ref: Option<&Path> = args.hash_or_path.as_deref().map(Path::new);

    // Read from path or stdin (CTR-1603 bounded).
    let bytes = match read_profile_input(path_ref) {
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

    // Check if the input is framed (has domain prefix) or raw JSON.
    // If it starts with the economics profile hash domain, treat as
    // framed. Otherwise, try to parse as raw JSON and add the framing.
    let framed_bytes =
        if bytes.starts_with(apm2_core::economics::profile::ECONOMICS_PROFILE_HASH_DOMAIN) {
            bytes
        } else {
            // Assume raw canonical JSON -- add domain prefix.
            let domain = apm2_core::economics::profile::ECONOMICS_PROFILE_HASH_DOMAIN;
            let mut framed = Vec::with_capacity(domain.len() + bytes.len());
            framed.extend_from_slice(domain);
            framed.extend_from_slice(&bytes);
            framed
        };

    // Validate before adoption to give early error.
    if let Err(e) = validate_economics_profile_bytes(&framed_bytes) {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "adopted": false,
                    "error": format!("{e}")
                })
            );
        } else {
            eprintln!("Economics profile validation failed: {e}");
        }
        return exit_codes::VALIDATION_ERROR;
    }

    // Check admission status before attempting adoption.
    if let Ok((_profile, hash)) = validate_economics_profile_bytes(&framed_bytes) {
        if is_economics_profile_hash_admitted(&fac_root, &hash) {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "adopted": false,
                        "error": format!("economics profile already admitted with hash {hash}"),
                        "admitted_profile_hash": hash,
                    })
                );
            } else {
                eprintln!("Economics profile already admitted with hash {hash}");
            }
            return exit_codes::VALIDATION_ERROR;
        }
    }

    match adopt_economics_profile(&fac_root, &framed_bytes, &actor_id, &args.reason) {
        Ok((root, receipt)) => {
            emit_adopt_success(json, &root, &receipt);
            exit_codes::SUCCESS
        },
        Err(e) => {
            emit_adopt_error(json, &e);
            exit_codes::VALIDATION_ERROR
        },
    }
}

/// Handle hash-only adoption: validate digest format, adopt by hash,
/// emit result.
fn run_adopt_by_hash(
    digest: &str,
    fac_root: &Path,
    actor_id: &str,
    reason: &str,
    json: bool,
) -> u8 {
    // Validate digest format first to give clear errors for malformed input.
    if let Err(e) = validate_digest_string(digest) {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "adopted": false,
                    "error": format!("{e}"),
                })
            );
        } else {
            eprintln!("Invalid digest: {e}");
        }
        return exit_codes::VALIDATION_ERROR;
    }

    match adopt_economics_profile_by_hash(fac_root, digest, actor_id, reason) {
        Ok((root, receipt)) => {
            emit_adopt_success(json, &root, &receipt);
            exit_codes::SUCCESS
        },
        Err(e) => {
            emit_adopt_error(json, &e);
            exit_codes::VALIDATION_ERROR
        },
    }
}

/// Emit adoption success output (shared by file and hash adoption paths).
fn emit_adopt_success(
    json: bool,
    root: &apm2_core::fac::economics_adoption::AdmittedEconomicsProfileRootV1,
    receipt: &apm2_core::fac::economics_adoption::EconomicsAdoptionReceiptV1,
) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "adopted": true,
                "admitted_profile_hash": root.admitted_profile_hash,
                "receipt_content_hash": receipt.content_hash,
                "old_digest": receipt.old_digest,
                "action": format!("{}", receipt.action),
            })
        );
    } else {
        println!("Economics profile adopted successfully.");
        println!("  new hash:      {}", root.admitted_profile_hash);
        if !receipt.old_digest.is_empty() {
            println!("  old hash:      {}", receipt.old_digest);
        }
        println!("  receipt hash:  {}", receipt.content_hash);
    }
}

/// Emit adoption error output (shared by file and hash adoption paths).
fn emit_adopt_error(json: bool, e: &apm2_core::fac::economics_adoption::EconomicsAdoptionError) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "adopted": false,
                "error": format!("{e}")
            })
        );
    } else {
        eprintln!("Economics profile adoption failed: {e}");
    }
}

// =============================================================================
// Rollback
// =============================================================================

fn run_rollback(args: &EconomicsRollbackArgs, json_global: bool) -> u8 {
    let json = args.json || json_global;
    let fac_root = resolve_fac_root();
    let actor_id = resolve_operator_identity();

    match rollback_economics_profile(&fac_root, &actor_id, &args.reason) {
        Ok((root, receipt)) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "rolled_back": true,
                        "admitted_profile_hash": root.admitted_profile_hash,
                        "receipt_content_hash": receipt.content_hash,
                        "old_digest": receipt.old_digest,
                        "action": format!("{}", receipt.action),
                    })
                );
            } else {
                println!("Economics profile rolled back successfully.");
                println!("  restored hash: {}", root.admitted_profile_hash);
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
                    serde_json::json!({
                        "rolled_back": false,
                        "error": format!("{e}")
                    })
                );
            } else {
                eprintln!("Economics profile rollback failed: {e}");
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
/// path resolution across all FAC commands.
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
/// the audit trail.
fn resolve_operator_identity() -> String {
    let raw_username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| {
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
    let sanitized: String = raw_username
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
        .collect();

    if sanitized.is_empty() {
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

/// Read economics profile input from a file path or stdin.
///
/// When `path` is `None` or `Some("-")`, reads from stdin with bounded
/// semantics (CTR-1603). Otherwise reads from the given file path.
fn read_profile_input(path: Option<&Path>) -> Result<Vec<u8>, String> {
    match path {
        None => read_bounded_stdin(MAX_ECONOMICS_PROFILE_SIZE),
        Some(p) if p.as_os_str() == "-" => read_bounded_stdin(MAX_ECONOMICS_PROFILE_SIZE),
        Some(p) => cli_read_bounded_file(p, MAX_ECONOMICS_PROFILE_SIZE),
    }
}

/// Read a file with a size cap before reading into memory (CTR-1603).
///
/// Delegates to the shared `read_bounded_file` in
/// `economics_adoption`.
fn cli_read_bounded_file(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    read_bounded_file(path, max_size).map_err(|e| format!("{e}"))
}

/// Read from stdin with bounded semantics (CTR-1603).
///
/// Reads at most `max_size + 1` bytes. Returns an error if the input
/// exceeds `max_size`.
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
        return Err("stdin is empty; provide a profile file via path or pipe".to_string());
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
        let user_part = identity.strip_prefix("operator:").unwrap();
        assert!(
            !user_part.is_empty(),
            "operator identity should have a non-empty user part"
        );
    }

    #[test]
    fn test_cli_read_bounded_file_rejects_symlink() {
        use tempfile::tempdir;

        let tmp = tempdir().expect("tempdir");
        let real_file = tmp.path().join("real.json");
        std::fs::write(&real_file, b"{}").expect("write");

        #[cfg(unix)]
        {
            let symlink = tmp.path().join("link.json");
            std::os::unix::fs::symlink(&real_file, &symlink).expect("symlink");
            let result = cli_read_bounded_file(&symlink, 1024);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                err.contains("symlink rejected") || err.contains("loop"),
                "should reject symlink via O_NOFOLLOW, got: {err}"
            );
        }
    }

    #[test]
    fn test_cli_read_bounded_file_rejects_oversized() {
        use tempfile::tempdir;

        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("big.json");
        std::fs::write(&path, vec![b' '; 100]).expect("write");

        let result = cli_read_bounded_file(&path, 50);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }
}
