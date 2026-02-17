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

use std::fs;
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
    /// Path to the policy file to validate.
    pub path: PathBuf,

    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac policy adopt`.
#[derive(Debug, Args)]
pub struct PolicyAdoptArgs {
    /// Path to the policy file to adopt.
    pub path: PathBuf,

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

    // Bounded read (CTR-1603).
    let bytes = match read_bounded_file(&args.path, MAX_POLICY_SIZE) {
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

    // Bounded read (CTR-1603).
    let bytes = match read_bounded_file(&args.path, MAX_POLICY_SIZE) {
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

    match adopt_policy(&fac_root, &bytes, "operator:local", &args.reason) {
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

    match rollback_policy(&fac_root, "operator:local", &args.reason) {
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
fn resolve_fac_root() -> PathBuf {
    apm2_core::github::resolve_apm2_home()
        .unwrap_or_else(|| PathBuf::from("/tmp/.apm2"))
        .join("private")
        .join("fac")
}

/// Read a file with a size cap before reading into memory (CTR-1603).
///
/// Uses `symlink_metadata` to avoid following symlinks.
fn read_bounded_file(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    let meta =
        fs::symlink_metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;

    if meta.file_type().is_symlink() {
        return Err(format!("refusing to follow symlink at {}", path.display()));
    }

    let file_size = meta.len();
    if file_size > max_size as u64 {
        return Err(format!(
            "file size {file_size} exceeds maximum {max_size} bytes"
        ));
    }

    fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}
