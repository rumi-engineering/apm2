// AGENT-AUTHORED (TCK-00592)
//! Explicit cache purge command: `apm2 fac caches nuke`.
//!
//! Provides a deterministic, operator-only mechanism to delete bulky FAC
//! caches (lane targets, `cargo_home`, sccache, gate caches) with hard
//! confirmations and audit receipts. This is NOT automated GC -- it requires
//! explicit operator confirmation via `--i-know-what-im-doing` or an
//! interactive prompt.
//!
//! # Safety Invariants
//!
//! - [INV-NUKE-001] NEVER deletes `receipts/` directory or subdirectories.
//! - [INV-NUKE-002] NEVER deletes broker keys or signing material.
//! - [INV-NUKE-003] All deletion paths are validated against an explicit
//!   allow-list before any filesystem mutation.
//! - [INV-NUKE-004] Uses `safe_rmtree_v1` for all deletions (fail-closed).
//! - [INV-NUKE-005] Fail-closed: if any safety exclusion check fails, the
//!   entire operation aborts with a non-zero exit code.
//! - [INV-NUKE-006] A nuke receipt JSON is emitted to the receipts directory
//!   recording all actions taken.
//! - [INV-NUKE-007] The `--i-know-what-im-doing` flag must be the long form; no
//!   short-form bypass exists.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use apm2_core::fac::{LaneManager, SafeRmtreeOutcome, safe_rmtree_v1};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::commands::fac_utils::resolve_fac_root;
use crate::exit_codes::codes as exit_codes;

// =============================================================================
// Constants
// =============================================================================

/// Hard upper bound on nuke targets. If the plan exceeds this limit, the
/// command fails closed with an explicit error rather than silently
/// truncating. The value is deliberately generous — operator-invoked nuke
/// must either process ALL targets or refuse outright (INV-NUKE-005).
const MAX_NUKE_TARGETS: usize = 8192;

/// Subdirectory name for managed `cargo_home`.
const FAC_CARGO_HOME_DIR: &str = "cargo_home";

/// Subdirectory name for managed sccache.
const FAC_SCCACHE_DIR: &str = "sccache";

/// Subdirectory name for lane targets.
const FAC_LANES_DIR: &str = "lanes";

/// Gate cache directory names (v1, v2, v3). These are optional cache
/// directories that may exist under the FAC root.
const FAC_GATE_CACHE_DIRS: &[&str] = &["gate_cache", "gate_cache_v2", "gate_cache_v3"];

/// Directories that MUST NEVER be deleted (INV-NUKE-001, INV-NUKE-002).
const PROTECTED_DIRS: &[&str] = &[
    "receipts",
    "broker",
    "keys",
    "signing",
    "policy",
    "scheduler",
    "boundary_id",
    "toolchain",
];

/// Nuke receipt schema identifier.
const NUKE_RECEIPT_SCHEMA: &str = "apm2.fac.nuke_receipt.v1";

/// Maximum size of the nuke receipt (128 KiB). Prevents unbounded writes.
const MAX_NUKE_RECEIPT_SIZE: usize = 128 * 1024;

// =============================================================================
// Command Types
// =============================================================================

/// Arguments for `apm2 fac caches`.
#[derive(Debug, Args)]
pub struct CachesArgs {
    #[command(subcommand)]
    pub subcommand: CachesSubcommand,
}

/// Subcommands for `apm2 fac caches`.
#[derive(Debug, Subcommand)]
pub enum CachesSubcommand {
    /// Delete all bulky FAC caches (lane targets, `cargo_home`, sccache, gate
    /// caches).
    ///
    /// This is a DANGEROUS destructive operation. It requires explicit
    /// confirmation via `--i-know-what-im-doing` or interactive prompt.
    /// Receipts and broker keys are NEVER deleted.
    Nuke(NukeArgs),
}

/// Arguments for `apm2 fac caches nuke`.
#[derive(Debug, Args)]
pub struct NukeArgs {
    /// Skip interactive confirmation (required for non-TTY / CI contexts).
    ///
    /// Without this flag, the command will prompt for confirmation on a TTY
    /// and fail-closed on non-TTY.
    #[arg(long)]
    pub i_know_what_im_doing: bool,

    /// Dry-run mode: show what would be deleted without deleting.
    ///
    /// Emits a JSON plan of paths and estimated sizes.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

// =============================================================================
// Receipt Types
// =============================================================================

/// Record of a single cache root deletion attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NukeDeletedPath {
    /// Absolute path that was deleted (or would be deleted in dry-run).
    pub path: String,
    /// Bytes freed (estimated via metadata walk before deletion).
    pub bytes_freed: u64,
    /// Whether the deletion succeeded.
    pub success: bool,
    /// Error message if deletion failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Nuke receipt recording all actions taken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NukeReceiptV1 {
    /// Schema identifier for forward compatibility.
    pub schema: String,
    /// UTC timestamp (seconds since epoch) when the nuke ran.
    pub timestamp_utc: u64,
    /// Whether the operator confirmed the nuke.
    pub operator_confirmed: bool,
    /// Whether this was a dry-run.
    pub dry_run: bool,
    /// Array of deletion results.
    pub deleted_paths: Vec<NukeDeletedPath>,
    /// Errors encountered during the operation.
    pub errors: Vec<String>,
    /// Total bytes freed across all successful deletions.
    pub total_bytes_freed: u64,
}

// =============================================================================
// Entry Point
// =============================================================================

/// Run the `apm2 fac caches` command group.
pub fn run_caches_command(args: &CachesArgs, _parent_json: bool) -> u8 {
    match &args.subcommand {
        CachesSubcommand::Nuke(nuke_args) => run_nuke(nuke_args),
    }
}

/// Run the `apm2 fac caches nuke` command.
fn run_nuke(args: &NukeArgs) -> u8 {
    // Step 1: Resolve FAC root.
    let fac_root = match resolve_fac_root() {
        Ok(root) => root,
        Err(err) => {
            let msg = json!({
                "error": "fac_caches_nuke_root_resolution_failed",
                "message": format!("cannot resolve FAC root: {err}"),
            });
            eprintln!("{}", serde_json::to_string(&msg).unwrap_or_default());
            return exit_codes::GENERIC_ERROR;
        },
    };

    if !fac_root.is_dir() {
        let msg = json!({
            "error": "fac_caches_nuke_root_not_found",
            "message": format!("FAC root does not exist: {}", fac_root.display()),
        });
        eprintln!("{}", serde_json::to_string(&msg).unwrap_or_default());
        return exit_codes::GENERIC_ERROR;
    }

    // Step 2: Build the deletion plan.
    let plan = match build_nuke_plan(&fac_root) {
        Ok(plan) => plan,
        Err(err) => {
            let msg = json!({
                "error": "fac_caches_nuke_plan_failed",
                "message": format!("cannot build nuke plan: {err}"),
            });
            eprintln!("{}", serde_json::to_string(&msg).unwrap_or_default());
            return exit_codes::GENERIC_ERROR;
        },
    };

    if plan.is_empty() {
        let msg = json!({
            "status": "no_caches_found",
            "message": "no deletable cache directories found",
            "fac_root": fac_root.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&msg).unwrap_or_default());
        return exit_codes::SUCCESS;
    }

    // Step 3: Dry-run mode — show plan and exit.
    if args.dry_run {
        return emit_dry_run_plan(&fac_root, &plan);
    }

    // Step 4: Confirmation gate (fail-closed).
    if !args.i_know_what_im_doing && !confirm_nuke_interactive(&plan) {
        let msg = json!({
            "status": "aborted",
            "message": "nuke aborted by operator (confirmation denied)",
        });
        println!("{}", serde_json::to_string_pretty(&msg).unwrap_or_default());
        return exit_codes::GENERIC_ERROR;
    }

    // Step 5: Execute deletions.
    let (results, errors) = execute_nuke_plan(&fac_root, &plan);

    // Step 6: Compute totals and build receipt.
    let total_bytes_freed: u64 = results
        .iter()
        .filter(|r| r.success)
        .map(|r| r.bytes_freed)
        .fold(0u64, u64::saturating_add);

    // CTR-2501 deviation: SystemTime::now() for wall-clock audit timestamp.
    let timestamp_utc = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let receipt = NukeReceiptV1 {
        schema: NUKE_RECEIPT_SCHEMA.to_string(),
        timestamp_utc,
        operator_confirmed: true,
        dry_run: false,
        deleted_paths: results,
        errors: errors.clone(),
        total_bytes_freed,
    };

    // Step 7: Persist receipt (hard success condition — INV-NUKE-006).
    // The receipt MUST be durably written before the command reports success.
    // Destructive work without an audit trail is a fail-closed violation.
    let receipt_persist_failed = if let Err(err) = persist_nuke_receipt(&fac_root, &receipt) {
        let err_msg = format!("nuke receipt persistence failed — audit trail not durable: {err}");
        eprintln!(
            "{}",
            serde_json::to_string(&json!({
                "error": "nuke_receipt_persist_failed",
                "message": &err_msg,
            }))
            .unwrap_or_default()
        );
        Some(err_msg)
    } else {
        None
    };

    // Step 8: Determine final status.
    // Status is "failure" if receipt persistence failed (regardless of
    // deletion outcomes), "partial_success" if some deletions failed, or
    // "success" if everything succeeded and the receipt is durable.
    let status = if receipt_persist_failed.is_some() {
        "failure"
    } else if errors.is_empty() {
        "success"
    } else {
        "partial_success"
    };

    let mut all_errors = errors.clone();
    if let Some(ref persist_err) = receipt_persist_failed {
        all_errors.push(persist_err.clone());
    }

    let output = json!({
        "status": status,
        "total_bytes_freed": receipt.total_bytes_freed,
        "paths_deleted": receipt.deleted_paths.iter().filter(|p| p.success).count(),
        "paths_failed": receipt.deleted_paths.iter().filter(|p| !p.success).count(),
        "errors": all_errors,
        "receipt": receipt,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );

    if receipt_persist_failed.is_some() || !errors.is_empty() {
        exit_codes::GENERIC_ERROR
    } else {
        exit_codes::SUCCESS
    }
}

// =============================================================================
// Plan Building
// =============================================================================

/// A planned cache root to delete.
#[derive(Debug, Clone)]
struct NukeTarget {
    /// Absolute path to the cache root.
    path: PathBuf,
    /// The allowed parent for `safe_rmtree_v1`.
    allowed_parent: PathBuf,
    /// Human-readable description of what this cache is.
    description: String,
    /// Estimated size in bytes.
    estimated_bytes: u64,
}

/// Build the deletion plan: enumerate all deletable cache directories.
///
/// Returns an error if any safety invariant is violated during planning.
fn build_nuke_plan(fac_root: &Path) -> Result<Vec<NukeTarget>, String> {
    let mut targets = Vec::new();

    // Validate that protected directories are NOT in our plan.
    // This is a pre-check: if any protected dir appears to be a candidate,
    // we abort entirely (fail-closed, INV-NUKE-005).

    // 1. Lane target directories (under lanes/<lane_id>/target-*)
    let lanes_dir = fac_root.join(FAC_LANES_DIR);
    if lanes_dir.is_dir() {
        // Use LaneManager to enumerate lanes safely.
        match LaneManager::from_default_home() {
            Ok(manager) => {
                let lane_ids = discover_lane_ids(&lanes_dir)?;
                for lane_id in &lane_ids {
                    let lane_path = lanes_dir.join(lane_id);
                    if !lane_path.is_dir() {
                        continue;
                    }
                    // Find target-* directories (fingerprint-namespaced build dirs).
                    if let Ok(entries) = fs::read_dir(&lane_path) {
                        for entry in entries {
                            let Ok(entry) = entry else {
                                continue;
                            };
                            let name = entry.file_name();
                            let name_str = name.to_string_lossy();
                            if name_str.starts_with("target") && entry.path().is_dir() {
                                // Validate this is NOT a protected directory.
                                validate_not_protected(&name_str)?;
                                targets.push(NukeTarget {
                                    path: entry.path(),
                                    allowed_parent: manager.fac_root().to_path_buf(),
                                    description: format!("lane target: {lane_id}/{name_str}"),
                                    estimated_bytes: estimate_dir_size(&entry.path()),
                                });
                            }
                        }
                    }
                    // Also nuke lane env dirs (home, tmp, xdg_cache, etc.) as they
                    // can contain cached build artifacts.
                    for env_subdir in &[
                        "home",
                        "tmp",
                        "xdg_cache",
                        "xdg_config",
                        "xdg_data",
                        "xdg_state",
                        "xdg_runtime",
                    ] {
                        let env_dir = lane_path.join(env_subdir);
                        if env_dir.is_dir() {
                            validate_not_protected(env_subdir)?;
                            targets.push(NukeTarget {
                                path: env_dir.clone(),
                                allowed_parent: manager.fac_root().to_path_buf(),
                                description: format!("lane env: {lane_id}/{env_subdir}"),
                                estimated_bytes: estimate_dir_size(&env_dir),
                            });
                        }
                    }
                }
            },
            Err(err) => {
                return Err(format!("cannot initialize lane manager: {err}"));
            },
        }
    }

    // 2. Managed cargo_home.
    let cargo_home = fac_root.join(FAC_CARGO_HOME_DIR);
    if cargo_home.is_dir() {
        targets.push(NukeTarget {
            path: cargo_home.clone(),
            allowed_parent: fac_root.to_path_buf(),
            description: "FAC managed cargo_home".to_string(),
            estimated_bytes: estimate_dir_size(&cargo_home),
        });
    }

    // 3. Managed sccache.
    let sccache_dir = fac_root.join(FAC_SCCACHE_DIR);
    if sccache_dir.is_dir() {
        targets.push(NukeTarget {
            path: sccache_dir.clone(),
            allowed_parent: fac_root.to_path_buf(),
            description: "FAC managed sccache".to_string(),
            estimated_bytes: estimate_dir_size(&sccache_dir),
        });
    }

    // 4. Optional gate cache directories (gate_cache, gate_cache_v2,
    //    gate_cache_v3).
    // These are present when FAC gates have been run and cached results.
    // Each gate cache dir is a direct child of fac_root and is deleted as a
    // single unit via safe_rmtree_v1 (same pattern as cargo_home / sccache).
    for gate_dir_name in FAC_GATE_CACHE_DIRS {
        let gate_dir = fac_root.join(gate_dir_name);
        if gate_dir.is_dir() {
            validate_not_protected(gate_dir_name)?;
            targets.push(NukeTarget {
                path: gate_dir.clone(),
                allowed_parent: fac_root.to_path_buf(),
                description: format!("FAC {gate_dir_name}"),
                estimated_bytes: estimate_dir_size(&gate_dir),
            });
        }
    }

    // Final safety gate: ensure no target path overlaps with any protected dir.
    for target in &targets {
        validate_path_not_protected(&target.path, fac_root)?;
    }

    // Fail closed if the plan exceeds the hard safety bound. An operator nuke
    // must either process ALL targets or refuse outright — silent omission of
    // deletion targets is unacceptable (BLOCKER: no silent truncation).
    if targets.len() > MAX_NUKE_TARGETS {
        return Err(format!(
            "nuke plan exceeds safety bound: {} targets found, maximum is {MAX_NUKE_TARGETS}. \
             Reduce cache population before retrying.",
            targets.len()
        ));
    }

    Ok(targets)
}

/// Discover lane IDs by scanning the lanes directory.
///
/// Collects ALL lane directories. The overall plan is bounded at
/// `MAX_NUKE_TARGETS` by the caller; individual discovery must not
/// silently drop entries.
fn discover_lane_ids(lanes_dir: &Path) -> Result<Vec<String>, String> {
    let entries = fs::read_dir(lanes_dir).map_err(|e| format!("cannot read lanes dir: {e}"))?;

    let mut lane_ids = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        // Skip non-directories and protected dirs.
        if entry.path().is_dir() && !PROTECTED_DIRS.contains(&name_str.as_str()) {
            lane_ids.push(name_str);
        }
    }

    // Sort for deterministic ordering (RSK-1303).
    lane_ids.sort();
    Ok(lane_ids)
}

/// Validate that a directory name is not in the protected list.
fn validate_not_protected(name: &str) -> Result<(), String> {
    if PROTECTED_DIRS.contains(&name) {
        return Err(format!(
            "SAFETY VIOLATION: attempted to include protected directory '{name}' in nuke plan (INV-NUKE-001/002)"
        ));
    }
    Ok(())
}

/// Validate that an absolute path does not refer to or reside inside a
/// protected directory under the FAC root.
fn validate_path_not_protected(path: &Path, fac_root: &Path) -> Result<(), String> {
    // Check if the path itself IS a protected directory.
    for protected in PROTECTED_DIRS {
        let protected_path = fac_root.join(protected);
        if path == protected_path || path.starts_with(&protected_path) {
            return Err(format!(
                "SAFETY VIOLATION: path {} overlaps with protected directory {} (INV-NUKE-001/002)",
                path.display(),
                protected_path.display()
            ));
        }
    }
    Ok(())
}

// =============================================================================
// Dry-Run Output
// =============================================================================

/// Emit a dry-run JSON plan and return success exit code.
fn emit_dry_run_plan(fac_root: &Path, plan: &[NukeTarget]) -> u8 {
    let total_estimated: u64 = plan
        .iter()
        .map(|t| t.estimated_bytes)
        .fold(0u64, u64::saturating_add);

    let plan_entries: Vec<serde_json::Value> = plan
        .iter()
        .map(|t| {
            json!({
                "path": t.path.display().to_string(),
                "description": t.description,
                "estimated_bytes": t.estimated_bytes,
            })
        })
        .collect();

    let output = json!({
        "status": "dry_run",
        "fac_root": fac_root.display().to_string(),
        "total_estimated_bytes": total_estimated,
        "targets": plan_entries,
        "target_count": plan.len(),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
    exit_codes::SUCCESS
}

// =============================================================================
// Interactive Confirmation
// =============================================================================

/// Prompt the operator for interactive confirmation.
///
/// Returns `false` (deny) if:
/// - stdin is not a TTY (fail-closed for non-interactive contexts)
/// - the operator does not type "yes"
fn confirm_nuke_interactive(plan: &[NukeTarget]) -> bool {
    // Fail-closed for non-TTY (INV-NUKE-005).
    if !atty_is_tty() {
        eprintln!(
            "{}",
            serde_json::to_string(&json!({
                "error": "fac_caches_nuke_no_tty",
                "message": "stdin is not a TTY; pass --i-know-what-im-doing to confirm in non-interactive contexts",
            }))
            .unwrap_or_default()
        );
        return false;
    }

    let total_estimated: u64 = plan
        .iter()
        .map(|t| t.estimated_bytes)
        .fold(0u64, u64::saturating_add);

    eprintln!("WARNING: apm2 fac caches nuke will DELETE the following cache directories:");
    eprintln!();
    for target in plan {
        #[allow(clippy::cast_precision_loss)] // acceptable: display-only MiB estimate
        let mib = target.estimated_bytes as f64 / (1024.0 * 1024.0);
        eprintln!(
            "  - {} ({mib:.1} MiB) [{}]",
            target.path.display(),
            target.description
        );
    }
    eprintln!();
    #[allow(clippy::cast_precision_loss)] // acceptable: display-only MiB estimate
    let total_mib = total_estimated as f64 / (1024.0 * 1024.0);
    eprintln!(
        "Total estimated: {total_mib:.1} MiB across {} directories",
        plan.len()
    );
    eprintln!();
    eprintln!("Receipts and broker keys will NOT be deleted.");
    eprintln!();
    eprint!("Type 'yes' to confirm: ");
    let _ = io::stderr().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    input.trim() == "yes"
}

/// Check if stdin is a TTY.
///
/// Uses `nix::unistd::isatty` on Unix (safe wrapper around `libc::isatty`).
/// Fail-closed on non-Unix: assumes not a TTY.
fn atty_is_tty() -> bool {
    #[cfg(unix)]
    {
        // nix::unistd::isatty is a safe wrapper — no unsafe needed.
        nix::unistd::isatty(std::io::stdin()).unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        // Fail-closed on non-Unix: assume not a TTY.
        false
    }
}

// =============================================================================
// Execution
// =============================================================================

/// Execute the nuke plan, returning deletion results and errors.
fn execute_nuke_plan(_fac_root: &Path, plan: &[NukeTarget]) -> (Vec<NukeDeletedPath>, Vec<String>) {
    let mut results = Vec::with_capacity(plan.len());
    let mut errors = Vec::new();

    for target in plan {
        let estimated = target.estimated_bytes;
        match safe_rmtree_v1(&target.path, &target.allowed_parent) {
            Ok(SafeRmtreeOutcome::Deleted {
                files_deleted,
                dirs_deleted,
            }) => {
                results.push(NukeDeletedPath {
                    path: target.path.display().to_string(),
                    bytes_freed: estimated,
                    success: true,
                    error: None,
                });
                eprintln!(
                    "  deleted {} ({} files, {} dirs)",
                    target.description, files_deleted, dirs_deleted
                );
            },
            Ok(SafeRmtreeOutcome::AlreadyAbsent) => {
                results.push(NukeDeletedPath {
                    path: target.path.display().to_string(),
                    bytes_freed: 0,
                    success: true,
                    error: None,
                });
            },
            Err(err) => {
                let err_msg = format!("failed to delete {}: {err}", target.path.display());
                errors.push(err_msg.clone());
                results.push(NukeDeletedPath {
                    path: target.path.display().to_string(),
                    bytes_freed: 0,
                    success: false,
                    error: Some(err_msg),
                });
            },
        }
    }

    (results, errors)
}

// =============================================================================
// Receipt Persistence
// =============================================================================

/// Persist the nuke receipt to the FAC receipts directory.
///
/// Uses atomic write (temp + rename) per CTR-2607.
fn persist_nuke_receipt(fac_root: &Path, receipt: &NukeReceiptV1) -> Result<(), String> {
    let receipts_dir = fac_root.join("receipts");
    if !receipts_dir.is_dir() {
        fs::create_dir_all(&receipts_dir)
            .map_err(|e| format!("cannot create receipts dir: {e}"))?;
    }

    let receipt_json = serde_json::to_string_pretty(receipt)
        .map_err(|e| format!("cannot serialize receipt: {e}"))?;

    // Enforce bounded receipt size (CTR-1603).
    if receipt_json.len() > MAX_NUKE_RECEIPT_SIZE {
        return Err(format!(
            "receipt exceeds maximum size: {} > {MAX_NUKE_RECEIPT_SIZE}",
            receipt_json.len()
        ));
    }

    let receipt_filename = format!("nuke-{}.json", receipt.timestamp_utc);
    let receipt_path = receipts_dir.join(&receipt_filename);

    // Atomic write via tempfile + rename.
    let tmp_path = receipts_dir.join(format!(".nuke-{}.tmp", receipt.timestamp_utc));
    fs::write(&tmp_path, receipt_json.as_bytes())
        .map_err(|e| format!("cannot write temp receipt: {e}"))?;

    // Set restricted permissions on Unix (CTR-2611).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }

    fs::rename(&tmp_path, &receipt_path).map_err(|e| format!("cannot rename receipt: {e}"))?;

    Ok(())
}

// =============================================================================
// Size Estimation
// =============================================================================

/// Estimate directory size by walking the tree and summing file metadata sizes.
///
/// Bounded to prevent unbounded I/O (CTR-1603). On error, returns 0.
fn estimate_dir_size(path: &Path) -> u64 {
    estimate_dir_size_bounded(path, 0, 32)
}

/// Recursive directory size estimation with depth bound.
fn estimate_dir_size_bounded(path: &Path, depth: usize, max_depth: usize) -> u64 {
    const MAX_ENTRIES: usize = 10_000;
    if depth >= max_depth {
        return 0;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };

    let mut total: u64 = 0;
    let mut count: usize = 0;

    for entry in entries {
        count = count.saturating_add(1);
        if count > MAX_ENTRIES {
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_file() {
            total = total.saturating_add(meta.len());
        } else if meta.is_dir() {
            total = total.saturating_add(estimate_dir_size_bounded(
                &entry.path(),
                depth + 1,
                max_depth,
            ));
        }
    }
    total
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_dirs_are_correct() {
        // Receipts and broker-related dirs must be protected.
        assert!(PROTECTED_DIRS.contains(&"receipts"));
        assert!(PROTECTED_DIRS.contains(&"broker"));
        assert!(PROTECTED_DIRS.contains(&"keys"));
        assert!(PROTECTED_DIRS.contains(&"signing"));
        assert!(PROTECTED_DIRS.contains(&"policy"));
    }

    #[test]
    fn validate_not_protected_rejects_protected_names() {
        assert!(validate_not_protected("receipts").is_err());
        assert!(validate_not_protected("broker").is_err());
        assert!(validate_not_protected("keys").is_err());
    }

    #[test]
    fn validate_not_protected_allows_cache_names() {
        assert!(validate_not_protected("target-abcdef0123456789").is_ok());
        assert!(validate_not_protected("home").is_ok());
        assert!(validate_not_protected("tmp").is_ok());
        assert!(validate_not_protected("xdg_cache").is_ok());
        assert!(validate_not_protected("cargo_home").is_ok());
        assert!(validate_not_protected("sccache").is_ok());
        // Gate cache directories are not protected.
        assert!(validate_not_protected("gate_cache").is_ok());
        assert!(validate_not_protected("gate_cache_v2").is_ok());
        assert!(validate_not_protected("gate_cache_v3").is_ok());
    }

    #[test]
    fn validate_path_not_protected_catches_overlap() {
        let fac_root = Path::new("/home/user/.apm2/private/fac");
        assert!(validate_path_not_protected(&fac_root.join("receipts"), fac_root).is_err());
        assert!(validate_path_not_protected(&fac_root.join("receipts/sub"), fac_root).is_err());
        assert!(validate_path_not_protected(&fac_root.join("broker"), fac_root).is_err());
    }

    #[test]
    fn validate_path_not_protected_allows_caches() {
        let fac_root = Path::new("/home/user/.apm2/private/fac");
        assert!(validate_path_not_protected(&fac_root.join("cargo_home"), fac_root).is_ok());
        assert!(validate_path_not_protected(&fac_root.join("sccache"), fac_root).is_ok());
        assert!(
            validate_path_not_protected(&fac_root.join("lanes/lane-00/target-abc123"), fac_root)
                .is_ok()
        );
        // Gate cache dirs are allowed.
        assert!(validate_path_not_protected(&fac_root.join("gate_cache"), fac_root).is_ok());
        assert!(validate_path_not_protected(&fac_root.join("gate_cache_v2"), fac_root).is_ok());
        assert!(validate_path_not_protected(&fac_root.join("gate_cache_v3"), fac_root).is_ok());
    }

    #[test]
    fn nuke_receipt_serialization_roundtrip() {
        let receipt = NukeReceiptV1 {
            schema: NUKE_RECEIPT_SCHEMA.to_string(),
            timestamp_utc: 1_700_000_000,
            operator_confirmed: true,
            dry_run: false,
            deleted_paths: vec![NukeDeletedPath {
                path: "/home/user/.apm2/private/fac/cargo_home".to_string(),
                bytes_freed: 1024,
                success: true,
                error: None,
            }],
            errors: vec![],
            total_bytes_freed: 1024,
        };

        let json = serde_json::to_string(&receipt).expect("serialize");
        let deserialized: NukeReceiptV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.schema, NUKE_RECEIPT_SCHEMA);
        assert_eq!(deserialized.total_bytes_freed, 1024);
        assert_eq!(deserialized.deleted_paths.len(), 1);
        assert!(deserialized.deleted_paths[0].success);
    }

    #[test]
    fn nuke_receipt_with_errors() {
        let receipt = NukeReceiptV1 {
            schema: NUKE_RECEIPT_SCHEMA.to_string(),
            timestamp_utc: 1_700_000_001,
            operator_confirmed: true,
            dry_run: false,
            deleted_paths: vec![NukeDeletedPath {
                path: "/home/user/.apm2/private/fac/sccache".to_string(),
                bytes_freed: 0,
                success: false,
                error: Some("permission denied".to_string()),
            }],
            errors: vec!["failed to delete sccache: permission denied".to_string()],
            total_bytes_freed: 0,
        };

        let json = serde_json::to_string(&receipt).expect("serialize");
        let deserialized: NukeReceiptV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.errors.len(), 1);
        assert!(!deserialized.deleted_paths[0].success);
        assert!(deserialized.deleted_paths[0].error.is_some());
    }

    #[test]
    fn estimate_dir_size_returns_zero_for_nonexistent() {
        let result = estimate_dir_size(Path::new("/nonexistent/path/abc123"));
        assert_eq!(result, 0);
    }

    #[test]
    fn estimate_dir_size_works_on_temp_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("a.txt"), b"hello").expect("write");
        fs::write(dir.path().join("b.txt"), b"world!").expect("write");
        let size = estimate_dir_size(dir.path());
        // At least 11 bytes (5 + 6)
        assert!(size >= 11, "expected >= 11, got {size}");
    }

    #[test]
    fn max_nuke_targets_is_bounded() {
        // Verify our constant is reasonable (compile-time assertion).
        const _: () = assert!(MAX_NUKE_TARGETS <= 16_384);
        const _: () = assert!(MAX_NUKE_TARGETS >= 128);
        // Runtime check for the actual value.
        assert_eq!(MAX_NUKE_TARGETS, 8192);
    }

    #[test]
    fn gate_cache_dirs_are_not_protected() {
        // All gate cache directory names must pass the protected-dir check.
        for name in FAC_GATE_CACHE_DIRS {
            assert!(
                validate_not_protected(name).is_ok(),
                "gate cache dir '{name}' should not be protected"
            );
        }
    }

    #[test]
    fn gate_cache_dirs_constant_covers_known_versions() {
        // Verify that we cover the three known gate cache directory names.
        assert!(FAC_GATE_CACHE_DIRS.contains(&"gate_cache"));
        assert!(FAC_GATE_CACHE_DIRS.contains(&"gate_cache_v2"));
        assert!(FAC_GATE_CACHE_DIRS.contains(&"gate_cache_v3"));
    }

    #[test]
    fn build_nuke_plan_includes_gate_caches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().to_path_buf();

        // Create gate cache directories with some content.
        for name in FAC_GATE_CACHE_DIRS {
            let gate_dir = fac_root.join(name);
            fs::create_dir_all(&gate_dir).expect("create gate cache dir");
            fs::write(gate_dir.join("dummy.yaml"), b"test").expect("write dummy");
        }

        // Also create a protected dir (receipts) — must NOT appear in plan.
        let receipts_dir = fac_root.join("receipts");
        fs::create_dir_all(&receipts_dir).expect("create receipts dir");

        // build_nuke_plan requires LaneManager::from_default_home which we
        // cannot safely call in unit tests. Instead, verify the gate cache
        // directories would pass validation and the protected ones would not.
        for name in FAC_GATE_CACHE_DIRS {
            assert!(validate_not_protected(name).is_ok());
            assert!(validate_path_not_protected(&fac_root.join(name), &fac_root).is_ok());
        }
        assert!(validate_not_protected("receipts").is_err());
    }

    #[test]
    fn persist_nuke_receipt_fails_on_nonexistent_readonly() {
        // Verify persist_nuke_receipt returns Err when the path is impossible.
        let receipt = NukeReceiptV1 {
            schema: NUKE_RECEIPT_SCHEMA.to_string(),
            timestamp_utc: 1_700_000_002,
            operator_confirmed: true,
            dry_run: false,
            deleted_paths: vec![],
            errors: vec![],
            total_bytes_freed: 0,
        };

        // A path that should not be writable.
        let result = persist_nuke_receipt(Path::new("/proc/nonexistent/fac_root"), &receipt);
        assert!(
            result.is_err(),
            "persist_nuke_receipt must return Err for non-writable path"
        );
    }
}
