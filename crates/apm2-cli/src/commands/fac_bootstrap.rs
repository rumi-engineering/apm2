// AGENT-AUTHORED
//! `apm2 fac bootstrap` — one-shot compute-host provisioning.
//!
//! Creates the required `$APM2_HOME/private/fac/**` directory tree with
//! correct permissions (0o700), writes a minimal default `FacPolicyV1` (safe
//! no-secrets posture), initializes lanes, optionally installs systemd
//! services, and runs doctor checks to verify host readiness.
//!
//! # Design
//!
//! - **Idempotent**: safe to re-run without destroying existing state. Existing
//!   policy files and lane profiles are left untouched.
//! - **Fail-closed**: exits non-zero with actionable output when the host
//!   cannot support `FESv1`.
//! - **No secrets**: bootstrap never creates, reads, or leaks secrets.
//!   Credential mounts are stubs only.
//! - **`--dry-run`**: shows planned filesystem and systemd actions without
//!   mutating anything.
//!
//! # Security Invariants
//!
//! - [INV-BOOT-001] All directories are created with 0o700 permissions
//!   (CTR-2611). No TOCTOU window between create and chmod.
//! - [INV-BOOT-002] Policy files are written with 0o600 permissions.
//! - [INV-BOOT-003] Existing state is never destroyed — bootstrap is
//!   additive-only.
//! - [INV-BOOT-004] Doctor checks run after provisioning and gate the exit
//!   code.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use apm2_core::fac::policy::FacPolicyV1;
use apm2_core::fac::{LaneManager, persist_policy};
use serde::Serialize;

use crate::exit_codes::codes as exit_codes;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of planned actions to collect in dry-run mode.
/// Prevents unbounded memory growth from adversarial lane counts.
const MAX_PLANNED_ACTIONS: usize = 256;

/// Subdirectories under `$APM2_HOME/private/fac/` that bootstrap creates.
const FAC_SUBDIRS: &[&str] = &[
    "lanes",
    "queue",
    "queue/pending",
    "queue/claimed",
    "queue/completed",
    "queue/cancelled",
    "queue/denied",
    "queue/quarantine",
    "receipts",
    "locks",
    "locks/lanes",
    "evidence",
    "repo_mirror",
    "cargo_home",
    "broker",
    "broker/time_envelopes",
    "broker/horizons",
    "scheduler",
    "policy",
    "blobs",
];

/// Subdirectories under `$APM2_HOME/private/` (above fac).
const PRIVATE_SUBDIRS: &[&str] = &["creds"];

// =============================================================================
// Types
// =============================================================================

/// Arguments for `apm2 fac bootstrap`.
#[allow(clippy::struct_excessive_bools)] // CLI flags are naturally boolean.
#[derive(Debug, clap::Args)]
pub struct BootstrapArgs {
    /// Show planned actions without mutating the filesystem.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Install and enable user-mode systemd services for local development.
    #[arg(long, default_value_t = false, conflicts_with = "system")]
    pub user: bool,

    /// Install and enable system-mode systemd services under a dedicated
    /// service user.
    #[arg(long, default_value_t = false, conflicts_with = "user")]
    pub system: bool,

    /// Emit JSON output for this command.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// A planned or completed bootstrap action for reporting.
#[derive(Debug, Clone, Serialize)]
struct BootstrapAction {
    /// Category of the action.
    kind: &'static str,
    /// Human-readable description.
    description: String,
    /// Whether the action was skipped (item already exists).
    skipped: bool,
}

/// Result of the bootstrap operation.
#[allow(clippy::struct_excessive_bools)] // Receipt fields mirror distinct operational phases.
#[derive(Debug, Serialize)]
struct BootstrapReceipt {
    schema: &'static str,
    apm2_home: String,
    fac_root: String,
    dry_run: bool,
    actions: Vec<BootstrapAction>,
    dirs_created: usize,
    dirs_existing: usize,
    policy_written: bool,
    lanes_initialized: bool,
    services_installed: bool,
    doctor_passed: bool,
    doctor_checks: Vec<DoctorCheckSummary>,
}

#[derive(Debug, Serialize)]
struct DoctorCheckSummary {
    name: String,
    status: String,
    message: String,
}

// =============================================================================
// Implementation
// =============================================================================

/// Entry point for `apm2 fac bootstrap`.
pub fn run_bootstrap(args: &BootstrapArgs, operator_socket: &Path, config_path: &Path) -> u8 {
    let json_output = args.json;

    // Resolve APM2_HOME.
    let apm2_home = match resolve_apm2_home() {
        Ok(h) => h,
        Err(msg) => {
            return output_error(json_output, "bootstrap_home_error", &msg);
        },
    };

    let private_dir = apm2_home.join("private");
    let fac_root = private_dir.join("fac");

    let mut actions: Vec<BootstrapAction> = Vec::with_capacity(MAX_PLANNED_ACTIONS);
    let mut dirs_created: usize = 0;
    let mut dirs_existing: usize = 0;

    if args.dry_run {
        // Dry-run: collect planned actions without mutation.
        plan_directories(&apm2_home, &private_dir, &fac_root, &mut actions);
        plan_policy(&fac_root, &mut actions);
        plan_lanes(&mut actions);
        if args.user || args.system {
            plan_services(args.user, &mut actions);
        }
        plan_doctor(&mut actions);

        let receipt = BootstrapReceipt {
            schema: "apm2.fac.bootstrap_receipt.v1",
            apm2_home: apm2_home.display().to_string(),
            fac_root: fac_root.display().to_string(),
            dry_run: true,
            actions,
            dirs_created: 0,
            dirs_existing: 0,
            policy_written: false,
            lanes_initialized: false,
            services_installed: false,
            doctor_passed: false,
            doctor_checks: Vec::new(),
        };

        print_receipt(&receipt, json_output);
        return exit_codes::SUCCESS;
    }

    // ── Phase 1: Create directory tree ──────────────────────────────────
    match create_directory_tree(
        &apm2_home,
        &private_dir,
        &fac_root,
        &mut actions,
        &mut dirs_created,
        &mut dirs_existing,
    ) {
        Ok(()) => {},
        Err(msg) => {
            return output_error(json_output, "bootstrap_dir_error", &msg);
        },
    }

    // ── Phase 2: Write default policy ───────────────────────────────────
    let policy_written = match write_default_policy(&fac_root, &mut actions) {
        Ok(written) => written,
        Err(msg) => {
            return output_error(json_output, "bootstrap_policy_error", &msg);
        },
    };

    // ── Phase 3: Initialize lanes ───────────────────────────────────────
    let lanes_initialized = match initialize_lanes(&mut actions) {
        Ok(init) => init,
        Err(msg) => {
            return output_error(json_output, "bootstrap_lane_error", &msg);
        },
    };

    // ── Phase 4: Install services (optional) ────────────────────────────
    let services_installed = if args.user || args.system {
        match install_services(args.user, &mut actions) {
            Ok(installed) => installed,
            Err(msg) => {
                return output_error(json_output, "bootstrap_service_error", &msg);
            },
        }
    } else {
        false
    };

    // ── Phase 5: Run doctor checks ──────────────────────────────────────
    let (doctor_passed, doctor_checks) =
        run_doctor_checks(operator_socket, config_path, &mut actions);

    let receipt = BootstrapReceipt {
        schema: "apm2.fac.bootstrap_receipt.v1",
        apm2_home: apm2_home.display().to_string(),
        fac_root: fac_root.display().to_string(),
        dry_run: false,
        actions,
        dirs_created,
        dirs_existing,
        policy_written,
        lanes_initialized,
        services_installed,
        doctor_passed,
        doctor_checks,
    };

    print_receipt(&receipt, json_output);

    if doctor_passed {
        exit_codes::SUCCESS
    } else {
        exit_codes::GENERIC_ERROR
    }
}

// =============================================================================
// Directory Creation
// =============================================================================

fn create_directory_tree(
    apm2_home: &Path,
    private_dir: &Path,
    fac_root: &Path,
    actions: &mut Vec<BootstrapAction>,
    dirs_created: &mut usize,
    dirs_existing: &mut usize,
) -> Result<(), String> {
    // Create $APM2_HOME
    create_dir_idempotent(apm2_home, actions, dirs_created, dirs_existing)?;

    // Create $APM2_HOME/private
    create_dir_idempotent(private_dir, actions, dirs_created, dirs_existing)?;

    // Create $APM2_HOME/private/creds and other private subdirs
    for subdir in PRIVATE_SUBDIRS {
        let path = private_dir.join(subdir);
        create_dir_idempotent(&path, actions, dirs_created, dirs_existing)?;
    }

    // Create $APM2_HOME/private/fac
    create_dir_idempotent(fac_root, actions, dirs_created, dirs_existing)?;

    // Create all FAC subdirectories
    for subdir in FAC_SUBDIRS {
        if actions.len() >= MAX_PLANNED_ACTIONS {
            return Err(format!(
                "exceeded maximum planned actions ({MAX_PLANNED_ACTIONS}); \
                 possible configuration error"
            ));
        }
        let path = fac_root.join(subdir);
        create_dir_idempotent(&path, actions, dirs_created, dirs_existing)?;
    }

    Ok(())
}

/// Create a directory with 0o700 permissions if it does not already exist.
///
/// Uses `DirBuilder` with mode set at create-time to avoid TOCTOU window
/// between create and chmod (CTR-2611).
fn create_dir_idempotent(
    path: &Path,
    actions: &mut Vec<BootstrapAction>,
    created: &mut usize,
    existing: &mut usize,
) -> Result<(), String> {
    // Check if path already exists using lstat (symlink_metadata) to avoid
    // following symlinks (INV-BOOT-001).
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.is_dir() {
                *existing += 1;
                actions.push(BootstrapAction {
                    kind: "create_dir",
                    description: format!("directory already exists: {}", path.display()),
                    skipped: true,
                });
                return Ok(());
            }
            // Path exists but is not a directory — fail closed.
            return Err(format!(
                "path exists but is not a directory: {}",
                path.display()
            ));
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Does not exist — create it below.
        },
        Err(e) => {
            return Err(format!("cannot stat {}: {e}", path.display()));
        },
    }

    // Create directory with restrictive permissions at create-time.
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|e| format!("cannot create directory {}: {e}", path.display()))?;

    *created += 1;
    actions.push(BootstrapAction {
        kind: "create_dir",
        description: format!("created directory: {} (mode 0700)", path.display()),
        skipped: false,
    });

    Ok(())
}

// =============================================================================
// Policy
// =============================================================================

fn write_default_policy(
    fac_root: &Path,
    actions: &mut Vec<BootstrapAction>,
) -> Result<bool, String> {
    let policy_path = fac_root.join("policy").join("fac_policy.v1.json");

    // Idempotent: do not overwrite existing policy.
    if policy_path.exists() {
        actions.push(BootstrapAction {
            kind: "write_policy",
            description: format!("policy already exists: {} (skipped)", policy_path.display()),
            skipped: true,
        });
        return Ok(false);
    }

    let policy = FacPolicyV1::default_policy();
    let written_path = persist_policy(fac_root, &policy)?;

    actions.push(BootstrapAction {
        kind: "write_policy",
        description: format!(
            "wrote default FacPolicyV1: {} (safe no-secrets posture)",
            written_path.display()
        ),
        skipped: false,
    });

    Ok(true)
}

// =============================================================================
// Lane Initialization
// =============================================================================

fn initialize_lanes(actions: &mut Vec<BootstrapAction>) -> Result<bool, String> {
    let manager = LaneManager::from_default_home()
        .map_err(|e| format!("failed to initialize lane manager: {e}"))?;

    let receipt = manager
        .init_lanes()
        .map_err(|e| format!("lane initialization failed: {e}"))?;

    let total = receipt.lanes_created.len() + receipt.lanes_existing.len();
    let created = receipt.lanes_created.len();
    let existing = receipt.lanes_existing.len();

    actions.push(BootstrapAction {
        kind: "init_lanes",
        description: format!("lane pool: {total} lanes ({created} created, {existing} existing)"),
        skipped: created == 0,
    });

    Ok(created > 0)
}

// =============================================================================
// Service Installation
// =============================================================================

fn install_services(user_mode: bool, actions: &mut Vec<BootstrapAction>) -> Result<bool, String> {
    let scope = if user_mode { "user" } else { "system" };
    let source_dir = if user_mode {
        "contrib/systemd/user"
    } else {
        "contrib/systemd"
    };

    let target_dir = if user_mode {
        // ~/.config/systemd/user/
        let base_dirs = directories::BaseDirs::new().ok_or_else(|| {
            "cannot resolve home directory for user systemd unit installation".to_string()
        })?;
        base_dirs
            .home_dir()
            .join(".config")
            .join("systemd")
            .join("user")
    } else {
        PathBuf::from("/etc/systemd/system")
    };

    // Find the repo root to locate contrib/ templates.
    let repo_root = find_repo_root().ok_or_else(|| {
        format!(
            "cannot find repository root for systemd unit templates; \
             expected {source_dir}/ in ancestor directory. \
             Remediation: run bootstrap from within the apm2 repository"
        )
    })?;

    let units = &[
        "apm2-daemon.service",
        "apm2-daemon.socket",
        "apm2-worker.service",
    ];

    // Ensure target directory exists.
    if !target_dir.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o755);
        builder.create(&target_dir).map_err(|e| {
            format!(
                "cannot create systemd unit directory {}: {e}",
                target_dir.display()
            )
        })?;
    }

    let mut installed_any = false;

    for unit_name in units {
        let source = repo_root.join(source_dir).join(unit_name);
        let dest = target_dir.join(unit_name);

        if !source.exists() {
            actions.push(BootstrapAction {
                kind: "install_service",
                description: format!("source template not found: {} (skipped)", source.display()),
                skipped: true,
            });
            continue;
        }

        if dest.exists() {
            actions.push(BootstrapAction {
                kind: "install_service",
                description: format!("unit file already installed: {} (skipped)", dest.display()),
                skipped: true,
            });
            continue;
        }

        fs::copy(&source, &dest).map_err(|e| {
            format!(
                "cannot install unit {} -> {}: {e}",
                source.display(),
                dest.display()
            )
        })?;

        #[cfg(unix)]
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o644)).map_err(|e| {
            format!(
                "cannot set unit file permissions on {}: {e}",
                dest.display()
            )
        })?;

        actions.push(BootstrapAction {
            kind: "install_service",
            description: format!("installed {unit_name} -> {}", dest.display()),
            skipped: false,
        });
        installed_any = true;
    }

    // Reload systemd and enable units.
    let reload_result = if user_mode {
        Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output()
    } else {
        Command::new("systemctl").arg("daemon-reload").output()
    };

    match reload_result {
        Ok(output) if output.status.success() => {
            actions.push(BootstrapAction {
                kind: "systemd_reload",
                description: format!("systemd daemon-reload ({scope})"),
                skipped: false,
            });
        },
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            actions.push(BootstrapAction {
                kind: "systemd_reload",
                description: format!("systemd daemon-reload ({scope}) failed: {stderr}"),
                skipped: false,
            });
        },
        Err(e) => {
            actions.push(BootstrapAction {
                kind: "systemd_reload",
                description: format!(
                    "systemd daemon-reload ({scope}) failed: {e}. \
                     Remediation: run `systemctl {reload_flag} daemon-reload` manually",
                    reload_flag = if user_mode { "--user" } else { "" }
                ),
                skipped: false,
            });
        },
    }

    // Enable units (but do not start).
    for unit_name in &[
        "apm2-daemon.socket",
        "apm2-daemon.service",
        "apm2-worker.service",
    ] {
        let enable_result = if user_mode {
            Command::new("systemctl")
                .args(["--user", "enable", unit_name])
                .output()
        } else {
            Command::new("systemctl")
                .args(["enable", unit_name])
                .output()
        };

        match enable_result {
            Ok(output) if output.status.success() => {
                actions.push(BootstrapAction {
                    kind: "enable_service",
                    description: format!("enabled {unit_name} ({scope})"),
                    skipped: false,
                });
            },
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                actions.push(BootstrapAction {
                    kind: "enable_service",
                    description: format!("failed to enable {unit_name} ({scope}): {stderr}"),
                    skipped: false,
                });
            },
            Err(e) => {
                actions.push(BootstrapAction {
                    kind: "enable_service",
                    description: format!("failed to enable {unit_name} ({scope}): {e}"),
                    skipped: false,
                });
            },
        }
    }

    // Enable linger for user mode so services survive logout.
    if user_mode {
        let linger_result = Command::new("loginctl").args(["enable-linger"]).output();

        match linger_result {
            Ok(output) if output.status.success() => {
                actions.push(BootstrapAction {
                    kind: "enable_linger",
                    description: "enabled user linger (services survive logout)".to_string(),
                    skipped: false,
                });
            },
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                actions.push(BootstrapAction {
                    kind: "enable_linger",
                    description: format!(
                        "failed to enable linger: {stderr}. \
                         Remediation: run `loginctl enable-linger` manually"
                    ),
                    skipped: false,
                });
            },
            Err(e) => {
                actions.push(BootstrapAction {
                    kind: "enable_linger",
                    description: format!(
                        "failed to enable linger: {e}. \
                         Remediation: run `loginctl enable-linger` manually"
                    ),
                    skipped: false,
                });
            },
        }
    }

    Ok(installed_any)
}

// =============================================================================
// Doctor Integration
// =============================================================================

fn run_doctor_checks(
    operator_socket: &Path,
    config_path: &Path,
    actions: &mut Vec<BootstrapAction>,
) -> (bool, Vec<DoctorCheckSummary>) {
    let (checks, has_error) =
        match crate::commands::daemon::collect_doctor_checks(operator_socket, config_path, false) {
            Ok(value) => value,
            Err(err) => {
                actions.push(BootstrapAction {
                    kind: "doctor",
                    description: format!("doctor checks failed to run: {err}"),
                    skipped: false,
                });
                return (false, Vec::new());
            },
        };

    let summaries: Vec<DoctorCheckSummary> = checks
        .iter()
        .map(|c| DoctorCheckSummary {
            name: c.name.clone(),
            status: c.status.to_string(),
            message: c.message.clone(),
        })
        .collect();

    let passed = !has_error;
    actions.push(BootstrapAction {
        kind: "doctor",
        description: if passed {
            "all doctor checks passed".to_string()
        } else {
            "doctor checks found errors (see details below)".to_string()
        },
        skipped: false,
    });

    (passed, summaries)
}

// =============================================================================
// Dry-Run Planners
// =============================================================================

fn plan_directories(
    apm2_home: &Path,
    private_dir: &Path,
    fac_root: &Path,
    actions: &mut Vec<BootstrapAction>,
) {
    let plan_dir = |path: &Path, actions: &mut Vec<BootstrapAction>| {
        if actions.len() >= MAX_PLANNED_ACTIONS {
            return;
        }
        let exists = path.exists();
        actions.push(BootstrapAction {
            kind: "create_dir",
            description: if exists {
                format!("[skip] directory already exists: {}", path.display())
            } else {
                format!("[plan] create directory: {} (mode 0700)", path.display())
            },
            skipped: exists,
        });
    };

    plan_dir(apm2_home, actions);
    plan_dir(private_dir, actions);

    for subdir in PRIVATE_SUBDIRS {
        plan_dir(&private_dir.join(subdir), actions);
    }

    plan_dir(fac_root, actions);

    for subdir in FAC_SUBDIRS {
        plan_dir(&fac_root.join(subdir), actions);
    }
}

fn plan_policy(fac_root: &Path, actions: &mut Vec<BootstrapAction>) {
    let policy_path = fac_root.join("policy").join("fac_policy.v1.json");
    let exists = policy_path.exists();
    actions.push(BootstrapAction {
        kind: "write_policy",
        description: if exists {
            format!("[skip] policy already exists: {}", policy_path.display())
        } else {
            format!(
                "[plan] write default FacPolicyV1: {} (safe no-secrets posture)",
                policy_path.display()
            )
        },
        skipped: exists,
    });
}

fn plan_lanes(actions: &mut Vec<BootstrapAction>) {
    let count = LaneManager::lane_count();
    actions.push(BootstrapAction {
        kind: "init_lanes",
        description: format!("[plan] initialize lane pool ({count} lanes)"),
        skipped: false,
    });
}

fn plan_services(user_mode: bool, actions: &mut Vec<BootstrapAction>) {
    let scope = if user_mode { "user" } else { "system" };
    actions.push(BootstrapAction {
        kind: "install_service",
        description: format!("[plan] install and enable systemd services ({scope} mode)"),
        skipped: false,
    });
}

fn plan_doctor(actions: &mut Vec<BootstrapAction>) {
    actions.push(BootstrapAction {
        kind: "doctor",
        description: "[plan] run doctor checks to verify host readiness".to_string(),
        skipped: false,
    });
}

// =============================================================================
// Helpers
// =============================================================================

fn resolve_apm2_home() -> Result<PathBuf, String> {
    if let Some(override_dir) = std::env::var_os("APM2_HOME") {
        let path = PathBuf::from(override_dir);
        if !path.as_os_str().is_empty() {
            return Ok(path);
        }
    }
    let base_dirs = directories::BaseDirs::new()
        .ok_or_else(|| "could not resolve home directory".to_string())?;
    Ok(base_dirs.home_dir().join(".apm2"))
}

fn find_repo_root() -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path_str = String::from_utf8_lossy(&output.stdout);
    let path = PathBuf::from(path_str.trim());
    if path.is_dir() { Some(path) } else { None }
}

fn output_error(json_output: bool, code: &str, message: &str) -> u8 {
    if json_output {
        let err = serde_json::json!({
            "error": code,
            "message": message,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&err).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        eprintln!("ERROR [{code}]: {message}");
    }
    exit_codes::GENERIC_ERROR
}

fn print_receipt(receipt: &BootstrapReceipt, json_output: bool) {
    if json_output {
        if let Ok(json) = serde_json::to_string_pretty(receipt) {
            println!("{json}");
        } else {
            println!("{{\"error\":\"serialization_error\"}}");
        }
    } else {
        println!(
            "Bootstrap {}",
            if receipt.dry_run {
                "(dry-run)"
            } else {
                "complete"
            }
        );
        println!();
        println!("  APM2_HOME:    {}", receipt.apm2_home);
        println!("  FAC root:     {}", receipt.fac_root);
        println!();
        println!(
            "  Directories:  {} created, {} existing",
            receipt.dirs_created, receipt.dirs_existing
        );
        println!(
            "  Policy:       {}",
            if receipt.policy_written {
                "written"
            } else {
                "existing (untouched)"
            }
        );
        println!(
            "  Lanes:        {}",
            if receipt.lanes_initialized {
                "initialized"
            } else {
                "existing (untouched)"
            }
        );
        println!(
            "  Services:     {}",
            if receipt.services_installed {
                "installed"
            } else if receipt.dry_run {
                "not requested"
            } else {
                "not requested (use --user or --system)"
            }
        );
        println!(
            "  Doctor:       {}",
            if receipt.doctor_passed {
                "PASS"
            } else if receipt.dry_run {
                "pending"
            } else {
                "FAIL (see errors below)"
            }
        );

        // Print actions summary.
        let mutating: Vec<_> = receipt.actions.iter().filter(|a| !a.skipped).collect();
        if !mutating.is_empty() && !receipt.dry_run {
            println!();
            println!("  Actions:");
            for action in &mutating {
                println!("    [{:>15}] {}", action.kind, action.description);
            }
        }

        // Print dry-run plan.
        if receipt.dry_run {
            println!();
            println!("  Planned actions:");
            for action in &receipt.actions {
                println!("    {}", action.description);
            }
        }

        // Print doctor failures.
        if !receipt.doctor_passed && !receipt.dry_run {
            let errors: Vec<_> = receipt
                .doctor_checks
                .iter()
                .filter(|c| c.status == "ERROR")
                .collect();
            if !errors.is_empty() {
                println!();
                println!("  Doctor errors:");
                for check in &errors {
                    println!("    [{}] {}", check.name, check.message);
                }
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fac_subdirs_has_required_entries() {
        // Verify the required RFC directory layout is covered.
        assert!(FAC_SUBDIRS.contains(&"lanes"));
        assert!(FAC_SUBDIRS.contains(&"queue"));
        assert!(FAC_SUBDIRS.contains(&"queue/pending"));
        assert!(FAC_SUBDIRS.contains(&"queue/claimed"));
        assert!(FAC_SUBDIRS.contains(&"queue/completed"));
        assert!(FAC_SUBDIRS.contains(&"queue/cancelled"));
        assert!(FAC_SUBDIRS.contains(&"queue/denied"));
        assert!(FAC_SUBDIRS.contains(&"queue/quarantine"));
        assert!(FAC_SUBDIRS.contains(&"receipts"));
        assert!(FAC_SUBDIRS.contains(&"locks"));
        assert!(FAC_SUBDIRS.contains(&"locks/lanes"));
        assert!(FAC_SUBDIRS.contains(&"evidence"));
        assert!(FAC_SUBDIRS.contains(&"repo_mirror"));
        assert!(FAC_SUBDIRS.contains(&"cargo_home"));
        assert!(FAC_SUBDIRS.contains(&"broker"));
        assert!(FAC_SUBDIRS.contains(&"scheduler"));
        assert!(FAC_SUBDIRS.contains(&"policy"));
        assert!(FAC_SUBDIRS.contains(&"blobs"));
    }

    #[test]
    fn test_max_planned_actions_is_reasonable() {
        // FAC_SUBDIRS + PRIVATE_SUBDIRS + fixed dirs + policy + lanes + doctor < MAX.
        let total = FAC_SUBDIRS.len() + PRIVATE_SUBDIRS.len() + 10; // apm2_home, private, fac, etc.
        assert!(
            total < MAX_PLANNED_ACTIONS,
            "total planned directories ({total}) must be less than MAX_PLANNED_ACTIONS ({MAX_PLANNED_ACTIONS})"
        );
    }

    #[test]
    fn test_bootstrap_action_serializes() {
        let action = BootstrapAction {
            kind: "create_dir",
            description: "test directory".to_string(),
            skipped: false,
        };
        let json = serde_json::to_string(&action).expect("action should serialize");
        assert!(json.contains("create_dir"));
        assert!(json.contains("test directory"));
    }

    #[test]
    fn test_bootstrap_receipt_serializes() {
        let receipt = BootstrapReceipt {
            schema: "apm2.fac.bootstrap_receipt.v1",
            apm2_home: "/tmp/test/.apm2".to_string(),
            fac_root: "/tmp/test/.apm2/private/fac".to_string(),
            dry_run: true,
            actions: vec![],
            dirs_created: 0,
            dirs_existing: 0,
            policy_written: false,
            lanes_initialized: false,
            services_installed: false,
            doctor_passed: false,
            doctor_checks: vec![],
        };
        let json = serde_json::to_string_pretty(&receipt).expect("receipt should serialize");
        assert!(json.contains("apm2.fac.bootstrap_receipt.v1"));
    }

    #[allow(unsafe_code)] // Env var mutation is required for test setup and teardown.
    #[test]
    fn test_resolve_apm2_home_uses_env_override() {
        // Serialize env-var access to prevent data races with parallel tests.
        let _lock = crate::commands::env_var_test_lock().lock().unwrap();
        // Temporarily set APM2_HOME and verify it is used.
        let key = "APM2_HOME";
        let original = std::env::var_os(key);
        // SAFETY: serialized through env_var_test_lock in test scope.
        unsafe { std::env::set_var(key, "/tmp/test_apm2_home_bootstrap") };
        let result = resolve_apm2_home();
        // Restore original.
        // SAFETY: serialized through env_var_test_lock in test scope.
        unsafe {
            match original {
                Some(val) => std::env::set_var(key, val),
                None => std::env::remove_var(key),
            }
        }
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/tmp/test_apm2_home_bootstrap")
        );
    }

    #[test]
    fn test_create_dir_idempotent_creates_and_skips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let test_path = dir.path().join("bootstrap_test");
        let mut actions = Vec::new();
        let mut created = 0usize;
        let mut existing = 0usize;

        // First call: creates.
        create_dir_idempotent(&test_path, &mut actions, &mut created, &mut existing)
            .expect("first create");
        assert_eq!(created, 1);
        assert_eq!(existing, 0);

        // Second call: skips.
        create_dir_idempotent(&test_path, &mut actions, &mut created, &mut existing)
            .expect("second create");
        assert_eq!(created, 1);
        assert_eq!(existing, 1);

        // Verify permissions on Unix.
        #[cfg(unix)]
        {
            let meta = fs::metadata(&test_path).expect("metadata");
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn test_create_dir_rejects_non_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("not_a_dir");
        fs::write(&file_path, b"file").expect("write file");

        let mut actions = Vec::new();
        let mut created = 0usize;
        let mut existing = 0usize;

        let result = create_dir_idempotent(&file_path, &mut actions, &mut created, &mut existing);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a directory"));
    }

    #[test]
    fn test_write_default_policy_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fac_root = dir.path().join("fac");
        fs::create_dir_all(fac_root.join("policy")).expect("create policy dir");

        let mut actions = Vec::new();

        // First write.
        let written = write_default_policy(&fac_root, &mut actions).expect("first write");
        assert!(written);

        // Second write: skipped because file exists.
        let written2 = write_default_policy(&fac_root, &mut actions).expect("second write");
        assert!(!written2);
        assert_eq!(actions.len(), 2);
        assert!(actions[1].skipped);
    }
}
