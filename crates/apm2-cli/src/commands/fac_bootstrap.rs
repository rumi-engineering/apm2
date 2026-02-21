// AGENT-AUTHORED
//! `apm2 fac bootstrap` — one-shot compute-host provisioning.
//!
//! Creates the required `$APM2_HOME/private/fac/**` directory tree with
//! correct permissions (0o700 user-mode, 0o770 system-mode), writes a minimal
//! default `FacPolicyV1` (safe no-secrets posture), initializes lanes,
//! optionally installs systemd services, and runs doctor checks to verify host
//! readiness.
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
//! - [INV-BOOT-001] All directories are created with restricted permissions via
//!   `create_dir_restricted` (0o700 user-mode, 0o770 system-mode) (CTR-2611).
//!   No TOCTOU window between create and chmod.
//! - [INV-BOOT-002] Policy files are written with 0o600 permissions.
//! - [INV-BOOT-003] Existing state is never destroyed — bootstrap is
//!   additive-only.
//! - [INV-BOOT-004] Doctor checks run after provisioning and gate the exit
//!   code.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use apm2_core::fac::policy::FacPolicyV1;
#[cfg(unix)]
use apm2_core::fac::service_user_gate::resolve_service_user_identity;
use apm2_core::fac::{LaneManager, SystemModeConfig, create_dir_restricted, persist_policy};
#[cfg(unix)]
use nix::fcntl::AtFlags;
#[cfg(unix)]
use nix::unistd::{self, Gid, Uid};
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
    "repo_mirror",
    "cargo_home",
    "broker",
    "broker/time_envelopes",
    "broker/horizons",
    "scheduler",
    "policy",
    "blobs",
];

/// Queue subdirectories under `$APM2_HOME/queue/`.
const QUEUE_SUBDIRS: &[&str] = &[
    "pending",
    "claimed",
    "completed",
    "cancelled",
    "denied",
    "quarantine",
    "authority_consumed",
    "broker_requests",
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
        if args.system {
            plan_system_mode_provisioning(&apm2_home, &fac_root, &mut actions);
        }
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

    // ── Phase 2: Provision system-mode service user (optional) ──────────
    if args.system {
        if let Err(msg) = provision_system_mode_identity(&apm2_home, &fac_root, &mut actions) {
            return output_error(json_output, "bootstrap_system_identity_error", &msg);
        }
    }

    // ── Phase 3: Write default policy ───────────────────────────────────
    let policy_written = match write_default_policy(&fac_root, &mut actions) {
        Ok(written) => written,
        Err(msg) => {
            return output_error(json_output, "bootstrap_policy_error", &msg);
        },
    };

    // ── Phase 4: Initialize lanes ───────────────────────────────────────
    let lanes_initialized = match initialize_lanes(&mut actions) {
        Ok(init) => init,
        Err(msg) => {
            return output_error(json_output, "bootstrap_lane_error", &msg);
        },
    };

    // ── Phase 5: Install services (optional) ────────────────────────────
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

    // ── Phase 6: Run doctor checks ──────────────────────────────────────
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

    // Create $APM2_HOME/queue and standard queue subdirectories.
    let queue_root = apm2_home.join("queue");
    create_dir_idempotent(&queue_root, actions, dirs_created, dirs_existing)?;
    for subdir in QUEUE_SUBDIRS {
        if actions.len() >= MAX_PLANNED_ACTIONS {
            return Err(format!(
                "exceeded maximum planned actions ({MAX_PLANNED_ACTIONS}); \
                 possible configuration error"
            ));
        }
        create_dir_idempotent(
            &queue_root.join(subdir),
            actions,
            dirs_created,
            dirs_existing,
        )?;
    }

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

/// Create a directory with restricted permissions if it does not already exist.
///
/// Delegates to `apm2_core::fac::create_dir_restricted` which is recursive,
/// enforces permissions on all intermediate components, and selects
/// 0o700 (user-mode) or 0o770 (system-mode) based on `select_backend()`
/// (CTR-2611). Symlink paths are rejected (INV-BOOT-001).
fn create_dir_idempotent(
    path: &Path,
    actions: &mut Vec<BootstrapAction>,
    created: &mut usize,
    existing: &mut usize,
) -> Result<(), String> {
    // Check if path already exists using lstat (symlink_metadata) to avoid
    // following symlinks (INV-BOOT-001). This check drives the
    // created/existing counters; create_dir_restricted also does its own
    // lstat-based check internally.
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

    // Delegate to the robust create_dir_restricted from apm2-core which:
    // - Is recursive (creates missing intermediate directories)
    // - Enforces permissions on all newly created components
    // - Selects 0o700 (user-mode) or 0o770 (system-mode) via select_backend()
    // - Rejects symlink paths (INV-BOOT-001, CTR-2611)
    create_dir_restricted(path)
        .map_err(|e| format!("cannot create directory {}: {e}", path.display()))?;

    *created += 1;
    actions.push(BootstrapAction {
        kind: "create_dir",
        description: format!(
            "created directory: {} (restricted permissions)",
            path.display()
        ),
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
    // Graceful degradation: if not in a git repository (e.g. binary release),
    // skip service installation with a warning instead of failing fatally.
    let Some(repo_root) = find_repo_root() else {
        actions.push(BootstrapAction {
            kind: "install_service",
            description: format!(
                "cannot find repository root for systemd unit templates; \
                 expected {source_dir}/ in ancestor directory. \
                 Skipping service installation. \
                 Remediation: run bootstrap from within the apm2 repository, \
                 or manually copy unit files from contrib/systemd/"
            ),
            skipped: true,
        });
        return Ok(false);
    };

    let units: &[&str] = &[
        "apm2-daemon.service",
        "apm2-daemon.socket",
        "apm2-worker.service",
        "apm2-worker@.service",
    ];

    // Ensure target directory exists.
    if !target_dir.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o755);
        }
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
    // Note: apm2-worker@.service is a template and is instantiated
    // on-demand (e.g. apm2-worker@lane_00.service), so it is not
    // enabled here.
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
// System-Mode Identity Provisioning
// =============================================================================

fn plan_system_mode_provisioning(
    apm2_home: &Path,
    fac_root: &Path,
    actions: &mut Vec<BootstrapAction>,
) {
    let queue_root = apm2_home.join("queue");
    actions.push(BootstrapAction {
        kind: "system_identity",
        description: "[plan] ensure system service user exists (useradd -r -s nologin -U)"
            .to_string(),
        skipped: false,
    });
    actions.push(BootstrapAction {
        kind: "system_identity",
        description: format!(
            "[plan] set queue directory modes for system-mode: {} (0711), {}/broker_requests (01733)",
            queue_root.display(),
            queue_root.display()
        ),
        skipped: false,
    });
    actions.push(BootstrapAction {
        kind: "system_identity",
        description: format!(
            "[plan] chown/chgrp FAC runtime roots to service user: {}, {}",
            fac_root.display(),
            queue_root.display()
        ),
        skipped: false,
    });
    actions.push(BootstrapAction {
        kind: "system_identity",
        description:
            "[plan] add invoking user to service group (usermod -aG <service_user> <caller>)"
                .to_string(),
        skipped: false,
    });
}

#[cfg(unix)]
fn provision_system_mode_identity(
    apm2_home: &Path,
    fac_root: &Path,
    actions: &mut Vec<BootstrapAction>,
) -> Result<(), String> {
    let current_uid = unistd::geteuid().as_raw();
    if current_uid != 0 {
        return Err(
            "system bootstrap requires root privileges. Run with sudo for --system provisioning."
                .to_string(),
        );
    }

    let system_config = SystemModeConfig::from_env()
        .map_err(|err| format!("invalid system-mode service user configuration: {err}"))?;
    let service_user = system_config.service_user;

    let created = ensure_system_service_user_exists(&service_user)?;
    actions.push(BootstrapAction {
        kind: "system_identity",
        description: if created {
            format!("created system service user '{service_user}'")
        } else {
            format!("system service user '{service_user}' already exists")
        },
        skipped: !created,
    });

    let queue_root = apm2_home.join("queue");
    apply_system_queue_modes(&queue_root)?;
    actions.push(BootstrapAction {
        kind: "system_identity",
        description: format!(
            "applied system-mode queue permissions: {} (0711), {}/broker_requests (01733)",
            queue_root.display(),
            queue_root.display()
        ),
        skipped: false,
    });

    let identity = resolve_service_user_identity()
        .map_err(|err| format!("cannot resolve provisioned service user identity: {err}"))?;
    let owner_uid = Uid::from_raw(identity.uid);
    let owner_group = Gid::from_raw(identity.gid);

    chown_tree_no_symlink(fac_root, owner_uid, owner_group)?;
    actions.push(BootstrapAction {
        kind: "system_identity",
        description: format!(
            "applied recursive ownership {}:{} to {}",
            identity.name,
            identity.name,
            fac_root.display()
        ),
        skipped: false,
    });

    chown_tree_no_symlink(&queue_root, owner_uid, owner_group)?;
    actions.push(BootstrapAction {
        kind: "system_identity",
        description: format!(
            "applied recursive ownership {}:{} to {}",
            identity.name,
            identity.name,
            queue_root.display()
        ),
        skipped: false,
    });

    match resolve_bootstrap_caller_user() {
        Some(caller_user) => {
            let added = ensure_user_in_service_group(&caller_user, &identity.name, owner_group)?;
            actions.push(BootstrapAction {
                kind: "system_identity",
                description: if added {
                    format!(
                        "added user '{caller_user}' to group '{}'; re-login may be required",
                        identity.name
                    )
                } else {
                    format!(
                        "user '{caller_user}' is already a member of group '{}'",
                        identity.name
                    )
                },
                skipped: !added,
            });
        },
        None => {
            actions.push(BootstrapAction {
                kind: "system_identity",
                description: "no non-root caller user detected (SUDO_USER/USER); skipped group membership update".to_string(),
                skipped: true,
            });
        },
    }

    Ok(())
}

#[cfg(not(unix))]
fn provision_system_mode_identity(
    _apm2_home: &Path,
    _fac_root: &Path,
    _actions: &mut Vec<BootstrapAction>,
) -> Result<(), String> {
    Err("system bootstrap provisioning is only supported on Unix hosts".to_string())
}

#[cfg(unix)]
fn ensure_system_service_user_exists(service_user: &str) -> Result<bool, String> {
    if unistd::User::from_name(service_user)
        .map_err(|err| format!("cannot resolve service user '{service_user}': {err}"))?
        .is_some()
    {
        return Ok(false);
    }

    let nologin_shell = if Path::new("/usr/sbin/nologin").exists() {
        "/usr/sbin/nologin"
    } else {
        "/usr/bin/nologin"
    };

    let output = Command::new("useradd")
        .args(["-r", "-s", nologin_shell, "-U", service_user])
        .output()
        .map_err(|err| format!("failed to execute useradd: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "useradd failed for '{service_user}': {}",
            stderr.trim()
        ));
    }

    let created = unistd::User::from_name(service_user)
        .map_err(|err| format!("cannot verify service user '{service_user}': {err}"))?;
    if created.is_none() {
        return Err(format!(
            "service user '{service_user}' still unresolved after useradd"
        ));
    }
    Ok(true)
}

#[cfg(unix)]
fn apply_system_queue_modes(queue_root: &Path) -> Result<(), String> {
    ensure_directory_with_mode(queue_root, 0o711)?;
    for subdir in QUEUE_SUBDIRS {
        let mode = if *subdir == "broker_requests" {
            0o1733
        } else {
            0o711
        };
        ensure_directory_with_mode(&queue_root.join(subdir), mode)?;
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_directory_with_mode(path: &Path, mode: u32) -> Result<(), String> {
    if !path.exists() {
        fs::create_dir_all(path)
            .map_err(|err| format!("cannot create directory {}: {err}", path.display()))?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("cannot read metadata for {}: {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing to operate on symlink directory path: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "path exists but is not a directory: {}",
            path.display()
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("cannot set mode {:04o} on {}: {err}", mode, path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn chown_tree_no_symlink(path: &Path, uid: Uid, gid: Gid) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let cwd_fd = fs::File::open(".")
        .map_err(|err| format!("cannot open current directory for fchownat: {err}"))?;
    let mut stack = vec![path.to_path_buf()];
    while let Some(current) = stack.pop() {
        let metadata = fs::symlink_metadata(&current)
            .map_err(|err| format!("cannot stat {}: {err}", current.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing recursive ownership update on symlink path: {}",
                current.display()
            ));
        }
        unistd::fchownat(
            &cwd_fd,
            current.as_path(),
            Some(uid),
            Some(gid),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|err| format!("fchownat failed for {}: {err}", current.display()))?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&current)
                .map_err(|err| format!("cannot read directory {}: {err}", current.display()))?
            {
                let entry = entry.map_err(|err| {
                    format!(
                        "cannot read directory entry under {}: {err}",
                        current.display()
                    )
                })?;
                stack.push(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn resolve_bootstrap_caller_user() -> Option<String> {
    for var in ["SUDO_USER", "USER"] {
        let Ok(value) = std::env::var(var) else {
            continue;
        };
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed == "root" {
            continue;
        }
        return Some(trimmed.to_string());
    }
    None
}

#[cfg(unix)]
fn ensure_user_in_service_group(
    caller_user: &str,
    service_group: &str,
    service_gid: Gid,
) -> Result<bool, String> {
    let caller = unistd::User::from_name(caller_user)
        .map_err(|err| format!("cannot resolve caller user '{caller_user}': {err}"))?
        .ok_or_else(|| format!("caller user '{caller_user}' not found"))?;

    let group = unistd::Group::from_name(service_group)
        .map_err(|err| format!("cannot resolve service group '{service_group}': {err}"))?
        .ok_or_else(|| format!("service group '{service_group}' not found"))?;

    let already_member =
        caller.gid == service_gid || group.mem.iter().any(|member| member == caller_user);
    if already_member {
        return Ok(false);
    }

    let output = Command::new("usermod")
        .args(["-aG", service_group, caller_user])
        .output()
        .map_err(|err| format!("failed to execute usermod: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "usermod failed while adding '{caller_user}' to '{service_group}': {}",
            stderr.trim()
        ));
    }

    Ok(true)
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
        // Use symlink_metadata to match actual-run logic (lstat, not stat).
        // path.exists() follows symlinks, which would give inconsistent
        // reporting when symlinks are present at candidate paths.
        let exists = fs::symlink_metadata(path).is_ok();
        actions.push(BootstrapAction {
            kind: "create_dir",
            description: if exists {
                format!("[skip] directory already exists: {}", path.display())
            } else {
                format!(
                    "[plan] create directory: {} (restricted permissions)",
                    path.display()
                )
            },
            skipped: exists,
        });
    };

    plan_dir(apm2_home, actions);
    plan_dir(private_dir, actions);
    plan_dir(&apm2_home.join("queue"), actions);
    for subdir in QUEUE_SUBDIRS {
        plan_dir(&apm2_home.join("queue").join(subdir), actions);
    }

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
        assert!(FAC_SUBDIRS.contains(&"repo_mirror"));
        assert!(FAC_SUBDIRS.contains(&"cargo_home"));
        assert!(FAC_SUBDIRS.contains(&"broker"));
        assert!(FAC_SUBDIRS.contains(&"scheduler"));
        assert!(FAC_SUBDIRS.contains(&"policy"));
        assert!(FAC_SUBDIRS.contains(&"blobs"));
    }

    #[test]
    fn test_queue_subdirs_has_required_entries() {
        assert!(QUEUE_SUBDIRS.contains(&"pending"));
        assert!(QUEUE_SUBDIRS.contains(&"claimed"));
        assert!(QUEUE_SUBDIRS.contains(&"completed"));
        assert!(QUEUE_SUBDIRS.contains(&"cancelled"));
        assert!(QUEUE_SUBDIRS.contains(&"denied"));
        assert!(QUEUE_SUBDIRS.contains(&"quarantine"));
        assert!(QUEUE_SUBDIRS.contains(&"authority_consumed"));
        assert!(QUEUE_SUBDIRS.contains(&"broker_requests"));
    }

    #[test]
    fn test_max_planned_actions_is_reasonable() {
        // FAC_SUBDIRS + QUEUE_SUBDIRS + PRIVATE_SUBDIRS + fixed dirs + policy + lanes +
        // doctor < MAX.
        let total = FAC_SUBDIRS.len() + QUEUE_SUBDIRS.len() + PRIVATE_SUBDIRS.len() + 12; // apm2_home, private, queue root, fac, etc.
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
            // In user-mode (no service user), create_dir_restricted uses 0o700.
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
    fn test_create_dir_idempotent_creates_intermediates() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Deep path where intermediate directories do not exist.
        let deep_path = dir.path().join("a").join("b").join("c");
        let mut actions = Vec::new();
        let mut created = 0usize;
        let mut existing = 0usize;

        create_dir_idempotent(&deep_path, &mut actions, &mut created, &mut existing)
            .expect("create deep path");
        assert_eq!(created, 1);
        assert!(deep_path.is_dir());

        // Verify intermediate directories also have restricted permissions.
        #[cfg(unix)]
        {
            let meta_a = fs::metadata(dir.path().join("a")).expect("metadata a");
            let meta_b = fs::metadata(dir.path().join("a").join("b")).expect("metadata b");
            let meta_c = fs::metadata(&deep_path).expect("metadata c");
            assert_eq!(meta_a.permissions().mode() & 0o777, 0o700);
            assert_eq!(meta_b.permissions().mode() & 0o777, 0o700);
            assert_eq!(meta_c.permissions().mode() & 0o777, 0o700);
        }
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
