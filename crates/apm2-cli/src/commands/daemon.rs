//! Daemon management commands.
//!
//! # TCK-00288: Protocol-Based IPC
//!
//! Per DD-009 (RFC-0017), the CLI uses tag-based protobuf communication via
//! the operator socket. The `kill` command sends a Shutdown request using
//! the `OperatorClient`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use apm2_core::config::{default_data_dir, normalize_pid_file_path, normalize_state_file_path};
use apm2_core::fac::execution_backend::{probe_user_bus, select_backend};
use apm2_core::github::{GitHubAppTokenProvider, resolve_apm2_home};
use apm2_daemon::telemetry::is_cgroup_v2_available;
use tracing::info;

use crate::client::protocol::{OperatorClient, ProtocolClientError};
use crate::commands::fac_permissions::{
    ensure_dir_exists_standard, ensure_dir_with_mode, validate_fac_root_permissions,
};

const FAC_RUNTIME_SUBDIRS: [&str; 14] = [
    "private",
    "private/creds",
    "private/fac/lanes",
    "private/fac/locks",
    "private/fac/receipts",
    "private/fac/policy",
    "private/fac/queue",
    "private/fac/queue/pending",
    "private/fac/queue/claimed",
    "private/fac/queue/completed",
    "private/fac/queue/denied",
    "private/fac/queue/quarantine",
    "private/fac/queue/quarantined",
    "private/fac/queue/authority_consumed",
];

const USER_SYSTEMD_DIR: &str = ".config/systemd/user";

/// TCK-00595: Systemd user service template for `apm2 daemon install`.
///
/// `%exe_path%` is replaced at install-time with the resolved binary path.
/// Uses `Restart=always` + `WatchdogSec=300` for crash resilience.
/// `LoadCredential` reads the GH token from the systemd credential store,
/// ensuring tokens are never persisted in unit files (security policy).
/// TCK-00600: Type=notify so systemd waits for READY=1 before considering
/// the daemon started. The daemon calls `sd_notify::notify_ready()` after
/// socket bind. `WatchdogSec=300` restarts the daemon if it fails to send
/// `WATCHDOG=1` within 5 minutes (the daemon pings every ~150s).
const DAEMON_SERVICE_TEMPLATE: &str = "\
[Unit]\n\
Description=APM2 Daemon — Forge Admission Cycle\n\
Documentation=https://github.com/guardian-intelligence/apm2\n\
After=network-online.target\n\
Wants=network-online.target\n\
Requires=apm2-daemon.socket\n\
\n\
[Service]\n\
Type=notify\n\
ExecStart=%exe_path% daemon --no-daemon\n\
ExecStop=%exe_path% kill\n\
Restart=always\n\
RestartSec=5\n\
WatchdogSec=300\n\
WorkingDirectory=%h/.apm2\n\
Environment=APM2_HOME=%h/.apm2\n\
Environment=RUST_LOG=info\n\
Environment=XDG_RUNTIME_DIR=%t\n\
LoadCredential=gh-token:%h/.apm2/private/creds/gh-token\n\
Sockets=apm2-daemon.socket\n\
ProtectSystem=strict\n\
ProtectHome=read-only\n\
ReadWritePaths=%h/.apm2 %h/.local/share/apm2\n\
NoNewPrivileges=yes\n\
PrivateTmp=yes\n\
\n\
[Install]\n\
WantedBy=default.target\n\
";

/// TCK-00600: Type=notify so systemd waits for READY=1 before considering
/// the worker started. The worker calls `sd_notify::notify_ready()` after
/// broker connection. `WatchdogSec=300` restarts the worker if it fails to
/// send `WATCHDOG=1` within 5 minutes (the worker pings every ~150s).
const WORKER_SERVICE_TEMPLATE: &str = "\
[Unit]\n\
Description=APM2 FAC Worker\n\
Documentation=https://github.com/guardian-intelligence/apm2\n\
After=network-online.target apm2-daemon.service\n\
Wants=apm2-daemon.service\n\
BindsTo=apm2-daemon.service\n\
PartOf=apm2-daemon.service\n\
\n\
[Service]\n\
Type=notify\n\
ExecStart=%exe_path% fac worker --poll-interval-secs 10\n\
Restart=always\n\
RestartSec=5\n\
WatchdogSec=300\n\
WorkingDirectory=%h/.apm2\n\
Environment=APM2_HOME=%h/.apm2\n\
Environment=RUST_LOG=info\n\
LoadCredential=gh-token:%h/.apm2/private/creds/gh-token\n\
ProtectSystem=strict\n\
ProtectHome=read-only\n\
ReadWritePaths=%h/.apm2 %h/.local/share/apm2\n\
NoNewPrivileges=yes\n\
PrivateTmp=yes\n\
\n\
[Install]\n\
WantedBy=default.target\n\
";

/// TCK-00600: Type=notify for template-instance workers too.
const WORKER_TEMPLATE_SERVICE_TEMPLATE: &str = "\
[Unit]\n\
Description=APM2 FAC Worker (%i)\n\
Documentation=https://github.com/guardian-intelligence/apm2\n\
After=network-online.target apm2-daemon.service\n\
Wants=apm2-daemon.service\n\
BindsTo=apm2-daemon.service\n\
PartOf=apm2-daemon.service\n\
\n\
[Service]\n\
Type=notify\n\
ExecStart=%exe_path% fac worker --poll-interval-secs 10\n\
Restart=always\n\
RestartSec=5\n\
WatchdogSec=300\n\
WorkingDirectory=%h/.apm2\n\
Environment=APM2_HOME=%h/.apm2\n\
Environment=RUST_LOG=info\n\
LoadCredential=gh-token:%h/.apm2/private/creds/gh-token\n\
ProtectSystem=strict\n\
ProtectHome=read-only\n\
ReadWritePaths=%h/.apm2 %h/.local/share/apm2\n\
NoNewPrivileges=yes\n\
PrivateTmp=yes\n\
\n\
[Install]\n\
WantedBy=default.target\n\
";

const DAEMON_SOCKET: &str = "\
[Unit]\n\
Description=APM2 Daemon Operator Socket\n\
Documentation=https://github.com/guardian-intelligence/apm2\n\
\n\
[Socket]\n\
ListenStream=%t/apm2/operator.sock\n\
SocketMode=0600\n\
RemoveOnStop=yes\n\
Service=apm2-daemon.service\n\
RuntimeDirectory=apm2\n\
\n\
[Install]\n\
WantedBy=sockets.target\n\
";

/// Start the daemon.
pub fn run(config: &Path, no_daemon: bool) -> Result<()> {
    let mut cmd = Command::new("apm2-daemon");
    cmd.arg("--config").arg(config);

    if no_daemon {
        cmd.arg("--no-daemon");
    }

    info!("Starting apm2 daemon...");

    if no_daemon {
        // Run in foreground
        let status = cmd.status().context("failed to start daemon")?;
        if !status.success() {
            bail!("daemon exited with error");
        }
    } else {
        // Run in background
        cmd.spawn().context("failed to start daemon")?;
        println!("apm2 daemon started");
    }

    Ok(())
}

/// Install the systemd user service for apm2-daemon (TCK-00595).
///
/// Writes four unit files to `~/.config/systemd/user/`:
/// - `apm2-daemon.service` — main broker with Restart=always + `WatchdogSec`
/// - `apm2-daemon.socket` — operator socket activation (mode 0600)
/// - `apm2-worker.service` — FAC worker (depends on daemon)
/// - `apm2-worker@.service` — template for scaled workers
///
/// Then runs `systemctl --user daemon-reload && enable && start`.
/// Optionally enables linger via `loginctl enable-linger` so services
/// survive user logout.
pub fn install(enable_linger: bool) -> Result<()> {
    let exe_path = std::env::current_exe()
        .map_err(|e| anyhow!("failed to resolve current executable: {e}"))?;
    let exe_path = exe_path
        .canonicalize()
        .map_err(|e| anyhow!("failed to canonicalize exe path: {e}"))?;
    let exe_path = exe_path.display().to_string();

    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    let systemd_user_dir = Path::new(&home).join(USER_SYSTEMD_DIR);
    ensure_dir_exists_standard(&systemd_user_dir)
        .context("failed to create user systemd unit directory")?;

    let apm2_home = resolve_apm2_home().ok_or_else(|| {
        anyhow!("cannot resolve APM2_HOME; set APM2_HOME or HOME to a valid directory")
    })?;
    ensure_fac_runtime_dirs(&apm2_home)?;

    let daemon_service = DAEMON_SERVICE_TEMPLATE.replace("%exe_path%", &exe_path);
    let worker_service = WORKER_SERVICE_TEMPLATE.replace("%exe_path%", &exe_path);
    let worker_template_service = WORKER_TEMPLATE_SERVICE_TEMPLATE.replace("%exe_path%", &exe_path);

    let unit_files = [
        ("apm2-daemon.service", daemon_service),
        ("apm2-worker.service", worker_service),
        ("apm2-worker@.service", worker_template_service),
        ("apm2-daemon.socket", DAEMON_SOCKET.to_string()),
    ];
    for (filename, content) in unit_files {
        let unit_path = systemd_user_dir.join(filename);
        std::fs::write(&unit_path, content).with_context(|| {
            format!(
                "failed to write user systemd unit file {}",
                unit_path.display()
            )
        })?;
        // Restrict unit file permissions to owner-read/write + group/other-read (0644).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&unit_path, std::fs::Permissions::from_mode(0o644))
                .with_context(|| {
                    format!(
                        "failed to set permissions on unit file {}",
                        unit_path.display()
                    )
                })?;
        }
    }

    run_user_systemctl(&["daemon-reload"])?;
    for unit in [
        "apm2-daemon.service",
        "apm2-daemon.socket",
        "apm2-worker.service",
    ] {
        run_user_systemctl(&["enable", unit])?;
    }
    run_user_systemctl(&["start", "apm2-daemon.socket"])?;
    run_user_systemctl(&["start", "apm2-daemon.service"])?;

    if enable_linger {
        if let Ok(user) = std::env::var("USER") {
            match Command::new("loginctl")
                .args(["enable-linger", "--", &user])
                .status()
            {
                Ok(status) if !status.success() => {
                    eprintln!(
                        "WARNING: loginctl enable-linger {user} failed with status {status}; continuing without linger"
                    );
                },
                Err(error) => {
                    eprintln!("WARNING: loginctl enable-linger failed: {error}");
                },
                _ => {},
            }
        }
    } else {
        eprintln!(
            "info: linger not enabled. To keep services running after logout: apm2 daemon install --enable-linger"
        );
    }

    println!(
        "Installed FAC systemd units under {}",
        systemd_user_dir.display()
    );
    println!(
        "Configured runtime directories under {}/private/fac",
        apm2_home.display()
    );
    println!(
        "Configured credential source at {}/private/creds/gh-token",
        apm2_home.display()
    );
    println!(
        "Run `systemctl --user status apm2-daemon.service apm2-worker.service` to verify service health."
    );

    Ok(())
}

fn ensure_fac_runtime_dirs(apm2_home: &Path) -> Result<()> {
    for rel in FAC_RUNTIME_SUBDIRS {
        let path = apm2_home.join(rel);
        ensure_dir_with_mode(&path).with_context(|| {
            format!(
                "failed to create or validate FAC runtime directory {}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn run_user_systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .context("failed to run `systemctl --user`")?;
    if !status.success() {
        bail!(
            "`systemctl --user {}` failed with status {}",
            args.join(" "),
            status
        );
    }
    Ok(())
}

/// Ensure the daemon is running, starting it when necessary (TCK-00595).
///
/// Called by all `apm2 fac` subcommands so the daemon auto-starts without
/// manual intervention. Resolution order:
///
/// 1. Probe the operator socket — if reachable, daemon is already up.
/// 2. Try `systemctl --user start apm2-daemon.service`.
/// 3. Fallback: spawn the daemon binary directly with `--config <path>`.
///
/// The `config_path` parameter threads the caller's `--config` flag into
/// the spawn path so the daemon binds to the same sockets the CLI expects.
pub fn ensure_daemon_running(operator_socket: &Path, config_path: &Path) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for daemon check")?;

    if check_socket_reachable(&rt, operator_socket).is_ok() {
        return Ok(());
    }

    let launched_by_systemctl = match Command::new("systemctl")
        .args(["--user", "start", "apm2-daemon.service"])
        .status()
    {
        Ok(status) => status.success(),
        Err(error) => {
            eprintln!("systemctl start failed: {error}, falling back to direct spawn");
            false
        },
    };

    if !launched_by_systemctl {
        let self_exe =
            std::env::current_exe().context("failed to determine current executable path")?;
        // TCK-00595 MAJOR-2 FIX: Forward the caller's --config path so the
        // daemon binds to the same sockets the CLI client expects.
        Command::new(&self_exe)
            .arg("--config")
            .arg(config_path)
            .arg("daemon")
            .spawn()
            .context("failed to auto-start daemon via systemctl, and direct spawn failed")?;
    }

    let mut attempts = 0_u8;
    while attempts < 10 {
        if check_socket_reachable(&rt, operator_socket).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        attempts = attempts.saturating_add(1);
    }

    bail!(
        "daemon did not become reachable on socket {} after auto-start attempts",
        operator_socket.display()
    );
}

/// Report health and prerequisite checks for daemon runtime.
///
/// TCK-00547: Enhanced with host capability, toolchain, security posture,
/// and credentials posture checks.
///
/// TCK-00595 MAJOR-3 FIX: Includes a projection-worker liveness probe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DaemonDoctorCheck {
    pub name: String,
    pub status: &'static str,
    pub message: String,
}

/// Initial capacity for doctor checks vector. This is an optimization hint;
/// the vector can grow beyond this if more checks are added.
const MAX_DOCTOR_CHECKS: usize = 64;

pub fn collect_doctor_checks(
    operator_socket: &Path,
    config_path: &Path,
    full: bool,
) -> Result<(Vec<DaemonDoctorCheck>, bool)> {
    let mut checks: Vec<DaemonDoctorCheck> = Vec::with_capacity(MAX_DOCTOR_CHECKS);
    let mut has_error = false;

    // ── Host Capability ─────────────────────────────────────────────────

    // cgroup v2 availability (required for bounded test execution)
    let cgroupv2 = is_cgroup_v2_available();
    checks.push(DaemonDoctorCheck {
        name: "cgroup_v2".to_string(),
        status: if cgroupv2 { "OK" } else { "ERROR" },
        message: if cgroupv2 {
            "cgroup v2 unified hierarchy available".to_string()
        } else {
            "cgroup v2 not available at /sys/fs/cgroup/cgroup.controllers; \
             bounded test execution requires cgroup v2. \
             Remediation: boot with systemd.unified_cgroup_hierarchy=1 or upgrade to a cgroup v2 kernel"
                .to_string()
        },
    });
    if !cgroupv2 {
        has_error = true;
    }

    // systemd execution backend selection
    let backend_result = select_backend();
    match &backend_result {
        Ok(backend) => {
            let user_bus_ok = probe_user_bus();
            let (status, message) = match backend {
                apm2_core::fac::ExecutionBackend::UserMode => {
                    if user_bus_ok {
                        (
                            "OK",
                            "execution backend: user-mode (user D-Bus session available)"
                                .to_string(),
                        )
                    } else {
                        has_error = true;
                        ("ERROR", "execution backend: user-mode selected but user D-Bus session bus not found. \
                         Remediation: ensure DBUS_SESSION_BUS_ADDRESS is set or XDG_RUNTIME_DIR/bus exists".to_string())
                    }
                },
                apm2_core::fac::ExecutionBackend::SystemMode => (
                    "OK",
                    format!(
                        "execution backend: system-mode{}",
                        if user_bus_ok {
                            ""
                        } else {
                            " (user bus unavailable, using system fallback)"
                        }
                    ),
                ),
            };
            checks.push(DaemonDoctorCheck {
                name: "systemd_backend".to_string(),
                status,
                message,
            });
        },
        Err(err) => {
            has_error = true;
            checks.push(DaemonDoctorCheck {
                name: "systemd_backend".to_string(),
                status: "ERROR",
                message: format!(
                    "execution backend selection failed: {err}. \
                     Remediation: set APM2_FAC_EXECUTION_BACKEND to 'user', 'system', or 'auto'"
                ),
            });
        },
    }

    // ── Control-Plane Readiness ─────────────────────────────────────────

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for doctor check")?;

    // Broker socket reachability
    let (daemon_running, daemon_probe_message) = match check_socket_reachable(&rt, operator_socket)
    {
        Ok(()) => (true, "operator socket is reachable".to_string()),
        Err(msg) => (false, msg),
    };
    let daemon_running_ok = daemon_running;
    checks.push(DaemonDoctorCheck {
        name: "broker_socket".to_string(),
        status: if daemon_running_ok { "OK" } else { "ERROR" },
        message: if daemon_probe_message.is_empty() {
            "operator socket is not reachable".to_string()
        } else {
            daemon_probe_message
        },
    });
    if !daemon_running_ok {
        has_error = true;
    }

    // Worker liveness (projection worker probe)
    let projection_check = check_projection_worker_health(config_path, daemon_running_ok);
    if projection_check.is_error {
        has_error = true;
    }
    checks.push(DaemonDoctorCheck {
        name: "worker_liveness".to_string(),
        status: projection_check.status,
        message: projection_check.message,
    });

    // Disk space
    let data_dir = default_data_dir();
    match available_space_bytes(&data_dir) {
        Ok(free_bytes) => {
            let has_space = free_bytes >= 1_073_741_824;
            checks.push(DaemonDoctorCheck {
                name: "disk_space".to_string(),
                status: if has_space { "OK" } else { "ERROR" },
                message: if has_space {
                    format!("{} has {} free bytes", data_dir.display(), free_bytes)
                } else {
                    format!(
                        "{} has only {} free bytes (minimum 1 GiB required). \
                         Remediation: free disk space or move $APM2_HOME to a larger volume",
                        data_dir.display(),
                        free_bytes
                    )
                },
            });
            if !has_space {
                has_error = true;
            }
        },
        Err(error) => {
            has_error = true;
            checks.push(DaemonDoctorCheck {
                name: "disk_space".to_string(),
                status: "ERROR",
                message: format!(
                    "failed to read free space for {}: {error}",
                    data_dir.display()
                ),
            });
        },
    }

    // ── Toolchain ───────────────────────────────────────────────────────

    // cargo availability
    let cargo_ok = check_binary_available("cargo", &["--version"]);
    checks.push(DaemonDoctorCheck {
        name: "toolchain_cargo".to_string(),
        status: if cargo_ok { "OK" } else { "ERROR" },
        message: if cargo_ok {
            "cargo is available on PATH".to_string()
        } else {
            "cargo not found on PATH. Remediation: install Rust via https://rustup.rs".to_string()
        },
    });
    if !cargo_ok {
        has_error = true;
    }

    // cargo-nextest availability (required for FAC test gates)
    let nextest_ok = check_binary_available("cargo", &["nextest", "--version"]);
    checks.push(DaemonDoctorCheck {
        name: "toolchain_nextest".to_string(),
        status: if nextest_ok { "OK" } else { "ERROR" },
        message: if nextest_ok {
            "cargo-nextest is available".to_string()
        } else {
            "cargo-nextest not found. Remediation: cargo install cargo-nextest".to_string()
        },
    });
    if !nextest_ok {
        has_error = true;
    }

    // systemd-run availability (required for bounded test execution)
    let systemd_run_ok = check_binary_available("systemd-run", &["--version"]);
    checks.push(DaemonDoctorCheck {
        name: "toolchain_systemd_run".to_string(),
        status: if systemd_run_ok { "OK" } else { "ERROR" },
        message: if systemd_run_ok {
            "systemd-run is available on PATH".to_string()
        } else {
            "systemd-run not found on PATH. Remediation: install systemd (apt install systemd)"
                .to_string()
        },
    });
    if !systemd_run_ok {
        has_error = true;
    }

    // ── Security Posture ────────────────────────────────────────────────

    // FAC root permissions (ownership + mode 0700 on $APM2_HOME and subdirs)
    match validate_fac_root_permissions() {
        Ok(()) => {
            checks.push(DaemonDoctorCheck {
                name: "fac_root_permissions".to_string(),
                status: "OK",
                message: "FAC root directories have safe permissions (0700, correct ownership)"
                    .to_string(),
            });
        },
        Err(err) => {
            has_error = true;
            checks.push(DaemonDoctorCheck {
                name: "fac_root_permissions".to_string(),
                status: "ERROR",
                message: format!("{err}"),
            });
        },
    }

    // Operator socket permissions (mode 0600)
    match socket_permission_check(operator_socket) {
        Ok(permission_ok) => {
            checks.push(DaemonDoctorCheck {
                name: "socket_permissions".to_string(),
                status: if permission_ok { "OK" } else { "ERROR" },
                message: if permission_ok {
                    format!("{} is mode 0600", operator_socket.display())
                } else {
                    format!(
                        "{} is not mode 0600. Remediation: chmod 0600 {}",
                        operator_socket.display(),
                        operator_socket.display()
                    )
                },
            });
            if !permission_ok {
                has_error = true;
            }
        },
        Err(error) => {
            // Socket may not exist if daemon is not running — downgrade to WARN
            if daemon_running_ok {
                has_error = true;
                checks.push(DaemonDoctorCheck {
                    name: "socket_permissions".to_string(),
                    status: "ERROR",
                    message: format!(
                        "failed to check {} permissions: {error}",
                        operator_socket.display()
                    ),
                });
            } else {
                checks.push(DaemonDoctorCheck {
                    name: "socket_permissions".to_string(),
                    status: "WARN",
                    message: format!(
                        "cannot check {} permissions (daemon not running): {error}",
                        operator_socket.display()
                    ),
                });
            }
        },
    }

    // Lane directory symlink check
    let lane_check = check_lane_directory_safety();
    if lane_check.status == "ERROR" {
        has_error = true;
    }
    checks.push(lane_check);

    // ── Credentials Posture ────────────────────────────────────────────
    // TCK-00547: Credentials are WARN by default, but upgraded to ERROR
    // when --full is set (for GitHub-facing workflows like push/review).
    //
    // BLOCKER FIX: Compute credential readiness holistically. Check ALL
    // credential sources (token env vars AND GitHub App config) FIRST,
    // then determine status. In --full mode, only ERROR if NO credential
    // source is available (neither token nor app config).
    let cred_fail_status: &str = if full { "ERROR" } else { "WARN" };

    // Probe all credential sources before determining status.
    // TCK-00595 MAJOR FIX: Use unified token resolution chain that checks
    // env vars, $CREDENTIALS_DIRECTORY/gh-token (systemd LoadCredential),
    // and $APM2_HOME/private/creds/gh-token.
    let github_token_set = matches!(std::env::var("GITHUB_TOKEN"), Ok(ref v) if !v.is_empty());
    let gh_token_set = matches!(std::env::var("GH_TOKEN"), Ok(ref v) if !v.is_empty());
    let any_env_token = github_token_set || gh_token_set;
    // Unified resolution: checks env + systemd creds + APM2 cred file
    let unified_token_available = apm2_core::config::resolve_github_token("GITHUB_TOKEN").is_some()
        || apm2_core::config::resolve_github_token("GH_TOKEN").is_some();
    let app_config = apm2_core::github::load_github_app_config();
    let app_configured = app_config.is_some();

    // Any valid credential source (token OR app) satisfies the requirement
    let any_credential_source = unified_token_available || app_configured;

    // GitHub token — check all resolution sources
    let creds_token_status = if unified_token_available {
        "OK"
    } else if app_configured {
        // App config is present as alternative — tokens are optional
        "OK"
    } else {
        cred_fail_status
    };
    checks.push(DaemonDoctorCheck {
        name: "creds_github_token".to_string(),
        status: creds_token_status,
        message: if any_env_token {
            "GitHub token environment variable is set (GITHUB_TOKEN or GH_TOKEN)".to_string()
        } else if unified_token_available {
            "GitHub token resolved via systemd credentials or APM2 credential file".to_string()
        } else if app_configured {
            "GitHub token not set, but GitHub App credentials are configured (OK as alternative)"
                .to_string()
        } else {
            "GitHub token not found. Checked: GITHUB_TOKEN/GH_TOKEN env vars, \
             $CREDENTIALS_DIRECTORY/gh-token (systemd), $APM2_HOME/private/creds/gh-token. \
             Remediation: export GITHUB_TOKEN=<token>, write token to \
             $APM2_HOME/private/creds/gh-token, or configure GitHub App credentials \
             (see `apm2 fac pr auth-setup`)"
                .to_string()
        },
    });
    if creds_token_status == "ERROR" {
        has_error = true;
    }

    // GitHub App config (github_app.toml) — only ERROR in full mode when
    // neither app config NOR token is available
    let app_status = if app_configured || unified_token_available {
        "OK"
    } else {
        cred_fail_status
    };
    checks.push(DaemonDoctorCheck {
        name: "creds_github_app".to_string(),
        status: app_status,
        message: if app_configured {
            "GitHub App configuration found (github_app.toml)".to_string()
        } else if unified_token_available {
            "GitHub App not configured, but token auth is available (OK as alternative)".to_string()
        } else {
            "GitHub App not configured (no github_app.toml found). \
             Remediation: run `apm2 fac pr auth-setup` to configure GitHub App credentials \
             (on headless hosts use `apm2 fac pr auth-setup --for-systemd`), \
             or export GITHUB_TOKEN as an alternative"
                .to_string()
        },
    });
    if app_status == "ERROR" {
        has_error = true;
    }

    // TCK-00598: When --full/--include-secrets is set and App config exists,
    // verify the private key is actually resolvable. A config file that
    // references an inaccessible key should not report OK.
    if full {
        if let Some(ref cfg) = app_config {
            let allow_file_fallback = cfg.allow_private_key_file_fallback.unwrap_or(false);
            let key_result = GitHubAppTokenProvider::resolve_private_key(
                &cfg.app_id,
                "APM2_GITHUB_APP_PRIVATE_KEY",
                Some(cfg),
                cfg.keyring_service.as_deref(),
                cfg.keyring_account.as_deref(),
                allow_file_fallback,
            );
            let (secret_status, secret_message) = match key_result {
                Ok(_) => (
                    "OK",
                    "GitHub App private key resolved successfully".to_string(),
                ),
                Err(err) => {
                    has_error = true;
                    (
                        "ERROR",
                        format!("GitHub App private key could not be resolved. {err}"),
                    )
                },
            };
            checks.push(DaemonDoctorCheck {
                name: "creds_github_app_secret".to_string(),
                status: secret_status,
                message: secret_message,
            });
        } else if !unified_token_available {
            // No app config and no token — secret check is not applicable but
            // surfaces guidance for users who have neither credential source.
            checks.push(DaemonDoctorCheck {
                name: "creds_github_app_secret".to_string(),
                status: "WARN",
                message: "GitHub App private key check skipped (no github_app.toml). \
                          Remediation: run `apm2 fac pr auth-setup` \
                          (on headless hosts use `apm2 fac pr auth-setup --for-systemd`)"
                    .to_string(),
            });
        }
    }

    // Systemd credential file for GH token — supplementary; only ERROR
    // when no other credential source is available
    let cred_file_exists =
        resolve_apm2_home().is_some_and(|home| home.join("private/creds/gh-token").exists());
    let cred_file_status = if cred_file_exists || any_credential_source {
        "OK"
    } else {
        cred_fail_status
    };
    checks.push(DaemonDoctorCheck {
        name: "creds_systemd_gh_token".to_string(),
        status: cred_file_status,
        message: if cred_file_exists {
            "systemd credential file for gh-token exists".to_string()
        } else if any_credential_source {
            "systemd credential file not found at $APM2_HOME/private/creds/gh-token, \
             but other credential sources are available. \
             Note: systemd-managed workers specifically need this file"
                .to_string()
        } else {
            "systemd credential file not found at $APM2_HOME/private/creds/gh-token; \
             systemd-managed workers will not have GitHub access. \
             Remediation: run `apm2 daemon install` to set up credential paths"
                .to_string()
        },
    });
    if cred_file_status == "ERROR" {
        has_error = true;
    }

    // ── Binary Alignment (INV-PADOPT-004 prevention) ──────────────────
    // FU-001: Compare digest of `which apm2` against ExecStart binaries
    // for apm2-daemon.service and apm2-worker.service. Mismatches indicate
    // binary drift that caused the INV-PADOPT-004 incident.
    let alignment_check = check_binary_alignment();
    if alignment_check.status == "ERROR" {
        has_error = true;
    }
    checks.push(alignment_check);

    Ok((checks, has_error))
}

pub fn doctor(operator_socket: &Path, config_path: &Path, json: bool) -> Result<()> {
    let (checks, has_error) = collect_doctor_checks(operator_socket, config_path, false)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&checks)
                .context("failed to serialize doctor checks to JSON")?
        );
    } else {
        println!("{:<28} {:<6} Message", "Check", "Status");
        println!("{}", "-".repeat(78));
        for check in checks {
            println!("{:<28} {:<6} {}", check.name, check.status, check.message);
        }
    }

    if has_error {
        bail!("one or more critical checks failed");
    }

    Ok(())
}

/// Result of a projection worker health probe.
struct ProjectionHealthResult {
    status: &'static str,
    message: String,
    is_error: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DaemonRuntimePathOverrides {
    state_file: Option<PathBuf>,
    ledger_db: Option<PathBuf>,
}

fn projection_cache_path_for_daemon_paths(
    state_file_path: &Path,
    ledger_db_path: Option<&Path>,
) -> PathBuf {
    ledger_db_path.map_or_else(
        || {
            state_file_path.parent().map_or_else(
                || PathBuf::from("/var/lib/apm2/projection_cache.db"),
                |parent| parent.join("projection_cache.db"),
            )
        },
        |ledger_db| ledger_db.with_extension("projection_cache.db"),
    )
}

fn parse_daemon_runtime_overrides_from_argv(args: &[String]) -> DaemonRuntimePathOverrides {
    let mut overrides = DaemonRuntimePathOverrides::default();
    let mut idx = 0usize;

    while idx < args.len() {
        let arg = args[idx].as_str();

        if let Some(value) = arg.strip_prefix("--state-file=") {
            if !value.trim().is_empty() {
                overrides.state_file = Some(PathBuf::from(value));
            }
            idx = idx.saturating_add(1);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--ledger-db=") {
            if !value.trim().is_empty() {
                overrides.ledger_db = Some(PathBuf::from(value));
            }
            idx = idx.saturating_add(1);
            continue;
        }

        if arg == "--state-file" {
            if let Some(value) = args.get(idx.saturating_add(1))
                && !value.trim().is_empty()
            {
                overrides.state_file = Some(PathBuf::from(value));
            }
            idx = idx.saturating_add(2);
            continue;
        }

        if arg == "--ledger-db" {
            if let Some(value) = args.get(idx.saturating_add(1))
                && !value.trim().is_empty()
            {
                overrides.ledger_db = Some(PathBuf::from(value));
            }
            idx = idx.saturating_add(2);
            continue;
        }

        idx = idx.saturating_add(1);
    }

    overrides
}

fn read_process_cmdline(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let args = raw
        .split(|byte| *byte == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>();
    if args.is_empty() { None } else { Some(args) }
}

fn read_daemon_runtime_overrides_for_pid(pid: u32) -> Option<DaemonRuntimePathOverrides> {
    let args = read_process_cmdline(pid)?;
    let program = args.first()?;
    if !program.contains("apm2-daemon") {
        return None;
    }
    let mut overrides = parse_daemon_runtime_overrides_from_argv(&args[1..]);
    let cwd = std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap_or_else(|_| PathBuf::from("/"));
    overrides.state_file = overrides.state_file.map(|path| {
        if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        }
    });
    overrides.ledger_db = overrides.ledger_db.map(|path| {
        if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        }
    });
    Some(overrides)
}

fn read_daemon_pid(pid_file: &Path) -> Option<u32> {
    let raw = std::fs::read_to_string(pid_file).ok()?;
    let parsed = raw.trim().parse::<u32>().ok()?;
    if parsed == 0 { None } else { Some(parsed) }
}

fn resolve_daemon_runtime_overrides(
    config: &apm2_core::config::DaemonConfig,
) -> Option<DaemonRuntimePathOverrides> {
    let pid = read_daemon_pid(&normalize_pid_file_path(&config.pid_file))?;
    read_daemon_runtime_overrides_for_pid(pid)
}

/// Check projection worker health by examining config and runtime artifacts.
///
/// The projection worker creates a cache database file on startup. When
/// projection is enabled in config but this file is absent, the worker
/// is either not started or has failed.
fn check_projection_worker_health(
    config_path: &Path,
    daemon_running: bool,
) -> ProjectionHealthResult {
    let runtime_overrides = if daemon_running {
        config_path
            .exists()
            .then(|| apm2_core::config::EcosystemConfig::from_file(config_path).ok())
            .flatten()
            .and_then(|config| resolve_daemon_runtime_overrides(&config.daemon))
    } else {
        None
    };
    check_projection_worker_health_with_overrides(
        config_path,
        daemon_running,
        runtime_overrides.as_ref(),
    )
}

fn check_projection_worker_health_with_overrides(
    config_path: &Path,
    daemon_running: bool,
    runtime_overrides: Option<&DaemonRuntimePathOverrides>,
) -> ProjectionHealthResult {
    // Try to load the config to check projection settings
    let config = config_path
        .exists()
        .then(|| apm2_core::config::EcosystemConfig::from_file(config_path).ok())
        .flatten();

    let Some(config) = config else {
        return ProjectionHealthResult {
            status: "WARN",
            message: "no ecosystem.toml found; projection worker status unknown".to_string(),
            is_error: false,
        };
    };

    let projection = &config.daemon.projection;

    if !projection.enabled {
        return ProjectionHealthResult {
            status: "OK",
            message: "projection is disabled in config (no worker expected)".to_string(),
            is_error: false,
        };
    }

    // Projection is enabled -- check prerequisites
    if projection.github_owner.is_empty() || projection.github_repo.is_empty() {
        return ProjectionHealthResult {
            status: "ERROR",
            message: "projection.enabled=true but github_owner or github_repo \
                      is not configured in ecosystem.toml"
                .to_string(),
            is_error: true,
        };
    }

    if !daemon_running {
        return ProjectionHealthResult {
            status: "ERROR",
            message: format!(
                "projection.enabled=true for {}/{} but daemon is not running",
                projection.github_owner, projection.github_repo
            ),
            is_error: true,
        };
    }

    // Check for projection cache database as evidence the worker started.
    // Mirror daemon path derivation exactly:
    // - if ledger_db_path is set:
    //   `ledger_db_path.with_extension("projection_cache.db")`
    // - otherwise: `{state_file_dir}/projection_cache.db`
    let effective_state_file = runtime_overrides
        .and_then(|overrides| overrides.state_file.clone())
        .unwrap_or_else(|| normalize_state_file_path(&config.daemon.state_file));
    let effective_ledger_db = runtime_overrides
        .and_then(|overrides| overrides.ledger_db.clone())
        .or_else(|| config.daemon.ledger_db.clone());
    let cache_path = projection_cache_path_for_daemon_paths(
        &effective_state_file,
        effective_ledger_db.as_deref(),
    );

    if cache_path.exists() {
        ProjectionHealthResult {
            status: "OK",
            message: format!(
                "projection worker active for {}/{}",
                projection.github_owner, projection.github_repo
            ),
            is_error: false,
        }
    } else {
        ProjectionHealthResult {
            status: "ERROR",
            message: format!(
                "projection.enabled=true for {}/{} but projection cache not found at {}; \
                 worker may not be active",
                projection.github_owner,
                projection.github_repo,
                cache_path.display()
            ),
            is_error: true,
        }
    }
}

/// Check whether a binary is available by running it with the given args.
///
/// Returns `true` if the process spawns AND exits with a successful status.
/// This prevents false positives where a parent binary exists (e.g. `cargo`)
/// but a required subcommand (e.g. `cargo nextest`) is not installed.
fn check_binary_available(binary: &str, args: &[&str]) -> bool {
    Command::new(binary)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Maximum binary file size to read for digest computation (256 MiB).
/// Prevents unbounded memory allocation if the binary is unusually large.
const MAX_BINARY_DIGEST_SIZE: u64 = 256 * 1024 * 1024;

/// Systemd user service units to check for binary alignment.
const BINARY_ALIGNMENT_UNIT_NAMES: [&str; 2] = ["apm2-daemon.service", "apm2-worker.service"];

/// Compute SHA-256 digest of a file at the given path.
///
/// Returns the hex-encoded digest or an error message. Reads are bounded
/// to `MAX_BINARY_DIGEST_SIZE` to prevent memory exhaustion (CTR-1603).
fn sha256_file_digest(path: &Path) -> Result<String, String> {
    use std::io::Read;

    use sha2::{Digest, Sha256};

    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if metadata.len() > MAX_BINARY_DIGEST_SIZE {
        return Err(format!(
            "{} is too large ({} bytes, max {MAX_BINARY_DIGEST_SIZE})",
            path.display(),
            metadata.len()
        ));
    }

    let mut reader = std::io::BufReader::new(file.take(MAX_BINARY_DIGEST_SIZE));
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("read error on {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Resolve the binary path from `which apm2`.
fn resolve_which_apm2() -> Result<PathBuf, String> {
    let output = Command::new("which")
        .arg("apm2")
        .output()
        .map_err(|e| format!("failed to run `which apm2`: {e}"))?;
    if !output.status.success() {
        return Err("apm2 not found on PATH".to_string());
    }
    let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path_str.is_empty() {
        return Err("which apm2 returned empty output".to_string());
    }
    // Resolve symlinks to get the canonical path
    std::fs::canonicalize(&path_str).map_err(|e| format!("cannot canonicalize {path_str}: {e}"))
}

/// Parse the binary path from a systemd `ExecStart` property value.
///
/// `systemctl show --property ExecStart` returns something like:
/// `ExecStart={ path=/home/user/.cargo/bin/apm2 ;
/// argv[]=/home/user/.cargo/bin/apm2 ... }` or in simpler form:
/// `/home/user/.cargo/bin/apm2 daemon --no-daemon`
fn parse_execstart_binary(exec_start_value: &str) -> Result<PathBuf, String> {
    let trimmed = exec_start_value.trim();
    if trimmed.is_empty() || trimmed == "ExecStart=" {
        return Err("ExecStart is empty or unset".to_string());
    }

    // Strip "ExecStart=" prefix if present
    let value = trimmed.strip_prefix("ExecStart=").unwrap_or(trimmed);

    // Handle structured format: { path=/path/to/bin ; ... }
    if let Some(rest) = value.strip_prefix("{ path=") {
        if let Some(path_end) = rest.find([' ', ';']) {
            let path_str = &rest[..path_end];
            return std::fs::canonicalize(path_str)
                .map_err(|e| format!("cannot canonicalize {path_str}: {e}"));
        }
        // Try the whole rest as a path
        let path_str = rest.trim_end_matches([' ', ';', '}']);
        return std::fs::canonicalize(path_str)
            .map_err(|e| format!("cannot canonicalize {path_str}: {e}"));
    }

    // Handle simple format: /path/to/bin arg1 arg2
    let first_token = value.split_whitespace().next().unwrap_or("");
    if first_token.is_empty() {
        return Err("cannot parse ExecStart binary path".to_string());
    }
    std::fs::canonicalize(first_token)
        .map_err(|e| format!("cannot canonicalize {first_token}: {e}"))
}

/// Resolve `ExecStart` binary path for a systemd user unit.
fn resolve_service_binary(unit_name: &str) -> Result<PathBuf, String> {
    let output = Command::new("systemctl")
        .args(["--user", "show", unit_name, "--property", "ExecStart"])
        .output()
        .map_err(|e| format!("failed to query {unit_name}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "systemctl show {unit_name} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_execstart_binary(&stdout)
}

/// FU-001 (TCK-00625): Check binary alignment between interactive CLI
/// (`which apm2`) and systemd service `ExecStart` binaries.
///
/// Computes SHA-256 digests of all resolved binary paths and enforces
/// fail-closed semantics: any mismatch or unverifiable state is ERROR.
/// This prevents recurrence of INV-PADOPT-004 where binary drift caused
/// non-deterministic behavior.
///
/// # Status semantics
///
/// - `OK`: ALL required service binaries resolved AND all digests match.
/// - `WARN`: Partial resolution — at least one unit resolved and matched but
///   other units failed to resolve. This is a degraded but non-fatal state
///   (e.g., only daemon is installed, worker unit is absent).
/// - `ERROR`: Digest mismatch detected, no service binaries resolvable, or CLI
///   binary itself cannot be resolved/digested. Fail-closed.
fn check_binary_alignment() -> DaemonDoctorCheck {
    let cli_path = match resolve_which_apm2() {
        Ok(p) => p,
        Err(e) => {
            // CLI binary itself cannot be resolved — ERROR (fail-closed).
            return DaemonDoctorCheck {
                name: "binary_alignment".to_string(),
                status: "ERROR",
                message: format!(
                    "cannot resolve CLI binary path: {e}. \
                     Remediation: ensure apm2 is on PATH"
                ),
            };
        },
    };

    let cli_digest = match sha256_file_digest(&cli_path) {
        Ok(d) => d,
        Err(e) => {
            // Cannot compute CLI digest — ERROR (fail-closed).
            return DaemonDoctorCheck {
                name: "binary_alignment".to_string(),
                status: "ERROR",
                message: format!("cannot compute CLI binary digest: {e}"),
            };
        },
    };

    // Resolve each service unit's binary and compute its digest.
    let unit_results: Vec<(&str, Result<String, String>)> = BINARY_ALIGNMENT_UNIT_NAMES
        .iter()
        .map(|unit| {
            let digest_result =
                resolve_service_binary(unit).and_then(|svc_path| sha256_file_digest(&svc_path));
            (*unit, digest_result)
        })
        .collect();

    // Convert to borrowed slices for the shared inner function.
    let borrowed: Vec<(&str, Result<&str, &str>)> = unit_results
        .iter()
        .map(|(unit, res)| {
            (
                *unit,
                res.as_ref().map(String::as_str).map_err(String::as_str),
            )
        })
        .collect();

    check_binary_alignment_inner(
        &cli_path.display().to_string(),
        &cli_digest,
        &borrowed,
        BINARY_ALIGNMENT_UNIT_NAMES.len(),
    )
}

/// Testable inner logic for binary alignment checking.
///
/// Accepts pre-resolved CLI binary info and per-unit resolution results,
/// avoiding external shell-outs (`which`, `systemctl`) in tests.
///
/// Each entry in `unit_results` is `(unit_name, Result<digest, error_msg>)`:
/// - `Ok(digest)` means the unit's binary was resolved and its SHA-256
///   computed.
/// - `Err(msg)` means resolution or digest computation failed.
fn check_binary_alignment_inner(
    cli_display: &str,
    cli_digest: &str,
    unit_results: &[(&str, Result<&str, &str>)],
    total_units: usize,
) -> DaemonDoctorCheck {
    let mut mismatches: Vec<String> = Vec::new();
    let mut resolve_failures: Vec<String> = Vec::new();
    let mut resolved_ok_count: usize = 0;

    for &(unit, ref result) in unit_results {
        match result {
            Ok(svc_digest) => {
                if *svc_digest == cli_digest {
                    resolved_ok_count += 1;
                } else {
                    mismatches.push(format!(
                        "{unit}: sha256={svc_digest} (CLI: {cli_display} sha256={cli_digest})"
                    ));
                }
            },
            Err(e) => {
                resolve_failures.push(format!("{unit}: {e}"));
            },
        }
    }

    // Fail-closed: digest mismatch is always ERROR.
    if !mismatches.is_empty() {
        let mut parts = Vec::with_capacity(mismatches.len() + resolve_failures.len());
        parts.extend(mismatches);
        if !resolve_failures.is_empty() {
            parts.extend(resolve_failures);
        }
        return DaemonDoctorCheck {
            name: "binary_alignment".to_string(),
            status: "ERROR",
            message: format!(
                "binary digest mismatch detected (INV-PADOPT-004 risk): {}. \
                 Remediation: run `apm2 fac install` to realign binaries",
                parts.join("; ")
            ),
        };
    }

    // Fail-closed: no service binary verified at all.
    if resolved_ok_count == 0 {
        let detail = if resolve_failures.is_empty() {
            "no service units configured for alignment check".to_string()
        } else {
            resolve_failures.join("; ")
        };
        return DaemonDoctorCheck {
            name: "binary_alignment".to_string(),
            status: "ERROR",
            message: format!(
                "no service binary could be verified ({detail}). \
                 Remediation: ensure apm2-daemon.service and \
                 apm2-worker.service are installed and active"
            ),
        };
    }

    // Partial: some matched, some failed to resolve — WARN.
    if !resolve_failures.is_empty() {
        return DaemonDoctorCheck {
            name: "binary_alignment".to_string(),
            status: "WARN",
            message: format!(
                "partial binary verification ({resolved_ok_count}/{total_units} units ok): {}. \
                 Remediation: run `apm2 fac install` to realign binaries",
                resolve_failures.join("; ")
            ),
        };
    }

    // All resolved and matched — OK.
    DaemonDoctorCheck {
        name: "binary_alignment".to_string(),
        status: "OK",
        message: format!(
            "CLI binary ({cli_display}) and all {resolved_ok_count} service binaries \
             have matching SHA-256 digest ({})",
            &cli_digest[..cli_digest.len().min(16)]
        ),
    }
}

/// Maximum number of lane directories to scan for symlink safety.
const MAX_LANE_SCAN: usize = 256;

/// Check lane directory safety: no symlinks, correct ownership.
///
/// Scans `$APM2_HOME/private/fac/lanes/` for symlink patterns that could
/// allow path traversal attacks.
fn check_lane_directory_safety() -> DaemonDoctorCheck {
    let lanes_dir = match resolve_apm2_home() {
        Some(home) => home.join("private/fac/lanes"),
        None => {
            return DaemonDoctorCheck {
                name: "lane_safety".to_string(),
                status: "WARN",
                message: "cannot resolve APM2_HOME; lane directory safety not checked".to_string(),
            };
        },
    };

    check_lane_directory_safety_at(&lanes_dir)
}

/// Inner implementation that accepts an explicit path for testability.
fn check_lane_directory_safety_at(lanes_dir: &Path) -> DaemonDoctorCheck {
    // SECURITY FIX: Use symlink_metadata as the first probe instead of
    // exists(). A dangling symlink makes exists() return false, which
    // would skip symlink detection entirely and report OK. Using
    // symlink_metadata catches both dangling and live symlinks.
    let root_meta = match std::fs::symlink_metadata(lanes_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                // Catch both dangling and live symlinks on the root path
                return DaemonDoctorCheck {
                    name: "lane_safety".to_string(),
                    status: "ERROR",
                    message: format!(
                        "lane directory {} is a symlink (potential path traversal). \
                         Remediation: remove the symlink and recreate as a real directory",
                        lanes_dir.display()
                    ),
                };
            }
            if !meta.is_dir() {
                return DaemonDoctorCheck {
                    name: "lane_safety".to_string(),
                    status: "ERROR",
                    message: format!(
                        "lane path {} exists but is not a directory",
                        lanes_dir.display()
                    ),
                };
            }
            meta
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return DaemonDoctorCheck {
                name: "lane_safety".to_string(),
                status: "OK",
                message: "lane directory does not exist yet (no lanes created)".to_string(),
            };
        },
        Err(err) => {
            return DaemonDoctorCheck {
                name: "lane_safety".to_string(),
                status: "ERROR",
                message: format!(
                    "failed to stat lane directory {}: {err}",
                    lanes_dir.display()
                ),
            };
        },
    };

    // Ownership and permission checks on the lane root
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current_uid = nix::unistd::geteuid().as_raw();
        if root_meta.uid() != current_uid {
            return DaemonDoctorCheck {
                name: "lane_safety".to_string(),
                status: "ERROR",
                message: format!(
                    "lane directory {} is owned by uid {} but current user is uid {}. \
                     Remediation: chown {} {}",
                    lanes_dir.display(),
                    root_meta.uid(),
                    current_uid,
                    current_uid,
                    lanes_dir.display()
                ),
            };
        }
        let mode = root_meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return DaemonDoctorCheck {
                name: "lane_safety".to_string(),
                status: "ERROR",
                message: format!(
                    "lane directory {} has unsafe permissions (mode {:04o}). \
                     Remediation: chmod 0700 {}",
                    lanes_dir.display(),
                    mode,
                    lanes_dir.display()
                ),
            };
        }
    }

    let entries = match std::fs::read_dir(lanes_dir) {
        Ok(entries) => entries,
        Err(err) => {
            return DaemonDoctorCheck {
                name: "lane_safety".to_string(),
                status: "ERROR",
                message: format!(
                    "failed to read lane directory {}: {err}",
                    lanes_dir.display()
                ),
            };
        },
    };

    // MAJOR FIX: Use a bounded vector collection to prevent memory DoS.
    // If the number of entries exceeds MAX_LANE_SCAN, fail closed (ERROR)
    // instead of truncating and warning. This prevents hiding malicious
    // symlinks in a large directory.
    let mut sorted_entries = Vec::with_capacity(MAX_LANE_SCAN);
    for entry in entries {
        match entry {
            Ok(e) => {
                sorted_entries.push(e);
                if sorted_entries.len() > MAX_LANE_SCAN {
                    return DaemonDoctorCheck {
                        name: "lane_safety".to_string(),
                        status: "ERROR",
                        message: format!(
                            "lane directory contains too many entries (> {MAX_LANE_SCAN}). \
                             Security checks cannot run safely. Remediation: clean up old lanes"
                        ),
                    };
                }
            },
            Err(e) => {
                return DaemonDoctorCheck {
                    name: "lane_safety".to_string(),
                    status: "ERROR",
                    message: format!("failed to read lane entry: {e}"),
                };
            },
        }
    }

    // Sort for deterministic reporting
    sorted_entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut symlink_found = false;
    let mut symlink_path = String::new();

    for entry in sorted_entries {
        // Check if the entry is a symlink (TOCTOU defense)
        let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            symlink_found = true;
            symlink_path = entry.path().display().to_string();
            break;
        }

        // Per-entry ownership and permission checks
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let current_uid = nix::unistd::geteuid().as_raw();
            if metadata.uid() != current_uid {
                return DaemonDoctorCheck {
                    name: "lane_safety".to_string(),
                    status: "ERROR",
                    message: format!(
                        "lane entry {} is owned by uid {} but current user is uid {}. \
                         Remediation: chown -R {} {}",
                        entry.path().display(),
                        metadata.uid(),
                        current_uid,
                        current_uid,
                        lanes_dir.display()
                    ),
                };
            }
            if metadata.is_dir() {
                let mode = metadata.mode() & 0o777;
                if mode & 0o077 != 0 {
                    return DaemonDoctorCheck {
                        name: "lane_safety".to_string(),
                        status: "ERROR",
                        message: format!(
                            "lane entry {} has unsafe permissions (mode {:04o}). \
                             Remediation: chmod 0700 {}",
                            entry.path().display(),
                            mode,
                            entry.path().display()
                        ),
                    };
                }
            }
        }
    }

    if symlink_found {
        DaemonDoctorCheck {
            name: "lane_safety".to_string(),
            status: "ERROR",
            message: format!(
                "symlink detected in lane directory: {symlink_path}. \
                 Remediation: remove the symlink and recreate as a real directory"
            ),
        }
    } else {
        DaemonDoctorCheck {
            name: "lane_safety".to_string(),
            status: "OK",
            message: "lane directory safe (no symlinks, ownership and permissions OK)".to_string(),
        }
    }
}

/// Kill the daemon via protocol-based Shutdown request.
///
/// # TCK-00288: Protocol-Based IPC
///
/// Sends a Shutdown request to the daemon via the operator socket using
/// tag-based protobuf framing per DD-009 and RFC-0017.
pub fn kill(socket_path: &Path) -> Result<()> {
    // Build async runtime for the protocol client
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    rt.block_on(async {
        // Connect to operator socket
        let mut client = OperatorClient::connect(socket_path)
            .await
            .map_err(map_protocol_error)?;

        // Send shutdown request
        let response = client
            .shutdown(Some("CLI shutdown request"))
            .await
            .map_err(map_protocol_error)?;

        println!("Daemon shutdown initiated");
        if !response.message.is_empty() {
            println!("  Message: {}", response.message);
        }

        Ok(())
    })
}

/// Maps protocol client errors to anyhow errors with user-friendly messages.
fn map_protocol_error(err: ProtocolClientError) -> anyhow::Error {
    match err {
        ProtocolClientError::DaemonNotRunning => {
            anyhow::anyhow!("Daemon is not running (socket does not exist)")
        },
        ProtocolClientError::ConnectionFailed(msg) => {
            anyhow::anyhow!("Failed to connect to daemon: {msg}")
        },
        ProtocolClientError::HandshakeFailed(msg) => {
            anyhow::anyhow!("Protocol handshake failed: {msg}")
        },
        ProtocolClientError::VersionMismatch { client, server } => {
            anyhow::anyhow!(
                "Protocol version mismatch: CLI version {client}, daemon version {server}"
            )
        },
        ProtocolClientError::IoError(e) => {
            anyhow::anyhow!("I/O error communicating with daemon: {e}")
        },
        ProtocolClientError::ProtocolError(e) => {
            anyhow::anyhow!("Protocol error: {e}")
        },
        ProtocolClientError::DecodeError(msg) => {
            anyhow::anyhow!("Failed to decode daemon response: {msg}")
        },
        ProtocolClientError::DaemonError { code, message } => {
            anyhow::anyhow!("Daemon error ({code}): {message}")
        },
        ProtocolClientError::UnexpectedResponse(msg) => {
            anyhow::anyhow!("Unexpected daemon response: {msg}")
        },
        ProtocolClientError::Timeout => {
            anyhow::anyhow!("Operation timed out waiting for daemon response")
        },
        ProtocolClientError::FrameTooLarge { size, max } => {
            anyhow::anyhow!("Response frame too large: {size} bytes (max: {max})")
        },
    }
}

fn check_socket_reachable(rt: &tokio::runtime::Runtime, path: &Path) -> Result<(), String> {
    let result = rt.block_on(async {
        OperatorClient::connect_with_timeout(path, std::time::Duration::from_secs(1)).await
    });

    match result {
        Ok(_) => Ok(()),
        Err(ProtocolClientError::DaemonNotRunning) => Err("daemon not running".to_string()),
        Err(error) => Err(error.to_string()),
    }
}

fn available_space_bytes(path: &std::path::Path) -> Result<u64> {
    if !path.exists() {
        crate::commands::fac_permissions::ensure_dir_exists_standard(path)
            .context("failed to create data directory")?;
    }
    fs2::available_space(path).context("failed to read available space")
}

fn socket_permission_check(path: &Path) -> Result<bool> {
    // Follow symlinks: the socket may be reached via a symlink (e.g.
    // /tmp/apm2/operator.sock -> /run/user/1000/apm2/operator.sock). We want
    // the target's permissions, not the symlink's (symlinks always report 0777
    // on Linux).
    let metadata = std::fs::metadata(path).context("socket path is missing")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        if metadata.file_type().is_socket() {
            return Ok(metadata.permissions().mode() & 0o777 == 0o600);
        }
        Ok(false)
    }

    #[cfg(not(unix))]
    {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TCK-00595 MAJOR-2 regression: `ensure_daemon_running` accepts
    /// `config_path` and the function signature is correct. We cannot test
    /// the actual daemon spawn in unit tests, but we verify the function
    /// compiles with the new signature and fails gracefully on a
    /// non-existent socket.
    #[test]
    fn ensure_daemon_running_accepts_config_path() {
        let socket = std::path::Path::new("/tmp/apm2-test-nonexistent/operator.sock");
        let config = std::path::Path::new("/tmp/apm2-test-nonexistent/ecosystem.toml");
        // Should fail (socket not reachable, systemctl/spawn will fail) but
        // must not panic.
        let result = ensure_daemon_running(socket, config);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn socket_permission_check_follows_symlink_to_socket_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::os::unix::net::UnixListener;

        let temp = tempfile::TempDir::new().expect("tempdir");
        let socket_path = temp.path().join("operator.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .expect("set socket permissions");

        let symlink_path = temp.path().join("operator-link.sock");
        symlink(&socket_path, &symlink_path).expect("create symlink");

        let secure = socket_permission_check(&symlink_path).expect("socket permission check");
        assert!(
            secure,
            "symlink path should resolve to secure target socket"
        );
    }

    #[cfg(unix)]
    #[test]
    fn socket_permission_check_rejects_non_0600_socket_permissions() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let temp = tempfile::TempDir::new().expect("tempdir");
        let socket_path = temp.path().join("operator.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind socket");
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))
            .expect("set socket permissions");

        let secure = socket_permission_check(&socket_path).expect("socket permission check");
        assert!(
            !secure,
            "socket permissions broader than 0600 must fail doctor check"
        );
    }

    /// TCK-00595 MAJOR-3: projection worker health check returns OK when
    /// projection is disabled in config.
    #[test]
    fn projection_health_disabled_returns_ok() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("ecosystem.toml");
        // Minimal config with projection disabled (default)
        std::fs::write(
            &config_path,
            "[daemon]\noperator_socket = \"/tmp/op.sock\"\nsession_socket = \"/tmp/sess.sock\"\n",
        )
        .unwrap();

        let result = check_projection_worker_health_with_overrides(&config_path, true, None);
        assert_eq!(result.status, "OK");
        assert!(!result.is_error);
    }

    /// TCK-00595 MAJOR-3: projection worker health check returns ERROR when
    /// enabled but daemon not running.
    #[test]
    fn projection_health_enabled_daemon_down_returns_error() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("ecosystem.toml");
        std::fs::write(
            &config_path,
            "[daemon]\noperator_socket = \"/tmp/op.sock\"\nsession_socket = \"/tmp/sess.sock\"\n\
             [daemon.projection]\nenabled = true\ngithub_owner = \"owner\"\ngithub_repo = \"repo\"\n",
        )
        .unwrap();

        let result = check_projection_worker_health_with_overrides(&config_path, false, None);
        assert_eq!(result.status, "ERROR");
        assert!(result.is_error);
        assert!(result.message.contains("daemon is not running"));
    }

    /// TCK-00595 MAJOR-3: projection worker health check returns ERROR when
    /// enabled but cache file missing.
    #[test]
    fn projection_health_enabled_no_cache_returns_error() {
        let temp = tempfile::TempDir::new().unwrap();
        let ledger_path = temp.path().join("ledger.db");
        let config_path = temp.path().join("ecosystem.toml");
        std::fs::write(
            &config_path,
            format!(
                "[daemon]\noperator_socket = \"/tmp/op.sock\"\nsession_socket = \"/tmp/sess.sock\"\n\
                 ledger_db = \"{}\"\n\
                 [daemon.projection]\nenabled = true\ngithub_owner = \"owner\"\ngithub_repo = \"repo\"\n",
                ledger_path.display()
            ),
        )
        .unwrap();

        let result = check_projection_worker_health_with_overrides(&config_path, true, None);
        assert_eq!(result.status, "ERROR");
        assert!(result.is_error);
        assert!(result.message.contains("projection cache not found"));
    }

    /// TCK-00595 MAJOR-3: projection worker health check returns OK when
    /// enabled, daemon running, and cache exists.
    #[test]
    fn projection_health_enabled_with_cache_returns_ok() {
        let temp = tempfile::TempDir::new().unwrap();
        let ledger_path = temp.path().join("ledger.db");
        let config_path = temp.path().join("ecosystem.toml");
        // Create the projection cache file to simulate active worker
        let cache_path = ledger_path.with_extension("projection_cache.db");
        std::fs::write(&cache_path, b"dummy").unwrap();

        std::fs::write(
            &config_path,
            format!(
                "[daemon]\noperator_socket = \"/tmp/op.sock\"\nsession_socket = \"/tmp/sess.sock\"\n\
                 ledger_db = \"{}\"\n\
                 [daemon.projection]\nenabled = true\ngithub_owner = \"owner\"\ngithub_repo = \"repo\"\n",
                ledger_path.display()
            ),
        )
        .unwrap();

        let result = check_projection_worker_health_with_overrides(&config_path, true, None);
        assert_eq!(result.status, "OK");
        assert!(!result.is_error);
        assert!(result.message.contains("projection worker active"));
    }

    #[test]
    fn daemon_service_templates_use_expected_worker_flag_and_rw_paths() {
        assert!(
            WORKER_SERVICE_TEMPLATE.contains("fac worker --poll-interval-secs 10"),
            "worker service template must use --poll-interval-secs"
        );
        assert!(
            WORKER_TEMPLATE_SERVICE_TEMPLATE.contains("fac worker --poll-interval-secs 10"),
            "worker@ template must use --poll-interval-secs"
        );
        for worker_template in [WORKER_SERVICE_TEMPLATE, WORKER_TEMPLATE_SERVICE_TEMPLATE] {
            assert!(
                worker_template.contains("BindsTo=apm2-daemon.service"),
                "worker templates must co-lifecycle with daemon via BindsTo"
            );
            assert!(
                worker_template.contains("PartOf=apm2-daemon.service"),
                "worker templates must co-lifecycle with daemon via PartOf"
            );
            assert!(
                !worker_template.contains("Requires=apm2-daemon.service"),
                "worker templates must not use Requires=apm2-daemon.service"
            );
        }
        for template in [
            DAEMON_SERVICE_TEMPLATE,
            WORKER_SERVICE_TEMPLATE,
            WORKER_TEMPLATE_SERVICE_TEMPLATE,
        ] {
            assert!(
                template.contains("ReadWritePaths=%h/.apm2 %h/.local/share/apm2"),
                "template must allow writes to both APM2 home and XDG data path"
            );
        }
    }

    #[test]
    fn projection_cache_path_uses_ledger_db_extension_when_present() {
        let state_file = Path::new("/tmp/apm2/state.json");
        let ledger = Path::new("/tmp/apm2/ledger.db");
        let cache = projection_cache_path_for_daemon_paths(state_file, Some(ledger));
        assert_eq!(cache, PathBuf::from("/tmp/apm2/ledger.projection_cache.db"));
    }

    #[test]
    fn parse_daemon_runtime_overrides_supports_split_and_equals_flags() {
        let args = vec![
            "--state-file".to_string(),
            "/tmp/state-a.json".to_string(),
            "--ledger-db=/tmp/ledger-a.db".to_string(),
        ];
        let parsed = parse_daemon_runtime_overrides_from_argv(&args);
        assert_eq!(parsed.state_file, Some(PathBuf::from("/tmp/state-a.json")));
        assert_eq!(parsed.ledger_db, Some(PathBuf::from("/tmp/ledger-a.db")));
    }

    #[test]
    fn projection_health_uses_runtime_ledger_override_when_present() {
        let temp = tempfile::TempDir::new().unwrap();
        let state_path = temp.path().join("state.json");
        let config_path = temp.path().join("ecosystem.toml");
        std::fs::write(
            &config_path,
            format!(
                "[daemon]\noperator_socket = \"/tmp/op.sock\"\nsession_socket = \"/tmp/sess.sock\"\n\
                 state_file = \"{}\"\n\
                 [daemon.projection]\nenabled = true\ngithub_owner = \"owner\"\ngithub_repo = \"repo\"\n",
                state_path.display()
            ),
        )
        .unwrap();

        let runtime_ledger = temp.path().join("ledger.db");
        let runtime_cache = runtime_ledger.with_extension("projection_cache.db");
        std::fs::write(&runtime_cache, b"dummy").unwrap();
        let runtime_overrides = DaemonRuntimePathOverrides {
            state_file: None,
            ledger_db: Some(runtime_ledger),
        };

        let result = check_projection_worker_health_with_overrides(
            &config_path,
            true,
            Some(&runtime_overrides),
        );
        assert_eq!(result.status, "OK");
        assert!(!result.is_error);
    }

    /// TCK-00595 MAJOR-3: projection health check returns ERROR when
    /// enabled but `github_owner` is missing.
    #[test]
    fn projection_health_enabled_missing_owner_returns_error() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("ecosystem.toml");
        std::fs::write(
            &config_path,
            "[daemon]\noperator_socket = \"/tmp/op.sock\"\nsession_socket = \"/tmp/sess.sock\"\n\
             [daemon.projection]\nenabled = true\n",
        )
        .unwrap();

        let result = check_projection_worker_health_with_overrides(&config_path, true, None);
        assert_eq!(result.status, "ERROR");
        assert!(result.is_error);
        assert!(result.message.contains("github_owner or github_repo"));
    }

    /// TCK-00595 MAJOR-3: projection health check returns WARN when
    /// no config file exists.
    #[test]
    fn projection_health_no_config_returns_warn() {
        let result = check_projection_worker_health(
            std::path::Path::new("/tmp/apm2-test-nonexistent/ecosystem.toml"),
            true,
        );
        assert_eq!(result.status, "WARN");
        assert!(!result.is_error);
    }

    /// TCK-00547: `check_binary_available` returns true for a known binary.
    #[test]
    fn check_binary_available_true_for_known_binary() {
        // `true` is a shell built-in / binary available on all unix systems
        assert!(check_binary_available("true", &[]));
    }

    /// TCK-00547: `check_binary_available` returns false for a non-existent
    /// binary.
    #[test]
    fn check_binary_available_false_for_missing_binary() {
        assert!(!check_binary_available(
            "nonexistent-binary-apm2-test-12345",
            &[]
        ));
    }

    /// TCK-00547 MAJOR-3: `check_binary_available` returns false when the
    /// binary spawns but exits with a non-zero status (e.g. missing
    /// subcommand).
    #[test]
    fn check_binary_available_false_for_failing_exit_status() {
        // `false` binary always exits with code 1
        assert!(!check_binary_available("false", &[]));
    }

    /// TCK-00547: lane safety check returns OK when lane dir does not exist.
    #[test]
    fn lane_safety_ok_when_no_lane_dir() {
        let temp = tempfile::TempDir::new().unwrap();
        let nonexistent = temp.path().join("nonexistent_lanes");
        let result = check_lane_directory_safety_at(&nonexistent);
        assert_eq!(result.status, "OK");
        assert!(result.message.contains("does not exist"));
    }

    /// TCK-00547: lane safety detects symlinks in lane directory.
    #[cfg(unix)]
    #[test]
    fn lane_safety_detects_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::TempDir::new().unwrap();
        let lanes_dir = temp.path().join("lanes");
        std::fs::create_dir_all(&lanes_dir).unwrap();
        std::fs::set_permissions(&lanes_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Create a symlink inside the lanes directory
        let real_dir = temp.path().join("real_target");
        std::fs::create_dir(&real_dir).unwrap();
        let symlink_path = lanes_dir.join("evil-lane");
        std::os::unix::fs::symlink(&real_dir, &symlink_path).unwrap();

        let result = check_lane_directory_safety_at(&lanes_dir);
        assert_eq!(result.status, "ERROR");
        assert!(result.message.contains("symlink"));
    }

    /// TCK-00547: lane safety returns OK when no symlinks present.
    #[cfg(unix)]
    #[test]
    fn lane_safety_ok_when_clean() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::TempDir::new().unwrap();
        let lanes_dir = temp.path().join("lanes");
        std::fs::create_dir_all(&lanes_dir).unwrap();
        std::fs::set_permissions(&lanes_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Create a normal directory (not a symlink)
        let lane_path = lanes_dir.join("lane-0");
        std::fs::create_dir(&lane_path).unwrap();
        std::fs::set_permissions(&lane_path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let result = check_lane_directory_safety_at(&lanes_dir);
        assert_eq!(result.status, "OK");
        assert!(result.message.contains("no symlinks"));
    }

    /// TCK-00547 MAJOR-2: lane safety detects `lanes_dir` itself being a
    /// symlink.
    #[cfg(unix)]
    #[test]
    fn lane_safety_detects_root_symlink() {
        let temp = tempfile::TempDir::new().unwrap();
        let real_dir = temp.path().join("real_lanes");
        std::fs::create_dir_all(&real_dir).unwrap();

        let symlink_lanes = temp.path().join("lanes_symlink");
        std::os::unix::fs::symlink(&real_dir, &symlink_lanes).unwrap();

        let result = check_lane_directory_safety_at(&symlink_lanes);
        assert_eq!(result.status, "ERROR");
        assert!(result.message.contains("is a symlink"));
    }

    /// TCK-00547 MAJOR-4: lane safety detects unsafe permissions (group/world
    /// writable).
    #[cfg(unix)]
    #[test]
    fn lane_safety_detects_unsafe_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new().unwrap();
        let lanes_dir = temp.path().join("lanes");
        std::fs::create_dir_all(&lanes_dir).unwrap();

        // Make lanes_dir world-writable
        std::fs::set_permissions(&lanes_dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let result = check_lane_directory_safety_at(&lanes_dir);
        assert_eq!(result.status, "ERROR");
        assert!(result.message.contains("unsafe permissions"));
    }

    /// TCK-00547 MAJOR-1: lane safety returns ERROR when scan limit is reached
    /// (fail-closed).
    #[cfg(unix)]
    #[test]
    fn lane_safety_errors_on_too_many_entries() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::TempDir::new().unwrap();
        let lanes_dir = temp.path().join("lanes");
        std::fs::create_dir_all(&lanes_dir).unwrap();
        std::fs::set_permissions(&lanes_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Create MAX_LANE_SCAN + 1 entries to trigger overflow
        for i in 0..=MAX_LANE_SCAN {
            let path = lanes_dir.join(format!("lane-{i:04}"));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let result = check_lane_directory_safety_at(&lanes_dir);
        assert_eq!(result.status, "ERROR");
        assert!(result.message.contains("too many entries"));
    }

    /// TCK-00547 R2 MINOR (security): dangling symlink on lanes root is
    /// detected as ERROR, not silently treated as absent.
    #[cfg(unix)]
    #[test]
    fn lane_safety_detects_dangling_root_symlink() {
        let temp = tempfile::TempDir::new().unwrap();
        // Point to a target that does not exist — a dangling symlink
        let dangling_target = temp.path().join("nonexistent_target");
        let symlink_lanes = temp.path().join("lanes_dangling");
        std::os::unix::fs::symlink(&dangling_target, &symlink_lanes).unwrap();

        let result = check_lane_directory_safety_at(&symlink_lanes);
        assert_eq!(result.status, "ERROR");
        assert!(result.message.contains("is a symlink"));
    }

    /// TCK-00547 R2 MAJOR: lane scan is deterministic — sorting by name
    /// ensures the same entries are always checked regardless of filesystem
    /// iteration order. Here we verify that a symlink placed at a
    /// lexicographically early name is always detected, even with many entries.
    #[cfg(unix)]
    #[test]
    fn lane_safety_deterministic_scan_order() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::TempDir::new().unwrap();
        let lanes_dir = temp.path().join("lanes");
        std::fs::create_dir_all(&lanes_dir).unwrap();
        std::fs::set_permissions(&lanes_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Create entries that would come after the symlink in sorted order
        for i in 0..10 {
            let path = lanes_dir.join(format!("lane-{i:04}"));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        // Place a symlink with a name that sorts first (aaa-evil)
        let real_target = temp.path().join("real_target");
        std::fs::create_dir(&real_target).unwrap();
        std::os::unix::fs::symlink(&real_target, lanes_dir.join("aaa-evil")).unwrap();

        // Run multiple times to confirm deterministic detection
        for _ in 0..5 {
            let result = check_lane_directory_safety_at(&lanes_dir);
            assert_eq!(result.status, "ERROR", "symlink must always be detected");
            assert!(result.message.contains("symlink"));
        }
    }

    // ── Binary alignment doctor check tests (TCK-00625 MAJOR-2) ────────

    /// TCK-00625 MAJOR-2: Digest mismatch must produce ERROR status
    /// (fail-closed), not WARN.
    #[test]
    fn binary_alignment_digest_mismatch_is_error() {
        let cli_digest = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666";
        let svc_digest = "9999888877776666555544443333222211110000ffffeeee";
        let result = check_binary_alignment_inner(
            "/usr/bin/apm2",
            cli_digest,
            &[
                ("apm2-daemon.service", Ok(svc_digest)),
                ("apm2-worker.service", Ok(cli_digest)),
            ],
            2,
        );
        assert_eq!(
            result.status, "ERROR",
            "digest mismatch must be ERROR, got: {} — {}",
            result.status, result.message
        );
        assert!(
            result.message.contains("mismatch"),
            "message must mention mismatch: {}",
            result.message
        );
        assert!(
            result.message.contains("INV-PADOPT-004"),
            "message must cite INV-PADOPT-004: {}",
            result.message
        );
    }

    /// TCK-00625 MAJOR-2: No service binaries resolvable must produce
    /// ERROR status (fail-closed), not WARN.
    #[test]
    fn binary_alignment_no_service_resolvable_is_error() {
        let cli_digest = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666";
        let result = check_binary_alignment_inner(
            "/usr/bin/apm2",
            cli_digest,
            &[
                (
                    "apm2-daemon.service",
                    Err("cannot resolve service binary: unit not found"),
                ),
                (
                    "apm2-worker.service",
                    Err("cannot resolve service binary: unit not found"),
                ),
            ],
            2,
        );
        assert_eq!(
            result.status, "ERROR",
            "no resolvable service binaries must be ERROR, got: {} — {}",
            result.status, result.message
        );
        assert!(
            result
                .message
                .contains("no service binary could be verified"),
            "message must indicate no verification: {}",
            result.message
        );
    }

    /// TCK-00625 MAJOR-2: Partial resolution (at least one matched, others
    /// failed to resolve) produces WARN — degraded but not fatal.
    #[test]
    fn binary_alignment_partial_resolution_is_warn() {
        let cli_digest = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666";
        let result = check_binary_alignment_inner(
            "/usr/bin/apm2",
            cli_digest,
            &[
                ("apm2-daemon.service", Ok(cli_digest)),
                (
                    "apm2-worker.service",
                    Err("cannot resolve service binary: unit not found"),
                ),
            ],
            2,
        );
        assert_eq!(
            result.status, "WARN",
            "partial resolution must be WARN, got: {} — {}",
            result.status, result.message
        );
        assert!(
            result.message.contains("partial binary verification"),
            "message must indicate partial verification: {}",
            result.message
        );
        assert!(
            result.message.contains("1/2 units ok"),
            "message must show count: {}",
            result.message
        );
    }

    /// TCK-00625 MAJOR-2: All service binaries resolved and all digests
    /// match produces OK status.
    #[test]
    fn binary_alignment_all_match_is_ok() {
        let cli_digest = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666";
        let result = check_binary_alignment_inner(
            "/usr/bin/apm2",
            cli_digest,
            &[
                ("apm2-daemon.service", Ok(cli_digest)),
                ("apm2-worker.service", Ok(cli_digest)),
            ],
            2,
        );
        assert_eq!(
            result.status, "OK",
            "all matching digests must be OK, got: {} — {}",
            result.status, result.message
        );
        assert!(
            result.message.contains("matching SHA-256 digest"),
            "message must confirm matching digest: {}",
            result.message
        );
    }

    /// TCK-00625 MAJOR-2: Mismatch + resolve failure is still ERROR
    /// (mismatch takes precedence over partial resolution).
    #[test]
    fn binary_alignment_mismatch_plus_resolve_failure_is_error() {
        let cli_digest = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666";
        let bad_digest = "9999888877776666555544443333222211110000ffffeeee";
        let result = check_binary_alignment_inner(
            "/usr/bin/apm2",
            cli_digest,
            &[
                ("apm2-daemon.service", Ok(bad_digest)),
                (
                    "apm2-worker.service",
                    Err("cannot resolve service binary: unit not found"),
                ),
            ],
            2,
        );
        assert_eq!(
            result.status, "ERROR",
            "mismatch must dominate over resolve failure: {} — {}",
            result.status, result.message
        );
    }
}
