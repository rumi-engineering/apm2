//! Daemon management commands.
//!
//! # TCK-00288: Protocol-Based IPC
//!
//! Per DD-009 (RFC-0017), the CLI uses tag-based protobuf communication via
//! the operator socket. The `kill` command sends a Shutdown request using
//! the `OperatorClient`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use apm2_core::config::default_data_dir;
use apm2_core::github::resolve_apm2_home;
use tracing::info;

use crate::client::protocol::{OperatorClient, ProtocolClientError};
use crate::commands::fac_permissions::{ensure_dir_exists_standard, ensure_dir_with_mode};

const FAC_RUNTIME_SUBDIRS: [&str; 13] = [
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
    "private/fac/queue/quarantined",
    "private/fac/queue/authority_consumed",
];

const USER_SYSTEMD_DIR: &str = ".config/systemd/user";

const DAEMON_SERVICE: &str = "\
[Unit]\n\
Description=APM2 Daemon — Forge Admission Cycle broker\n\
Documentation=https://github.com/guardian-intelligence/apm2\n\
After=network-online.target\n\
Wants=network-online.target\n\
Requires=apm2-daemon.socket\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart=/usr/local/bin/apm2 daemon --no-daemon\n\
ExecStop=/usr/local/bin/apm2 kill\n\
Restart=always\n\
RestartSec=5\n\
WatchdogSec=300\n\
WorkingDirectory=%h\n\
Environment=APM2_HOME=%h/.apm2\n\
Environment=RUST_LOG=info\n\
Environment=XDG_RUNTIME_DIR=%t\n\
LoadCredential=gh-token:%h/.apm2/private/creds/gh-token\n\
Sockets=apm2-daemon.socket\n\
ProtectSystem=strict\n\
ProtectHome=read-only\n\
ReadWritePaths=%h/.apm2\n\
NoNewPrivileges=yes\n\
PrivateTmp=yes\n\
\n\
[Install]\n\
WantedBy=default.target\n\
";

const WORKER_SERVICE: &str = "\
[Unit]\n\
Description=APM2 FAC Worker\n\
Documentation=https://github.com/guardian-intelligence/apm2\n\
After=network-online.target apm2-daemon.service\n\
Wants=apm2-daemon.service\n\
Requires=apm2-daemon.service\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart=/usr/local/bin/apm2 fac worker --poll-interval 10\n\
Restart=always\n\
RestartSec=5\n\
WatchdogSec=300\n\
WorkingDirectory=%h\n\
Environment=APM2_HOME=%h/.apm2\n\
Environment=RUST_LOG=info\n\
LoadCredential=gh-token:%h/.apm2/private/creds/gh-token\n\
ProtectSystem=strict\n\
ProtectHome=read-only\n\
ReadWritePaths=%h/.apm2\n\
NoNewPrivileges=yes\n\
PrivateTmp=yes\n\
\n\
[Install]\n\
WantedBy=default.target\n\
";

const WORKER_TEMPLATE_SERVICE: &str = "\
[Unit]\n\
Description=APM2 FAC Worker (%i)\n\
Documentation=https://github.com/guardian-intelligence/apm2\n\
After=network-online.target apm2-daemon.service\n\
Wants=apm2-daemon.service\n\
Requires=apm2-daemon.service\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart=/usr/local/bin/apm2 fac worker --poll-interval 10\n\
Restart=always\n\
RestartSec=5\n\
WatchdogSec=300\n\
WorkingDirectory=%h\n\
Environment=APM2_HOME=%h/.apm2\n\
Environment=RUST_LOG=info\n\
LoadCredential=gh-token:%h/.apm2/private/creds/gh-token\n\
ProtectSystem=strict\n\
ProtectHome=read-only\n\
ReadWritePaths=%h/.apm2\n\
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

/// Install the systemd user service for apm2-daemon.
pub fn install() -> Result<()> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    let systemd_user_dir = Path::new(&home).join(USER_SYSTEMD_DIR);
    ensure_dir_exists_standard(&systemd_user_dir)
        .context("failed to create user systemd unit directory")?;

    let apm2_home = resolve_apm2_home().ok_or_else(|| {
        anyhow!("cannot resolve APM2_HOME; set APM2_HOME or HOME to a valid directory")
    })?;
    ensure_fac_runtime_dirs(&apm2_home)?;

    let unit_files = [
        ("apm2-daemon.service", DAEMON_SERVICE),
        ("apm2-worker.service", WORKER_SERVICE),
        ("apm2-worker@.service", WORKER_TEMPLATE_SERVICE),
        ("apm2-daemon.socket", DAEMON_SOCKET),
    ];
    for (filename, content) in unit_files {
        let unit_path = systemd_user_dir.join(filename);
        std::fs::write(&unit_path, content).with_context(|| {
            format!(
                "failed to write user systemd unit file {}",
                unit_path.display()
            )
        })?;
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

/// Ensure the daemon is running, starting it when necessary.
///
/// TCK-00595 MAJOR-2 FIX: The `config_path` parameter threads the caller's
/// effective config file into the spawn path. When the direct-spawn fallback
/// is used (systemctl unavailable), the daemon is launched with
/// `--config <same-path>` so it binds to the same sockets the caller expects.
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
/// TCK-00595 MAJOR-3 FIX: Now includes a projection-worker liveness probe.
/// When projection is enabled in config, the check verifies that the
/// projection cache database exists (created by the projection worker on
/// startup), which serves as evidence the worker is active.
pub fn doctor(operator_socket: &Path, config_path: &Path, json: bool) -> Result<()> {
    #[derive(serde::Serialize)]
    struct DoctorCheck {
        name: String,
        status: &'static str,
        message: String,
    }

    let mut checks = Vec::new();
    let mut has_error = false;

    let github_token_set = matches!(std::env::var("GITHUB_TOKEN"), Ok(value) if !value.is_empty());
    checks.push(DoctorCheck {
        name: "GITHUB_TOKEN".to_string(),
        status: if github_token_set { "OK" } else { "ERROR" },
        message: if github_token_set {
            "GITHUB_TOKEN is set".to_string()
        } else {
            "GITHUB_TOKEN is not set".to_string()
        },
    });
    if !github_token_set {
        has_error = true;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for doctor check")?;

    let (daemon_running, daemon_probe_message) = match check_socket_reachable(&rt, operator_socket)
    {
        Ok(()) => (true, "operator socket is reachable".to_string()),
        Err(msg) => (false, msg),
    };
    let daemon_running_ok = daemon_running;
    checks.push(DoctorCheck {
        name: "daemon_running".to_string(),
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

    let data_dir = default_data_dir();
    match available_space_bytes(&data_dir) {
        Ok(free_bytes) => {
            let has_space = free_bytes >= 1_073_741_824;
            checks.push(DoctorCheck {
                name: "disk_space".to_string(),
                status: if has_space { "OK" } else { "ERROR" },
                message: if has_space {
                    format!("{} has {} free bytes", data_dir.display(), free_bytes)
                } else {
                    format!(
                        "{} has only {} free bytes (minimum 1 GiB required)",
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
            checks.push(DoctorCheck {
                name: "disk_space".to_string(),
                status: "ERROR",
                message: format!(
                    "failed to read free space for {}: {error}",
                    data_dir.display()
                ),
            });
        },
    }

    match socket_permission_check(operator_socket) {
        Ok(permission_ok) => {
            checks.push(DoctorCheck {
                name: "socket_permissions".to_string(),
                status: if permission_ok { "OK" } else { "ERROR" },
                message: if permission_ok {
                    format!("{} is mode 0600", operator_socket.display())
                } else {
                    format!("{} is not mode 0600", operator_socket.display())
                },
            });
            if !permission_ok {
                has_error = true;
            }
        },
        Err(error) => {
            has_error = true;
            checks.push(DoctorCheck {
                name: "socket_permissions".to_string(),
                status: "ERROR",
                message: format!(
                    "failed to check {} permissions: {error}",
                    operator_socket.display()
                ),
            });
        },
    }

    // TCK-00595 MAJOR-3 FIX: Projection worker liveness probe.
    //
    // When projection is enabled in config, verify the projection worker
    // has started by checking for its cache database file. The projection
    // worker creates this file on startup, so its absence indicates the
    // worker is not active.
    {
        let projection_check = check_projection_worker_health(config_path, daemon_running_ok);
        if projection_check.is_error {
            has_error = true;
        }
        checks.push(DoctorCheck {
            name: "projection_worker".to_string(),
            status: projection_check.status,
            message: projection_check.message,
        });
    }

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

/// Check projection worker health by examining config and runtime artifacts.
///
/// The projection worker creates a cache database file on startup. When
/// projection is enabled in config but this file is absent, the worker
/// is either not started or has failed.
fn check_projection_worker_health(
    config_path: &Path,
    daemon_running: bool,
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
    // The worker creates {state_dir}/projection_cache.db on initialization.
    let state_dir = config
        .daemon
        .state_file
        .parent()
        .map_or_else(default_data_dir, Path::to_path_buf);

    let cache_path = state_dir.join("projection_cache.db");
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
    let metadata = std::fs::symlink_metadata(path).context("socket path is missing")?;
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

        let result = check_projection_worker_health(&config_path, true);
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

        let result = check_projection_worker_health(&config_path, false);
        assert_eq!(result.status, "ERROR");
        assert!(result.is_error);
        assert!(result.message.contains("daemon is not running"));
    }

    /// TCK-00595 MAJOR-3: projection worker health check returns ERROR when
    /// enabled but cache file missing.
    #[test]
    fn projection_health_enabled_no_cache_returns_error() {
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

        let result = check_projection_worker_health(&config_path, true);
        assert_eq!(result.status, "ERROR");
        assert!(result.is_error);
        assert!(result.message.contains("projection cache not found"));
    }

    /// TCK-00595 MAJOR-3: projection worker health check returns OK when
    /// enabled, daemon running, and cache exists.
    #[test]
    fn projection_health_enabled_with_cache_returns_ok() {
        let temp = tempfile::TempDir::new().unwrap();
        let state_path = temp.path().join("state.json");
        let config_path = temp.path().join("ecosystem.toml");
        // Create the projection cache file to simulate active worker
        let cache_path = temp.path().join("projection_cache.db");
        std::fs::write(&cache_path, b"dummy").unwrap();

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

        let result = check_projection_worker_health(&config_path, true);
        assert_eq!(result.status, "OK");
        assert!(!result.is_error);
        assert!(result.message.contains("projection worker active"));
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

        let result = check_projection_worker_health(&config_path, true);
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
}
