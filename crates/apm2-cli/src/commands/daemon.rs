//! Daemon management commands.
//!
//! # TCK-00288: Protocol-Based IPC
//!
//! Per DD-009 (RFC-0017), the CLI uses tag-based protobuf communication via
//! the operator socket. The `kill` command sends a Shutdown request using
//! the `OperatorClient`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use apm2_core::config::default_data_dir;
use tracing::info;

use crate::client::protocol::{OperatorClient, ProtocolClientError};

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
    let exe_path = std::env::current_exe()
        .context("failed to determine current executable path")?
        .canonicalize()
        .context("failed to canonicalize current executable path")?;
    let exe_str = exe_path.display().to_string();

    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    let unit_path = std::path::Path::new(&home)
        .join(".config")
        .join("systemd")
        .join("user")
        .join("apm2-daemon.service");

    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create systemd unit directory")?;
    }

    let unit_content = format!(
        "\
[Unit]
Description=APM2 Daemon — Forge Admission Cycle runtime
Documentation=https://github.com/guardian-intelligence/apm2
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart={exe_str} daemon
ExecStop={exe_str} kill
PIDFile=%t/apm2/apm2.pid
Restart=always
RestartSec=5
WatchdogSec=300
# Environment passthrough — GITHUB_TOKEN must be set in user session
# Do NOT put secrets in unit files. Use EnvironmentFile if needed.
# EnvironmentFile=-%h/.config/apm2/env
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
"
    );

    std::fs::write(&unit_path, &unit_content).context("failed to write systemd unit file")?;

    let daemon_reload_status = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()
        .context("failed to run `systemctl --user daemon-reload`")?;
    if !daemon_reload_status.success() {
        bail!("`systemctl --user daemon-reload` failed with status: {daemon_reload_status}");
    }

    let enable_status = Command::new("systemctl")
        .args(["--user", "enable", "apm2-daemon.service"])
        .status()
        .context("failed to run `systemctl --user enable apm2-daemon.service`")?;
    if !enable_status.success() {
        bail!("`systemctl --user enable apm2-daemon.service` failed with status: {enable_status}");
    }

    if let Ok(user) = std::env::var("USER") {
        match Command::new("loginctl")
            .args(["enable-linger", &user])
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

    let start_status = Command::new("systemctl")
        .args(["--user", "start", "apm2-daemon.service"])
        .status()
        .context("failed to run `systemctl --user start apm2-daemon.service`")?;
    if !start_status.success() {
        bail!("`systemctl --user start apm2-daemon.service` failed with status: {start_status}");
    }

    println!("Installed apm2 daemon service at {}", unit_path.display());
    println!("Hint: ensure GITHUB_TOKEN is set in your user session.");

    Ok(())
}

/// Ensure the daemon is running, starting it when necessary.
pub fn ensure_daemon_running(operator_socket: &Path) -> Result<()> {
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
        Command::new(&self_exe)
            .args(["daemon"])
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
pub fn doctor(operator_socket: &Path, json: bool) -> Result<()> {
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
        std::fs::create_dir_all(path).context("failed to create data directory")?;
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
