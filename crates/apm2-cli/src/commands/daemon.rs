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
