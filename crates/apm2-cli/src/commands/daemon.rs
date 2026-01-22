//! Daemon management commands.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use apm2_core::ipc::{IpcRequest, IpcResponse};
use tracing::info;

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

/// Kill the daemon.
pub fn kill(socket_path: &Path) -> Result<()> {
    // Try to send shutdown command via IPC
    match send_request(socket_path, &IpcRequest::Shutdown) {
        Ok(IpcResponse::Ok { message }) => {
            println!(
                "Daemon shutting down{}",
                message.map(|m| format!(": {m}")).unwrap_or_default()
            );
        },
        Ok(IpcResponse::Error { code, message }) => {
            bail!("Failed to shutdown daemon: {message} ({code:?})");
        },
        Err(e) => {
            // Daemon might not be running
            println!("Could not connect to daemon: {e}");
            println!("Daemon may not be running");
        },
        _ => {},
    }

    Ok(())
}

/// Send an IPC request to the daemon.
fn send_request(socket_path: &Path, request: &IpcRequest) -> Result<IpcResponse> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    // Connect to daemon
    let mut stream =
        UnixStream::connect(socket_path).context("failed to connect to daemon socket")?;

    // Send request
    let request_json = serde_json::to_vec(&request)?;
    let framed = apm2_core::ipc::frame_message(&request_json);
    stream.write_all(&framed)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response_buf = vec![0u8; len];
    stream.read_exact(&mut response_buf)?;

    let response: IpcResponse = serde_json::from_slice(&response_buf)?;
    Ok(response)
}
