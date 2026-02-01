//! IPC server for daemon communication.
//!
//! **DEPRECATED (TCK-00249):** This module is superseded by the dual-socket
//! `SocketManager` topology in `protocol/socket_manager.rs`. The legacy single-
//! socket JSON IPC has been replaced with privilege-separated operator/session
//! sockets per RFC-0017.
//!
//! This module is retained for backwards compatibility during the transition
//! period.

#![allow(dead_code)] // Legacy module - replaced by protocol::socket_manager

use std::path::Path;

use anyhow::{Context, Result};
use apm2_core::ipc::{IpcRequest, IpcResponse, frame_message, parse_frame_length};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

use crate::handlers::dispatch;
use crate::state::SharedState;

/// Maximum message size (16 MB).
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Run the IPC server.
///
/// Listens on the given Unix socket path and handles client connections.
/// Runs until shutdown is requested via the shared state.
///
/// # Arguments
///
/// * `socket_path` - Path to the Unix socket.
/// * `state` - Shared daemon state.
///
/// # Errors
///
/// Returns an error if the socket cannot be bound or an I/O error occurs.
pub async fn run(socket_path: &Path, state: SharedState) -> Result<()> {
    // Remove stale socket file if it exists
    if socket_path.exists() {
        std::fs::remove_file(socket_path).context("failed to remove stale socket")?;
    }

    // Create parent directory if needed
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create socket directory")?;
    }

    let listener = UnixListener::bind(socket_path).context("failed to bind Unix socket")?;
    info!("IPC server listening on {:?}", socket_path);

    loop {
        tokio::select! {
            // Accept new connections
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, state).await {
                                debug!("Connection handler error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }

            // Check for shutdown
            () = wait_for_shutdown(&state) => {
                info!("IPC server shutting down");
                break;
            }
        }
    }

    // Cleanup
    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    Ok(())
}

/// Wait until shutdown is requested.
async fn wait_for_shutdown(state: &SharedState) {
    loop {
        if state.is_shutdown_requested() {
            return;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}

/// Handle a single client connection.
async fn handle_connection(mut stream: UnixStream, state: SharedState) -> Result<()> {
    debug!("New IPC connection");

    loop {
        // Read the request
        let request = match read_request(&mut stream).await {
            Ok(Some(req)) => req,
            Ok(None) => {
                // Connection closed
                debug!("IPC connection closed");
                break;
            },
            Err(e) => {
                warn!("Failed to read request: {}", e);
                break;
            },
        };

        debug!("Received request: {:?}", request);

        // Dispatch to handler
        let response = dispatch(request, &state).await;

        debug!("Sending response: {:?}", response);

        // Send the response
        if let Err(e) = send_response(&mut stream, &response).await {
            warn!("Failed to send response: {}", e);
            break;
        }
    }

    Ok(())
}

/// Read a framed request from the stream.
///
/// Returns `Ok(None)` if the connection was closed.
async fn read_request(stream: &mut UnixStream) -> Result<Option<IpcRequest>> {
    // Read length prefix (4 bytes)
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        },
        Err(e) => return Err(e.into()),
    }

    let len = parse_frame_length(&len_buf).context("invalid frame length")?;

    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("message too large: {len} bytes");
    }

    // Read payload
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;

    // Parse JSON
    let request: IpcRequest =
        serde_json::from_slice(&payload).context("failed to parse request")?;

    Ok(Some(request))
}

/// Send a framed response to the stream.
async fn send_response(stream: &mut UnixStream, response: &IpcResponse) -> Result<()> {
    let json = serde_json::to_vec(response).context("failed to serialize response")?;
    let framed = frame_message(&json);
    stream.write_all(&framed).await?;
    stream.flush().await?;
    Ok(())
}
