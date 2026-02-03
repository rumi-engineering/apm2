//! Event management CLI commands.
//!
//! This module implements `apm2 event` subcommands for ledger event emission
//! using the protocol-based session socket (TCK-00288).
//!
//! # Commands
//!
//! - `apm2 event emit --session-token <token> --event-type <type>` - Emit event
//!   to ledger
//!
//! # Protocol
//!
//! Uses `SessionClient` for session-scoped operations via session.sock.
//! All communication uses tag-based protobuf framing per DD-009 and RFC-0017.
//!
//! # Exit Codes (RFC-0018)
//!
//! - 0: Success
//! - 10: Validation error
//! - 11: Permission denied
//! - 12: Not found
//! - 20: Daemon unavailable
//! - 21: Protocol error
//! - 22: Policy deny

use std::path::Path;

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::client::protocol::{ProtocolClientError, SessionClient};
use crate::exit_codes::{codes as exit_codes, map_protocol_error};

/// Event command group.
#[derive(Debug, Args)]
pub struct EventCommand {
    /// Output format (text or json).
    #[arg(long, default_value = "false")]
    pub json: bool,

    #[command(subcommand)]
    pub subcommand: EventSubcommand,
}

/// Event subcommands.
#[derive(Debug, Subcommand)]
pub enum EventSubcommand {
    /// Emit a signed event to the ledger.
    ///
    /// Events are recorded in the daemon's ledger with cryptographic
    /// signatures for tamper-evidence.
    Emit(EmitArgs),
}

/// Arguments for `apm2 event emit`.
#[derive(Debug, Args)]
pub struct EmitArgs {
    /// Session token for authentication.
    ///
    /// Obtained from `apm2 episode spawn` response.
    ///
    /// **Security (CWE-214)**: Prefer setting the `APM2_SESSION_TOKEN`
    /// environment variable instead of using this flag. CLI arguments
    /// are visible in process listings on multi-user systems.
    #[arg(long, env = "APM2_SESSION_TOKEN")]
    pub session_token: Option<String>,

    /// Event type identifier (e.g., "work.started", "tool.executed").
    #[arg(long, required = true)]
    pub event_type: String,

    /// Event payload as JSON string.
    #[arg(long, default_value = "{}")]
    pub payload: String,

    /// Correlation ID for event tracing.
    #[arg(long)]
    pub correlation_id: Option<String>,
}

// ============================================================================
// Response Types for JSON output
// ============================================================================

/// Response for event emit command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmitResponse {
    /// Event identifier in the ledger.
    pub event_id: String,
    /// Sequence number in the session.
    pub seq: u64,
    /// Timestamp when event was recorded (nanoseconds since epoch).
    pub timestamp_ns: u64,
}

/// Error response for JSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
}

// ============================================================================
// Command execution
// ============================================================================

/// Runs the event command, returning an appropriate exit code.
pub fn run_event(cmd: &EventCommand, socket_path: &Path) -> u8 {
    let json_output = cmd.json;

    match &cmd.subcommand {
        EventSubcommand::Emit(args) => run_emit(args, socket_path, json_output),
    }
}

/// Execute the emit command.
fn run_emit(args: &EmitArgs, socket_path: &Path, json_output: bool) -> u8 {
    // Resolve session token (CWE-214 mitigation: prefer env var over CLI arg)
    let session_token = match &args.session_token {
        Some(token) if !token.is_empty() => token.clone(),
        _ => {
            return output_error(
                json_output,
                "missing_session_token",
                "Session token is required. Set APM2_SESSION_TOKEN environment variable \
                 (preferred) or use --session-token flag.",
                exit_codes::VALIDATION_ERROR,
            );
        },
    };

    // Validate event type
    if args.event_type.is_empty() {
        return output_error(
            json_output,
            "invalid_event_type",
            "Event type cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Parse payload as JSON bytes
    let payload = args.payload.as_bytes().to_vec();

    // Generate correlation ID if not provided
    let correlation_id = args.correlation_id.clone().unwrap_or_else(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("cli-{ts}")
    });

    // Build async runtime
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return output_error(
                json_output,
                "runtime_error",
                &format!("Failed to build tokio runtime: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Execute emit
    let result = rt.block_on(async {
        let mut client = SessionClient::connect(socket_path).await?;
        client
            .emit_event(&session_token, &args.event_type, &payload, &correlation_id)
            .await
    });

    match result {
        Ok(response) => {
            let emit_response = EmitResponse {
                event_id: response.event_id,
                seq: response.seq,
                timestamp_ns: response.timestamp_ns,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&emit_response)
                        .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Event emitted successfully");
                println!("  Event ID:     {}", emit_response.event_id);
                println!("  Sequence:     {}", emit_response.seq);
                println!("  Timestamp:    {} ns", emit_response.timestamp_ns);
            }

            exit_codes::SUCCESS
        },
        Err(e) => handle_protocol_error(json_output, &e),
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Output an error in the appropriate format.
fn output_error(json_output: bool, code: &str, message: &str, exit_code: u8) -> u8 {
    if json_output {
        let error = ErrorResponse {
            code: code.to_string(),
            message: message.to_string(),
        };
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&error).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        eprintln!("Error: {message}");
    }
    exit_code
}

/// Handles protocol client errors and returns appropriate exit code (RFC-0018).
fn handle_protocol_error(json_output: bool, error: &ProtocolClientError) -> u8 {
    let exit_code = map_protocol_error(error);
    let (code, message) = match error {
        ProtocolClientError::DaemonNotRunning => (
            "daemon_not_running".to_string(),
            "Daemon is not running. Start with: apm2 daemon".to_string(),
        ),
        ProtocolClientError::ConnectionFailed(msg) => (
            "connection_failed".to_string(),
            format!("Failed to connect to daemon: {msg}"),
        ),
        ProtocolClientError::HandshakeFailed(msg) => (
            "handshake_failed".to_string(),
            format!("Protocol handshake failed: {msg}"),
        ),
        ProtocolClientError::VersionMismatch { client, server } => (
            "version_mismatch".to_string(),
            format!("Protocol version mismatch: client {client}, server {server}"),
        ),
        ProtocolClientError::DaemonError { code, message } => (code.clone(), message.clone()),
        ProtocolClientError::IoError(e) => ("io_error".to_string(), format!("I/O error: {e}")),
        ProtocolClientError::ProtocolError(e) => {
            ("protocol_error".to_string(), format!("Protocol error: {e}"))
        },
        ProtocolClientError::DecodeError(msg) => {
            ("decode_error".to_string(), format!("Decode error: {msg}"))
        },
        ProtocolClientError::UnexpectedResponse(msg) => (
            "unexpected_response".to_string(),
            format!("Unexpected response: {msg}"),
        ),
        ProtocolClientError::Timeout => ("timeout".to_string(), "Operation timed out".to_string()),
        ProtocolClientError::FrameTooLarge { size, max } => (
            "frame_too_large".to_string(),
            format!("Frame too large: {size} bytes (max: {max})"),
        ),
    };
    output_error(json_output, &code, &message, exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_response_serialization() {
        let response = EmitResponse {
            event_id: "evt-123".to_string(),
            seq: 42,
            timestamp_ns: 1_704_067_200_000_000_000,
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: EmitResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.event_id, "evt-123");
        assert_eq!(restored.seq, 42);
    }

    /// SECURITY TEST: Verify responses reject unknown fields.
    #[test]
    fn test_emit_response_rejects_unknown_fields() {
        let json = r#"{
            "event_id": "evt-1",
            "seq": 1,
            "timestamp_ns": 0,
            "malicious": "value"
        }"#;

        let result: Result<EmitResponse, _> = serde_json::from_str(json);
        assert!(result.is_err(), "EmitResponse should reject unknown fields");
    }
}
