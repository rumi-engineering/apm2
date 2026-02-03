//! Capability management CLI commands.
//!
//! This module implements `apm2 capability` subcommands for capability
//! operations using the protocol-based operator socket (TCK-00288).
//!
//! # Commands
//!
//! - `apm2 capability issue --session-id <id> --tool-class <class>` - Issue
//!   capability to session
//!
//! # Protocol
//!
//! Uses `OperatorClient` for privileged operations via operator.sock.
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

use crate::client::protocol::{OperatorClient, ProtocolClientError};
use crate::exit_codes::{codes as exit_codes, map_protocol_error};

/// Capability command group.
#[derive(Debug, Args)]
pub struct CapabilityCommand {
    /// Output format (text or json).
    #[arg(long, default_value = "false")]
    pub json: bool,

    #[command(subcommand)]
    pub subcommand: CapabilitySubcommand,
}

/// Capability subcommands.
#[derive(Debug, Subcommand)]
pub enum CapabilitySubcommand {
    /// Issue a capability to a session.
    ///
    /// Grants additional tool access or path patterns to an existing session.
    /// Requires operator privileges.
    Issue(IssueArgs),
}

/// Arguments for `apm2 capability issue`.
#[derive(Debug, Args)]
pub struct IssueArgs {
    /// Target session identifier.
    #[arg(long, required = true)]
    pub session_id: String,

    /// Tool class to grant access to (e.g., "`file_read`", "`shell_exec`").
    #[arg(long, required = true)]
    pub tool_class: String,

    /// Path patterns for read access (can be specified multiple times).
    #[arg(long)]
    pub read_pattern: Vec<String>,

    /// Path patterns for write access (can be specified multiple times).
    #[arg(long)]
    pub write_pattern: Vec<String>,

    /// Duration in seconds for the capability grant.
    #[arg(long, default_value = "3600")]
    pub duration_secs: u64,
}

// ============================================================================
// Response Types for JSON output
// ============================================================================

/// Response for capability issue command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueResponse {
    /// Unique identifier for this capability grant.
    pub capability_id: String,
    /// Unix timestamp when capability was granted.
    pub granted_at: u64,
    /// Unix timestamp when capability expires.
    pub expires_at: u64,
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

/// Runs the capability command, returning an appropriate exit code.
pub fn run_capability(cmd: &CapabilityCommand, socket_path: &Path) -> u8 {
    let json_output = cmd.json;

    match &cmd.subcommand {
        CapabilitySubcommand::Issue(args) => run_issue(args, socket_path, json_output),
    }
}

/// Execute the issue command.
fn run_issue(args: &IssueArgs, socket_path: &Path, json_output: bool) -> u8 {
    // Validate session ID
    if args.session_id.is_empty() {
        return output_error(
            json_output,
            "invalid_session_id",
            "Session ID cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Validate tool class
    if args.tool_class.is_empty() {
        return output_error(
            json_output,
            "invalid_tool_class",
            "Tool class cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

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

    // Execute issue capability
    let result = rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path).await?;
        client
            .issue_capability(
                &args.session_id,
                &args.tool_class,
                &args.read_pattern,
                &args.write_pattern,
                args.duration_secs,
            )
            .await
    });

    match result {
        Ok(response) => {
            let issue_response = IssueResponse {
                capability_id: response.capability_id,
                granted_at: response.granted_at,
                expires_at: response.expires_at,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&issue_response)
                        .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Capability issued successfully");
                println!("  Capability ID:  {}", issue_response.capability_id);
                println!("  Granted At:     {}", issue_response.granted_at);
                println!("  Expires At:     {}", issue_response.expires_at);
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
    fn test_issue_response_serialization() {
        let response = IssueResponse {
            capability_id: "cap-123".to_string(),
            granted_at: 1_704_067_200,
            expires_at: 1_704_070_800,
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: IssueResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.capability_id, "cap-123");
    }

    /// SECURITY TEST: Verify responses reject unknown fields.
    #[test]
    fn test_issue_response_rejects_unknown_fields() {
        let json = r#"{
            "capability_id": "cap-1",
            "granted_at": 0,
            "expires_at": 0,
            "malicious": "value"
        }"#;

        let result: Result<IssueResponse, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "IssueResponse should reject unknown fields"
        );
    }
}
