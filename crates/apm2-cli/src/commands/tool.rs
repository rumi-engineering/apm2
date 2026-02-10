//! Tool management CLI commands.
//!
//! This module implements `apm2 tool` subcommands for tool execution
//! using the protocol-based session socket (TCK-00288).
//!
//! # Commands
//!
//! - `apm2 tool request --session-token <token> --tool-id <id>` - Request tool
//!   execution
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

use apm2_daemon::protocol::messages::DecisionType;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::client::protocol::{ProtocolClientError, SessionClient};
use crate::exit_codes::{codes as exit_codes, map_protocol_error};

/// Tool command group.
#[derive(Debug, Args)]
pub struct ToolCommand {
    /// Output format (text or json).
    #[arg(long, default_value = "false")]
    pub json: bool,

    #[command(subcommand)]
    pub subcommand: ToolSubcommand,
}

/// Tool subcommands.
#[derive(Debug, Subcommand)]
pub enum ToolSubcommand {
    /// Request tool execution within session capability bounds.
    ///
    /// The daemon validates the session token and checks capabilities
    /// before allowing tool execution.
    Request(RequestArgs),
}

/// Arguments for `apm2 tool request`.
#[derive(Debug, Args)]
pub struct RequestArgs {
    /// Session token for authentication.
    ///
    /// Obtained from `apm2 episode spawn` response.
    ///
    /// **Security (CWE-214)**: Prefer setting the `APM2_SESSION_TOKEN`
    /// environment variable instead of using this flag. CLI arguments
    /// are visible in process listings on multi-user systems.
    #[arg(long, env = "APM2_SESSION_TOKEN")]
    pub session_token: Option<String>,

    /// Tool identifier (e.g., "`file_read`", "`shell_exec`").
    #[arg(long, required = true)]
    pub tool_id: String,

    /// Tool arguments as JSON string.
    #[arg(long, default_value = "{}")]
    pub arguments: String,

    /// Deduplication key for idempotent requests.
    #[arg(long)]
    pub dedupe_key: Option<String>,
}

// ============================================================================
// Response Types for JSON output
// ============================================================================

/// Response for tool request command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestResponse {
    /// Request identifier for tracking.
    pub request_id: String,
    /// Tool decision (ALLOW, DENY, `DEDUPE_HIT`).
    pub decision: String,
    /// Rule that matched (if DENY).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Policy hash at decision time (hex-encoded).
    pub policy_hash: String,
    /// Signed daemon-issued channel context token for FAC role launch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_context_token: Option<String>,
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

/// Runs the tool command, returning an appropriate exit code.
pub fn run_tool(cmd: &ToolCommand, socket_path: &Path) -> u8 {
    let json_output = cmd.json;

    match &cmd.subcommand {
        ToolSubcommand::Request(args) => run_request(args, socket_path, json_output),
    }
}

/// Execute the request command.
fn run_request(args: &RequestArgs, socket_path: &Path, json_output: bool) -> u8 {
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

    // Validate tool ID
    if args.tool_id.is_empty() {
        return output_error(
            json_output,
            "invalid_tool_id",
            "Tool ID cannot be empty",
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Parse arguments as JSON bytes
    let arguments = args.arguments.as_bytes().to_vec();

    // Generate dedupe key if not provided
    let dedupe_key = args.dedupe_key.clone().unwrap_or_else(|| {
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

    // Execute request
    let result = rt.block_on(async {
        let mut client = SessionClient::connect(socket_path).await?;
        client
            .request_tool(&session_token, &args.tool_id, &arguments, &dedupe_key)
            .await
    });

    match result {
        Ok(response) => {
            let decision_str = match DecisionType::try_from(response.decision) {
                Ok(DecisionType::Allow) => "ALLOW",
                Ok(DecisionType::Deny) => "DENY",
                Ok(DecisionType::DedupeHit) => "DEDUPE_HIT",
                Err(_) => "UNKNOWN",
            };

            let request_response = RequestResponse {
                request_id: response.request_id,
                decision: decision_str.to_string(),
                rule_id: response.rule_id,
                policy_hash: hex::encode(&response.policy_hash),
                channel_context_token: response.channel_context_token,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&request_response)
                        .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Tool request processed");
                println!("  Request ID:   {}", request_response.request_id);
                println!("  Decision:     {}", request_response.decision);
                if let Some(ref rule) = request_response.rule_id {
                    println!("  Rule ID:      {rule}");
                }
                println!("  Policy Hash:  {}", request_response.policy_hash);
                if let Some(ref token) = request_response.channel_context_token {
                    println!("  Channel Context Token:  {token}");
                    println!(
                        "  Use with: apm2 fac role-launch ... --channel-context-token <token>"
                    );
                }
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
    fn test_request_response_serialization() {
        let response = RequestResponse {
            request_id: "req-123".to_string(),
            decision: "ALLOW".to_string(),
            rule_id: None,
            policy_hash: "abc123".to_string(),
            channel_context_token: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: RequestResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.request_id, "req-123");
        assert!(!json.contains("rule_id")); // Should be skipped when None
    }

    #[test]
    fn test_request_response_with_rule_id() {
        let response = RequestResponse {
            request_id: "req-456".to_string(),
            decision: "DENY".to_string(),
            rule_id: Some("rule-block-foo".to_string()),
            policy_hash: "def456".to_string(),
            channel_context_token: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("rule-block-foo"));
    }

    /// SECURITY TEST: Verify responses reject unknown fields.
    #[test]
    fn test_request_response_rejects_unknown_fields() {
        let json = r#"{
            "request_id": "req-1",
            "decision": "ALLOW",
            "policy_hash": "abc",
            "malicious": "value"
        }"#;

        let result: Result<RequestResponse, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "RequestResponse should reject unknown fields"
        );
    }
}
