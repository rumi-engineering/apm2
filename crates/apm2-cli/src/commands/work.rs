//! Work management CLI commands.
//!
//! This module implements `apm2 work` subcommands for work queue operations
//! using the protocol-based operator socket (TCK-00288).
//!
//! # Commands
//!
//! - `apm2 work claim --actor-id <id> --role <role>` - Claim work from the
//!   queue
//!
//! # Protocol
//!
//! Uses `OperatorClient` for privileged operations via operator.sock.
//! All communication uses tag-based protobuf framing per DD-009 and RFC-0017.
//!
//! # Exit Codes
//!
//! - 0: Success
//! - 1: Error (daemon connection, validation, etc.)

use std::path::Path;

use apm2_daemon::protocol::WorkRole;
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::client::protocol::{OperatorClient, ProtocolClientError};

/// Exit codes for work commands.
pub mod exit_codes {
    /// Success exit code.
    pub const SUCCESS: u8 = 0;
    /// General error exit code.
    pub const ERROR: u8 = 1;
}

/// Work command group.
#[derive(Debug, Args)]
pub struct WorkCommand {
    /// Output format (text or json).
    #[arg(long, default_value = "false")]
    pub json: bool,

    #[command(subcommand)]
    pub subcommand: WorkSubcommand,
}

/// Work subcommands.
#[derive(Debug, Subcommand)]
pub enum WorkSubcommand {
    /// Claim work from the daemon's work queue.
    ///
    /// Requests a work assignment with policy-resolved capabilities.
    /// The daemon validates the credential signature and returns work details.
    Claim(ClaimArgs),
}

/// Role for work claiming.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum RoleArg {
    /// Implementer role (default).
    #[default]
    Implementer,
    /// Gate executor role.
    GateExecutor,
    /// Reviewer role.
    Reviewer,
    /// Coordinator role.
    Coordinator,
}

impl From<RoleArg> for WorkRole {
    fn from(arg: RoleArg) -> Self {
        match arg {
            RoleArg::Implementer => Self::Implementer,
            RoleArg::GateExecutor => Self::GateExecutor,
            RoleArg::Reviewer => Self::Reviewer,
            RoleArg::Coordinator => Self::Coordinator,
        }
    }
}

impl std::fmt::Display for RoleArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Implementer => write!(f, "implementer"),
            Self::GateExecutor => write!(f, "gate_executor"),
            Self::Reviewer => write!(f, "reviewer"),
            Self::Coordinator => write!(f, "coordinator"),
        }
    }
}

/// Arguments for `apm2 work claim`.
#[derive(Debug, Args)]
pub struct ClaimArgs {
    /// Actor ID (display hint, authoritative ID derived from credential).
    #[arg(long, required = true)]
    pub actor_id: String,

    /// Role for work assignment.
    #[arg(long, value_enum, default_value = "implementer")]
    pub role: RoleArg,

    /// Credential signature (hex-encoded Ed25519 signature).
    ///
    /// The signature is computed over (`actor_id` || role || nonce).
    #[arg(long)]
    pub signature: Option<String>,

    /// Nonce (hex-encoded) for replay protection.
    #[arg(long)]
    pub nonce: Option<String>,
}

// ============================================================================
// Response Types for JSON output
// ============================================================================

/// Response for work claim command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimResponse {
    /// Assigned work identifier.
    pub work_id: String,
    /// Lease identifier for this work claim.
    pub lease_id: String,
    /// Blake3 hash of the capability manifest (hex-encoded).
    pub capability_manifest_hash: String,
    /// Reference to the `PolicyResolvedForChangeSet` event.
    pub policy_resolved_ref: String,
    /// Blake3 hash of the sealed context pack (hex-encoded).
    pub context_pack_hash: String,
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

/// Runs the work command, returning an appropriate exit code.
pub fn run_work(cmd: &WorkCommand, socket_path: &Path) -> u8 {
    let json_output = cmd.json;

    match &cmd.subcommand {
        WorkSubcommand::Claim(args) => run_claim(args, socket_path, json_output),
    }
}

/// Execute the claim command.
fn run_claim(args: &ClaimArgs, socket_path: &Path, json_output: bool) -> u8 {
    // Validate actor ID
    if args.actor_id.is_empty() {
        return output_error(
            json_output,
            "invalid_actor_id",
            "Actor ID cannot be empty",
            exit_codes::ERROR,
        );
    }

    // Parse signature (use empty if not provided - daemon will reject if required)
    let signature = match &args.signature {
        Some(hex) => match hex::decode(hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                return output_error(
                    json_output,
                    "invalid_signature",
                    &format!("Invalid signature hex: {e}"),
                    exit_codes::ERROR,
                );
            },
        },
        None => Vec::new(),
    };

    // Parse nonce (use empty if not provided)
    let nonce = match &args.nonce {
        Some(hex) => match hex::decode(hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                return output_error(
                    json_output,
                    "invalid_nonce",
                    &format!("Invalid nonce hex: {e}"),
                    exit_codes::ERROR,
                );
            },
        },
        None => Vec::new(),
    };

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
                exit_codes::ERROR,
            );
        },
    };

    // Execute claim
    let result = rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path).await?;
        client
            .claim_work(&args.actor_id, args.role.into(), &signature, &nonce)
            .await
    });

    match result {
        Ok(response) => {
            let claim_response = ClaimResponse {
                work_id: response.work_id,
                lease_id: response.lease_id,
                capability_manifest_hash: hex::encode(&response.capability_manifest_hash),
                policy_resolved_ref: response.policy_resolved_ref,
                context_pack_hash: hex::encode(&response.context_pack_hash),
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&claim_response)
                        .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Work claimed successfully");
                println!("  Work ID:                {}", claim_response.work_id);
                println!("  Lease ID:               {}", claim_response.lease_id);
                println!(
                    "  Capability Manifest:    {}",
                    claim_response.capability_manifest_hash
                );
                println!(
                    "  Policy Resolved Ref:    {}",
                    claim_response.policy_resolved_ref
                );
                println!(
                    "  Context Pack Hash:      {}",
                    claim_response.context_pack_hash
                );
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

/// Handles protocol client errors and returns appropriate exit code.
fn handle_protocol_error(json_output: bool, error: &ProtocolClientError) -> u8 {
    match error {
        ProtocolClientError::DaemonNotRunning => output_error(
            json_output,
            "daemon_not_running",
            "Daemon is not running. Start with: apm2 daemon",
            exit_codes::ERROR,
        ),
        ProtocolClientError::ConnectionFailed(msg) => output_error(
            json_output,
            "connection_failed",
            &format!("Failed to connect to daemon: {msg}"),
            exit_codes::ERROR,
        ),
        ProtocolClientError::HandshakeFailed(msg) => output_error(
            json_output,
            "handshake_failed",
            &format!("Protocol handshake failed: {msg}"),
            exit_codes::ERROR,
        ),
        ProtocolClientError::VersionMismatch { client, server } => output_error(
            json_output,
            "version_mismatch",
            &format!("Protocol version mismatch: client {client}, server {server}"),
            exit_codes::ERROR,
        ),
        ProtocolClientError::DaemonError { code, message } => {
            output_error(json_output, code, message, exit_codes::ERROR)
        },
        ProtocolClientError::IoError(e) => output_error(
            json_output,
            "io_error",
            &format!("I/O error: {e}"),
            exit_codes::ERROR,
        ),
        ProtocolClientError::ProtocolError(e) => output_error(
            json_output,
            "protocol_error",
            &format!("Protocol error: {e}"),
            exit_codes::ERROR,
        ),
        ProtocolClientError::DecodeError(msg) => output_error(
            json_output,
            "decode_error",
            &format!("Decode error: {msg}"),
            exit_codes::ERROR,
        ),
        ProtocolClientError::UnexpectedResponse(msg) => output_error(
            json_output,
            "unexpected_response",
            &format!("Unexpected response: {msg}"),
            exit_codes::ERROR,
        ),
        ProtocolClientError::Timeout => output_error(
            json_output,
            "timeout",
            "Operation timed out",
            exit_codes::ERROR,
        ),
        ProtocolClientError::FrameTooLarge { size, max } => output_error(
            json_output,
            "frame_too_large",
            &format!("Frame too large: {size} bytes (max: {max})"),
            exit_codes::ERROR,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_display() {
        assert_eq!(RoleArg::Implementer.to_string(), "implementer");
        assert_eq!(RoleArg::GateExecutor.to_string(), "gate_executor");
        assert_eq!(RoleArg::Reviewer.to_string(), "reviewer");
        assert_eq!(RoleArg::Coordinator.to_string(), "coordinator");
    }

    #[test]
    fn test_role_conversion() {
        assert_eq!(WorkRole::from(RoleArg::Implementer), WorkRole::Implementer);
        assert_eq!(
            WorkRole::from(RoleArg::GateExecutor),
            WorkRole::GateExecutor
        );
        assert_eq!(WorkRole::from(RoleArg::Reviewer), WorkRole::Reviewer);
        assert_eq!(WorkRole::from(RoleArg::Coordinator), WorkRole::Coordinator);
    }

    #[test]
    fn test_claim_response_serialization() {
        let response = ClaimResponse {
            work_id: "work-123".to_string(),
            lease_id: "lease-456".to_string(),
            capability_manifest_hash: "abc123".to_string(),
            policy_resolved_ref: "policy-ref".to_string(),
            context_pack_hash: "def456".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: ClaimResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.work_id, "work-123");
    }

    /// SECURITY TEST: Verify responses reject unknown fields.
    #[test]
    fn test_claim_response_rejects_unknown_fields() {
        let json = r#"{
            "work_id": "work-1",
            "lease_id": "lease-1",
            "capability_manifest_hash": "abc",
            "policy_resolved_ref": "ref",
            "context_pack_hash": "def",
            "malicious": "value"
        }"#;

        let result: Result<ClaimResponse, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "ClaimResponse should reject unknown fields"
        );
    }
}
