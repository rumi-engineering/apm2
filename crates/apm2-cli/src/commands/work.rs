//! Work management CLI commands.
//!
//! This module implements `apm2 work` subcommands for work queue operations
//! using the protocol-based operator socket (TCK-00288).
//!
//! # Commands
//!
//! - `apm2 work claim --actor-id <id> --role <role>` - Claim work from the
//!   queue
//! - `apm2 work status --work-id <id>` - Query work status
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

use std::io::Read as _;
use std::path::Path;

use apm2_daemon::protocol::WorkRole;
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::client::protocol::{OperatorClient, ProtocolClientError};
use crate::exit_codes::{codes as exit_codes, map_protocol_error};

/// Maximum ticket YAML file size (1 MiB) to prevent denial-of-service via
/// oversized files.
const MAX_TICKET_FILE_SIZE: u64 = 1_048_576;

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

    /// Query work status (TCK-00288).
    ///
    /// Returns the current status of a work item including assigned
    /// actor, role, and associated session information.
    Status(StatusArgs),

    /// Open a new work item from a ticket YAML file (TCK-00635).
    ///
    /// Imports a ticket YAML, converts it to a `WorkSpec`, canonicalizes
    /// the JSON, and sends to the daemon via the `OpenWork` RPC.
    Open(OpenArgs),
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

/// Arguments for `apm2 work status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Work identifier to query.
    #[arg(long, required = true)]
    pub work_id: String,
}

/// Arguments for `apm2 work open` (TCK-00635).
#[derive(Debug, Args)]
pub struct OpenArgs {
    /// Path to the ticket YAML file to import as a `WorkSpec`.
    #[arg(long, required = true)]
    pub from_ticket: String,
    /// Governing lease ID for PCAC lifecycle enforcement.
    #[arg(long, required = true)]
    pub lease_id: String,
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

/// Response for work status command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    /// Work identifier.
    pub work_id: String,
    /// Current work status.
    pub status: String,
    /// Actor who claimed this work (if claimed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    /// Role of the actor (if claimed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Associated session ID (if spawned).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Lease ID (if claimed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
}

/// Response for work open command (TCK-00635).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenResponse {
    /// Canonical work identifier.
    pub work_id: String,
    /// BLAKE3 hash of the canonical `WorkSpec` stored in CAS (hex-encoded).
    pub spec_snapshot_hash: String,
    /// Whether this was an idempotent no-op.
    pub already_existed: bool,
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
        WorkSubcommand::Status(args) => run_status(args, socket_path, json_output),
        WorkSubcommand::Open(args) => run_open(args, socket_path, json_output),
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
            exit_codes::VALIDATION_ERROR,
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
                    exit_codes::VALIDATION_ERROR,
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
                    exit_codes::VALIDATION_ERROR,
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
                exit_codes::GENERIC_ERROR,
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

/// Execute the status command (TCK-00344).
///
/// Queries the daemon for work status via the operator socket.
fn run_status(args: &StatusArgs, socket_path: &Path, json_output: bool) -> u8 {
    // Validate work ID
    if args.work_id.is_empty() {
        return output_error(
            json_output,
            "invalid_work_id",
            "Work ID cannot be empty",
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

    // Execute status query
    let result = rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path).await?;
        client.work_status(&args.work_id).await
    });

    match result {
        Ok(response) => {
            // Convert protocol response to CLI response
            let role_str = WorkRole::try_from(response.role.unwrap_or(0))
                .map(|r| format!("{r:?}"))
                .ok();

            let status_response = StatusResponse {
                work_id: response.work_id,
                status: response.status,
                actor_id: response.actor_id,
                role: role_str,
                session_id: response.session_id,
                lease_id: response.lease_id,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&status_response)
                        .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Work Status");
                println!("  Work ID:   {}", status_response.work_id);
                println!("  Status:    {}", status_response.status);
                if let Some(actor) = &status_response.actor_id {
                    println!("  Actor ID:  {actor}");
                }
                if let Some(role) = &status_response.role {
                    println!("  Role:      {role}");
                }
                if let Some(session) = &status_response.session_id {
                    println!("  Session:   {session}");
                }
                if let Some(lease) = &status_response.lease_id {
                    println!("  Lease ID:  {lease}");
                }
            }

            exit_codes::SUCCESS
        },
        Err(e) => handle_protocol_error(json_output, &e),
    }
}

/// Execute the open command (TCK-00635).
///
/// Reads a ticket YAML file, converts it to a `WorkSpec` JSON, canonicalizes
/// it, and sends to the daemon via the `OpenWork` RPC.
fn run_open(args: &OpenArgs, socket_path: &Path, json_output: bool) -> u8 {
    // CTR-1603: Bounded file read via file handle to prevent TOCTOU.
    // Open file first, then enforce size bound on the file handle itself
    // so that a replaced-after-stat file or special file (/dev/zero) cannot
    // bypass the size limit.
    let ticket_path = Path::new(&args.from_ticket);
    let file = match std::fs::File::open(ticket_path) {
        Ok(f) => f,
        Err(e) => {
            let (code, msg) = if e.kind() == std::io::ErrorKind::NotFound {
                (
                    "file_not_found",
                    format!("Ticket file not found: {}", args.from_ticket),
                )
            } else {
                ("io_error", format!("Failed to open ticket file: {e}"))
            };
            return output_error(json_output, code, &msg, exit_codes::VALIDATION_ERROR);
        },
    };

    // Read at most MAX_TICKET_FILE_SIZE + 1 bytes from the file handle.
    // If we read more than MAX_TICKET_FILE_SIZE, the file is too large.
    let mut yaml_content = String::new();
    let bytes_read = match file
        .take(MAX_TICKET_FILE_SIZE + 1)
        .read_to_string(&mut yaml_content)
    {
        Ok(n) => n as u64,
        Err(e) => {
            return output_error(
                json_output,
                "io_error",
                &format!("Failed to read ticket file: {e}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    if bytes_read > MAX_TICKET_FILE_SIZE {
        return output_error(
            json_output,
            "file_too_large",
            &format!("Ticket file exceeds maximum size (>{MAX_TICKET_FILE_SIZE} bytes)"),
            exit_codes::VALIDATION_ERROR,
        );
    }

    // Parse YAML and convert to WorkSpec JSON
    let work_spec_json = match ticket_yaml_to_work_spec_json(&yaml_content) {
        Ok(json) => json,
        Err(e) => {
            return output_error(
                json_output,
                "invalid_ticket",
                &format!("Failed to convert ticket to WorkSpec: {e}"),
                exit_codes::VALIDATION_ERROR,
            );
        },
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
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // Execute OpenWork RPC
    let result = rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path).await?;
        client
            .open_work(work_spec_json.as_bytes(), &args.lease_id)
            .await
    });

    match result {
        Ok(response) => {
            let open_response = OpenResponse {
                work_id: response.work_id,
                spec_snapshot_hash: hex::encode(&response.spec_snapshot_hash),
                already_existed: response.already_existed,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&open_response)
                        .unwrap_or_else(|_| "{}".to_string())
                );
            } else if open_response.already_existed {
                println!("Work already exists (idempotent)");
                println!("  Work ID:         {}", open_response.work_id);
                println!("  Spec Hash:       {}", open_response.spec_snapshot_hash);
            } else {
                println!("Work opened successfully");
                println!("  Work ID:         {}", open_response.work_id);
                println!("  Spec Hash:       {}", open_response.spec_snapshot_hash);
            }

            exit_codes::SUCCESS
        },
        Err(e) => handle_protocol_error(json_output, &e),
    }
}

/// Converts a ticket YAML string to a canonical `WorkSpec` JSON string.
///
/// Extracts fields from the ticket YAML structure and maps them to
/// the `apm2.work_spec.v1` schema.
///
/// # Errors
///
/// Returns a string error if the YAML is malformed or missing required fields.
fn ticket_yaml_to_work_spec_json(yaml_content: &str) -> Result<String, String> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(yaml_content).map_err(|e| format!("YAML parse error: {e}"))?;

    // Navigate to ticket_meta
    let ticket_meta = yaml.get("ticket_meta").ok_or("missing 'ticket_meta' key")?;

    // Extract ticket fields
    let ticket = ticket_meta
        .get("ticket")
        .ok_or("missing 'ticket_meta.ticket' key")?;

    let ticket_id = ticket
        .get("id")
        .and_then(serde_yaml::Value::as_str)
        .ok_or("missing 'ticket_meta.ticket.id'")?;

    let title = ticket
        .get("title")
        .and_then(serde_yaml::Value::as_str)
        .ok_or("missing 'ticket_meta.ticket.title'")?;

    // Extract optional binds fields
    let binds = ticket_meta.get("binds");

    let rfc_id = binds
        .and_then(|b| b.get("rfc_id"))
        .and_then(serde_yaml::Value::as_str)
        .filter(|s| !s.is_empty() && *s != "RFC-PLACEHOLDER");

    // Extract requirement IDs from binds.requirements
    let requirement_ids: Vec<String> = binds
        .and_then(|b| b.get("requirements"))
        .and_then(serde_yaml::Value::as_sequence)
        .map(|reqs| {
            reqs.iter()
                .filter_map(|r| {
                    r.get("requirement_ref")
                        .and_then(serde_yaml::Value::as_str)
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default();

    // Derive work_id deterministically from ticket_id so retrying the CLI
    // with the same ticket file yields the same work_id, preserving daemon
    // idempotency semantics.
    let work_id = format!("W-{ticket_id}");

    // Build WorkSpec JSON
    let mut spec = serde_json::Map::new();
    spec.insert(
        "schema".to_string(),
        serde_json::Value::String("apm2.work_spec.v1".to_string()),
    );
    spec.insert("work_id".to_string(), serde_json::Value::String(work_id));
    spec.insert(
        "ticket_alias".to_string(),
        serde_json::Value::String(ticket_id.to_string()),
    );
    spec.insert(
        "title".to_string(),
        serde_json::Value::String(title.to_string()),
    );
    spec.insert(
        "work_type".to_string(),
        serde_json::Value::String("TICKET".to_string()),
    );

    if let Some(rfc) = rfc_id {
        spec.insert(
            "rfc_id".to_string(),
            serde_json::Value::String(rfc.to_string()),
        );
    }

    if !requirement_ids.is_empty() {
        spec.insert(
            "requirement_ids".to_string(),
            serde_json::Value::Array(
                requirement_ids
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }

    serde_json::to_string(&serde_json::Value::Object(spec))
        .map_err(|e| format!("JSON serialization failed: {e}"))
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

    #[test]
    fn test_status_response_serialization() {
        let response = StatusResponse {
            work_id: "work-123".to_string(),
            status: "CLAIMED".to_string(),
            actor_id: Some("actor-1".to_string()),
            role: Some("implementer".to_string()),
            session_id: None,
            lease_id: Some("lease-1".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("work-123"));
        assert!(!json.contains("session_id")); // Should be skipped when None
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

    /// SECURITY TEST: Verify status responses reject unknown fields.
    #[test]
    fn test_status_response_rejects_unknown_fields() {
        let json = r#"{
            "work_id": "work-1",
            "status": "CLAIMED",
            "malicious": "value"
        }"#;

        let result: Result<StatusResponse, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "StatusResponse should reject unknown fields"
        );
    }

    // =========================================================================
    // Work Status Command Tests (TCK-00344)
    // =========================================================================

    /// Tests that work status validates empty work ID.
    #[test]
    fn test_work_status_rejects_empty_work_id() {
        let args = StatusArgs {
            work_id: String::new(),
        };
        let socket_path = std::path::Path::new("/nonexistent/operator.sock");
        let exit_code = run_status(&args, socket_path, true);
        assert_eq!(
            exit_code,
            exit_codes::VALIDATION_ERROR,
            "Empty work ID should return VALIDATION_ERROR"
        );
    }

    /// Tests that work status returns daemon unavailable for missing socket.
    #[test]
    fn test_work_status_daemon_not_running() {
        let args = StatusArgs {
            work_id: "work-123".to_string(),
        };
        let socket_path = std::path::Path::new("/nonexistent/operator.sock");
        let exit_code = run_status(&args, socket_path, true);
        assert_eq!(
            exit_code,
            exit_codes::DAEMON_UNAVAILABLE,
            "Non-existent socket should return DAEMON_UNAVAILABLE"
        );
    }

    /// Tests that work status response includes all optional fields when
    /// present.
    #[test]
    fn test_status_response_full_serialization() {
        let response = StatusResponse {
            work_id: "work-full".to_string(),
            status: "SPAWNED".to_string(),
            actor_id: Some("actor-x".to_string()),
            role: Some("Implementer".to_string()),
            session_id: Some("sess-y".to_string()),
            lease_id: Some("lease-z".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: StatusResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.work_id, "work-full");
        assert_eq!(restored.status, "SPAWNED");
        assert_eq!(restored.actor_id.as_deref(), Some("actor-x"));
        assert_eq!(restored.role.as_deref(), Some("Implementer"));
        assert_eq!(restored.session_id.as_deref(), Some("sess-y"));
        assert_eq!(restored.lease_id.as_deref(), Some("lease-z"));
    }

    // =========================================================================
    // OpenWork Command Tests (TCK-00635)
    // =========================================================================

    /// Tests `OpenResponse` serialization roundtrip.
    #[test]
    fn test_open_response_serialization() {
        let response = OpenResponse {
            work_id: "W-test-123".to_string(),
            spec_snapshot_hash: "abc123".to_string(),
            already_existed: false,
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: OpenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.work_id, "W-test-123");
        assert_eq!(restored.spec_snapshot_hash, "abc123");
        assert!(!restored.already_existed);
    }

    /// Tests `OpenResponse` serialization with `already_existed`=true.
    #[test]
    fn test_open_response_idempotent_serialization() {
        let response = OpenResponse {
            work_id: "W-test-456".to_string(),
            spec_snapshot_hash: "def789".to_string(),
            already_existed: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"already_existed\":true"));
    }

    /// SECURITY TEST: Verify `OpenResponse` rejects unknown fields.
    #[test]
    fn test_open_response_rejects_unknown_fields() {
        let json = r#"{
            "work_id": "W-1",
            "spec_snapshot_hash": "abc",
            "already_existed": false,
            "extra": "bad"
        }"#;

        let result: Result<OpenResponse, _> = serde_json::from_str(json);
        assert!(result.is_err(), "OpenResponse should reject unknown fields");
    }

    /// Tests that `run_open` validates missing files.
    #[test]
    fn test_open_rejects_missing_file() {
        let args = OpenArgs {
            from_ticket: "/nonexistent/ticket.yaml".to_string(),
            lease_id: "L-test-001".to_string(),
        };
        let socket_path = Path::new("/nonexistent/operator.sock");
        let exit_code = run_open(&args, socket_path, true);
        assert_eq!(
            exit_code,
            exit_codes::VALIDATION_ERROR,
            "Missing file should return VALIDATION_ERROR"
        );
    }

    /// Tests ticket YAML to `WorkSpec` JSON conversion.
    #[test]
    fn test_ticket_yaml_to_work_spec_json_basic() {
        let yaml = r"
ticket_meta:
  ticket:
    id: TCK-00999
    title: 'Test ticket title'
  binds:
    rfc_id: RFC-0032
    requirements: []
";

        let result = ticket_yaml_to_work_spec_json(yaml);
        assert!(result.is_ok(), "Should parse valid ticket YAML");

        let json_str = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["schema"], "apm2.work_spec.v1");
        assert_eq!(parsed["ticket_alias"], "TCK-00999");
        assert_eq!(parsed["title"], "Test ticket title");
        assert_eq!(parsed["work_type"], "TICKET");
        assert_eq!(parsed["rfc_id"], "RFC-0032");
        // work_id is deterministic: "W-<ticket_id>"
        assert_eq!(parsed["work_id"], "W-TCK-00999");
    }

    /// Tests that `work_id` is deterministic across invocations (MAJOR-1 fix).
    #[test]
    fn test_ticket_yaml_deterministic_work_id() {
        let yaml = r"
ticket_meta:
  ticket:
    id: TCK-12345
    title: 'Determinism test'
";
        let first = ticket_yaml_to_work_spec_json(yaml).unwrap();
        let second = ticket_yaml_to_work_spec_json(yaml).unwrap();

        let p1: serde_json::Value = serde_json::from_str(&first).unwrap();
        let p2: serde_json::Value = serde_json::from_str(&second).unwrap();

        assert_eq!(
            p1["work_id"], p2["work_id"],
            "Repeated invocations with same ticket must produce identical work_id"
        );
        assert_eq!(p1["work_id"], "W-TCK-12345");
    }

    /// Tests that ticket YAML conversion rejects missing required fields.
    #[test]
    fn test_ticket_yaml_rejects_missing_ticket_id() {
        let yaml = r"
ticket_meta:
  ticket:
    title: 'Missing ID'
";
        let result = ticket_yaml_to_work_spec_json(yaml);
        assert!(result.is_err(), "Should reject missing ticket id");
    }

    /// Tests that ticket YAML conversion rejects missing title.
    #[test]
    fn test_ticket_yaml_rejects_missing_title() {
        let yaml = r"
ticket_meta:
  ticket:
    id: TCK-00999
";
        let result = ticket_yaml_to_work_spec_json(yaml);
        assert!(result.is_err(), "Should reject missing title");
    }

    /// Tests that ticket YAML conversion handles missing binds gracefully.
    #[test]
    fn test_ticket_yaml_handles_missing_binds() {
        let yaml = r"
ticket_meta:
  ticket:
    id: TCK-00999
    title: 'No binds'
";
        let result = ticket_yaml_to_work_spec_json(yaml);
        assert!(result.is_ok(), "Should handle missing binds");

        let json_str = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.get("rfc_id").is_none());
    }

    /// Tests that RFC-PLACEHOLDER is filtered out.
    #[test]
    fn test_ticket_yaml_filters_rfc_placeholder() {
        let yaml = r"
ticket_meta:
  ticket:
    id: TCK-00999
    title: 'With placeholder'
  binds:
    rfc_id: RFC-PLACEHOLDER
    requirements: []
";
        let result = ticket_yaml_to_work_spec_json(yaml);
        assert!(result.is_ok());

        let json_str = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(
            parsed.get("rfc_id").is_none(),
            "RFC-PLACEHOLDER should be filtered"
        );
    }

    /// Tests that `requirement_ids` are extracted from binds.requirements.
    #[test]
    fn test_ticket_yaml_extracts_requirement_ids() {
        let yaml = r#"
ticket_meta:
  ticket:
    id: TCK-00999
    title: 'With requirements'
  binds:
    rfc_id: RFC-0032
    requirements:
      - requirement_ref: "REQ-001"
      - requirement_ref: "REQ-002"
"#;
        let result = ticket_yaml_to_work_spec_json(yaml);
        assert!(result.is_ok());

        let json_str = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let req_ids = parsed["requirement_ids"].as_array().unwrap();
        assert_eq!(req_ids.len(), 2);
        assert_eq!(req_ids[0], "REQ-001");
        assert_eq!(req_ids[1], "REQ-002");
    }
}
