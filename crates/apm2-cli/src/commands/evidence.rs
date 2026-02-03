//! Evidence management CLI commands.
//!
//! This module implements `apm2 evidence` subcommands for evidence publishing
//! using the protocol-based session socket (TCK-00288).
//!
//! # Commands
//!
//! - `apm2 evidence publish --session-token <token> --kind <kind> --path
//!   <file>`
//!   - Publish evidence artifact
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

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use apm2_daemon::protocol::messages::{EvidenceKind, RetentionHint};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::client::protocol::{ProtocolClientError, SessionClient};
use crate::exit_codes::{codes as exit_codes, map_protocol_error};

/// Maximum evidence file size (100 MiB).
///
/// Per CTR-1603, this limit prevents denial-of-service attacks via memory
/// exhaustion from large file inputs.
pub const MAX_EVIDENCE_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Evidence command group.
#[derive(Debug, Args)]
pub struct EvidenceCommand {
    /// Output format (text or json).
    #[arg(long, default_value = "false")]
    pub json: bool,

    #[command(subcommand)]
    pub subcommand: EvidenceSubcommand,
}

/// Evidence subcommands.
#[derive(Debug, Subcommand)]
pub enum EvidenceSubcommand {
    /// Publish evidence artifact to content-addressed storage.
    ///
    /// Uploads the artifact content and returns the content hash.
    Publish(PublishArgs),
}

/// Evidence kind for categorization.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum EvidenceKindArg {
    /// PTY transcript.
    #[default]
    PtyTranscript,
    /// Tool I/O.
    ToolIo,
    /// Raw telemetry.
    TelemetryRaw,
    /// Adapter failure.
    AdapterFailure,
    /// Incident snapshot.
    IncidentSnapshot,
}

impl From<EvidenceKindArg> for i32 {
    fn from(kind: EvidenceKindArg) -> Self {
        match kind {
            EvidenceKindArg::PtyTranscript => EvidenceKind::PtyTranscript.into(),
            EvidenceKindArg::ToolIo => EvidenceKind::ToolIo.into(),
            EvidenceKindArg::TelemetryRaw => EvidenceKind::TelemetryRaw.into(),
            EvidenceKindArg::AdapterFailure => EvidenceKind::AdapterFailure.into(),
            EvidenceKindArg::IncidentSnapshot => EvidenceKind::IncidentSnapshot.into(),
        }
    }
}

impl std::fmt::Display for EvidenceKindArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PtyTranscript => write!(f, "pty_transcript"),
            Self::ToolIo => write!(f, "tool_io"),
            Self::TelemetryRaw => write!(f, "telemetry_raw"),
            Self::AdapterFailure => write!(f, "adapter_failure"),
            Self::IncidentSnapshot => write!(f, "incident_snapshot"),
        }
    }
}

/// Retention hint for storage policy.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum RetentionHintArg {
    /// Ephemeral retention (short-lived).
    #[default]
    Ephemeral,
    /// Standard retention (typical TTL).
    Standard,
    /// Archival retention (long-term storage).
    Archival,
}

impl From<RetentionHintArg> for i32 {
    fn from(hint: RetentionHintArg) -> Self {
        match hint {
            RetentionHintArg::Ephemeral => RetentionHint::Ephemeral.into(),
            RetentionHintArg::Standard => RetentionHint::Standard.into(),
            RetentionHintArg::Archival => RetentionHint::Archival.into(),
        }
    }
}

impl std::fmt::Display for RetentionHintArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ephemeral => write!(f, "ephemeral"),
            Self::Standard => write!(f, "standard"),
            Self::Archival => write!(f, "archival"),
        }
    }
}

/// Arguments for `apm2 evidence publish`.
#[derive(Debug, Args)]
pub struct PublishArgs {
    /// Session token for authentication.
    ///
    /// Obtained from `apm2 episode spawn` response.
    ///
    /// **Security (CWE-214)**: Prefer setting the `APM2_SESSION_TOKEN`
    /// environment variable instead of using this flag. CLI arguments
    /// are visible in process listings on multi-user systems.
    #[arg(long, env = "APM2_SESSION_TOKEN")]
    pub session_token: Option<String>,

    /// Evidence kind for categorization.
    #[arg(long, value_enum, default_value = "pty-transcript")]
    pub kind: EvidenceKindArg,

    /// Path to the artifact file.
    #[arg(long, required = true)]
    pub path: PathBuf,

    /// Retention hint for storage policy.
    #[arg(long, value_enum, default_value = "ephemeral")]
    pub retention: RetentionHintArg,
}

// ============================================================================
// Response Types for JSON output
// ============================================================================

/// Response for evidence publish command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishResponse {
    /// Blake3 hash of the artifact (hex-encoded).
    pub artifact_hash: String,
    /// Storage location hint.
    pub storage_path: String,
    /// TTL in seconds (0 = permanent).
    pub ttl_secs: u64,
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

/// Runs the evidence command, returning an appropriate exit code.
pub fn run_evidence(cmd: &EvidenceCommand, socket_path: &Path) -> u8 {
    let json_output = cmd.json;

    match &cmd.subcommand {
        EvidenceSubcommand::Publish(args) => run_publish(args, socket_path, json_output),
    }
}

/// Execute the publish command.
fn run_publish(args: &PublishArgs, socket_path: &Path, json_output: bool) -> u8 {
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

    // Read artifact content with bounded size (CTR-1603)
    let artifact = match read_bounded_file(&args.path, MAX_EVIDENCE_FILE_SIZE) {
        Ok(content) => content,
        Err((code, message)) => {
            return output_error(json_output, &code, &message, exit_codes::VALIDATION_ERROR);
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

    // Execute publish
    let result = rt.block_on(async {
        let mut client = SessionClient::connect(socket_path).await?;
        client
            .publish_evidence(
                &session_token,
                &artifact,
                args.kind.into(),
                args.retention.into(),
            )
            .await
    });

    match result {
        Ok(response) => {
            let publish_response = PublishResponse {
                artifact_hash: hex::encode(&response.artifact_hash),
                storage_path: response.storage_path,
                ttl_secs: response.ttl_secs,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&publish_response)
                        .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("Evidence published successfully");
                println!("  Artifact Hash:   {}", publish_response.artifact_hash);
                println!("  Storage Path:    {}", publish_response.storage_path);
                println!(
                    "  TTL:             {} seconds{}",
                    publish_response.ttl_secs,
                    if publish_response.ttl_secs == 0 {
                        " (permanent)"
                    } else {
                        ""
                    }
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

/// Reads a file with bounded size to prevent TOCTOU and denial-of-service
/// attacks.
///
/// Opens the file handle first, then uses `.take(limit)` to enforce the
/// size limit. This is TOCTOU-safe because we read from the handle we
/// opened, not from a separate open operation.
///
/// Per CTR-1603 (Bounded Reads) and RSK-1501 (TOCTOU Canonicalization).
fn read_bounded_file(path: &Path, max_size: u64) -> Result<Vec<u8>, (String, String)> {
    let file = File::open(path).map_err(|e| {
        (
            "io_error".to_string(),
            format!("Failed to open file '{}': {e}", path.display()),
        )
    })?;

    // Use take() to limit reads - TOCTOU-safe as we read from the same handle
    let mut reader = BufReader::new(file.take(max_size + 1));
    let mut content = Vec::new();

    reader.read_to_end(&mut content).map_err(|e| {
        (
            "io_error".to_string(),
            format!("Failed to read file '{}': {e}", path.display()),
        )
    })?;

    // Check if we hit the limit (read more than max_size)
    if content.len() as u64 > max_size {
        return Err((
            "file_too_large".to_string(),
            format!(
                "File '{}' exceeds maximum size of {max_size} bytes",
                path.display()
            ),
        ));
    }

    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_kind_display() {
        assert_eq!(EvidenceKindArg::PtyTranscript.to_string(), "pty_transcript");
        assert_eq!(EvidenceKindArg::ToolIo.to_string(), "tool_io");
        assert_eq!(EvidenceKindArg::TelemetryRaw.to_string(), "telemetry_raw");
    }

    #[test]
    fn test_retention_hint_display() {
        assert_eq!(RetentionHintArg::Ephemeral.to_string(), "ephemeral");
        assert_eq!(RetentionHintArg::Standard.to_string(), "standard");
        assert_eq!(RetentionHintArg::Archival.to_string(), "archival");
    }

    #[test]
    fn test_publish_response_serialization() {
        let response = PublishResponse {
            artifact_hash: "abc123".to_string(),
            storage_path: "/evidence/abc123".to_string(),
            ttl_secs: 3600,
        };

        let json = serde_json::to_string(&response).unwrap();
        let restored: PublishResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.artifact_hash, "abc123");
    }

    /// SECURITY TEST: Verify responses reject unknown fields.
    #[test]
    fn test_publish_response_rejects_unknown_fields() {
        let json = r#"{
            "artifact_hash": "abc",
            "storage_path": "/path",
            "ttl_secs": 0,
            "malicious": "value"
        }"#;

        let result: Result<PublishResponse, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "PublishResponse should reject unknown fields"
        );
    }

    #[test]
    fn test_read_bounded_file_success() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.bin");
        std::fs::write(&file_path, b"test content").unwrap();

        let result = read_bounded_file(&file_path, 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test content");
    }

    #[test]
    fn test_read_bounded_file_exceeds_limit() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("large.bin");
        std::fs::write(&file_path, vec![0u8; 1001]).unwrap();

        let result = read_bounded_file(&file_path, 1000);
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, "file_too_large");
    }
}
