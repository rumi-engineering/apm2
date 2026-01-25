//! Normalized adapter events.
//!
//! This module defines the `AdapterEvent` type that all adapters emit,
//! providing a common contract for both black-box and instrumented adapters.
//!
//! # Event Categories
//!
//! - **Lifecycle**: Process started, exited, crashed
//! - **Progress**: Activity detected, heartbeat, tool completion
//! - **Filesystem**: File changes detected in watched directories
//! - **Tool**: Tool request detected (from side effects or instrumentation)

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A normalized event emitted by an adapter.
///
/// All adapter types (black-box and instrumented) emit these events,
/// enabling the supervisor to handle agents uniformly regardless of
/// their observability mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterEvent {
    /// Monotonically increasing sequence number for ordering.
    pub sequence: u64,

    /// Timestamp when the event was detected (nanoseconds since Unix epoch).
    pub timestamp_nanos: u64,

    /// The session ID this event belongs to.
    pub session_id: String,

    /// The specific event payload.
    pub payload: AdapterEventPayload,
}

/// The payload of an adapter event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AdapterEventPayload {
    /// Agent process has started.
    ProcessStarted(ProcessStarted),

    /// Agent process has exited.
    ProcessExited(ProcessExited),

    /// Progress signal derived from activity.
    Progress(ProgressSignal),

    /// Filesystem change detected.
    FilesystemChange(FilesystemChange),

    /// Tool request detected (from side effects or instrumentation).
    ToolRequestDetected(ToolRequestDetected),

    /// Stall detected (no activity for configured duration).
    StallDetected(StallDetected),

    /// Diagnostic event for protocol violations and security issues.
    Diagnostic(Diagnostic),
}

/// Diagnostic event for protocol violations and security issues.
///
/// These events indicate problems detected at the adapter boundary that
/// may warrant investigation or termination of the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Severity of the diagnostic.
    pub severity: DiagnosticSeverity,

    /// Category of the diagnostic.
    pub category: DiagnosticCategory,

    /// Human-readable message describing the issue.
    pub message: String,

    /// Additional context about the diagnostic.
    pub context: BTreeMap<String, String>,
}

/// Severity level of a diagnostic event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticSeverity {
    /// Informational diagnostic (e.g., protocol quirks).
    Info,

    /// Warning that may indicate a problem.
    Warning,

    /// Error that indicates a security or protocol violation.
    Error,
}

impl DiagnosticSeverity {
    /// Returns the severity as a string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
        }
    }
}

/// Category of diagnostic event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticCategory {
    /// Protocol violation (e.g., malformed JSON).
    ProtocolViolation,

    /// Security policy violation (e.g., unauthorized tool).
    SecurityViolation,

    /// Resource limit exceeded.
    ResourceLimit,

    /// Internal adapter error.
    InternalError,
}

impl DiagnosticCategory {
    /// Returns the category as a string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolViolation => "PROTOCOL_VIOLATION",
            Self::SecurityViolation => "SECURITY_VIOLATION",
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }
}

/// Agent process started event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStarted {
    /// OS process ID.
    pub pid: u32,

    /// Command that was executed.
    pub command: String,

    /// Arguments passed to the command.
    pub args: Vec<String>,

    /// Working directory.
    pub working_dir: PathBuf,

    /// Environment variables (filtered to safe keys).
    pub env: BTreeMap<String, String>,

    /// Type of adapter (e.g., "black-box", "instrumented").
    pub adapter_type: String,
}

/// Agent process exited event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExited {
    /// OS process ID.
    pub pid: u32,

    /// Exit code if available.
    pub exit_code: Option<i32>,

    /// Signal that terminated the process, if any.
    pub signal: Option<i32>,

    /// Duration the process was running.
    pub uptime: Duration,

    /// Classification of the exit.
    pub classification: ExitClassification,
}

/// Classification of how the process exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitClassification {
    /// Clean exit with success code (0).
    CleanSuccess,

    /// Clean exit with error code (non-zero).
    CleanError,

    /// Terminated by signal.
    Signal,

    /// Process timed out.
    Timeout,

    /// Terminated due to entropy budget exceeded.
    EntropyExceeded,

    /// Unknown/unexpected termination.
    Unknown,
}

impl ExitClassification {
    /// Returns the classification as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CleanSuccess => "CLEAN_SUCCESS",
            Self::CleanError => "CLEAN_ERROR",
            Self::Signal => "SIGNAL",
            Self::Timeout => "TIMEOUT",
            Self::EntropyExceeded => "ENTROPY_EXCEEDED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Progress signal derived from activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressSignal {
    /// Type of progress signal.
    pub signal_type: ProgressType,

    /// Human-readable description of what triggered the signal.
    pub description: String,

    /// Entropy cost of this progress event (if any).
    pub entropy_cost: u64,
}

/// Type of progress signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgressType {
    /// Heartbeat derived from periodic activity.
    Heartbeat,

    /// Tool execution completed.
    ToolComplete,

    /// Milestone reached (e.g., file written, test passed).
    Milestone,

    /// Generic activity detected.
    Activity,
}

impl ProgressType {
    /// Returns the type as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Heartbeat => "HEARTBEAT",
            Self::ToolComplete => "TOOL_COMPLETE",
            Self::Milestone => "MILESTONE",
            Self::Activity => "ACTIVITY",
        }
    }
}

/// Filesystem change detected event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemChange {
    /// Path that changed.
    pub path: PathBuf,

    /// Type of change.
    pub change_type: FileChangeType,

    /// Size of the file after change (if applicable).
    pub size_bytes: Option<u64>,
}

/// Type of filesystem change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileChangeType {
    /// File was created.
    Created,

    /// File was modified.
    Modified,

    /// File was deleted.
    Deleted,

    /// File was renamed.
    Renamed,
}

impl FileChangeType {
    /// Returns the type as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Modified => "MODIFIED",
            Self::Deleted => "DELETED",
            Self::Renamed => "RENAMED",
        }
    }
}

/// Tool request detected from side effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRequestDetected {
    /// Inferred tool name (e.g., "`file_write`", "`shell_execute`").
    pub tool_name: String,

    /// Detection method.
    pub detection_method: DetectionMethod,

    /// Confidence percentage (0-100) indicating how certain the detection is.
    pub confidence_percent: u8,

    /// Additional context about the detection.
    pub context: BTreeMap<String, String>,
}

/// Method used to detect the tool request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionMethod {
    /// Detected from filesystem changes.
    FilesystemObservation,

    /// Detected from process tree changes.
    ProcessObservation,

    /// Detected from network activity.
    NetworkObservation,

    /// Detected from stdout/stderr parsing.
    OutputParsing,

    /// Detected from instrumentation (for instrumented adapters).
    Instrumentation,
}

impl DetectionMethod {
    /// Returns the method as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FilesystemObservation => "FILESYSTEM_OBSERVATION",
            Self::ProcessObservation => "PROCESS_OBSERVATION",
            Self::NetworkObservation => "NETWORK_OBSERVATION",
            Self::OutputParsing => "OUTPUT_PARSING",
            Self::Instrumentation => "INSTRUMENTATION",
        }
    }
}

/// Stall detected event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StallDetected {
    /// Duration since last activity.
    pub idle_duration: Duration,

    /// Configured stall threshold that was exceeded.
    pub threshold: Duration,

    /// Number of stalls detected for this session.
    pub stall_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_classification_as_str() {
        assert_eq!(ExitClassification::CleanSuccess.as_str(), "CLEAN_SUCCESS");
        assert_eq!(ExitClassification::CleanError.as_str(), "CLEAN_ERROR");
        assert_eq!(ExitClassification::Signal.as_str(), "SIGNAL");
        assert_eq!(ExitClassification::Timeout.as_str(), "TIMEOUT");
        assert_eq!(
            ExitClassification::EntropyExceeded.as_str(),
            "ENTROPY_EXCEEDED"
        );
        assert_eq!(ExitClassification::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn test_progress_type_as_str() {
        assert_eq!(ProgressType::Heartbeat.as_str(), "HEARTBEAT");
        assert_eq!(ProgressType::ToolComplete.as_str(), "TOOL_COMPLETE");
        assert_eq!(ProgressType::Milestone.as_str(), "MILESTONE");
        assert_eq!(ProgressType::Activity.as_str(), "ACTIVITY");
    }

    #[test]
    fn test_file_change_type_as_str() {
        assert_eq!(FileChangeType::Created.as_str(), "CREATED");
        assert_eq!(FileChangeType::Modified.as_str(), "MODIFIED");
        assert_eq!(FileChangeType::Deleted.as_str(), "DELETED");
        assert_eq!(FileChangeType::Renamed.as_str(), "RENAMED");
    }

    #[test]
    fn test_detection_method_as_str() {
        assert_eq!(
            DetectionMethod::FilesystemObservation.as_str(),
            "FILESYSTEM_OBSERVATION"
        );
        assert_eq!(
            DetectionMethod::ProcessObservation.as_str(),
            "PROCESS_OBSERVATION"
        );
        assert_eq!(
            DetectionMethod::NetworkObservation.as_str(),
            "NETWORK_OBSERVATION"
        );
        assert_eq!(DetectionMethod::OutputParsing.as_str(), "OUTPUT_PARSING");
        assert_eq!(DetectionMethod::Instrumentation.as_str(), "INSTRUMENTATION");
    }

    #[test]
    fn test_adapter_event_serialization() {
        let event = AdapterEvent {
            sequence: 1,
            timestamp_nanos: 1_000_000_000,
            session_id: "session-123".to_string(),
            payload: AdapterEventPayload::ProcessStarted(ProcessStarted {
                pid: 12345,
                command: "claude".to_string(),
                args: vec!["--help".to_string()],
                working_dir: PathBuf::from("/tmp"),
                env: BTreeMap::new(),
                adapter_type: "black-box".to_string(),
            }),
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: AdapterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn test_filesystem_change_event() {
        let change = FilesystemChange {
            path: PathBuf::from("/tmp/test.txt"),
            change_type: FileChangeType::Created,
            size_bytes: Some(1024),
        };

        assert_eq!(change.path, PathBuf::from("/tmp/test.txt"));
        assert_eq!(change.change_type, FileChangeType::Created);
        assert_eq!(change.size_bytes, Some(1024));
    }

    #[test]
    fn test_tool_request_detected() {
        let mut context = BTreeMap::new();
        context.insert("path".to_string(), "/tmp/output.txt".to_string());

        let tool = ToolRequestDetected {
            tool_name: "file_write".to_string(),
            detection_method: DetectionMethod::FilesystemObservation,
            confidence_percent: 85,
            context,
        };

        assert_eq!(tool.tool_name, "file_write");
        assert_eq!(
            tool.detection_method,
            DetectionMethod::FilesystemObservation
        );
        assert_eq!(tool.confidence_percent, 85);
        assert_eq!(
            tool.context.get("path"),
            Some(&"/tmp/output.txt".to_string())
        );
    }

    #[test]
    fn test_stall_detected() {
        let stall = StallDetected {
            idle_duration: Duration::from_secs(120),
            threshold: Duration::from_secs(60),
            stall_count: 3,
        };

        assert_eq!(stall.idle_duration, Duration::from_secs(120));
        assert_eq!(stall.threshold, Duration::from_secs(60));
        assert_eq!(stall.stall_count, 3);
    }

    #[test]
    fn test_diagnostic_severity_as_str() {
        assert_eq!(DiagnosticSeverity::Info.as_str(), "INFO");
        assert_eq!(DiagnosticSeverity::Warning.as_str(), "WARNING");
        assert_eq!(DiagnosticSeverity::Error.as_str(), "ERROR");
    }

    #[test]
    fn test_diagnostic_category_as_str() {
        assert_eq!(
            DiagnosticCategory::ProtocolViolation.as_str(),
            "PROTOCOL_VIOLATION"
        );
        assert_eq!(
            DiagnosticCategory::SecurityViolation.as_str(),
            "SECURITY_VIOLATION"
        );
        assert_eq!(DiagnosticCategory::ResourceLimit.as_str(), "RESOURCE_LIMIT");
        assert_eq!(DiagnosticCategory::InternalError.as_str(), "INTERNAL_ERROR");
    }

    #[test]
    fn test_diagnostic_serialization() {
        let mut context = BTreeMap::new();
        context.insert("line".to_string(), "invalid json".to_string());

        let diagnostic = Diagnostic {
            severity: DiagnosticSeverity::Error,
            category: DiagnosticCategory::ProtocolViolation,
            message: "JSON parse error".to_string(),
            context,
        };

        let json = serde_json::to_string(&diagnostic).unwrap();
        let parsed: Diagnostic = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.severity, DiagnosticSeverity::Error);
        assert_eq!(parsed.category, DiagnosticCategory::ProtocolViolation);
        assert_eq!(parsed.message, "JSON parse error");
        assert_eq!(
            parsed.context.get("line"),
            Some(&"invalid json".to_string())
        );
    }

    #[test]
    fn test_diagnostic_event_payload() {
        let event = AdapterEvent {
            sequence: 42,
            timestamp_nanos: 1_000_000_000,
            session_id: "session-diag".to_string(),
            payload: AdapterEventPayload::Diagnostic(Diagnostic {
                severity: DiagnosticSeverity::Warning,
                category: DiagnosticCategory::SecurityViolation,
                message: "Unauthorized tool detected".to_string(),
                context: BTreeMap::new(),
            }),
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: AdapterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }
}
