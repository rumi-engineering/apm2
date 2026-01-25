//! Crash detection and classification for session processes.
//!
//! This module provides types and functions for detecting and classifying
//! how a session process exited, enabling appropriate restart decisions.

use std::fmt;
use std::process::ExitStatus as StdExitStatus;

use nix::libc;
use serde::{Deserialize, Serialize};

/// Classification of how a session process crashed or exited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrashType {
    /// Process exited with code 0 (success).
    CleanExit,
    /// Process exited with a non-zero error code.
    ErrorExit {
        /// The exit code returned by the process.
        exit_code: i32,
    },
    /// Process was terminated by a signal.
    Signal {
        /// The signal number that terminated the process.
        signal: i32,
        /// Human-readable name of the signal.
        signal_name: String,
    },
    /// Process timed out and was killed.
    Timeout,
    /// Process was terminated due to entropy budget exhaustion.
    EntropyExceeded,
    /// Exit status could not be determined.
    Unknown,
}

impl CrashType {
    /// Returns the string representation for protobuf encoding.
    #[must_use]
    pub const fn as_proto_str(&self) -> &'static str {
        match self {
            Self::CleanExit => "CLEAN_EXIT",
            Self::ErrorExit { .. } => "ERROR_EXIT",
            Self::Signal { .. } => "SIGNAL",
            Self::Timeout => "TIMEOUT",
            Self::EntropyExceeded => "ENTROPY_EXCEEDED",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Parses a crash type from a protobuf string representation.
    ///
    /// Note: For `ERROR_EXIT` and `SIGNAL`, this returns a default instance
    /// since the full details require additional fields.
    #[must_use]
    pub fn from_proto_str(s: &str) -> Self {
        match s {
            "CLEAN_EXIT" => Self::CleanExit,
            "ERROR_EXIT" => Self::ErrorExit { exit_code: 1 },
            "SIGNAL" => Self::Signal {
                signal: 0,
                signal_name: "UNKNOWN".to_string(),
            },
            "TIMEOUT" => Self::Timeout,
            "ENTROPY_EXCEEDED" => Self::EntropyExceeded,
            _ => Self::Unknown,
        }
    }

    /// Returns the exit code if this is an `ErrorExit`.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        match self {
            Self::ErrorExit { exit_code } => Some(*exit_code),
            Self::CleanExit => Some(0),
            _ => None,
        }
    }

    /// Returns the signal number if this is a `Signal`.
    #[must_use]
    pub const fn signal(&self) -> Option<i32> {
        match self {
            Self::Signal { signal, .. } => Some(*signal),
            _ => None,
        }
    }

    /// Returns whether this crash type represents a successful exit.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::CleanExit)
    }

    /// Returns whether this crash type should generally allow restart.
    ///
    /// This is a default policy; actual restart decisions may vary based
    /// on configuration.
    #[must_use]
    pub const fn is_restartable(&self) -> bool {
        match self {
            // Success and entropy exhaustion don't need restart
            Self::CleanExit | Self::EntropyExceeded => false,
            Self::ErrorExit { .. } | Self::Timeout | Self::Unknown => true,
            Self::Signal { signal, .. } => is_signal_restartable(*signal),
        }
    }
}

impl fmt::Display for CrashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CleanExit => write!(f, "clean exit (code 0)"),
            Self::ErrorExit { exit_code } => write!(f, "error exit (code {exit_code})"),
            Self::Signal {
                signal,
                signal_name,
            } => {
                write!(f, "signal {signal} ({signal_name})")
            },
            Self::Timeout => write!(f, "timeout"),
            Self::EntropyExceeded => write!(f, "entropy budget exceeded"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Represents a crash event with full context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashEvent {
    /// ID of the session that crashed.
    pub session_id: String,
    /// ID of the work item the session was processing.
    pub work_id: String,
    /// Classification of the crash.
    pub crash_type: CrashType,
    /// Timestamp when the crash was detected (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Last known ledger cursor for this session.
    pub last_ledger_cursor: u64,
    /// How many times this session has been restarted.
    pub restart_count: u32,
    /// How long the session was running before crashing (milliseconds).
    pub uptime_ms: u64,
}

impl CrashEvent {
    /// Creates a new crash event.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        work_id: impl Into<String>,
        crash_type: CrashType,
        timestamp_ns: u64,
        last_ledger_cursor: u64,
        restart_count: u32,
        uptime_ms: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            work_id: work_id.into(),
            crash_type,
            timestamp_ns,
            last_ledger_cursor,
            restart_count,
            uptime_ms,
        }
    }
}

/// Configuration for crash detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashDetectionConfig {
    /// How often to poll for process status (if using polling).
    #[serde(with = "humantime_serde")]
    pub poll_interval: std::time::Duration,

    /// How long to wait before considering a process unresponsive.
    #[serde(with = "humantime_serde")]
    pub unresponsive_timeout: std::time::Duration,

    /// Whether to restart processes that exit due to signals.
    pub restart_on_signal: bool,

    /// Signals that should NOT trigger a restart (e.g., SIGSEGV, SIGBUS).
    pub non_restartable_signals: Vec<i32>,
}

impl Default for CrashDetectionConfig {
    fn default() -> Self {
        Self {
            poll_interval: std::time::Duration::from_millis(100),
            unresponsive_timeout: std::time::Duration::from_secs(30),
            restart_on_signal: true,
            non_restartable_signals: vec![
                libc::SIGSEGV, // Segmentation fault
                libc::SIGBUS,  // Bus error
                libc::SIGFPE,  // Floating point exception
                libc::SIGILL,  // Illegal instruction
                libc::SIGABRT, // Abort
            ],
        }
    }
}

/// Wrapper around `std::process::ExitStatus` for serialization and
/// cross-platform handling.
#[derive(Debug, Clone, Copy)]
pub struct ExitStatus {
    /// The raw exit code, if the process exited normally.
    pub code: Option<i32>,
    /// The signal that terminated the process (Unix only).
    #[cfg(unix)]
    pub signal: Option<i32>,
    /// Always None on non-Unix platforms.
    #[cfg(not(unix))]
    pub signal: Option<i32>,
}

impl ExitStatus {
    /// Creates an `ExitStatus` from a standard library `ExitStatus`.
    #[must_use]
    pub fn from_std(status: StdExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Self {
                code: status.code(),
                signal: status.signal(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                code: status.code(),
                signal: None,
            }
        }
    }

    /// Creates an `ExitStatus` representing a clean exit (code 0).
    #[must_use]
    pub const fn success() -> Self {
        Self {
            code: Some(0),
            signal: None,
        }
    }

    /// Creates an `ExitStatus` representing an error exit with the given code.
    #[must_use]
    pub const fn error(code: i32) -> Self {
        Self {
            code: Some(code),
            signal: None,
        }
    }

    /// Creates an `ExitStatus` representing termination by a signal.
    #[must_use]
    pub const fn from_signal(signal: i32) -> Self {
        Self {
            code: None,
            signal: Some(signal),
        }
    }

    /// Returns whether the exit was successful (code 0).
    #[must_use]
    pub const fn success_exit(&self) -> bool {
        matches!(self.code, Some(0))
    }
}

/// Classifies an exit status into a `CrashType`.
#[must_use]
pub fn classify_exit_status(status: ExitStatus) -> CrashType {
    // Check for signal termination first (Unix)
    if let Some(signal) = status.signal {
        let (signal_name, _is_restartable) = classify_signal(signal);
        return CrashType::Signal {
            signal,
            signal_name,
        };
    }

    // Check exit code
    match status.code {
        Some(0) => CrashType::CleanExit,
        Some(code) => CrashType::ErrorExit { exit_code: code },
        None => CrashType::Unknown,
    }
}

/// Classifies a signal number and returns its name and whether it's
/// restartable.
///
/// Returns `(signal_name, is_restartable)`.
#[must_use]
pub fn classify_signal(signal: i32) -> (String, bool) {
    let (name, restartable) = match signal {
        libc::SIGTERM => ("SIGTERM", true),
        libc::SIGINT => ("SIGINT", true),
        libc::SIGHUP => ("SIGHUP", true),
        libc::SIGKILL => ("SIGKILL", true),
        libc::SIGQUIT => ("SIGQUIT", true),
        libc::SIGPIPE => ("SIGPIPE", true),
        libc::SIGALRM => ("SIGALRM", true),
        libc::SIGUSR1 => ("SIGUSR1", true),
        libc::SIGUSR2 => ("SIGUSR2", true),
        // Non-restartable signals (usually indicate bugs)
        libc::SIGSEGV => ("SIGSEGV", false),
        libc::SIGBUS => ("SIGBUS", false),
        libc::SIGFPE => ("SIGFPE", false),
        libc::SIGILL => ("SIGILL", false),
        libc::SIGABRT => ("SIGABRT", false),
        libc::SIGSYS => ("SIGSYS", false),
        _ => ("UNKNOWN", true),
    };
    (name.to_string(), restartable)
}

/// Returns whether a signal is considered restartable by default.
#[must_use]
pub const fn is_signal_restartable(signal: i32) -> bool {
    !matches!(
        signal,
        libc::SIGSEGV | libc::SIGBUS | libc::SIGFPE | libc::SIGILL | libc::SIGABRT | libc::SIGSYS
    )
}

/// Converts a `CrashType` to the session `ExitClassification`.
#[must_use]
pub const fn to_exit_classification(crash_type: &CrashType) -> super::ExitClassification {
    match crash_type {
        CrashType::CleanExit => super::ExitClassification::Success,
        CrashType::Timeout => super::ExitClassification::Timeout,
        CrashType::EntropyExceeded => super::ExitClassification::EntropyExceeded,
        CrashType::ErrorExit { .. } | CrashType::Signal { .. } | CrashType::Unknown => {
            super::ExitClassification::Failure
        },
    }
}

mod humantime_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&humantime::format_duration(*duration).to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_clean_exit() {
        let status = ExitStatus::success();
        let crash_type = classify_exit_status(status);
        assert_eq!(crash_type, CrashType::CleanExit);
        assert!(crash_type.is_success());
        assert!(!crash_type.is_restartable());
    }

    #[test]
    fn test_classify_error_exit() {
        let status = ExitStatus::error(1);
        let crash_type = classify_exit_status(status);
        assert_eq!(crash_type, CrashType::ErrorExit { exit_code: 1 });
        assert!(!crash_type.is_success());
        assert!(crash_type.is_restartable());
        assert_eq!(crash_type.exit_code(), Some(1));
    }

    #[test]
    fn test_classify_error_exit_high_code() {
        let status = ExitStatus::error(127);
        let crash_type = classify_exit_status(status);
        assert_eq!(crash_type, CrashType::ErrorExit { exit_code: 127 });
        assert!(crash_type.is_restartable());
    }

    #[test]
    fn test_classify_signal_sigterm() {
        let status = ExitStatus::from_signal(libc::SIGTERM);
        let crash_type = classify_exit_status(status);
        assert!(matches!(crash_type, CrashType::Signal { signal, .. } if signal == libc::SIGTERM));
        assert!(crash_type.is_restartable());
        assert_eq!(crash_type.signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn test_classify_signal_sigkill() {
        let status = ExitStatus::from_signal(libc::SIGKILL);
        let crash_type = classify_exit_status(status);
        assert!(matches!(crash_type, CrashType::Signal { signal, .. } if signal == libc::SIGKILL));
        assert!(crash_type.is_restartable());
    }

    #[test]
    fn test_classify_signal_sigsegv_not_restartable() {
        let status = ExitStatus::from_signal(libc::SIGSEGV);
        let crash_type = classify_exit_status(status);
        assert!(matches!(crash_type, CrashType::Signal { signal, .. } if signal == libc::SIGSEGV));
        assert!(!crash_type.is_restartable());
    }

    #[test]
    fn test_classify_signal_sigbus_not_restartable() {
        let status = ExitStatus::from_signal(libc::SIGBUS);
        let crash_type = classify_exit_status(status);
        assert!(!crash_type.is_restartable());
    }

    #[test]
    fn test_classify_signal_sigfpe_not_restartable() {
        let status = ExitStatus::from_signal(libc::SIGFPE);
        let crash_type = classify_exit_status(status);
        assert!(!crash_type.is_restartable());
    }

    #[test]
    fn test_signal_names() {
        assert_eq!(classify_signal(libc::SIGTERM).0, "SIGTERM");
        assert_eq!(classify_signal(libc::SIGKILL).0, "SIGKILL");
        assert_eq!(classify_signal(libc::SIGSEGV).0, "SIGSEGV");
        assert_eq!(classify_signal(libc::SIGINT).0, "SIGINT");
    }

    #[test]
    fn test_crash_type_proto_str_roundtrip() {
        let types = [
            CrashType::CleanExit,
            CrashType::ErrorExit { exit_code: 1 },
            CrashType::Signal {
                signal: 15,
                signal_name: "SIGTERM".to_string(),
            },
            CrashType::Timeout,
            CrashType::EntropyExceeded,
            CrashType::Unknown,
        ];

        for crash_type in types {
            let proto_str = crash_type.as_proto_str();
            // Note: roundtrip won't preserve all details for ERROR_EXIT/SIGNAL
            let _parsed = CrashType::from_proto_str(proto_str);
            // Just verify it doesn't panic
        }
    }

    #[test]
    fn test_crash_type_display() {
        assert_eq!(CrashType::CleanExit.to_string(), "clean exit (code 0)");
        assert_eq!(
            CrashType::ErrorExit { exit_code: 42 }.to_string(),
            "error exit (code 42)"
        );
        assert_eq!(
            CrashType::Signal {
                signal: 15,
                signal_name: "SIGTERM".to_string()
            }
            .to_string(),
            "signal 15 (SIGTERM)"
        );
        assert_eq!(CrashType::Timeout.to_string(), "timeout");
        assert_eq!(
            CrashType::EntropyExceeded.to_string(),
            "entropy budget exceeded"
        );
    }

    #[test]
    fn test_crash_event_creation() {
        let event = CrashEvent::new(
            "session-123",
            "work-456",
            CrashType::ErrorExit { exit_code: 1 },
            1_000_000_000,
            42,
            3,
            5000,
        );
        assert_eq!(event.session_id, "session-123");
        assert_eq!(event.work_id, "work-456");
        assert_eq!(event.restart_count, 3);
        assert_eq!(event.uptime_ms, 5000);
    }

    #[test]
    fn test_to_exit_classification() {
        assert_eq!(
            to_exit_classification(&CrashType::CleanExit),
            super::super::ExitClassification::Success
        );
        assert_eq!(
            to_exit_classification(&CrashType::ErrorExit { exit_code: 1 }),
            super::super::ExitClassification::Failure
        );
        assert_eq!(
            to_exit_classification(&CrashType::Timeout),
            super::super::ExitClassification::Timeout
        );
        assert_eq!(
            to_exit_classification(&CrashType::EntropyExceeded),
            super::super::ExitClassification::EntropyExceeded
        );
    }

    #[test]
    fn test_default_crash_detection_config() {
        let config = CrashDetectionConfig::default();
        assert_eq!(config.poll_interval, std::time::Duration::from_millis(100));
        assert!(config.restart_on_signal);
        assert!(config.non_restartable_signals.contains(&libc::SIGSEGV));
        assert!(config.non_restartable_signals.contains(&libc::SIGABRT));
    }
}
