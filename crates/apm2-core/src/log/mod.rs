#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Log management module.
//!
//! Handles log collection, rotation, and streaming for managed processes.
//!
//! This module also provides secret redaction functionality to prevent
//! accidental exposure of sensitive data in logs.

mod redact;

use std::path::PathBuf;

pub use redact::{SecretRedactor, is_sensitive_env_name, redact};
use serde::{Deserialize, Serialize};

/// Log configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Path to stdout log file.
    #[serde(default)]
    pub out_file: Option<PathBuf>,

    /// Path to stderr log file.
    #[serde(default)]
    pub err_file: Option<PathBuf>,

    /// Combined log file (stdout + stderr interleaved).
    #[serde(default)]
    pub combined_file: Option<PathBuf>,

    /// Whether to merge stderr into stdout.
    #[serde(default)]
    pub merge_stderr: bool,

    /// Log rotation configuration.
    #[serde(default)]
    pub rotation: Option<LogRotationConfig>,

    /// Whether to timestamp log lines.
    #[serde(default)]
    pub timestamp: bool,

    /// Timestamp format (if enabled).
    #[serde(default = "default_timestamp_format")]
    pub timestamp_format: String,
}

fn default_timestamp_format() -> String {
    "%Y-%m-%d %H:%M:%S%.3f".to_string()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            out_file: None,
            err_file: None,
            combined_file: None,
            merge_stderr: false,
            rotation: None,
            timestamp: false,
            timestamp_format: default_timestamp_format(),
        }
    }
}

/// Log rotation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Maximum log file size before rotation.
    #[serde(default = "default_max_size")]
    pub max_size: u64,

    /// Maximum number of rotated files to keep.
    #[serde(default = "default_max_files")]
    pub max_files: u32,

    /// Compress rotated files.
    #[serde(default)]
    pub compress: bool,

    /// Rotation mode.
    #[serde(default)]
    pub mode: RotationMode,
}

const fn default_max_size() -> u64 {
    10 * 1024 * 1024 // 10 MB
}

const fn default_max_files() -> u32 {
    10
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            max_size: default_max_size(),
            max_files: default_max_files(),
            compress: false,
            mode: RotationMode::Size,
        }
    }
}

/// Log rotation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationMode {
    /// Rotate based on file size.
    #[default]
    Size,
    /// Rotate daily.
    Daily,
    /// Rotate hourly.
    Hourly,
}

/// Log line with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    /// Timestamp of the log line.
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Log stream (stdout or stderr).
    pub stream: LogStream,

    /// Process name.
    pub process_name: String,

    /// Instance index.
    pub instance: u32,

    /// Log content.
    pub content: String,
}

/// Log stream type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl std::fmt::Display for LogStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdout => write!(f, "stdout"),
            Self::Stderr => write!(f, "stderr"),
        }
    }
}

/// Log manager for a process.
#[derive(Debug)]
pub struct LogManager {
    /// Log configuration.
    config: LogConfig,

    /// Process name.
    process_name: String,

    /// Instance index.
    instance: u32,

    /// Current stdout file size (for rotation).
    stdout_size: u64,

    /// Current stderr file size (for rotation).
    stderr_size: u64,
}

impl LogManager {
    /// Create a new log manager.
    #[must_use]
    pub const fn new(config: LogConfig, process_name: String, instance: u32) -> Self {
        Self {
            config,
            process_name,
            instance,
            stdout_size: 0,
            stderr_size: 0,
        }
    }

    /// Get the stdout log file path.
    #[must_use]
    pub fn stdout_path(&self) -> Option<PathBuf> {
        self.config
            .out_file
            .clone()
            .or_else(|| self.config.combined_file.clone())
    }

    /// Get the stderr log file path.
    #[must_use]
    pub fn stderr_path(&self) -> Option<PathBuf> {
        if self.config.merge_stderr {
            self.stdout_path()
        } else {
            self.config
                .err_file
                .clone()
                .or_else(|| self.config.combined_file.clone())
        }
    }

    /// Format a log line with optional timestamp.
    #[must_use]
    pub fn format_line(&self, content: &str, stream: LogStream) -> String {
        if self.config.timestamp {
            let timestamp = chrono::Utc::now().format(&self.config.timestamp_format);
            format!("[{timestamp}] [{stream}] {content}")
        } else {
            content.to_string()
        }
    }

    /// Check if rotation is needed for stdout.
    #[must_use]
    pub fn needs_stdout_rotation(&self) -> bool {
        if let Some(rotation) = &self.config.rotation {
            if rotation.mode == RotationMode::Size {
                return self.stdout_size >= rotation.max_size;
            }
        }
        false
    }

    /// Check if rotation is needed for stderr.
    #[must_use]
    pub fn needs_stderr_rotation(&self) -> bool {
        if let Some(rotation) = &self.config.rotation {
            if rotation.mode == RotationMode::Size && !self.config.merge_stderr {
                return self.stderr_size >= rotation.max_size;
            }
        }
        false
    }

    /// Record bytes written to stdout.
    pub const fn record_stdout_bytes(&mut self, bytes: u64) {
        self.stdout_size += bytes;
    }

    /// Record bytes written to stderr.
    pub const fn record_stderr_bytes(&mut self, bytes: u64) {
        self.stderr_size += bytes;
    }

    /// Reset file sizes after rotation.
    pub const fn reset_stdout_size(&mut self) {
        self.stdout_size = 0;
    }

    /// Reset stderr file size after rotation.
    pub const fn reset_stderr_size(&mut self) {
        self.stderr_size = 0;
    }

    /// Get the log configuration.
    #[must_use]
    pub const fn config(&self) -> &LogConfig {
        &self.config
    }

    /// Get the process name.
    #[must_use]
    pub fn process_name(&self) -> &str {
        &self.process_name
    }

    /// Get the instance index.
    #[must_use]
    pub const fn instance(&self) -> u32 {
        self.instance
    }
}

/// Errors related to log operations.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// Failed to create log file.
    #[error("failed to create log file: {0}")]
    CreateFailed(#[from] std::io::Error),

    /// Failed to rotate log file.
    #[error("failed to rotate log file: {0}")]
    RotationFailed(String),

    /// Log directory doesn't exist.
    #[error("log directory does not exist: {0}")]
    DirectoryNotFound(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_config_defaults() {
        let config = LogConfig::default();
        assert!(config.out_file.is_none());
        assert!(config.err_file.is_none());
        assert!(!config.merge_stderr);
        assert!(!config.timestamp);
    }

    #[test]
    fn test_format_line_with_timestamp() {
        let config = LogConfig {
            timestamp: true,
            timestamp_format: "%H:%M:%S".to_string(),
            ..Default::default()
        };
        let manager = LogManager::new(config, "test".to_string(), 0);

        let line = manager.format_line("hello", LogStream::Stdout);
        assert!(line.contains("[stdout]"));
        assert!(line.contains("hello"));
    }

    #[test]
    fn test_rotation_check() {
        let config = LogConfig {
            rotation: Some(LogRotationConfig {
                max_size: 100,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut manager = LogManager::new(config, "test".to_string(), 0);

        assert!(!manager.needs_stdout_rotation());

        manager.record_stdout_bytes(150);
        assert!(manager.needs_stdout_rotation());

        manager.reset_stdout_size();
        assert!(!manager.needs_stdout_rotation());
    }
}
