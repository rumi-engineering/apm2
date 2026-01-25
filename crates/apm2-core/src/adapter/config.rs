//! Configuration types for adapters.
//!
//! Provides configuration for black-box adapters, including:
//! - Process spawning settings
//! - Filesystem watching configuration
//! - Stall detection thresholds
//! - Progress signal derivation settings

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Configuration for a black-box adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackBoxConfig {
    /// Session ID for this adapter instance.
    pub session_id: String,

    /// Process configuration.
    pub process: ProcessConfig,

    /// Filesystem watching configuration.
    pub filesystem: FilesystemConfig,

    /// Stall detection configuration.
    pub stall_detection: StallDetectionConfig,

    /// Progress derivation configuration.
    pub progress: ProgressConfig,

    /// Environment variables to pass to the process.
    /// Only safe variables are allowed; sensitive ones are filtered.
    pub environment: EnvironmentConfig,
}

impl BlackBoxConfig {
    /// Creates a new configuration with sensible defaults.
    #[must_use]
    pub fn new(session_id: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            process: ProcessConfig {
                command: command.into(),
                args: Vec::new(),
                working_dir: None,
            },
            filesystem: FilesystemConfig::default(),
            stall_detection: StallDetectionConfig::default(),
            progress: ProgressConfig::default(),
            environment: EnvironmentConfig::default(),
        }
    }

    /// Sets the working directory.
    #[must_use]
    pub fn with_working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.process.working_dir = Some(dir.into());
        self
    }

    /// Sets the command arguments.
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.process.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Adds a path to watch for filesystem changes.
    #[must_use]
    pub fn with_watch_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.filesystem.watch_paths.push(path.into());
        self
    }

    /// Sets the stall timeout.
    #[must_use]
    pub const fn with_stall_timeout(mut self, timeout: Duration) -> Self {
        self.stall_detection.timeout = timeout;
        self
    }
}

/// Process spawning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    /// Command to execute.
    pub command: String,

    /// Arguments to pass to the command.
    pub args: Vec<String>,

    /// Working directory for the process.
    pub working_dir: Option<PathBuf>,
}

/// Filesystem watching configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemConfig {
    /// Paths to watch for changes.
    pub watch_paths: Vec<PathBuf>,

    /// Whether to watch directories recursively.
    pub recursive: bool,

    /// File patterns to ignore (glob patterns).
    pub ignore_patterns: Vec<String>,

    /// Debounce duration for filesystem events.
    pub debounce: Duration,

    /// Maximum number of events to buffer.
    pub buffer_size: usize,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            watch_paths: Vec::new(),
            recursive: true,
            ignore_patterns: vec![
                // Common patterns to ignore
                "*.swp".to_string(),
                "*~".to_string(),
                ".git/**".to_string(),
                "node_modules/**".to_string(),
                "target/**".to_string(),
                "__pycache__/**".to_string(),
            ],
            debounce: Duration::from_millis(100),
            buffer_size: 1024,
        }
    }
}

/// Stall detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallDetectionConfig {
    /// Duration of inactivity before a stall is detected.
    pub timeout: Duration,

    /// Whether stall detection is enabled.
    pub enabled: bool,

    /// Maximum number of stalls before the session is terminated.
    pub max_stalls: u32,
}

impl Default for StallDetectionConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            enabled: true,
            max_stalls: 5,
        }
    }
}

/// Progress signal derivation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressConfig {
    /// Interval for heartbeat signals (based on activity).
    pub heartbeat_interval: Duration,

    /// File extensions that indicate milestone completion.
    pub milestone_extensions: Vec<String>,

    /// Patterns that indicate tool completion.
    pub tool_complete_patterns: Vec<String>,
}

impl Default for ProgressConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(30),
            milestone_extensions: vec![
                ".rs".to_string(),
                ".py".to_string(),
                ".ts".to_string(),
                ".js".to_string(),
                ".go".to_string(),
                ".md".to_string(),
            ],
            tool_complete_patterns: vec![
                "test passed".to_string(),
                "build succeeded".to_string(),
                "compilation successful".to_string(),
            ],
        }
    }
}

/// Environment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    /// Environment variables to set.
    pub variables: Vec<(String, String)>,

    /// Whether to inherit the parent environment.
    pub inherit: bool,

    /// Variables to explicitly exclude (for security).
    pub exclude: Vec<String>,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            variables: Vec::new(),
            // Default to false for security (default-deny).
            // Users must explicitly opt-in to environment inheritance.
            inherit: false,
            exclude: vec![
                // Sensitive variables that should never be passed
                // These are excluded even if inherit is later set to true
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "AWS_ACCESS_KEY_ID".to_string(),
                "ANTHROPIC_API_KEY".to_string(),
                "OPENAI_API_KEY".to_string(),
                "GITHUB_TOKEN".to_string(),
                "NPM_TOKEN".to_string(),
                "DOCKER_PASSWORD".to_string(),
                "SSH_PRIVATE_KEY".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = BlackBoxConfig::new("session-123", "claude")
            .with_working_dir("/tmp/workspace")
            .with_args(["--help", "--version"])
            .with_watch_path("/tmp/workspace")
            .with_stall_timeout(Duration::from_secs(120));

        assert_eq!(config.session_id, "session-123");
        assert_eq!(config.process.command, "claude");
        assert_eq!(config.process.args, vec!["--help", "--version"]);
        assert_eq!(
            config.process.working_dir,
            Some(PathBuf::from("/tmp/workspace"))
        );
        assert_eq!(
            config.filesystem.watch_paths,
            vec![PathBuf::from("/tmp/workspace")]
        );
        assert_eq!(config.stall_detection.timeout, Duration::from_secs(120));
    }

    #[test]
    fn test_default_filesystem_config() {
        let config = FilesystemConfig::default();
        assert!(config.recursive);
        assert!(!config.ignore_patterns.is_empty());
        assert!(config.ignore_patterns.contains(&".git/**".to_string()));
        assert_eq!(config.buffer_size, 1024);
    }

    #[test]
    fn test_default_stall_detection_config() {
        let config = StallDetectionConfig::default();
        assert!(config.enabled);
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_stalls, 5);
    }

    #[test]
    fn test_default_environment_config() {
        let config = EnvironmentConfig::default();
        // Default-deny: inherit is false
        assert!(!config.inherit);
        assert!(config.exclude.contains(&"ANTHROPIC_API_KEY".to_string()));
        assert!(
            config
                .exclude
                .contains(&"AWS_SECRET_ACCESS_KEY".to_string())
        );
    }

    #[test]
    fn test_environment_default_deny() {
        // Security requirement: default configuration must not inherit parent env
        let config = EnvironmentConfig::default();
        assert!(
            !config.inherit,
            "Security: default config must use default-deny (inherit=false)"
        );
    }
}
