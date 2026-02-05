//! Configurable AI tool backend for AAT.
//!
//! This module provides configuration for selecting which AI tool backend
//! to use for AAT hypothesis generation and verification.
//!
//! # Configuration Precedence
//!
//! 1. CLI flag `--ai-tool` (highest priority)
//! 2. Environment variable `AAT_AI_TOOL`
//! 3. Default: Codex

use std::str::FromStr;
use std::{env, fmt};

/// AI tool backends supported by AAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AiTool {
    /// Codex CLI (default).
    #[default]
    Codex,
    /// Claude Code CLI.
    ClaudeCode,
}

impl AiTool {
    /// Returns the command name for this AI tool.
    #[must_use]
    pub const fn command(&self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude",
        }
    }
}

impl fmt::Display for AiTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codex => write!(f, "codex"),
            Self::ClaudeCode => write!(f, "claude-code"),
        }
    }
}

/// Error returned when parsing an invalid AI tool name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAiToolError {
    value: String,
}

impl fmt::Display for ParseAiToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid AI tool '{}': expected 'codex' or 'claude-code'",
            self.value
        )
    }
}

impl std::error::Error for ParseAiToolError {}

impl FromStr for AiTool {
    type Err = ParseAiToolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "codex" | "gemini" => Ok(Self::Codex),
            "claude-code" | "claude" => Ok(Self::ClaudeCode),
            _ => Err(ParseAiToolError {
                value: s.to_string(),
            }),
        }
    }
}

/// Configuration for the AAT AI tool backend.
#[derive(Debug, Clone, Default)]
pub struct AatToolConfig {
    /// The selected AI tool backend.
    pub ai_tool: AiTool,
}

impl AatToolConfig {
    /// Creates a new configuration from environment variables.
    ///
    /// Reads the `AAT_AI_TOOL` environment variable. Supported values:
    /// - `codex` (default)
    /// - `claude-code` or `claude`
    ///
    /// If the environment variable is not set or contains an invalid value,
    /// falls back to the default (Codex).
    #[must_use]
    pub fn from_env() -> Self {
        let ai_tool = env::var("AAT_AI_TOOL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_default();
        Self { ai_tool }
    }

    /// Applies a CLI override to the configuration.
    ///
    /// If `ai_tool` is `Some`, it overrides the environment variable setting.
    #[must_use]
    pub const fn with_override(mut self, ai_tool: Option<AiTool>) -> Self {
        if let Some(tool) = ai_tool {
            self.ai_tool = tool;
        }
        self
    }
}

// Allow unsafe in tests for environment variable manipulation.
// SAFETY: Tests use a mutex to serialize access to environment variables,
// preventing data races even when running tests in parallel.
#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Mutex to serialize tests that modify the `AAT_AI_TOOL` environment
    /// variable. This prevents race conditions when tests run in parallel.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_ai_tool_default_is_codex() {
        assert_eq!(AiTool::default(), AiTool::Codex);
    }

    #[test]
    fn test_ai_tool_command() {
        assert_eq!(AiTool::Codex.command(), "codex");
        assert_eq!(AiTool::ClaudeCode.command(), "claude");
    }

    #[test]
    fn test_ai_tool_display() {
        assert_eq!(format!("{}", AiTool::Codex), "codex");
        assert_eq!(format!("{}", AiTool::ClaudeCode), "claude-code");
    }

    #[test]
    fn test_ai_tool_from_str_codex() {
        assert_eq!("codex".parse::<AiTool>().unwrap(), AiTool::Codex);
        assert_eq!("CODEX".parse::<AiTool>().unwrap(), AiTool::Codex);
        assert_eq!("Codex".parse::<AiTool>().unwrap(), AiTool::Codex);
    }

    #[test]
    fn test_ai_tool_from_str_legacy_gemini_alias() {
        assert_eq!("gemini".parse::<AiTool>().unwrap(), AiTool::Codex);
        assert_eq!("GEMINI".parse::<AiTool>().unwrap(), AiTool::Codex);
        assert_eq!("Gemini".parse::<AiTool>().unwrap(), AiTool::Codex);
    }

    #[test]
    fn test_ai_tool_from_str_claude_code() {
        assert_eq!("claude-code".parse::<AiTool>().unwrap(), AiTool::ClaudeCode);
        assert_eq!("claude".parse::<AiTool>().unwrap(), AiTool::ClaudeCode);
        assert_eq!("CLAUDE-CODE".parse::<AiTool>().unwrap(), AiTool::ClaudeCode);
        assert_eq!("Claude".parse::<AiTool>().unwrap(), AiTool::ClaudeCode);
    }

    #[test]
    fn test_ai_tool_from_str_invalid() {
        let err = "invalid".parse::<AiTool>().unwrap_err();
        assert_eq!(err.value, "invalid");
        assert!(err.to_string().contains("invalid AI tool 'invalid'"));
    }

    #[test]
    fn test_aat_tool_config_default() {
        let config = AatToolConfig::default();
        assert_eq!(config.ai_tool, AiTool::Codex);
    }

    // Note: The following tests modify environment variables, which requires unsafe
    // in Rust 2024 edition. They use a mutex to serialize access.
    // SAFETY: Mutex ensures exclusive access to AAT_AI_TOOL env var.

    #[test]
    fn test_aat_tool_config_from_env_unset() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
        let config = AatToolConfig::from_env();
        assert_eq!(config.ai_tool, AiTool::Codex);
    }

    #[test]
    fn test_aat_tool_config_from_env_codex() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::set_var("AAT_AI_TOOL", "codex");
        }
        let config = AatToolConfig::from_env();
        assert_eq!(config.ai_tool, AiTool::Codex);
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
    }

    #[test]
    fn test_aat_tool_config_from_env_legacy_gemini_alias() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::set_var("AAT_AI_TOOL", "gemini");
        }
        let config = AatToolConfig::from_env();
        assert_eq!(config.ai_tool, AiTool::Codex);
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
    }

    #[test]
    fn test_aat_tool_config_from_env_claude_code() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::set_var("AAT_AI_TOOL", "claude-code");
        }
        let config = AatToolConfig::from_env();
        assert_eq!(config.ai_tool, AiTool::ClaudeCode);
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
    }

    #[test]
    fn test_aat_tool_config_from_env_invalid_falls_back_to_default() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::set_var("AAT_AI_TOOL", "invalid-tool");
        }
        let config = AatToolConfig::from_env();
        assert_eq!(config.ai_tool, AiTool::Codex);
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
    }

    #[test]
    fn test_aat_tool_config_with_override_none() {
        let config = AatToolConfig::default().with_override(None);
        assert_eq!(config.ai_tool, AiTool::Codex);
    }

    #[test]
    fn test_aat_tool_config_with_override_some() {
        let config = AatToolConfig::default().with_override(Some(AiTool::ClaudeCode));
        assert_eq!(config.ai_tool, AiTool::ClaudeCode);
    }

    #[test]
    fn test_aat_tool_config_override_takes_precedence_over_env() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::set_var("AAT_AI_TOOL", "codex");
        }
        let config = AatToolConfig::from_env().with_override(Some(AiTool::ClaudeCode));
        assert_eq!(config.ai_tool, AiTool::ClaudeCode);
        // SAFETY: Mutex held, exclusive access to env var.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
    }
}
