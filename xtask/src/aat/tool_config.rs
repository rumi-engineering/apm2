//! Configurable AI tool backend for AAT.
//!
//! This module provides configuration for selecting which AI tool backend
//! to use for AAT hypothesis generation and verification.
//!
//! # Configuration Precedence
//!
//! 1. CLI flag `--ai-tool` (highest priority)
//! 2. Environment variable `AAT_AI_TOOL`
//! 3. Default: Gemini

use std::str::FromStr;
use std::{env, fmt};

/// AI tool backends supported by AAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AiTool {
    /// Gemini CLI (default).
    #[default]
    Gemini,
    /// Claude Code CLI.
    ClaudeCode,
}

impl AiTool {
    /// Returns the command name for this AI tool.
    #[must_use]
    pub const fn command(&self) -> &'static str {
        match self {
            Self::Gemini => "gemini",
            Self::ClaudeCode => "claude",
        }
    }
}

impl fmt::Display for AiTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gemini => write!(f, "gemini"),
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
            "invalid AI tool '{}': expected 'gemini' or 'claude-code'",
            self.value
        )
    }
}

impl std::error::Error for ParseAiToolError {}

impl FromStr for AiTool {
    type Err = ParseAiToolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "gemini" => Ok(Self::Gemini),
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
    /// - `gemini` (default)
    /// - `claude-code` or `claude`
    ///
    /// If the environment variable is not set or contains an invalid value,
    /// falls back to the default (Gemini).
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
// SAFETY: Tests must be run with `--test-threads=1` to prevent data races.
#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_tool_default_is_gemini() {
        assert_eq!(AiTool::default(), AiTool::Gemini);
    }

    #[test]
    fn test_ai_tool_command() {
        assert_eq!(AiTool::Gemini.command(), "gemini");
        assert_eq!(AiTool::ClaudeCode.command(), "claude");
    }

    #[test]
    fn test_ai_tool_display() {
        assert_eq!(format!("{}", AiTool::Gemini), "gemini");
        assert_eq!(format!("{}", AiTool::ClaudeCode), "claude-code");
    }

    #[test]
    fn test_ai_tool_from_str_gemini() {
        assert_eq!("gemini".parse::<AiTool>().unwrap(), AiTool::Gemini);
        assert_eq!("GEMINI".parse::<AiTool>().unwrap(), AiTool::Gemini);
        assert_eq!("Gemini".parse::<AiTool>().unwrap(), AiTool::Gemini);
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
        assert_eq!(config.ai_tool, AiTool::Gemini);
    }

    // Note: The following tests modify environment variables, which requires unsafe
    // in Rust 2024 edition. They use `-- --test-threads=1` for safety.
    // SAFETY: Tests are run single-threaded to prevent data races on env vars.

    #[test]
    fn test_aat_tool_config_from_env_unset() {
        // SAFETY: Single-threaded test execution prevents data races.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
        let config = AatToolConfig::from_env();
        assert_eq!(config.ai_tool, AiTool::Gemini);
    }

    #[test]
    fn test_aat_tool_config_from_env_gemini() {
        // SAFETY: Single-threaded test execution prevents data races.
        unsafe {
            std::env::set_var("AAT_AI_TOOL", "gemini");
        }
        let config = AatToolConfig::from_env();
        assert_eq!(config.ai_tool, AiTool::Gemini);
        // SAFETY: Single-threaded test execution prevents data races.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
    }

    #[test]
    fn test_aat_tool_config_from_env_claude_code() {
        // SAFETY: Single-threaded test execution prevents data races.
        unsafe {
            std::env::set_var("AAT_AI_TOOL", "claude-code");
        }
        let config = AatToolConfig::from_env();
        assert_eq!(config.ai_tool, AiTool::ClaudeCode);
        // SAFETY: Single-threaded test execution prevents data races.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
    }

    #[test]
    fn test_aat_tool_config_from_env_invalid_falls_back_to_default() {
        // SAFETY: Single-threaded test execution prevents data races.
        unsafe {
            std::env::set_var("AAT_AI_TOOL", "invalid-tool");
        }
        let config = AatToolConfig::from_env();
        assert_eq!(config.ai_tool, AiTool::Gemini);
        // SAFETY: Single-threaded test execution prevents data races.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
    }

    #[test]
    fn test_aat_tool_config_with_override_none() {
        let config = AatToolConfig::default().with_override(None);
        assert_eq!(config.ai_tool, AiTool::Gemini);
    }

    #[test]
    fn test_aat_tool_config_with_override_some() {
        let config = AatToolConfig::default().with_override(Some(AiTool::ClaudeCode));
        assert_eq!(config.ai_tool, AiTool::ClaudeCode);
    }

    #[test]
    fn test_aat_tool_config_override_takes_precedence_over_env() {
        // SAFETY: Single-threaded test execution prevents data races.
        unsafe {
            std::env::set_var("AAT_AI_TOOL", "gemini");
        }
        let config = AatToolConfig::from_env().with_override(Some(AiTool::ClaudeCode));
        assert_eq!(config.ai_tool, AiTool::ClaudeCode);
        // SAFETY: Single-threaded test execution prevents data races.
        unsafe {
            std::env::remove_var("AAT_AI_TOOL");
        }
    }
}
