//! Secret redaction for log output.
//!
//! This module provides functionality to filter sensitive data from log output,
//! preventing accidental exposure of API keys, tokens, and other credentials.

use std::borrow::Cow;

use regex::Regex;

/// The replacement text for redacted secrets.
const REDACTED: &str = "[REDACTED]";

/// Patterns that match sensitive data in log output.
///
/// Each pattern is designed to match common secret formats while minimizing
/// false positives.
static SECRET_PATTERNS: std::sync::LazyLock<Vec<SecretPattern>> = std::sync::LazyLock::new(|| {
    vec![
        // API Keys with common prefixes
        SecretPattern::new("anthropic_api_key", r"sk-ant-[a-zA-Z0-9\-_]{20,}"),
        SecretPattern::new("openai_api_key", r"sk-[a-zA-Z0-9]{20,}"),
        SecretPattern::new("google_api_key", r"AIza[a-zA-Z0-9\-_]{35}"),
        // AWS credentials
        SecretPattern::new("aws_access_key", r"AKIA[A-Z0-9]{16}"),
        SecretPattern::new(
            "aws_secret_key",
            r#"(?i)aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})"#,
        ),
        // Generic tokens and secrets in key=value format
        SecretPattern::new(
            "generic_api_key",
            r#"(?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?"#,
        ),
        SecretPattern::new(
            "generic_token",
            r#"(?i)(access[_-]?token|auth[_-]?token|bearer)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_.=-]{20,})['"]?"#,
        ),
        SecretPattern::new(
            "generic_secret",
            r#"(?i)(secret|password|passwd|pwd)['"]?\s*[:=]\s*['"]?([^\s'"]{8,})['"]?"#,
        ),
        // Bearer tokens in headers
        SecretPattern::new("bearer_token", r"(?i)bearer\s+([a-zA-Z0-9_.=-]+)"),
        // Base64 encoded secrets (long base64 strings that look like keys)
        SecretPattern::new(
            "base64_secret",
            r#"(?i)(key|secret|token|credential)['"]?\s*[:=]\s*['"]?([A-Za-z0-9+/]{40,}={0,2})['"]?"#,
        ),
        // Private keys
        SecretPattern::new("private_key", r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
        // GitHub tokens
        SecretPattern::new("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        // Slack tokens
        SecretPattern::new(
            "slack_token",
            r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}",
        ),
    ]
});

/// Environment variable names that indicate sensitive content.
static SENSITIVE_ENV_NAMES: std::sync::LazyLock<Vec<Regex>> = std::sync::LazyLock::new(|| {
    [
        r"(?i).*api[_\-]?key.*",
        r"(?i).*secret.*",
        r"(?i).*token.*",
        r"(?i).*password.*",
        r"(?i).*credential.*",
        r"(?i)^ANTHROPIC_.*",
        r"(?i)^OPENAI_.*",
        r"(?i)^CLAUDE_.*",
        r"(?i)^AWS_.*",
        r"(?i)^GOOGLE_.*",
        r"(?i)^GITHUB_TOKEN$",
        r"(?i)^GH_TOKEN$",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("invalid sensitive env pattern"))
    .collect()
});

/// A pattern for matching secrets.
struct SecretPattern {
    /// Name of the pattern (for debugging).
    #[allow(dead_code)]
    name: &'static str,
    /// Compiled regex pattern.
    regex: Regex,
}

impl SecretPattern {
    /// Create a new secret pattern.
    fn new(name: &'static str, pattern: &str) -> Self {
        Self {
            name,
            regex: Regex::new(pattern).expect("invalid secret pattern"),
        }
    }
}

/// A secret redactor that filters sensitive data from strings.
///
/// # Example
///
/// ```
/// use apm2_core::log::SecretRedactor;
///
/// let redactor = SecretRedactor::new();
/// let input = "API key is sk-ant-api01-abc123xyz456defghijk";
/// let output = redactor.redact(input);
/// assert!(output.contains("[REDACTED]"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct SecretRedactor {
    /// Additional custom patterns to match.
    custom_patterns: Vec<Regex>,
}

impl SecretRedactor {
    /// Create a new secret redactor with default patterns.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a custom pattern to match.
    ///
    /// # Panics
    ///
    /// Panics if the pattern is not a valid regex.
    #[must_use]
    pub fn with_pattern(mut self, pattern: &str) -> Self {
        self.custom_patterns
            .push(Regex::new(pattern).expect("invalid custom pattern"));
        self
    }

    /// Redact sensitive data from a string.
    ///
    /// Returns a new string with all matched secrets replaced with
    /// `[REDACTED]`.
    #[must_use]
    pub fn redact<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = Cow::Borrowed(input);

        // Apply built-in patterns
        for pattern in SECRET_PATTERNS.iter() {
            if pattern.regex.is_match(&result) {
                result = Cow::Owned(pattern.regex.replace_all(&result, REDACTED).into_owned());
            }
        }

        // Apply custom patterns
        for pattern in &self.custom_patterns {
            if pattern.is_match(&result) {
                result = Cow::Owned(pattern.replace_all(&result, REDACTED).into_owned());
            }
        }

        result
    }

    /// Check if an environment variable name is sensitive.
    ///
    /// Returns `true` if the variable name matches any sensitive pattern.
    #[must_use]
    pub fn is_sensitive_env_name(name: &str) -> bool {
        SENSITIVE_ENV_NAMES.iter().any(|p| p.is_match(name))
    }

    /// Redact a value if the environment variable name is sensitive.
    ///
    /// Returns `[REDACTED]` if the name is sensitive, otherwise returns the
    /// value unchanged.
    #[must_use]
    pub fn redact_env_value<'a>(name: &str, value: &'a str) -> Cow<'a, str> {
        if Self::is_sensitive_env_name(name) {
            Cow::Borrowed(REDACTED)
        } else {
            Cow::Borrowed(value)
        }
    }
}

/// Redact secrets from a string using the default redactor.
///
/// This is a convenience function for one-off redaction.
#[must_use]
pub fn redact(input: &str) -> Cow<'_, str> {
    SecretRedactor::new().redact(input)
}

/// Check if an environment variable name is sensitive.
#[must_use]
pub fn is_sensitive_env_name(name: &str) -> bool {
    SecretRedactor::is_sensitive_env_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_api_key() {
        let redactor = SecretRedactor::new();
        let input = "Using key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        let output = redactor.redact(input);
        assert!(output.contains(REDACTED));
        assert!(!output.contains("sk-ant"));
    }

    #[test]
    fn test_openai_api_key() {
        let redactor = SecretRedactor::new();
        let input = "OPENAI_API_KEY=sk-proj-1234567890abcdefghij";
        let output = redactor.redact(input);
        assert!(output.contains(REDACTED));
    }

    #[test]
    fn test_aws_access_key() {
        let redactor = SecretRedactor::new();
        let input = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let output = redactor.redact(input);
        assert!(output.contains(REDACTED));
    }

    #[test]
    fn test_bearer_token() {
        let redactor = SecretRedactor::new();
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let output = redactor.redact(input);
        assert!(output.contains(REDACTED));
    }

    #[test]
    fn test_github_token() {
        let redactor = SecretRedactor::new();
        let input = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let output = redactor.redact(input);
        assert!(output.contains(REDACTED));
    }

    #[test]
    fn test_private_key_header() {
        let redactor = SecretRedactor::new();
        let input = "Found key: -----BEGIN RSA PRIVATE KEY-----";
        let output = redactor.redact(input);
        assert!(output.contains(REDACTED));
    }

    #[test]
    fn test_no_false_positive() {
        let redactor = SecretRedactor::new();
        let input = "Normal log message with no secrets";
        let output = redactor.redact(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_sensitive_env_names() {
        assert!(SecretRedactor::is_sensitive_env_name("ANTHROPIC_API_KEY"));
        assert!(SecretRedactor::is_sensitive_env_name("OPENAI_API_KEY"));
        assert!(SecretRedactor::is_sensitive_env_name(
            "AWS_SECRET_ACCESS_KEY"
        ));
        assert!(SecretRedactor::is_sensitive_env_name("MY_SECRET_TOKEN"));
        assert!(SecretRedactor::is_sensitive_env_name("password"));
        assert!(SecretRedactor::is_sensitive_env_name("GITHUB_TOKEN"));

        assert!(!SecretRedactor::is_sensitive_env_name("PATH"));
        assert!(!SecretRedactor::is_sensitive_env_name("HOME"));
        assert!(!SecretRedactor::is_sensitive_env_name("RUST_LOG"));
    }

    #[test]
    fn test_redact_env_value() {
        assert_eq!(
            SecretRedactor::redact_env_value("API_KEY", "secret123"),
            REDACTED
        );
        assert_eq!(
            SecretRedactor::redact_env_value("PATH", "/usr/bin"),
            "/usr/bin"
        );
    }

    #[test]
    fn test_custom_pattern() {
        let redactor = SecretRedactor::new().with_pattern(r"custom-secret-\d+");
        let input = "Found: custom-secret-12345";
        let output = redactor.redact(input);
        assert!(output.contains(REDACTED));
        assert!(!output.contains("custom-secret-12345"));
    }

    #[test]
    fn test_multiple_secrets() {
        let redactor = SecretRedactor::new();
        let input =
            "Keys: sk-ant-abc123xyz456789012345 and ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let output = redactor.redact(input);
        assert!(!output.contains("sk-ant"));
        assert!(!output.contains("ghp_"));
        // Should have two redactions
        assert_eq!(output.matches(REDACTED).count(), 2);
    }
}
