//! UX Verification for Agent-Friendly CLI Output (AAT).
//!
//! This module implements verification of agent-friendly UX patterns for CLI
//! tools:
//! - Structured output validation (JSON/YAML detection)
//! - Error message remediation guidance detection
//! - Help output consistency checking
//! - Exit code convention verification
//!
//! # Usage
//!
//! ```ignore
//! use xtask::aat::ux_verifier::{UxVerifier, UxAudit};
//!
//! let audit = UxVerifier::analyze_command_output(
//!     "my-tool",
//!     Some(0),
//!     r#"{"status": "ok"}"#,
//!     "",
//! );
//!
//! assert!(audit.has_structured_output);
//! ```
//!
//! # Output Format
//!
//! The module produces a `UxAudit` struct that can be serialized to JSON
//! for inclusion in the AAT evidence bundle.

use serde::{Deserialize, Serialize};

// =============================================================================
// Types
// =============================================================================

/// Severity level for UX findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UxSeverity {
    /// Informational finding (suggestion for improvement).
    Info,
    /// Warning (should be addressed but not blocking).
    Warning,
    /// Error (significant UX issue that should be fixed).
    Error,
}

/// Category of UX finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UxCategory {
    /// Finding related to structured output (JSON/YAML).
    StructuredOutput,
    /// Finding related to error message quality.
    ErrorMessage,
    /// Finding related to help text consistency.
    HelpOutput,
    /// Finding related to exit code conventions.
    ExitCode,
}

/// A single UX verification finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxFinding {
    /// Category of the finding.
    pub category: UxCategory,

    /// Severity level.
    pub severity: UxSeverity,

    /// Short description of the finding.
    pub message: String,

    /// Actionable remediation guidance.
    pub remediation: String,

    /// Optional code snippet or output sample related to the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

impl UxFinding {
    /// Create a new UX finding.
    #[must_use]
    pub fn new(
        category: UxCategory,
        severity: UxSeverity,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            category,
            severity,
            message: message.into(),
            remediation: remediation.into(),
            snippet: None,
        }
    }

    /// Add a code snippet to the finding.
    #[must_use]
    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }
}

/// Structured output detection result.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredOutputInfo {
    /// Whether the output is valid JSON.
    pub is_json: bool,

    /// Whether the output is valid YAML.
    pub is_yaml: bool,

    /// Whether the output appears to be structured (JSON or YAML).
    pub is_structured: bool,
}

/// Error message analysis result.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorMessageInfo {
    /// Whether error messages contain remediation guidance keywords.
    pub has_remediation_guidance: bool,

    /// Keywords found that indicate remediation guidance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guidance_keywords_found: Vec<String>,

    /// Whether error messages contain actionable suggestions.
    pub has_actionable_suggestion: bool,
}

/// Help output analysis result.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct HelpOutputInfo {
    /// Whether help output contains a usage section.
    pub has_usage_section: bool,

    /// Whether help output contains an options/flags section.
    pub has_options_section: bool,

    /// Whether help output contains a description.
    pub has_description: bool,

    /// Whether help output contains examples.
    pub has_examples: bool,

    /// Overall help output quality score (0-100).
    pub quality_score: u8,
}

/// Exit code analysis result.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitCodeInfo {
    /// The exit code that was observed.
    pub exit_code: Option<i32>,

    /// Whether the exit code follows conventions (0 for success, non-zero for
    /// error).
    pub follows_convention: bool,

    /// Whether the exit code is meaningful (distinct codes for different
    /// errors).
    pub is_meaningful: bool,
}

/// Complete UX audit result for a command.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxAudit {
    /// Command that was analyzed.
    pub command: String,

    /// Whether the command produces structured output.
    pub has_structured_output: bool,

    /// Structured output analysis details.
    pub structured_output: StructuredOutputInfo,

    /// Whether error messages contain remediation guidance.
    pub has_remediation_guidance: bool,

    /// Error message analysis details.
    pub error_message: ErrorMessageInfo,

    /// Help output analysis details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_output: Option<HelpOutputInfo>,

    /// Exit code analysis details.
    pub exit_code: ExitCodeInfo,

    /// List of UX findings (issues and suggestions).
    pub findings: Vec<UxFinding>,

    /// Overall UX quality score (0-100).
    pub overall_score: u8,
}

/// Aggregated UX audit section for the evidence bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxAuditSection {
    /// Individual command audits.
    pub command_audits: Vec<UxAudit>,

    /// Commands that lack structured output.
    pub tools_without_structured_output: Vec<String>,

    /// Error messages that lack actionable advice.
    pub errors_without_remediation: Vec<String>,

    /// Overall UX audit verdict.
    pub verdict: UxAuditVerdict,

    /// Summary of UX issues found.
    pub summary: String,
}

/// UX audit verdict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UxAuditVerdict {
    /// All UX checks passed.
    #[default]
    Passed,
    /// UX issues found but not blocking.
    PassedWithWarnings,
    /// Significant UX issues found.
    NeedsImprovement,
}

// =============================================================================
// UX Verifier Implementation
// =============================================================================

/// UX verification engine.
///
/// Analyzes CLI command output for agent-friendly patterns.
pub struct UxVerifier;

impl UxVerifier {
    // -------------------------------------------------------------------------
    // Structured Output Detection
    // -------------------------------------------------------------------------

    /// Check if output is valid JSON.
    #[must_use]
    pub fn is_valid_json(output: &str) -> bool {
        let trimmed = output.trim();
        if trimmed.is_empty() {
            return false;
        }
        serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
    }

    /// Check if output is valid YAML (with structured content).
    ///
    /// This is stricter than just "is parseable as YAML" because plain text
    /// is technically valid YAML (as a string scalar). We require the content
    /// to have actual YAML structure (mappings or sequences) to be useful
    /// for agent consumption.
    #[must_use]
    pub fn is_valid_yaml(output: &str) -> bool {
        let trimmed = output.trim();
        if trimmed.is_empty() {
            return false;
        }
        // Exclude pure JSON since it's also valid YAML but we want to
        // distinguish the two formats
        if Self::is_valid_json(trimmed) {
            return false;
        }
        // Parse as YAML and check if it's a mapping or sequence (not just a scalar)
        matches!(
            serde_yaml::from_str::<serde_yaml::Value>(trimmed),
            Ok(serde_yaml::Value::Mapping(_) | serde_yaml::Value::Sequence(_))
        )
    }

    /// Analyze output for structured format.
    #[must_use]
    pub fn analyze_structured_output(output: &str) -> StructuredOutputInfo {
        let is_json = Self::is_valid_json(output);
        let is_yaml = Self::is_valid_yaml(output);

        StructuredOutputInfo {
            is_json,
            is_yaml,
            is_structured: is_json || is_yaml,
        }
    }

    // -------------------------------------------------------------------------
    // Error Message Analysis
    // -------------------------------------------------------------------------

    /// Keywords that indicate remediation guidance in error messages.
    const REMEDIATION_KEYWORDS: &'static [&'static str] = &[
        "try",
        "fix",
        "ensure",
        "check",
        "verify",
        "make sure",
        "suggestion",
        "hint",
        "tip",
        "help",
        "did you mean",
        "instead",
        "consider",
        "should",
        "must",
        "required",
        "missing",
        "expected",
        "run",
        "use",
        "install",
        "update",
        "set",
        "add",
        "remove",
        "change",
    ];

    /// Patterns that indicate actionable suggestions.
    const ACTIONABLE_PATTERNS: &'static [&'static str] = &[
        "to fix this",
        "to resolve",
        "you can",
        "you may",
        "you should",
        "you need to",
        "please",
        "for example",
        "e.g.",
        "such as",
        "like:",
        "usage:",
        "example:",
        "see:",
        "refer to",
        "documentation",
        "more info",
    ];

    /// Analyze error output for remediation guidance.
    #[must_use]
    pub fn analyze_error_message(stderr: &str) -> ErrorMessageInfo {
        if stderr.trim().is_empty() {
            return ErrorMessageInfo::default();
        }

        let stderr_lower = stderr.to_lowercase();

        // Find remediation keywords
        let keywords_found: Vec<String> = Self::REMEDIATION_KEYWORDS
            .iter()
            .filter(|&&kw| stderr_lower.contains(kw))
            .map(|&s| s.to_string())
            .collect();

        // Check for actionable patterns
        let has_actionable = Self::ACTIONABLE_PATTERNS
            .iter()
            .any(|&pattern| stderr_lower.contains(pattern));

        let has_remediation = !keywords_found.is_empty() || has_actionable;

        ErrorMessageInfo {
            has_remediation_guidance: has_remediation,
            guidance_keywords_found: keywords_found,
            has_actionable_suggestion: has_actionable,
        }
    }

    // -------------------------------------------------------------------------
    // Help Output Analysis
    // -------------------------------------------------------------------------

    /// Analyze help output for consistency and completeness.
    #[must_use]
    pub fn analyze_help_output(help_text: &str) -> HelpOutputInfo {
        if help_text.trim().is_empty() {
            return HelpOutputInfo::default();
        }

        let text_lower = help_text.to_lowercase();

        // Check for usage section
        let has_usage = text_lower.contains("usage:")
            || text_lower.contains("usage\n")
            || text_lower.contains("synopsis")
            || help_text.contains("USAGE:");

        // Check for options/flags section
        let has_options = text_lower.contains("options:")
            || text_lower.contains("flags:")
            || text_lower.contains("arguments:")
            || text_lower.contains("args:")
            || help_text.contains("OPTIONS:")
            || help_text.contains("FLAGS:")
            || help_text.contains("-h, --help")
            || help_text.contains("--help");

        // Check for description
        let has_description = text_lower.contains("description:")
            || help_text.lines().count() > 3
            || text_lower.contains("about:");

        // Check for examples
        let has_examples = text_lower.contains("example")
            || text_lower.contains("e.g.")
            || help_text.contains("Examples:")
            || help_text.contains("EXAMPLES:");

        // Calculate quality score
        let mut score: u8 = 0;
        if has_usage {
            score += 30;
        }
        if has_options {
            score += 30;
        }
        if has_description {
            score += 20;
        }
        if has_examples {
            score += 20;
        }

        HelpOutputInfo {
            has_usage_section: has_usage,
            has_options_section: has_options,
            has_description,
            has_examples,
            quality_score: score,
        }
    }

    // -------------------------------------------------------------------------
    // Exit Code Analysis
    // -------------------------------------------------------------------------

    /// Analyze exit code for convention compliance.
    ///
    /// Standard conventions:
    /// - 0: Success
    /// - 1: General error
    /// - 2: Misuse of shell command (e.g., invalid arguments)
    /// - 126: Command cannot execute (permission issue)
    /// - 127: Command not found
    /// - 128+N: Fatal signal N
    #[must_use]
    pub const fn analyze_exit_code(exit_code: Option<i32>, had_error: bool) -> ExitCodeInfo {
        let follows_convention = match exit_code {
            Some(0) => !had_error,               // 0 should mean success
            Some(code) if code > 0 => had_error, // Non-zero should mean error
            // Negative exit codes or signal termination (None) don't follow convention
            Some(_) | None => false,
        };

        // Check if exit code is meaningful (common convention values)
        // Standard codes: 0 (success), 1 (general error), 2 (misuse)
        // Shell conventions: 126-255 (special meanings like permission denied, not
        // found, signals)
        let is_meaningful = matches!(exit_code, Some(0..=2 | 126..=255));

        ExitCodeInfo {
            exit_code,
            follows_convention,
            is_meaningful,
        }
    }

    // -------------------------------------------------------------------------
    // Complete Analysis
    // -------------------------------------------------------------------------

    /// Perform complete UX analysis on command output.
    ///
    /// # Arguments
    ///
    /// * `command` - The command that was executed
    /// * `exit_code` - The exit code of the command
    /// * `stdout` - Standard output from the command
    /// * `stderr` - Standard error from the command
    #[must_use]
    pub fn analyze_command_output(
        command: &str,
        exit_code: Option<i32>,
        stdout: &str,
        stderr: &str,
    ) -> UxAudit {
        let mut findings = Vec::new();

        // Analyze structured output
        let structured_output = Self::analyze_structured_output(stdout);
        let has_structured_output = structured_output.is_structured;

        if !has_structured_output && !stdout.trim().is_empty() {
            findings.push(
                UxFinding::new(
                    UxCategory::StructuredOutput,
                    UxSeverity::Warning,
                    "Output is not in a structured format (JSON/YAML)",
                    "Consider adding a --json or --format=json flag for machine-readable output",
                )
                .with_snippet(truncate_output(stdout, 200)),
            );
        }

        // Analyze error messages
        let error_message = Self::analyze_error_message(stderr);
        let has_remediation_guidance = error_message.has_remediation_guidance;

        let had_error = exit_code.is_some_and(|c| c != 0) || !stderr.trim().is_empty();

        if had_error && !has_remediation_guidance && !stderr.trim().is_empty() {
            findings.push(
                UxFinding::new(
                    UxCategory::ErrorMessage,
                    UxSeverity::Warning,
                    "Error message lacks remediation guidance",
                    "Add actionable suggestions like 'try X', 'ensure Y', or 'run Z to fix'",
                )
                .with_snippet(truncate_output(stderr, 200)),
            );
        }

        // Analyze exit code
        let exit_code_info = Self::analyze_exit_code(exit_code, had_error);

        if !exit_code_info.follows_convention {
            findings.push(UxFinding::new(
                UxCategory::ExitCode,
                UxSeverity::Error,
                format!(
                    "Exit code {} does not follow convention (error={had_error})",
                    exit_code.map_or_else(|| "None".to_string(), |c| c.to_string())
                ),
                "Use exit code 0 for success and non-zero for errors",
            ));
        }

        // Calculate overall score
        let mut overall_score: u8 = 50; // Base score

        if has_structured_output {
            overall_score += 20;
        }
        if has_remediation_guidance || !had_error {
            overall_score += 15;
        }
        if exit_code_info.follows_convention {
            overall_score += 15;
        }

        // Deduct for errors (cap at reasonable values to prevent overflow)
        let error_count = findings
            .iter()
            .filter(|f| f.severity == UxSeverity::Error)
            .count()
            .min(10); // Cap at 10 errors for scoring purposes
        let warning_count = findings
            .iter()
            .filter(|f| f.severity == UxSeverity::Warning)
            .count()
            .min(20); // Cap at 20 warnings for scoring purposes

        #[allow(clippy::cast_possible_truncation)]
        {
            overall_score = overall_score.saturating_sub((error_count * 15) as u8);
            overall_score = overall_score.saturating_sub((warning_count * 5) as u8);
        }

        UxAudit {
            command: command.to_string(),
            has_structured_output,
            structured_output,
            has_remediation_guidance,
            error_message,
            help_output: None,
            exit_code: exit_code_info,
            findings,
            overall_score,
        }
    }

    /// Analyze help output for a command.
    ///
    /// This should be called separately with the output of `command --help`.
    #[must_use]
    pub fn analyze_help(command: &str, help_output: &str) -> UxAudit {
        let mut findings = Vec::new();

        let help_info = Self::analyze_help_output(help_output);

        if !help_info.has_usage_section {
            findings.push(UxFinding::new(
                UxCategory::HelpOutput,
                UxSeverity::Warning,
                "Help output missing usage section",
                "Add a USAGE: section showing the command syntax",
            ));
        }

        if !help_info.has_options_section {
            findings.push(UxFinding::new(
                UxCategory::HelpOutput,
                UxSeverity::Warning,
                "Help output missing options/flags section",
                "Add an OPTIONS: or FLAGS: section documenting available flags",
            ));
        }

        if !help_info.has_examples {
            findings.push(UxFinding::new(
                UxCategory::HelpOutput,
                UxSeverity::Info,
                "Help output missing examples",
                "Add an EXAMPLES: section with common use cases",
            ));
        }

        UxAudit {
            command: format!("{command} --help"),
            has_structured_output: false,
            structured_output: StructuredOutputInfo::default(),
            has_remediation_guidance: true, // Help is inherently guidance
            error_message: ErrorMessageInfo::default(),
            help_output: Some(help_info.clone()),
            exit_code: ExitCodeInfo {
                exit_code: Some(0),
                follows_convention: true,
                is_meaningful: true,
            },
            findings,
            overall_score: help_info.quality_score,
        }
    }

    /// Build an aggregated UX audit section from multiple command audits.
    #[must_use]
    pub fn build_audit_section(audits: Vec<UxAudit>) -> UxAuditSection {
        let mut tools_without_structured_output = Vec::new();
        let mut errors_without_remediation = Vec::new();

        for audit in &audits {
            if !audit.has_structured_output && !audit.command.contains("--help") {
                tools_without_structured_output.push(audit.command.clone());
            }
            if !audit.has_remediation_guidance && audit.exit_code.exit_code.is_some_and(|c| c != 0)
            {
                errors_without_remediation.push(audit.command.clone());
            }
        }

        // Determine verdict
        let error_findings = audits
            .iter()
            .flat_map(|a| &a.findings)
            .filter(|f| f.severity == UxSeverity::Error)
            .count();

        let warning_findings = audits
            .iter()
            .flat_map(|a| &a.findings)
            .filter(|f| f.severity == UxSeverity::Warning)
            .count();

        let verdict = if error_findings > 0 {
            UxAuditVerdict::NeedsImprovement
        } else if warning_findings > 0 {
            UxAuditVerdict::PassedWithWarnings
        } else {
            UxAuditVerdict::Passed
        };

        let summary = format!(
            "Analyzed {} commands: {} errors, {} warnings, {} tools without structured output",
            audits.len(),
            error_findings,
            warning_findings,
            tools_without_structured_output.len()
        );

        UxAuditSection {
            command_audits: audits,
            tools_without_structured_output,
            errors_without_remediation,
            verdict,
            summary,
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Truncate output for inclusion in findings.
fn truncate_output(output: &str, max_len: usize) -> String {
    let trimmed = output.trim();
    if trimmed.len() <= max_len {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..max_len])
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Structured Output Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_valid_json_object() {
        assert!(UxVerifier::is_valid_json(r#"{"key": "value"}"#));
    }

    #[test]
    fn test_is_valid_json_array() {
        assert!(UxVerifier::is_valid_json(r"[1, 2, 3]"));
    }

    #[test]
    fn test_is_valid_json_with_whitespace() {
        assert!(UxVerifier::is_valid_json("  \n{\"key\": \"value\"}\n  "));
    }

    #[test]
    fn test_is_valid_json_invalid() {
        assert!(!UxVerifier::is_valid_json("not json"));
        assert!(!UxVerifier::is_valid_json(""));
        assert!(!UxVerifier::is_valid_json("{invalid}"));
    }

    #[test]
    fn test_is_valid_yaml() {
        let yaml = "key: value\nlist:\n  - item1\n  - item2";
        assert!(UxVerifier::is_valid_yaml(yaml));
    }

    #[test]
    fn test_is_valid_yaml_excludes_json() {
        // JSON is technically valid YAML, but we want to distinguish them
        assert!(!UxVerifier::is_valid_yaml(r#"{"key": "value"}"#));
    }

    #[test]
    fn test_is_valid_yaml_invalid() {
        assert!(!UxVerifier::is_valid_yaml(""));
        // Note: Most plain text is valid YAML (as a scalar), so this might pass
    }

    #[test]
    fn test_analyze_structured_output_json() {
        let info = UxVerifier::analyze_structured_output(r#"{"status": "ok"}"#);
        assert!(info.is_json);
        assert!(!info.is_yaml);
        assert!(info.is_structured);
    }

    #[test]
    fn test_analyze_structured_output_yaml() {
        let info = UxVerifier::analyze_structured_output("status: ok\ncount: 5");
        assert!(!info.is_json);
        assert!(info.is_yaml);
        assert!(info.is_structured);
    }

    #[test]
    fn test_analyze_structured_output_plain_text() {
        let info = UxVerifier::analyze_structured_output("Build completed successfully!");
        // Plain text might be valid YAML, so check is_json is false
        assert!(!info.is_json);
    }

    // -------------------------------------------------------------------------
    // Error Message Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_analyze_error_with_remediation() {
        let stderr = "Error: file not found\nTry running 'cargo build' first to generate the file.";
        let info = UxVerifier::analyze_error_message(stderr);
        assert!(info.has_remediation_guidance);
        assert!(info.guidance_keywords_found.contains(&"try".to_string()));
    }

    #[test]
    fn test_analyze_error_with_actionable_suggestion() {
        let stderr = "Error: invalid argument\nTo fix this, please provide a valid path.";
        let info = UxVerifier::analyze_error_message(stderr);
        assert!(info.has_actionable_suggestion);
        assert!(info.has_remediation_guidance);
    }

    #[test]
    fn test_analyze_error_without_guidance() {
        let stderr = "Error: operation failed";
        let info = UxVerifier::analyze_error_message(stderr);
        assert!(!info.has_remediation_guidance);
        assert!(!info.has_actionable_suggestion);
    }

    #[test]
    fn test_analyze_error_empty() {
        let info = UxVerifier::analyze_error_message("");
        assert!(!info.has_remediation_guidance);
    }

    // -------------------------------------------------------------------------
    // Help Output Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_analyze_help_complete() {
        let help = r"
my-tool 1.0.0
A tool for doing things

USAGE:
    my-tool [OPTIONS] <input>

OPTIONS:
    -h, --help     Print help information
    -v, --verbose  Enable verbose output

EXAMPLES:
    my-tool input.txt
    my-tool --verbose input.txt
";
        let info = UxVerifier::analyze_help_output(help);
        assert!(info.has_usage_section);
        assert!(info.has_options_section);
        assert!(info.has_description);
        assert!(info.has_examples);
        assert_eq!(info.quality_score, 100);
    }

    #[test]
    fn test_analyze_help_minimal() {
        let help = "my-tool: does things";
        let info = UxVerifier::analyze_help_output(help);
        assert!(!info.has_usage_section);
        assert!(!info.has_options_section);
        assert!(!info.has_examples);
        assert!(info.quality_score < 50);
    }

    #[test]
    fn test_analyze_help_with_options_flag() {
        let help = "Usage: tool [args]\n  -h, --help  Show help";
        let info = UxVerifier::analyze_help_output(help);
        assert!(info.has_options_section); // Detected via --help flag
    }

    // -------------------------------------------------------------------------
    // Exit Code Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_analyze_exit_code_success() {
        let info = UxVerifier::analyze_exit_code(Some(0), false);
        assert!(info.follows_convention);
        assert!(info.is_meaningful);
    }

    #[test]
    fn test_analyze_exit_code_error() {
        let info = UxVerifier::analyze_exit_code(Some(1), true);
        assert!(info.follows_convention);
        assert!(info.is_meaningful);
    }

    #[test]
    fn test_analyze_exit_code_mismatch_success_with_error() {
        // Exit 0 but had error - violates convention
        let info = UxVerifier::analyze_exit_code(Some(0), true);
        assert!(!info.follows_convention);
    }

    #[test]
    fn test_analyze_exit_code_mismatch_error_without_error() {
        // Exit 1 but no error - violates convention
        let info = UxVerifier::analyze_exit_code(Some(1), false);
        assert!(!info.follows_convention);
    }

    #[test]
    fn test_analyze_exit_code_none() {
        let info = UxVerifier::analyze_exit_code(None, true);
        assert!(!info.follows_convention);
        assert!(!info.is_meaningful);
    }

    // -------------------------------------------------------------------------
    // Complete Analysis Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_analyze_command_output_good() {
        let audit = UxVerifier::analyze_command_output(
            "my-tool --json",
            Some(0),
            r#"{"status": "success", "count": 42}"#,
            "",
        );

        assert!(audit.has_structured_output);
        assert!(audit.exit_code.follows_convention);
        assert!(audit.findings.is_empty());
        assert!(audit.overall_score >= 80);
    }

    #[test]
    fn test_analyze_command_output_with_good_error() {
        let audit = UxVerifier::analyze_command_output(
            "my-tool",
            Some(1),
            "",
            "Error: file not found\nTry running 'make build' first.",
        );

        assert!(audit.has_remediation_guidance);
        assert!(audit.exit_code.follows_convention);
    }

    #[test]
    fn test_analyze_command_output_with_bad_error() {
        let audit = UxVerifier::analyze_command_output(
            "my-tool",
            Some(1),
            "",
            "Error: something went wrong",
        );

        assert!(!audit.has_remediation_guidance);
        assert!(
            audit
                .findings
                .iter()
                .any(|f| f.category == UxCategory::ErrorMessage)
        );
    }

    #[test]
    fn test_analyze_command_output_unstructured() {
        // Use multi-line plain text that won't be interpreted as YAML structure
        let audit = UxVerifier::analyze_command_output(
            "my-tool",
            Some(0),
            "Build completed successfully!\nProcessing took 5 seconds.",
            "",
        );

        assert!(!audit.has_structured_output);
        assert!(
            audit
                .findings
                .iter()
                .any(|f| f.category == UxCategory::StructuredOutput)
        );
    }

    // -------------------------------------------------------------------------
    // Help Analysis Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_analyze_help() {
        let audit = UxVerifier::analyze_help(
            "my-tool",
            "USAGE: my-tool [options]\n\nOPTIONS:\n  -h  Help",
        );

        assert!(audit.help_output.is_some());
        let help = audit.help_output.unwrap();
        assert!(help.has_usage_section);
        assert!(help.has_options_section);
    }

    // -------------------------------------------------------------------------
    // Audit Section Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_build_audit_section_passed() {
        let audits = vec![UxVerifier::analyze_command_output(
            "tool",
            Some(0),
            r#"{"ok": true}"#,
            "",
        )];

        let section = UxVerifier::build_audit_section(audits);
        assert_eq!(section.verdict, UxAuditVerdict::Passed);
        assert!(section.tools_without_structured_output.is_empty());
    }

    #[test]
    fn test_build_audit_section_with_warnings() {
        // Use multi-line plain text output that won't be interpreted as YAML
        let audits = vec![UxVerifier::analyze_command_output(
            "tool",
            Some(0),
            "plain text output\nmore output here",
            "",
        )];

        let section = UxVerifier::build_audit_section(audits);
        assert_eq!(section.verdict, UxAuditVerdict::PassedWithWarnings);
        assert!(
            section
                .tools_without_structured_output
                .contains(&"tool".to_string())
        );
    }

    #[test]
    fn test_build_audit_section_needs_improvement() {
        let audits = vec![UxVerifier::analyze_command_output(
            "tool",
            Some(0), // Success exit code
            "",
            "error occurred", // But has error output - mismatch
        )];

        let section = UxVerifier::build_audit_section(audits);
        // Should have warnings due to lack of structured output and remediation
        assert!(
            section.verdict == UxAuditVerdict::PassedWithWarnings
                || section.verdict == UxAuditVerdict::NeedsImprovement
        );
    }

    // -------------------------------------------------------------------------
    // Serialization Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_ux_audit_serialization() {
        let audit = UxVerifier::analyze_command_output("tool", Some(0), r#"{"ok": true}"#, "");

        let json = serde_json::to_string_pretty(&audit).unwrap();
        assert!(json.contains("\"has_structured_output\": true"));
        assert!(json.contains("\"command\": \"tool\""));

        // Verify round-trip
        let parsed: UxAudit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.command, audit.command);
    }

    #[test]
    fn test_ux_audit_section_serialization() {
        let section = UxVerifier::build_audit_section(vec![]);
        let json = serde_json::to_string_pretty(&section).unwrap();
        assert!(json.contains("\"verdict\": \"PASSED\""));

        // Verify round-trip
        let parsed: UxAuditSection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.verdict, section.verdict);
    }

    // -------------------------------------------------------------------------
    // Truncate Helper Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_truncate_output_short() {
        let result = truncate_output("short", 100);
        assert_eq!(result, "short");
    }

    #[test]
    fn test_truncate_output_long() {
        let long = "a".repeat(300);
        let result = truncate_output(&long, 100);
        assert!(result.len() < 110);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_output_with_whitespace() {
        let result = truncate_output("  text  ", 100);
        assert_eq!(result, "text");
    }
}
