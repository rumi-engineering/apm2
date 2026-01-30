//! Shared types for the AAT (Agent Acceptance Testing) system.
//!
//! This module defines all data structures used across the AAT pipeline:
//! - PR description parsing types
//! - Anti-gaming analysis types
//! - Evidence bundle types
//!
//! These types enable parallel development of parser, anti-gaming, and evidence
//! modules (TCK-00051, TCK-00052, TCK-00053).

use serde::{Deserialize, Serialize};

// =============================================================================
// PR Description Parsing Types
// =============================================================================

/// Parsed PR description containing all AAT-required sections.
///
/// Extracted from PR body markdown by the parser module.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedPRDescription {
    /// Content of the `## Usage` section (CLI invocation examples).
    pub usage: String,

    /// List of expected outcomes from `## Expected Outcomes` section.
    pub expected_outcomes: Vec<OutcomeItem>,

    /// Content of the `## Evidence Script` section (script path/status).
    pub evidence_script: Option<String>,

    /// List of known limitations from `## Known Limitations` section.
    pub known_limitations: Vec<KnownLimitation>,
}

/// A single expected outcome item with checkbox state.
///
/// Parsed from markdown checkbox syntax: `- [x] outcome text` or `- [ ] outcome
/// text`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutcomeItem {
    /// The outcome description text.
    pub text: String,

    /// Whether the checkbox is checked (`[x]` vs `[ ]`).
    pub checked: bool,
}

/// A known limitation entry with optional waiver reference.
///
/// Parsed from `## Known Limitations` section, may include `(WAIVER-XXXX)`
/// reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownLimitation {
    /// The limitation description text.
    pub text: String,

    /// Optional waiver ID (e.g., "WAIVER-0001") if documented.
    pub waiver_id: Option<String>,
}

/// Errors that can occur during PR description parsing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParseError {
    /// The required `## Usage` section is missing.
    MissingUsage,

    /// The required `## Expected Outcomes` section is missing.
    MissingExpectedOutcomes,

    /// A section exists but is malformed or cannot be parsed.
    MalformedSection {
        /// Name of the malformed section.
        section: String,
        /// Description of what went wrong.
        reason: String,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingUsage => {
                write!(f, "Missing required '## Usage' section in PR description")
            },
            Self::MissingExpectedOutcomes => {
                write!(
                    f,
                    "Missing required '## Expected Outcomes' section in PR description"
                )
            },
            Self::MalformedSection { section, reason } => {
                write!(f, "Malformed '## {section}' section: {reason}")
            },
        }
    }
}

impl std::error::Error for ParseError {}

// =============================================================================
// Anti-Gaming Analysis Types
// =============================================================================

/// A detected gaming violation in the PR diff.
///
/// Gaming violations indicate potentially adversarial code patterns that
/// attempt to circumvent acceptance testing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GamingViolation {
    /// Detected `if test` or `cfg(test)` conditional that may bypass
    /// verification.
    IfTestConditional {
        /// File path where the pattern was found.
        file: String,
        /// Line number in the file.
        line: u32,
        /// The matched code snippet.
        snippet: String,
    },

    /// Detected hardcoded UUID that may indicate test-specific behavior.
    HardcodedUuid {
        /// File path where the UUID was found.
        file: String,
        /// Line number in the file.
        line: u32,
        /// The matched UUID string.
        snippet: String,
    },

    /// Detected mock/stub/fake pattern in non-test code.
    MockPattern {
        /// File path where the pattern was found.
        file: String,
        /// Line number in the file.
        line: u32,
        /// The matched pattern (e.g., `mock_service`).
        snippet: String,
    },

    /// A TODO/FIXME/HACK comment not documented in Known Limitations.
    UndocumentedTodo {
        /// File path where the TODO was found.
        file: String,
        /// Line number in the file.
        line: u32,
        /// The TODO comment text.
        snippet: String,
    },

    /// Detected hardcoded ISO 8601 timestamp that may indicate test-specific
    /// behavior.
    HardcodedTimestamp {
        /// File path where the timestamp was found.
        file: String,
        /// Line number in the file.
        line: u32,
        /// The matched timestamp string.
        snippet: String,
    },
}

/// A TODO/FIXME/HACK comment extracted from the diff.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TodoItem {
    /// The TODO comment text.
    pub text: String,

    /// File path where the TODO was found.
    pub file: String,

    /// Line number in the file.
    pub line: u32,
}

/// Result of anti-gaming analysis on a PR diff.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AntiGamingResult {
    /// List of detected gaming violations.
    pub violations: Vec<GamingViolation>,

    /// Whether the anti-gaming check passed (no violations).
    pub passed: bool,
}

impl Default for AntiGamingResult {
    fn default() -> Self {
        Self {
            violations: Vec::new(),
            passed: true,
        }
    }
}

// =============================================================================
// Evidence Bundle Types
// =============================================================================

/// A testable hypothesis formed before execution.
///
/// Hypotheses must be formed before verification to prevent gaming.
/// The `formed_at` timestamp must precede `executed_at`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hypothesis {
    /// Unique identifier (e.g., "H-001").
    pub id: String,

    /// The prediction being tested (e.g., "When X, then Y").
    pub prediction: String,

    /// How the hypothesis will be verified.
    pub verification_method: String,

    /// Whether this hypothesis tests error handling or edge cases.
    pub tests_error_handling: bool,

    /// Timestamp when the hypothesis was formed (before execution).
    pub formed_at: String,

    /// Timestamp when verification was executed.
    pub executed_at: Option<String>,

    /// Verification result.
    pub result: Option<HypothesisResult>,

    /// What actually happened during verification.
    pub actual_outcome: Option<String>,

    /// Standard output from verification command.
    pub stdout: Option<String>,

    /// Standard error from verification command.
    pub stderr: Option<String>,

    /// Exit code from verification command.
    pub exit_code: Option<i32>,
}

/// Result of hypothesis verification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HypothesisResult {
    /// The hypothesis was confirmed.
    Passed,
    /// The hypothesis was refuted.
    Failed,
}

/// Status of PR description section parsing.
///
/// This struct uses multiple booleans to match the JSON schema defined in
/// `documents/skills/aat/SKILL.md`. Each boolean indicates whether a required
/// PR description section was found during parsing.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct PrDescriptionParse {
    /// Whether the `## Usage` section was found.
    pub usage_found: bool,

    /// Whether the `## Expected Outcomes` section was found.
    pub expected_outcomes_found: bool,

    /// Whether the `## Evidence Script` section was found.
    pub evidence_script_found: bool,

    /// Whether the `## Known Limitations` section was found.
    pub known_limitations_found: bool,
}

/// Final verdict of the AAT analysis.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// All hypotheses passed and no anti-gaming violations.
    Passed,
    /// At least one hypothesis failed or anti-gaming violation detected.
    Failed,
    /// Unable to determine pass/fail, requires human review.
    NeedsAdjudication,
}

/// Static analysis results from anti-gaming checks.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StaticAnalysis {
    /// Detected `if test` patterns.
    pub if_test_patterns: Vec<String>,

    /// Detected hardcoded values (UUIDs, timestamps).
    pub hardcoded_values: Vec<String>,

    /// Detected mock/stub/fake patterns.
    pub mock_patterns: Vec<String>,
}

/// A single input variation test result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleVariation {
    /// The input command that was executed.
    pub input: String,

    /// The captured stdout output.
    pub output: String,

    /// The exit code of the command (None if terminated by signal).
    pub exit_code: Option<i32>,
}

/// Input variation testing results.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputVariation {
    /// Number of input variations tested.
    pub variations_tested: u32,

    /// Whether invariance was detected (same output for different inputs).
    pub invariance_detected: bool,

    /// Detailed results for each variation tested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variation_results: Vec<SingleVariation>,
}

/// TODO cross-reference check results.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TodoCheck {
    /// All TODOs found in the diff.
    pub todos_found: Vec<String>,

    /// TODOs that are documented in Known Limitations.
    pub documented_in_known_limitations: Vec<String>,

    /// TODOs that are NOT documented (violations).
    pub undocumented_todos: Vec<String>,
}

/// Anti-gaming section of the evidence bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AntiGamingSection {
    /// Static analysis results.
    pub static_analysis: StaticAnalysis,

    /// Input variation testing results.
    pub input_variation: InputVariation,

    /// TODO cross-reference check results.
    pub todo_check: TodoCheck,

    /// Overall anti-gaming result.
    #[serde(rename = "result")]
    pub anti_gaming_result: AntiGamingVerdict,
}

/// Anti-gaming check verdict.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AntiGamingVerdict {
    /// No anti-gaming violations detected.
    #[default]
    Passed,
    /// Anti-gaming violations detected.
    Failed,
}

/// Complete evidence bundle for an AAT run.
///
/// This is the primary artifact produced by AAT verification.
/// Written to `evidence/aat/PR-{number}_{timestamp}.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundle {
    /// Schema version for forward compatibility.
    pub schema_version: String,

    /// PR number being verified.
    pub pr_number: u64,

    /// Git commit SHA of the PR head.
    pub commit_sha: String,

    /// Timestamp when the AAT run completed.
    pub timestamp: String,

    /// PR description parsing results.
    pub pr_description_parse: PrDescriptionParse,

    /// List of hypotheses with verification results.
    pub hypotheses: Vec<Hypothesis>,

    /// Anti-gaming analysis results.
    pub anti_gaming: AntiGamingSection,

    /// UX audit results (agent-friendly CLI verification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ux_audit: Option<crate::aat::ux_verifier::UxAuditSection>,

    /// Final verdict.
    pub verdict: Verdict,

    /// Human-readable explanation of the verdict.
    pub verdict_reason: String,
}

impl EvidenceBundle {
    /// Current schema version.
    pub const SCHEMA_VERSION: &'static str = "1.0.0";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error_display() {
        assert_eq!(
            ParseError::MissingUsage.to_string(),
            "Missing required '## Usage' section in PR description"
        );

        assert_eq!(
            ParseError::MissingExpectedOutcomes.to_string(),
            "Missing required '## Expected Outcomes' section in PR description"
        );

        assert_eq!(
            ParseError::MalformedSection {
                section: "Evidence Script".to_string(),
                reason: "no code block found".to_string()
            }
            .to_string(),
            "Malformed '## Evidence Script' section: no code block found"
        );
    }

    #[test]
    fn test_verdict_serialization() {
        assert_eq!(
            serde_json::to_string(&Verdict::Passed).unwrap(),
            "\"PASSED\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Failed).unwrap(),
            "\"FAILED\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::NeedsAdjudication).unwrap(),
            "\"NEEDS_ADJUDICATION\""
        );
    }

    #[test]
    fn test_hypothesis_result_serialization() {
        assert_eq!(
            serde_json::to_string(&HypothesisResult::Passed).unwrap(),
            "\"PASSED\""
        );
        assert_eq!(
            serde_json::to_string(&HypothesisResult::Failed).unwrap(),
            "\"FAILED\""
        );
    }

    #[test]
    fn test_evidence_bundle_serialization() {
        let bundle = EvidenceBundle {
            schema_version: EvidenceBundle::SCHEMA_VERSION.to_string(),
            pr_number: 123,
            commit_sha: "abc123def456".to_string(),
            timestamp: "2026-01-24T10:15:00Z".to_string(),
            pr_description_parse: PrDescriptionParse {
                usage_found: true,
                expected_outcomes_found: true,
                evidence_script_found: true,
                known_limitations_found: true,
            },
            hypotheses: vec![Hypothesis {
                id: "H-001".to_string(),
                prediction: "When X, then Y".to_string(),
                verification_method: "Run test".to_string(),
                tests_error_handling: false,
                formed_at: "2026-01-24T10:00:00Z".to_string(),
                executed_at: Some("2026-01-24T10:05:00Z".to_string()),
                result: Some(HypothesisResult::Passed),
                actual_outcome: Some("Y occurred".to_string()),
                stdout: Some("output".to_string()),
                stderr: Some(String::new()),
                exit_code: Some(0),
            }],
            anti_gaming: AntiGamingSection::default(),
            ux_audit: None,
            verdict: Verdict::Passed,
            verdict_reason: "All hypotheses passed".to_string(),
        };

        let json = serde_json::to_string_pretty(&bundle).unwrap();
        assert!(json.contains("\"schema_version\": \"1.0.0\""));
        assert!(json.contains("\"pr_number\": 123"));
        assert!(json.contains("\"verdict\": \"PASSED\""));

        // Verify round-trip
        let parsed: EvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, bundle);
    }

    #[test]
    fn test_gaming_violation_variants() {
        let violations = vec![
            GamingViolation::IfTestConditional {
                file: "src/lib.rs".to_string(),
                line: 42,
                snippet: "if cfg!(test)".to_string(),
            },
            GamingViolation::HardcodedUuid {
                file: "src/main.rs".to_string(),
                line: 10,
                snippet: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            },
            GamingViolation::MockPattern {
                file: "src/service.rs".to_string(),
                line: 25,
                snippet: "mock_database".to_string(),
            },
            GamingViolation::UndocumentedTodo {
                file: "src/handler.rs".to_string(),
                line: 100,
                snippet: "TODO: implement caching".to_string(),
            },
            GamingViolation::HardcodedTimestamp {
                file: "src/config.rs".to_string(),
                line: 15,
                snippet: "2026-01-25T10:00:00Z".to_string(),
            },
        ];

        // All variants should serialize correctly
        for violation in &violations {
            let json = serde_json::to_string(violation).unwrap();
            let parsed: GamingViolation = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, violation);
        }
    }

    #[test]
    fn test_anti_gaming_result_default() {
        let result = AntiGamingResult::default();
        assert!(result.passed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_parsed_pr_description() {
        let desc = ParsedPRDescription {
            usage: "cargo xtask aat <PR_URL>".to_string(),
            expected_outcomes: vec![
                OutcomeItem {
                    text: "PR verified".to_string(),
                    checked: true,
                },
                OutcomeItem {
                    text: "Evidence generated".to_string(),
                    checked: false,
                },
            ],
            evidence_script: Some("evidence/aat/run.sh".to_string()),
            known_limitations: vec![KnownLimitation {
                text: "Does not support forks".to_string(),
                waiver_id: Some("WAIVER-0001".to_string()),
            }],
        };

        let json = serde_json::to_string(&desc).unwrap();
        let parsed: ParsedPRDescription = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, desc);
    }
}
