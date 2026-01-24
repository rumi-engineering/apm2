//! Evidence bundle builder and serialization for AAT results.
//!
//! This module provides the `EvidenceBundleBuilder` type for constructing
//! evidence bundles from AAT verification results. Evidence bundles are
//! written to `evidence/aat/PR-{number}_{timestamp}.json`.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;

use crate::aat::types::{
    AntiGamingResult, AntiGamingSection, AntiGamingVerdict, EvidenceBundle, GamingViolation,
    Hypothesis, HypothesisResult, InputVariation, ParsedPRDescription, PrDescriptionParse,
    StaticAnalysis, TodoCheck, Verdict,
};

/// Builder for constructing evidence bundles.
///
/// Use the builder pattern to accumulate AAT verification results,
/// then call `build()` to produce the final `EvidenceBundle`.
///
/// # Example
///
/// ```ignore
/// let bundle = EvidenceBundleBuilder::new(123, "abc123def456")
///     .set_pr_description_parse(&parsed_pr)
///     .add_hypothesis(hypothesis1)
///     .add_hypothesis(hypothesis2)
///     .set_anti_gaming_result(&anti_gaming)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct EvidenceBundleBuilder {
    pr_number: u64,
    commit_sha: String,
    pr_description_parse: PrDescriptionParse,
    hypotheses: Vec<Hypothesis>,
    anti_gaming: AntiGamingSection,
}

impl EvidenceBundleBuilder {
    /// Create a new evidence bundle builder.
    ///
    /// # Arguments
    ///
    /// * `pr_number` - The PR number being verified
    /// * `commit_sha` - The git commit SHA of the PR head
    #[must_use]
    pub fn new(pr_number: u64, commit_sha: impl Into<String>) -> Self {
        Self {
            pr_number,
            commit_sha: commit_sha.into(),
            pr_description_parse: PrDescriptionParse::default(),
            hypotheses: Vec::new(),
            anti_gaming: AntiGamingSection::default(),
        }
    }

    /// Set the PR description parsing results from a parsed PR description.
    ///
    /// This method extracts the parse status from the `ParsedPRDescription`
    /// and records which sections were found.
    #[must_use]
    pub fn set_pr_description_parse(mut self, parsed: &ParsedPRDescription) -> Self {
        self.pr_description_parse = PrDescriptionParse {
            usage_found: !parsed.usage.is_empty(),
            expected_outcomes_found: !parsed.expected_outcomes.is_empty(),
            evidence_script_found: parsed.evidence_script.is_some(),
            known_limitations_found: !parsed.known_limitations.is_empty(),
        };
        self
    }

    /// Set the PR description parse status directly.
    ///
    /// Use this when you have already extracted the parse status.
    #[must_use]
    pub const fn set_pr_description_parse_status(mut self, status: PrDescriptionParse) -> Self {
        self.pr_description_parse = status;
        self
    }

    /// Add a hypothesis to the evidence bundle.
    ///
    /// Hypotheses should be added in the order they were formed/executed.
    #[must_use]
    pub fn add_hypothesis(mut self, hypothesis: Hypothesis) -> Self {
        self.hypotheses.push(hypothesis);
        self
    }

    /// Add multiple hypotheses to the evidence bundle.
    #[must_use]
    pub fn add_hypotheses(mut self, hypotheses: impl IntoIterator<Item = Hypothesis>) -> Self {
        self.hypotheses.extend(hypotheses);
        self
    }

    /// Set the anti-gaming analysis result.
    ///
    /// This converts the `AntiGamingResult` into the structured
    /// `AntiGamingSection` format required by the evidence bundle schema.
    #[must_use]
    pub fn set_anti_gaming_result(mut self, result: &AntiGamingResult) -> Self {
        let mut static_analysis = StaticAnalysis::default();
        let mut todo_check = TodoCheck::default();

        for violation in &result.violations {
            match violation {
                GamingViolation::IfTestConditional { snippet, .. } => {
                    static_analysis.if_test_patterns.push(snippet.clone());
                },
                GamingViolation::HardcodedUuid { snippet, .. } => {
                    static_analysis.hardcoded_values.push(snippet.clone());
                },
                GamingViolation::MockPattern { snippet, .. } => {
                    static_analysis.mock_patterns.push(snippet.clone());
                },
                GamingViolation::UndocumentedTodo { snippet, .. } => {
                    todo_check.todos_found.push(snippet.clone());
                    todo_check.undocumented_todos.push(snippet.clone());
                },
            }
        }

        self.anti_gaming = AntiGamingSection {
            static_analysis,
            input_variation: InputVariation::default(),
            todo_check,
            anti_gaming_result: if result.passed {
                AntiGamingVerdict::Passed
            } else {
                AntiGamingVerdict::Failed
            },
        };
        self
    }

    /// Set the anti-gaming section directly.
    ///
    /// Use this when you have already constructed the full anti-gaming section.
    #[must_use]
    pub fn set_anti_gaming_section(mut self, section: AntiGamingSection) -> Self {
        self.anti_gaming = section;
        self
    }

    /// Compute the final verdict based on hypotheses and anti-gaming results.
    ///
    /// # Verdict logic:
    ///
    /// - `PASSED`: All hypotheses passed AND anti-gaming passed
    /// - `FAILED`: Any hypothesis failed OR anti-gaming failed
    /// - `NEEDS_ADJUDICATION`: No hypotheses verified (unable to determine)
    fn compute_verdict(&self) -> (Verdict, String) {
        // Check if we have any hypotheses
        if self.hypotheses.is_empty() {
            return (
                Verdict::NeedsAdjudication,
                "No hypotheses were verified".to_string(),
            );
        }

        // Check for any hypotheses without results
        let unverified: Vec<&str> = self
            .hypotheses
            .iter()
            .filter(|h| h.result.is_none())
            .map(|h| h.id.as_str())
            .collect();

        if !unverified.is_empty() {
            return (
                Verdict::NeedsAdjudication,
                format!(
                    "Some hypotheses were not verified: {}",
                    unverified.join(", ")
                ),
            );
        }

        // Count passed/failed hypotheses
        let mut passed_count = 0;
        let mut failed_count = 0;
        let mut failed_ids = Vec::new();

        for hypothesis in &self.hypotheses {
            match hypothesis.result {
                Some(HypothesisResult::Passed) => passed_count += 1,
                Some(HypothesisResult::Failed) => {
                    failed_count += 1;
                    failed_ids.push(hypothesis.id.as_str());
                },
                None => {},
            }
        }

        // Check anti-gaming result
        let anti_gaming_passed = self.anti_gaming.anti_gaming_result == AntiGamingVerdict::Passed;

        // Compute verdict
        if failed_count > 0 {
            (
                Verdict::Failed,
                format!(
                    "{} hypothesis(es) failed: {}",
                    failed_count,
                    failed_ids.join(", ")
                ),
            )
        } else if !anti_gaming_passed {
            let mut reasons = Vec::new();
            if !self.anti_gaming.static_analysis.if_test_patterns.is_empty() {
                reasons.push("if_test patterns detected");
            }
            if !self.anti_gaming.static_analysis.hardcoded_values.is_empty() {
                reasons.push("hardcoded values detected");
            }
            if !self.anti_gaming.static_analysis.mock_patterns.is_empty() {
                reasons.push("mock patterns detected");
            }
            if !self.anti_gaming.todo_check.undocumented_todos.is_empty() {
                reasons.push("undocumented TODOs");
            }
            (
                Verdict::Failed,
                format!("Anti-gaming check failed: {}", reasons.join(", ")),
            )
        } else {
            (
                Verdict::Passed,
                format!("All {passed_count} hypotheses passed, no anti-gaming violations"),
            )
        }
    }

    /// Build the final evidence bundle.
    ///
    /// This computes the verdict based on the accumulated results
    /// and returns a complete `EvidenceBundle`.
    #[must_use]
    pub fn build(self) -> EvidenceBundle {
        let (verdict, verdict_reason) = self.compute_verdict();
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        EvidenceBundle {
            schema_version: EvidenceBundle::SCHEMA_VERSION.to_string(),
            pr_number: self.pr_number,
            commit_sha: self.commit_sha,
            timestamp,
            pr_description_parse: self.pr_description_parse,
            hypotheses: self.hypotheses,
            anti_gaming: self.anti_gaming,
            verdict,
            verdict_reason,
        }
    }

    /// Build the evidence bundle with a specific timestamp.
    ///
    /// Use this for deterministic testing or when the timestamp
    /// should be set explicitly.
    #[must_use]
    pub fn build_with_timestamp(self, timestamp: impl Into<String>) -> EvidenceBundle {
        let (verdict, verdict_reason) = self.compute_verdict();

        EvidenceBundle {
            schema_version: EvidenceBundle::SCHEMA_VERSION.to_string(),
            pr_number: self.pr_number,
            commit_sha: self.commit_sha,
            timestamp: timestamp.into(),
            pr_description_parse: self.pr_description_parse,
            hypotheses: self.hypotheses,
            anti_gaming: self.anti_gaming,
            verdict,
            verdict_reason,
        }
    }
}

impl EvidenceBundle {
    /// Serialize the evidence bundle to JSON.
    ///
    /// Returns a pretty-printed JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (should not happen for valid
    /// bundles).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("Failed to serialize evidence bundle to JSON")
    }

    /// Write the evidence bundle to a file.
    ///
    /// Creates the directory structure `{base_path}/evidence/aat/` if it
    /// doesn't exist, then writes the bundle as
    /// `PR-{number}_{timestamp}.json`.
    ///
    /// # Arguments
    ///
    /// * `base_path` - The base directory (typically the repository root)
    ///
    /// # Returns
    ///
    /// The path to the written file.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file writing fails.
    pub fn write_to_file(&self, base_path: &Path) -> Result<std::path::PathBuf> {
        let aat_dir = base_path.join("evidence").join("aat");

        // Create directory if it doesn't exist
        fs::create_dir_all(&aat_dir)
            .with_context(|| format!("Failed to create directory: {}", aat_dir.display()))?;

        // Generate filename: PR-{number}_{timestamp}.json
        // Sanitize timestamp for filename (replace colons with dashes)
        let safe_timestamp = self.timestamp.replace(':', "-");
        let filename = format!("PR-{}_{}.json", self.pr_number, safe_timestamp);
        let file_path = aat_dir.join(&filename);

        // Serialize and write
        let json = self.to_json()?;
        fs::write(&file_path, json).with_context(|| {
            format!(
                "Failed to write evidence bundle to: {}",
                file_path.display()
            )
        })?;

        Ok(file_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aat::types::{KnownLimitation, OutcomeItem};

    fn make_passed_hypothesis(id: &str) -> Hypothesis {
        Hypothesis {
            id: id.to_string(),
            prediction: format!("Hypothesis {id} prediction"),
            verification_method: "Run test".to_string(),
            tests_error_handling: false,
            formed_at: "2026-01-24T10:00:00Z".to_string(),
            executed_at: Some("2026-01-24T10:05:00Z".to_string()),
            result: Some(HypothesisResult::Passed),
            actual_outcome: Some("As expected".to_string()),
            stdout: Some("output".to_string()),
            stderr: Some(String::new()),
            exit_code: Some(0),
        }
    }

    fn make_failed_hypothesis(id: &str) -> Hypothesis {
        Hypothesis {
            id: id.to_string(),
            prediction: format!("Hypothesis {id} prediction"),
            verification_method: "Run test".to_string(),
            tests_error_handling: false,
            formed_at: "2026-01-24T10:00:00Z".to_string(),
            executed_at: Some("2026-01-24T10:05:00Z".to_string()),
            result: Some(HypothesisResult::Failed),
            actual_outcome: Some("Unexpected result".to_string()),
            stdout: Some("output".to_string()),
            stderr: Some("error".to_string()),
            exit_code: Some(1),
        }
    }

    #[test]
    fn test_builder_new() {
        let builder = EvidenceBundleBuilder::new(123, "abc123");
        assert_eq!(builder.pr_number, 123);
        assert_eq!(builder.commit_sha, "abc123");
        assert!(builder.hypotheses.is_empty());
    }

    #[test]
    fn test_set_pr_description_parse() {
        let parsed = ParsedPRDescription {
            usage: "cargo xtask aat <PR>".to_string(),
            expected_outcomes: vec![OutcomeItem {
                text: "PR verified".to_string(),
                checked: true,
            }],
            evidence_script: Some("evidence/aat/run.sh".to_string()),
            known_limitations: vec![KnownLimitation {
                text: "Does not support forks".to_string(),
                waiver_id: None,
            }],
        };

        let builder = EvidenceBundleBuilder::new(123, "abc123").set_pr_description_parse(&parsed);

        assert!(builder.pr_description_parse.usage_found);
        assert!(builder.pr_description_parse.expected_outcomes_found);
        assert!(builder.pr_description_parse.evidence_script_found);
        assert!(builder.pr_description_parse.known_limitations_found);
    }

    #[test]
    fn test_set_pr_description_parse_empty_sections() {
        let parsed = ParsedPRDescription {
            usage: String::new(),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let builder = EvidenceBundleBuilder::new(123, "abc123").set_pr_description_parse(&parsed);

        assert!(!builder.pr_description_parse.usage_found);
        assert!(!builder.pr_description_parse.expected_outcomes_found);
        assert!(!builder.pr_description_parse.evidence_script_found);
        assert!(!builder.pr_description_parse.known_limitations_found);
    }

    #[test]
    fn test_add_hypothesis() {
        let h1 = make_passed_hypothesis("H-001");
        let h2 = make_passed_hypothesis("H-002");

        let builder = EvidenceBundleBuilder::new(123, "abc123")
            .add_hypothesis(h1)
            .add_hypothesis(h2);

        assert_eq!(builder.hypotheses.len(), 2);
        assert_eq!(builder.hypotheses[0].id, "H-001");
        assert_eq!(builder.hypotheses[1].id, "H-002");
    }

    #[test]
    fn test_add_hypotheses() {
        let hypotheses = vec![
            make_passed_hypothesis("H-001"),
            make_passed_hypothesis("H-002"),
            make_passed_hypothesis("H-003"),
        ];

        let builder = EvidenceBundleBuilder::new(123, "abc123").add_hypotheses(hypotheses);

        assert_eq!(builder.hypotheses.len(), 3);
    }

    #[test]
    fn test_set_anti_gaming_result_passed() {
        let result = AntiGamingResult {
            violations: vec![],
            passed: true,
        };

        let builder = EvidenceBundleBuilder::new(123, "abc123").set_anti_gaming_result(&result);

        assert_eq!(
            builder.anti_gaming.anti_gaming_result,
            AntiGamingVerdict::Passed
        );
        assert!(
            builder
                .anti_gaming
                .static_analysis
                .if_test_patterns
                .is_empty()
        );
    }

    #[test]
    fn test_set_anti_gaming_result_with_violations() {
        let result = AntiGamingResult {
            violations: vec![
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
            ],
            passed: false,
        };

        let builder = EvidenceBundleBuilder::new(123, "abc123").set_anti_gaming_result(&result);

        assert_eq!(
            builder.anti_gaming.anti_gaming_result,
            AntiGamingVerdict::Failed
        );
        assert_eq!(
            builder.anti_gaming.static_analysis.if_test_patterns.len(),
            1
        );
        assert_eq!(
            builder.anti_gaming.static_analysis.hardcoded_values.len(),
            1
        );
        assert_eq!(builder.anti_gaming.static_analysis.mock_patterns.len(), 1);
        assert_eq!(builder.anti_gaming.todo_check.undocumented_todos.len(), 1);
    }

    #[test]
    fn test_verdict_all_passed() {
        let bundle = EvidenceBundleBuilder::new(123, "abc123")
            .add_hypothesis(make_passed_hypothesis("H-001"))
            .add_hypothesis(make_passed_hypothesis("H-002"))
            .add_hypothesis(make_passed_hypothesis("H-003"))
            .build_with_timestamp("2026-01-24T10:15:00Z");

        assert_eq!(bundle.verdict, Verdict::Passed);
        assert!(bundle.verdict_reason.contains("All 3 hypotheses passed"));
    }

    #[test]
    fn test_verdict_hypothesis_failed() {
        let bundle = EvidenceBundleBuilder::new(123, "abc123")
            .add_hypothesis(make_passed_hypothesis("H-001"))
            .add_hypothesis(make_failed_hypothesis("H-002"))
            .add_hypothesis(make_passed_hypothesis("H-003"))
            .build_with_timestamp("2026-01-24T10:15:00Z");

        assert_eq!(bundle.verdict, Verdict::Failed);
        assert!(bundle.verdict_reason.contains("H-002"));
    }

    #[test]
    fn test_verdict_anti_gaming_failed() {
        let result = AntiGamingResult {
            violations: vec![GamingViolation::UndocumentedTodo {
                file: "src/lib.rs".to_string(),
                line: 10,
                snippet: "TODO: fix this".to_string(),
            }],
            passed: false,
        };

        let bundle = EvidenceBundleBuilder::new(123, "abc123")
            .add_hypothesis(make_passed_hypothesis("H-001"))
            .set_anti_gaming_result(&result)
            .build_with_timestamp("2026-01-24T10:15:00Z");

        assert_eq!(bundle.verdict, Verdict::Failed);
        assert!(bundle.verdict_reason.contains("Anti-gaming check failed"));
    }

    #[test]
    fn test_verdict_no_hypotheses() {
        let bundle =
            EvidenceBundleBuilder::new(123, "abc123").build_with_timestamp("2026-01-24T10:15:00Z");

        assert_eq!(bundle.verdict, Verdict::NeedsAdjudication);
        assert!(bundle.verdict_reason.contains("No hypotheses"));
    }

    #[test]
    fn test_verdict_unverified_hypothesis() {
        let unverified = Hypothesis {
            id: "H-001".to_string(),
            prediction: "Some prediction".to_string(),
            verification_method: "Run test".to_string(),
            tests_error_handling: false,
            formed_at: "2026-01-24T10:00:00Z".to_string(),
            executed_at: None,
            result: None,
            actual_outcome: None,
            stdout: None,
            stderr: None,
            exit_code: None,
        };

        let bundle = EvidenceBundleBuilder::new(123, "abc123")
            .add_hypothesis(unverified)
            .build_with_timestamp("2026-01-24T10:15:00Z");

        assert_eq!(bundle.verdict, Verdict::NeedsAdjudication);
        assert!(bundle.verdict_reason.contains("not verified"));
    }

    #[test]
    fn test_to_json() {
        let bundle = EvidenceBundleBuilder::new(123, "abc123def456")
            .add_hypothesis(make_passed_hypothesis("H-001"))
            .build_with_timestamp("2026-01-24T10:15:00Z");

        let json = bundle.to_json().unwrap();

        // Verify required fields are present
        assert!(json.contains("\"schema_version\": \"1.0.0\""));
        assert!(json.contains("\"pr_number\": 123"));
        assert!(json.contains("\"commit_sha\": \"abc123def456\""));
        assert!(json.contains("\"timestamp\": \"2026-01-24T10:15:00Z\""));
        assert!(json.contains("\"verdict\": \"PASSED\""));

        // Verify structure matches skill schema
        assert!(json.contains("\"pr_description_parse\""));
        assert!(json.contains("\"hypotheses\""));
        assert!(json.contains("\"anti_gaming\""));
        assert!(json.contains("\"static_analysis\""));
        assert!(json.contains("\"input_variation\""));
        assert!(json.contains("\"todo_check\""));
    }

    #[test]
    fn test_json_roundtrip() {
        let bundle = EvidenceBundleBuilder::new(123, "abc123def456")
            .add_hypothesis(make_passed_hypothesis("H-001"))
            .add_hypothesis(make_passed_hypothesis("H-002"))
            .build_with_timestamp("2026-01-24T10:15:00Z");

        let json = bundle.to_json().unwrap();
        let parsed: EvidenceBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.pr_number, bundle.pr_number);
        assert_eq!(parsed.commit_sha, bundle.commit_sha);
        assert_eq!(parsed.verdict, bundle.verdict);
        assert_eq!(parsed.hypotheses.len(), bundle.hypotheses.len());
    }

    #[test]
    fn test_json_matches_skill_schema() {
        // Build a complete bundle matching the skill schema example
        let bundle = EvidenceBundleBuilder::new(123, "abc123")
            .set_pr_description_parse_status(PrDescriptionParse {
                usage_found: true,
                expected_outcomes_found: true,
                evidence_script_found: true,
                known_limitations_found: true,
            })
            .add_hypothesis(Hypothesis {
                id: "H-001".to_string(),
                prediction: "When invoking command, output contains expected".to_string(),
                verification_method: "Run command and grep output".to_string(),
                tests_error_handling: false,
                formed_at: "2026-01-24T10:00:00Z".to_string(),
                executed_at: Some("2026-01-24T10:05:00Z".to_string()),
                result: Some(HypothesisResult::Passed),
                actual_outcome: Some("Output contained expected".to_string()),
                stdout: Some("expected output".to_string()),
                stderr: Some(String::new()),
                exit_code: Some(0),
            })
            .set_anti_gaming_section(AntiGamingSection {
                static_analysis: StaticAnalysis::default(),
                input_variation: InputVariation {
                    variations_tested: 3,
                    invariance_detected: false,
                },
                todo_check: TodoCheck {
                    todos_found: vec!["TODO: implement caching".to_string()],
                    documented_in_known_limitations: vec!["TODO: implement caching".to_string()],
                    undocumented_todos: vec![],
                },
                anti_gaming_result: AntiGamingVerdict::Passed,
            })
            .build_with_timestamp("2026-01-24T10:15:00Z");

        let json = bundle.to_json().unwrap();

        // Parse back and verify structure
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Check schema version
        assert_eq!(value["schema_version"], "1.0.0");

        // Check pr_description_parse structure
        assert!(
            value["pr_description_parse"]["usage_found"]
                .as_bool()
                .unwrap()
        );
        assert!(
            value["pr_description_parse"]["expected_outcomes_found"]
                .as_bool()
                .unwrap()
        );

        // Check hypotheses array
        let hypotheses = value["hypotheses"].as_array().unwrap();
        assert_eq!(hypotheses.len(), 1);
        assert_eq!(hypotheses[0]["id"], "H-001");
        assert_eq!(hypotheses[0]["result"], "PASSED");

        // Check anti_gaming structure
        assert!(value["anti_gaming"]["static_analysis"].is_object());
        assert_eq!(
            value["anti_gaming"]["input_variation"]["variations_tested"],
            3
        );
        assert!(
            !value["anti_gaming"]["input_variation"]["invariance_detected"]
                .as_bool()
                .unwrap()
        );

        // Check verdict
        assert_eq!(value["verdict"], "PASSED");
    }

    #[test]
    fn test_write_to_file() {
        use std::fs;

        let temp_dir = std::env::temp_dir().join("aat_test_write");
        let _ = fs::remove_dir_all(&temp_dir); // Clean up any previous run

        let bundle = EvidenceBundleBuilder::new(123, "abc123")
            .add_hypothesis(make_passed_hypothesis("H-001"))
            .build_with_timestamp("2026-01-24T10:15:00Z");

        let file_path = bundle.write_to_file(&temp_dir).unwrap();

        // Verify file was created
        assert!(file_path.exists());

        // Verify path structure
        assert!(file_path.starts_with(temp_dir.join("evidence").join("aat")));
        assert!(
            file_path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("PR-123_")
        );

        // Verify content is valid JSON
        let content = fs::read_to_string(&file_path).unwrap();
        let parsed: EvidenceBundle = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.pr_number, 123);

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
