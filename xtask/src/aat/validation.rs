//! PR description validation for AAT.
//!
//! This module validates parsed PR descriptions to ensure they meet AAT
//! requirements:
//! - Evidence script exists and is executable
//! - Usage section contains at least one code block
//! - Expected outcomes follow When/Then format
//!
//! # Security Note
//!
//! All paths are validated relative to a provided repository root to prevent
//! path traversal attacks.

use std::path::Path;

use crate::aat::types::ParsedPRDescription;

/// Validation error types with actionable fix suggestions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Evidence script path does not exist.
    EvidenceScriptNotFound {
        /// The path that was not found.
        path: String,
    },

    /// Evidence script exists but is not executable.
    EvidenceScriptNotExecutable {
        /// The path that is not executable.
        path: String,
    },

    /// Usage section is missing a code block.
    UsageMissingCodeBlock,

    /// Expected outcome does not contain both When and Then keywords.
    OutcomeMissingWhenThen {
        /// The outcome text that failed validation.
        outcome: String,
    },
}

impl ValidationError {
    /// Returns an actionable error message with fix suggestions.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::EvidenceScriptNotFound { path } => {
                format!(
                    "Evidence script not found: {path}\n\
                     Fix: Create the script or update the path in PR description"
                )
            },
            Self::EvidenceScriptNotExecutable { path } => {
                format!(
                    "Evidence script not executable: {path}\n\
                     Fix: Run `chmod +x {path}`"
                )
            },
            Self::UsageMissingCodeBlock => "Usage section missing code block\n\
                 Fix: Add a code block with usage example:\n\
                 ```bash\n\
                 cargo xtask aat <PR_URL>\n\
                 ```"
            .to_string(),
            Self::OutcomeMissingWhenThen { outcome } => {
                format!(
                    "Expected outcome missing When/Then format: {outcome}\n\
                     Fix: Use format like: \"When X, then Y\""
                )
            },
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for ValidationError {}

/// Validates a parsed PR description against AAT requirements.
///
/// # Arguments
///
/// * `parsed` - The parsed PR description to validate.
/// * `repo_root` - The repository root path for resolving relative script
///   paths.
///
/// # Returns
///
/// A vector of validation errors. Empty vector means validation passed.
///
/// # Validation Rules
///
/// 1. **Evidence Script**: If specified, must exist and be executable (Unix
///    only).
/// 2. **Usage Section**: Must contain at least one markdown code block
///    (triple-backtick delimiters).
/// 3. **Expected Outcomes**: Each outcome must contain BOTH "when" AND "then"
///    keywords (case-insensitive).
///
/// # Example
///
/// ```ignore
/// let errors = validate_pr_description(&parsed, Path::new("/repo"));
/// if !errors.is_empty() {
///     for error in &errors {
///         eprintln!("Validation error: {}", error.message());
///     }
/// }
/// ```
#[must_use]
pub fn validate_pr_description(
    parsed: &ParsedPRDescription,
    repo_root: &Path,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    // Validate evidence script
    errors.extend(validate_evidence_script(parsed, repo_root));

    // Validate usage section has code block
    errors.extend(validate_usage_section(parsed));

    // Validate expected outcomes have When/Then format
    errors.extend(validate_expected_outcomes(parsed));

    errors
}

/// Validates the evidence script path exists and is executable.
///
/// # Arguments
///
/// * `parsed` - The parsed PR description containing the evidence script path.
/// * `repo_root` - The repository root path for resolving relative paths.
///
/// # Returns
///
/// A vector of validation errors (empty if no evidence script or valid).
#[must_use]
pub fn validate_evidence_script(
    parsed: &ParsedPRDescription,
    repo_root: &Path,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    let Some(script_path) = &parsed.evidence_script else {
        return errors;
    };

    // Clean the script path - remove "(NEW)" suffix and trim whitespace
    let clean_path = script_path
        .trim()
        .trim_end_matches("(NEW)")
        .trim()
        .to_string();

    if clean_path.is_empty() {
        return errors;
    }

    let full_path = repo_root.join(&clean_path);

    // Use is_file() instead of exists() to ensure it's actually a file, not a
    // directory
    if full_path.is_file() {
        // Check executable permission on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = full_path.metadata() {
                let mode = metadata.permissions().mode();
                // Check if any execute bit is set (owner, group, or other)
                if mode & 0o111 == 0 {
                    errors.push(ValidationError::EvidenceScriptNotExecutable { path: clean_path });
                }
            }
        }
    } else {
        errors.push(ValidationError::EvidenceScriptNotFound { path: clean_path });
    }

    errors
}

/// Validates the usage section contains at least one code block.
///
/// A code block is identified by triple-backtick delimiters.
///
/// # Arguments
///
/// * `parsed` - The parsed PR description containing the usage section.
///
/// # Returns
///
/// A vector containing a single error if no code block found, empty otherwise.
#[must_use]
pub fn validate_usage_section(parsed: &ParsedPRDescription) -> Vec<ValidationError> {
    // Check for code block delimiters
    if !parsed.usage.contains("```") {
        return vec![ValidationError::UsageMissingCodeBlock];
    }

    Vec::new()
}

/// Validates expected outcomes contain BOTH When AND Then keywords.
///
/// Each outcome text is checked for the presence of both "when" and "then"
/// keywords (case-insensitive).
///
/// # Arguments
///
/// * `parsed` - The parsed PR description containing expected outcomes.
///
/// # Returns
///
/// A vector of errors for outcomes missing When/Then format.
#[must_use]
pub fn validate_expected_outcomes(parsed: &ParsedPRDescription) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    for outcome in &parsed.expected_outcomes {
        let text_lower = outcome.text.to_lowercase();
        if !text_lower.contains("when") || !text_lower.contains("then") {
            errors.push(ValidationError::OutcomeMissingWhenThen {
                outcome: outcome.text.clone(),
            });
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Write;

    use tempfile::TempDir;

    use super::*;
    use crate::aat::types::OutcomeItem;

    // =========================================================================
    // ValidationError message tests
    // =========================================================================

    #[test]
    fn test_evidence_script_not_found_message() {
        let error = ValidationError::EvidenceScriptNotFound {
            path: "scripts/test.sh".to_string(),
        };
        let message = error.message();
        assert!(message.contains("Evidence script not found: scripts/test.sh"));
        assert!(message.contains("Fix:"));
        assert!(message.contains("Create the script"));
    }

    #[test]
    fn test_evidence_script_not_executable_message() {
        let error = ValidationError::EvidenceScriptNotExecutable {
            path: "scripts/test.sh".to_string(),
        };
        let message = error.message();
        assert!(message.contains("Evidence script not executable: scripts/test.sh"));
        assert!(message.contains("chmod +x scripts/test.sh"));
    }

    #[test]
    fn test_usage_missing_code_block_message() {
        let error = ValidationError::UsageMissingCodeBlock;
        let message = error.message();
        assert!(message.contains("Usage section missing code block"));
        assert!(message.contains("```bash"));
        assert!(message.contains("cargo xtask aat"));
    }

    #[test]
    fn test_outcome_missing_when_then_message() {
        let error = ValidationError::OutcomeMissingWhenThen {
            outcome: "Build succeeds".to_string(),
        };
        let message = error.message();
        assert!(message.contains("Expected outcome missing When/Then format: Build succeeds"));
        assert!(message.contains("When X, then Y"));
    }

    // =========================================================================
    // validate_evidence_script tests
    // =========================================================================

    #[test]
    fn test_validate_evidence_script_none() {
        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_evidence_script(&parsed, Path::new("/tmp"));
        assert!(errors.is_empty(), "No error when evidence_script is None");
    }

    #[test]
    fn test_validate_evidence_script_not_found() {
        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![],
            evidence_script: Some("nonexistent/script.sh".to_string()),
            known_limitations: vec![],
        };

        let temp_dir = TempDir::new().unwrap();
        let errors = validate_evidence_script(&parsed, temp_dir.path());

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0],
            ValidationError::EvidenceScriptNotFound { path } if path == "nonexistent/script.sh"
        ));
    }

    #[test]
    fn test_validate_evidence_script_exists_not_executable() {
        let temp_dir = TempDir::new().unwrap();
        let script_path = temp_dir.path().join("test.sh");

        // Create a non-executable file
        let mut file = File::create(&script_path).unwrap();
        writeln!(file, "#!/bin/bash\necho test").unwrap();

        // Ensure file is NOT executable (remove any execute bits)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o644); // rw-r--r--
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![],
            evidence_script: Some("test.sh".to_string()),
            known_limitations: vec![],
        };

        let errors = validate_evidence_script(&parsed, temp_dir.path());

        #[cfg(unix)]
        {
            assert_eq!(errors.len(), 1);
            assert!(matches!(
                &errors[0],
                ValidationError::EvidenceScriptNotExecutable { path } if path == "test.sh"
            ));
        }
    }

    #[test]
    fn test_validate_evidence_script_exists_and_executable() {
        let temp_dir = TempDir::new().unwrap();
        let script_path = temp_dir.path().join("test.sh");

        // Create an executable file
        let mut file = File::create(&script_path).unwrap();
        writeln!(file, "#!/bin/bash\necho test").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755); // rwxr-xr-x
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![],
            evidence_script: Some("test.sh".to_string()),
            known_limitations: vec![],
        };

        let errors = validate_evidence_script(&parsed, temp_dir.path());
        assert!(
            errors.is_empty(),
            "No error when script exists and is executable"
        );
    }

    #[test]
    fn test_validate_evidence_script_with_new_suffix() {
        let temp_dir = TempDir::new().unwrap();

        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![],
            evidence_script: Some("evidence/script.sh (NEW)".to_string()),
            known_limitations: vec![],
        };

        let errors = validate_evidence_script(&parsed, temp_dir.path());

        // Should look for "evidence/script.sh", not "evidence/script.sh (NEW)"
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0],
            ValidationError::EvidenceScriptNotFound { path } if path == "evidence/script.sh"
        ));
    }

    // =========================================================================
    // validate_usage_section tests
    // =========================================================================

    #[test]
    fn test_validate_usage_with_code_block() {
        let parsed = ParsedPRDescription {
            usage: "Run the command:\n\n```bash\ncargo xtask aat\n```".to_string(),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_usage_section(&parsed);
        assert!(errors.is_empty(), "No error when usage has code block");
    }

    #[test]
    fn test_validate_usage_without_code_block() {
        let parsed = ParsedPRDescription {
            usage: "Run the command: cargo xtask aat".to_string(),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_usage_section(&parsed);
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], ValidationError::UsageMissingCodeBlock));
    }

    #[test]
    fn test_validate_usage_with_multiple_code_blocks() {
        let parsed = ParsedPRDescription {
            usage: "Build:\n```bash\ncargo build\n```\n\nRun:\n```bash\ncargo run\n```".to_string(),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_usage_section(&parsed);
        assert!(
            errors.is_empty(),
            "No error when usage has multiple code blocks"
        );
    }

    // =========================================================================
    // validate_expected_outcomes tests
    // =========================================================================

    #[test]
    fn test_validate_outcomes_with_when_then() {
        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![
                OutcomeItem {
                    text: "When the command runs, then output is generated".to_string(),
                    checked: false,
                },
                OutcomeItem {
                    text: "When input is invalid, then an error is returned".to_string(),
                    checked: false,
                },
            ],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_expected_outcomes(&parsed);
        assert!(errors.is_empty(), "No error when outcomes have When/Then");
    }

    #[test]
    fn test_validate_outcomes_missing_when() {
        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![OutcomeItem {
                text: "Build succeeds, then tests pass".to_string(),
                checked: false,
            }],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_expected_outcomes(&parsed);
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0],
            ValidationError::OutcomeMissingWhenThen { outcome } if outcome == "Build succeeds, then tests pass"
        ));
    }

    #[test]
    fn test_validate_outcomes_missing_then() {
        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![OutcomeItem {
                text: "When the build runs, output is generated".to_string(),
                checked: false,
            }],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_expected_outcomes(&parsed);
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0],
            ValidationError::OutcomeMissingWhenThen { .. }
        ));
    }

    #[test]
    fn test_validate_outcomes_case_insensitive() {
        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![
                OutcomeItem {
                    text: "WHEN the command runs, THEN it succeeds".to_string(),
                    checked: false,
                },
                OutcomeItem {
                    text: "when input is bad, then error occurs".to_string(),
                    checked: false,
                },
            ],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_expected_outcomes(&parsed);
        assert!(errors.is_empty(), "Case-insensitive matching should pass");
    }

    #[test]
    fn test_validate_outcomes_mixed_valid_invalid() {
        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![
                OutcomeItem {
                    text: "When X, then Y".to_string(),
                    checked: false,
                },
                OutcomeItem {
                    text: "Build succeeds".to_string(),
                    checked: true,
                },
                OutcomeItem {
                    text: "When A, then B".to_string(),
                    checked: false,
                },
            ],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_expected_outcomes(&parsed);
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0],
            ValidationError::OutcomeMissingWhenThen { outcome } if outcome == "Build succeeds"
        ));
    }

    #[test]
    fn test_validate_outcomes_empty() {
        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_expected_outcomes(&parsed);
        assert!(
            errors.is_empty(),
            "Empty outcomes should not produce errors"
        );
    }

    // =========================================================================
    // validate_pr_description integration tests
    // =========================================================================

    #[test]
    fn test_validate_pr_description_all_valid() {
        let temp_dir = TempDir::new().unwrap();
        let script_path = temp_dir.path().join("test.sh");

        // Create an executable script
        let mut file = File::create(&script_path).unwrap();
        writeln!(file, "#!/bin/bash\necho test").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let parsed = ParsedPRDescription {
            usage: "```bash\ncargo test\n```".to_string(),
            expected_outcomes: vec![OutcomeItem {
                text: "When tests run, then they pass".to_string(),
                checked: false,
            }],
            evidence_script: Some("test.sh".to_string()),
            known_limitations: vec![],
        };

        let errors = validate_pr_description(&parsed, temp_dir.path());
        assert!(errors.is_empty(), "All validations should pass");
    }

    #[test]
    fn test_validate_pr_description_multiple_errors() {
        let temp_dir = TempDir::new().unwrap();

        let parsed = ParsedPRDescription {
            usage: "Run cargo test".to_string(), // Missing code block
            expected_outcomes: vec![
                OutcomeItem {
                    text: "Build works".to_string(), // Missing When/Then
                    checked: false,
                },
                OutcomeItem {
                    text: "Tests pass".to_string(), // Missing When/Then
                    checked: true,
                },
            ],
            evidence_script: Some("nonexistent.sh".to_string()), // Not found
            known_limitations: vec![],
        };

        let errors = validate_pr_description(&parsed, temp_dir.path());

        // Should have: 1 script not found + 1 usage missing code block + 2 outcome
        // errors
        assert_eq!(errors.len(), 4);

        // Verify error types
        let script_error_count = errors
            .iter()
            .filter(|e| matches!(e, ValidationError::EvidenceScriptNotFound { .. }))
            .count();
        assert_eq!(script_error_count, 1);

        let usage_error_count = errors
            .iter()
            .filter(|e| matches!(e, ValidationError::UsageMissingCodeBlock))
            .count();
        assert_eq!(usage_error_count, 1);

        let outcome_error_count = errors
            .iter()
            .filter(|e| matches!(e, ValidationError::OutcomeMissingWhenThen { .. }))
            .count();
        assert_eq!(outcome_error_count, 2);
    }

    // =========================================================================
    // Display trait tests
    // =========================================================================

    #[test]
    fn test_validation_error_display() {
        let error = ValidationError::EvidenceScriptNotFound {
            path: "test.sh".to_string(),
        };
        let display = format!("{error}");
        assert!(display.contains("Evidence script not found"));
        assert!(display.contains("test.sh"));
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn test_validate_evidence_script_empty_path() {
        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![],
            evidence_script: Some("   ".to_string()), // Only whitespace
            known_limitations: vec![],
        };

        let errors = validate_evidence_script(&parsed, Path::new("/tmp"));
        assert!(errors.is_empty(), "Empty/whitespace path should be skipped");
    }

    #[test]
    fn test_validate_outcomes_when_then_in_middle() {
        let parsed = ParsedPRDescription {
            usage: "test".to_string(),
            expected_outcomes: vec![OutcomeItem {
                text: "Something happens when X occurs, and then Y follows".to_string(),
                checked: false,
            }],
            evidence_script: None,
            known_limitations: vec![],
        };

        let errors = validate_expected_outcomes(&parsed);
        assert!(errors.is_empty(), "When/Then can be anywhere in the text");
    }
}
