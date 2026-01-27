//! Implementation of the `selftest` command.
//!
//! This command runs CAC capability selftests to verify that advertised
//! capabilities actually work. It produces an AAT receipt that can be used
//! to prove capability compliance.
//!
//! # Exit Codes
//!
//! - 0: All tests passed
//! - 1: One or more tests failed
//!
//! # Output Formats
//!
//! - Human-readable (default): Summary with pass/fail counts
//! - JSON (`--json`): Full execution results
//!
//! # Example
//!
//! ```bash
//! # Run all selftests
//! cargo xtask selftest
//!
//! # Run only patch-related tests
//! cargo xtask selftest --filter patch
//!
//! # JSON output to file
//! cargo xtask selftest --json --output receipt.json
//!
//! # With custom timeout
//! cargo xtask selftest --timeout 300
//! ```

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use crate::aat::cac_harness::{BudgetConstraints, CacSelftestSuite, SuiteExecutionResult};

// ============================================================================
// Arguments
// ============================================================================

/// Arguments for the selftest command.
#[derive(Parser, Debug, Clone)]
pub struct SelftestArgs {
    /// Output in JSON format instead of human-readable.
    #[arg(long)]
    pub json: bool,

    /// Filter tests by name pattern.
    ///
    /// Only tests whose capability ID or test name contains this pattern
    /// will be executed. Matching is case-insensitive.
    #[arg(long, short = 'f')]
    pub filter: Option<String>,

    /// Write output to a file instead of stdout.
    ///
    /// Uses atomic write (tempfile + rename) to ensure data integrity.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Timeout in seconds for each test (default: 120).
    #[arg(long, short = 't', default_value = "120")]
    pub timeout: u64,
}

// ============================================================================
// Implementation
// ============================================================================

/// Runs the selftest command.
///
/// Discovers and executes CAC capability selftests, producing results that
/// can verify capability compliance.
///
/// # Arguments
///
/// * `args` - The selftest command arguments
///
/// # Returns
///
/// Returns `Ok(())` but may call `std::process::exit()` with:
/// - 0: All tests passed
/// - 1: One or more tests failed
///
/// # Errors
///
/// Returns an error if:
/// - Test discovery fails
/// - File output fails (when `--output` is specified)
pub fn run(args: &SelftestArgs) -> Result<()> {
    // Configure budget constraints
    let budget = BudgetConstraints::builder()
        .max_duration(Duration::from_secs(args.timeout))
        .build();

    // Discover tests
    let mut suite = CacSelftestSuite::discover();
    suite.set_budget(budget);

    // Apply filter if specified
    let tests_to_run: Vec<_> = args.filter.as_ref().map_or_else(
        || suite.iter().cloned().collect(),
        |pattern| {
            let pattern_lower = pattern.to_lowercase();
            suite
                .iter()
                .filter(|t| {
                    t.capability_id.to_lowercase().contains(&pattern_lower)
                        || t.test_name.to_lowercase().contains(&pattern_lower)
                })
                .cloned()
                .collect()
        },
    );

    // Check if we have tests to run
    if tests_to_run.is_empty() {
        let message = if args.filter.is_some() {
            "No tests match the specified filter"
        } else {
            "No selftests discovered"
        };

        if args.json {
            let empty_result = SuiteExecutionResult {
                tests_passed: 0,
                tests_failed: 0,
                total_tests: 0,
                results: vec![],
                total_budget_consumed: crate::aat::cac_harness::BudgetConsumed::default(),
                completed_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            };
            let output = serde_json::to_string_pretty(&empty_result)
                .context("Failed to serialize empty result")?;
            output_result(args, &output)?;
        } else {
            println!("{message}");
        }
        return Ok(());
    }

    // Create a new suite with only filtered tests
    let mut filtered_suite = CacSelftestSuite::with_budget(suite.budget().clone());
    for test in tests_to_run {
        filtered_suite.add_test(test);
    }

    // Print header in human-readable mode
    if !args.json {
        println!("Running {} selftest(s)...\n", filtered_suite.len());
    }

    // Execute the tests
    let result = filtered_suite
        .execute()
        .context("Failed to execute selftest suite")?;

    // Format and output results
    let output_content = if args.json {
        serde_json::to_string_pretty(&result).context("Failed to serialize results to JSON")?
    } else {
        format_human_readable(&result)
    };

    output_result(args, &output_content)?;

    // Exit with appropriate code
    if result.all_passed() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// Formats the execution result as human-readable text.
fn format_human_readable(result: &SuiteExecutionResult) -> String {
    use std::fmt::Write;
    let mut output = String::new();

    // Individual test results
    output.push_str("=== Test Results ===\n\n");

    for test_result in &result.results {
        let status = if test_result.passed { "PASS" } else { "FAIL" };
        let status_color = if test_result.passed {
            "\x1b[32m" // Green
        } else {
            "\x1b[31m" // Red
        };
        let reset = "\x1b[0m";

        let _ = writeln!(
            output,
            "[{status_color}{status}{reset}] {}",
            test_result.test_id
        );

        // Show error details for failed tests
        if !test_result.passed {
            if let Some(ref error) = test_result.error {
                let _ = writeln!(output, "      Error: {error}");
            }
            if let Some(ref evidence) = test_result.evidence {
                if !evidence.stderr.is_empty() {
                    // Truncate long stderr
                    let stderr_preview = if evidence.stderr.len() > 200 {
                        format!("{}...", &evidence.stderr[..200])
                    } else {
                        evidence.stderr.clone()
                    };
                    let _ = writeln!(output, "      Stderr: {stderr_preview}");
                }
            }
        }
    }

    // Summary
    output.push_str("\n=== Summary ===\n\n");

    let pass_indicator = if result.all_passed() {
        "\x1b[32mALL PASSED\x1b[0m"
    } else {
        "\x1b[31mFAILED\x1b[0m"
    };

    let _ = writeln!(output, "Status: {pass_indicator}");
    let _ = writeln!(output, "Passed: {}", result.tests_passed);
    let _ = writeln!(output, "Failed: {}", result.tests_failed);
    let _ = writeln!(output, "Total:  {}", result.total_tests);
    let _ = writeln!(output, "Pass Rate: {:.1}%", result.pass_rate());
    let _ = writeln!(
        output,
        "Duration: {:.2}s",
        result.total_budget_consumed.duration.as_secs_f64()
    );

    // List failed tests
    if result.tests_failed > 0 {
        output.push_str("\nFailed tests:\n");
        for test_id in result.failed_tests() {
            let _ = writeln!(output, "  - {test_id}");
        }
    }

    output
}

/// Outputs the result to stdout or file.
fn output_result(args: &SelftestArgs, content: &str) -> Result<()> {
    if let Some(ref output_path) = args.output {
        write_atomic(output_path, content)?;
        println!("Results written to: {}", output_path.display());
    } else {
        println!("{content}");
    }
    Ok(())
}

/// Writes content to a file atomically using tempfile + rename.
///
/// This follows CTR-2607: State Files Use Atomic Write.
fn write_atomic(path: &PathBuf, content: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));

    // Create a tempfile in the same directory for atomic rename
    let mut temp_file =
        tempfile::NamedTempFile::new_in(parent).context("Failed to create temp file")?;

    temp_file
        .write_all(content.as_bytes())
        .context("Failed to write to temp file")?;

    temp_file
        .persist(path)
        .context("Failed to persist temp file")?;

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selftest_args_default() {
        let args = SelftestArgs {
            json: false,
            filter: None,
            output: None,
            timeout: 120,
        };
        assert!(!args.json);
        assert!(args.filter.is_none());
        assert!(args.output.is_none());
        assert_eq!(args.timeout, 120);
    }

    #[test]
    fn test_selftest_args_json() {
        let args = SelftestArgs {
            json: true,
            filter: None,
            output: None,
            timeout: 120,
        };
        assert!(args.json);
    }

    #[test]
    fn test_selftest_args_filter() {
        let args = SelftestArgs {
            json: false,
            filter: Some("patch".to_string()),
            output: None,
            timeout: 120,
        };
        assert_eq!(args.filter, Some("patch".to_string()));
    }

    #[test]
    fn test_selftest_args_output() {
        let args = SelftestArgs {
            json: true,
            filter: None,
            output: Some(PathBuf::from("results.json")),
            timeout: 120,
        };
        assert_eq!(args.output, Some(PathBuf::from("results.json")));
    }

    #[test]
    fn test_selftest_args_timeout() {
        let args = SelftestArgs {
            json: false,
            filter: None,
            output: None,
            timeout: 300,
        };
        assert_eq!(args.timeout, 300);
    }

    #[test]
    fn test_format_human_readable_all_passed() {
        let result = SuiteExecutionResult {
            tests_passed: 3,
            tests_failed: 0,
            total_tests: 3,
            results: vec![
                crate::aat::cac_harness::TestExecutionResult {
                    test_id: "test1".to_string(),
                    passed: true,
                    evidence: None,
                    error: None,
                    budget_consumed: crate::aat::cac_harness::BudgetConsumed::default(),
                },
                crate::aat::cac_harness::TestExecutionResult {
                    test_id: "test2".to_string(),
                    passed: true,
                    evidence: None,
                    error: None,
                    budget_consumed: crate::aat::cac_harness::BudgetConsumed::default(),
                },
                crate::aat::cac_harness::TestExecutionResult {
                    test_id: "test3".to_string(),
                    passed: true,
                    evidence: None,
                    error: None,
                    budget_consumed: crate::aat::cac_harness::BudgetConsumed::default(),
                },
            ],
            total_budget_consumed: crate::aat::cac_harness::BudgetConsumed::default(),
            completed_at: "2026-01-27T12:00:00Z".to_string(),
        };

        let output = format_human_readable(&result);

        assert!(output.contains("PASS"));
        assert!(output.contains("Passed: 3"));
        assert!(output.contains("Failed: 0"));
        assert!(output.contains("ALL PASSED"));
    }

    #[test]
    fn test_format_human_readable_some_failed() {
        let result = SuiteExecutionResult {
            tests_passed: 2,
            tests_failed: 1,
            total_tests: 3,
            results: vec![
                crate::aat::cac_harness::TestExecutionResult {
                    test_id: "test1".to_string(),
                    passed: true,
                    evidence: None,
                    error: None,
                    budget_consumed: crate::aat::cac_harness::BudgetConsumed::default(),
                },
                crate::aat::cac_harness::TestExecutionResult {
                    test_id: "test2".to_string(),
                    passed: false,
                    evidence: None,
                    error: Some(crate::aat::cac_harness::CacHarnessError::ExecutionFailed {
                        test_name: "test2".to_string(),
                        message: "Test failed".to_string(),
                    }),
                    budget_consumed: crate::aat::cac_harness::BudgetConsumed::default(),
                },
                crate::aat::cac_harness::TestExecutionResult {
                    test_id: "test3".to_string(),
                    passed: true,
                    evidence: None,
                    error: None,
                    budget_consumed: crate::aat::cac_harness::BudgetConsumed::default(),
                },
            ],
            total_budget_consumed: crate::aat::cac_harness::BudgetConsumed::default(),
            completed_at: "2026-01-27T12:00:00Z".to_string(),
        };

        let output = format_human_readable(&result);

        assert!(output.contains("FAIL"));
        assert!(output.contains("Passed: 2"));
        assert!(output.contains("Failed: 1"));
        assert!(output.contains("FAILED"));
        assert!(output.contains("test2"));
    }

    #[test]
    fn test_write_atomic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test_output.txt");

        write_atomic(&path, "test content").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "test content");
    }
}
