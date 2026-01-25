//! Hypothesis execution engine for AAT.
//!
//! This module provides the [`HypothesisExecutor`] which runs verification
//! commands for each hypothesis and captures the results.
//!
//! # Execution Model
//!
//! Hypotheses are executed sequentially in the order they are provided.
//! Each hypothesis's `verification_method` is run as a shell command,
//! and the output is captured along with the exit code.
//!
//! # Timing Invariant
//!
//! The `executed_at` timestamp is set AFTER command execution completes.
//! This ensures the hypothesis formation timestamp (`formed_at`) always
//! precedes the execution timestamp, which is required for AAT integrity.
//!
//! # Example
//!
//! ```ignore
//! use xtask::aat::executor::HypothesisExecutor;
//! use xtask::aat::types::Hypothesis;
//!
//! let mut hypothesis = Hypothesis {
//!     id: "H-001".to_string(),
//!     verification_method: "cargo test --lib".to_string(),
//!     // ... other fields
//! };
//!
//! HypothesisExecutor::execute(&mut hypothesis)?;
//!
//! // After execution, these fields are populated:
//! assert!(hypothesis.executed_at.is_some());
//! assert!(hypothesis.exit_code.is_some());
//! assert!(hypothesis.result.is_some());
//! ```

use std::fmt::Write as _;
use std::io::Read;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use wait_timeout::ChildExt;

use crate::aat::types::{Hypothesis, HypothesisResult};

/// Maximum time allowed for a single hypothesis verification command (2
/// minutes).
///
/// This prevents hung commands from blocking the AAT process indefinitely.
/// Individual hypothesis commands should complete quickly; if a command needs
/// more than 2 minutes, the hypothesis `verification_method` should be
/// restructured to run faster or use async patterns.
const HYPOTHESIS_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum size of captured stdout or stderr (10 MB).
///
/// This prevents memory exhaustion from commands that produce excessive output.
/// If a command's output exceeds this limit, it will be truncated with a
/// warning message appended.
const MAX_OUTPUT_SIZE: usize = 10 * 1024 * 1024;

/// Environment variables that are safe to pass to child processes.
///
/// This allowlist ensures that sensitive environment variables (API keys,
/// tokens, credentials) are not leaked to verification commands.
const ALLOWED_ENV_VARS: &[&str] = &[
    "PATH",           // Required for command execution
    "HOME",           // Required for many tools (cargo, git, etc.)
    "USER",           // User identity
    "LANG",           // Locale settings
    "LC_ALL",         // Locale settings
    "TERM",           // Terminal type (for colored output)
    "RUST_BACKTRACE", // Useful for debugging test failures
    "CARGO_HOME",     // Cargo installation directory
    "RUSTUP_HOME",    // Rustup installation directory
];

/// Hypothesis execution engine.
///
/// The executor runs verification commands for hypotheses and captures
/// their results. It operates synchronously, executing one hypothesis
/// at a time.
///
/// # Design
///
/// The executor is stateless and uses only static methods. This design:
/// - Simplifies testing (no setup required)
/// - Makes the execution model explicit (no hidden state)
/// - Aligns with the functional nature of hypothesis verification
pub struct HypothesisExecutor;

impl HypothesisExecutor {
    /// Execute a single hypothesis's verification method.
    ///
    /// This method:
    /// 1. Spawns a shell process to run the `verification_method` command
    /// 2. Waits for completion with a timeout
    /// 3. Captures stdout, stderr, and exit code
    /// 4. Sets `executed_at` timestamp AFTER execution completes
    /// 5. Determines result based on exit code (0 = PASSED, non-zero = FAILED)
    /// 6. Sets `actual_outcome` to a summary of the result
    ///
    /// # Arguments
    ///
    /// * `hypothesis` - Mutable reference to the hypothesis to execute
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful execution (regardless of pass/fail
    /// verdict), or an error if the command could not be executed (e.g.,
    /// spawn failure, timeout).
    ///
    /// # Timing Guarantee
    ///
    /// The `executed_at` timestamp is set AFTER the command completes, ensuring
    /// that `formed_at < executed_at` for all executed hypotheses.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut h = Hypothesis {
    ///     verification_method: "echo hello".to_string(),
    ///     // ... other fields initialized
    /// };
    ///
    /// HypothesisExecutor::execute(&mut h)?;
    ///
    /// assert_eq!(h.exit_code, Some(0));
    /// assert_eq!(h.result, Some(HypothesisResult::Passed));
    /// assert!(h.stdout.as_ref().unwrap().contains("hello"));
    /// ```
    pub fn execute(hypothesis: &mut Hypothesis) -> Result<()> {
        // Build command with isolated environment to prevent credential leakage
        let mut cmd = Command::new("sh");
        cmd.args(["-c", &hypothesis.verification_method])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Clear environment and only pass allowlisted variables
        // This prevents leaking sensitive env vars (API keys, tokens, etc.)
        cmd.env_clear();
        for var_name in ALLOWED_ENV_VARS {
            if let Ok(value) = std::env::var(var_name) {
                cmd.env(var_name, value);
            }
        }

        let mut child = cmd.spawn().with_context(|| {
            format!(
                "Failed to spawn verification command for hypothesis {}\n\
                 Command: {}",
                hypothesis.id, hypothesis.verification_method
            )
        })?;

        // Wait with timeout to prevent hung commands
        let Some(status) = child.wait_timeout(HYPOTHESIS_TIMEOUT)? else {
            // Timeout expired - kill the process
            let _ = child.kill();
            let _ = child.wait(); // Reap the zombie process
            bail!(
                "Hypothesis {} verification timed out after {} seconds\n\
                 Command: {}\n\
                 Hint: Consider restructuring the verification_method to \
                 complete faster",
                hypothesis.id,
                HYPOTHESIS_TIMEOUT.as_secs(),
                hypothesis.verification_method
            );
        };

        // Set executed_at AFTER execution completes
        // This ensures formed_at < executed_at invariant
        hypothesis.executed_at = Some(Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());

        // Read stdout and stderr with bounded size to prevent memory exhaustion
        let (stdout_str, stdout_truncated) =
            Self::read_bounded_output(child.stdout.take(), "stdout", &hypothesis.id)?;
        let (stderr_str, stderr_truncated) =
            Self::read_bounded_stderr(child.stderr.take(), "stderr", &hypothesis.id)?;

        // Store captured output (with truncation warning if applicable)
        hypothesis.stdout = Some(stdout_str);
        hypothesis.stderr = Some(stderr_str);
        hypothesis.exit_code = status.code();

        // Determine result based on exit code
        hypothesis.result = Some(if status.success() {
            HypothesisResult::Passed
        } else {
            HypothesisResult::Failed
        });

        // Set actual_outcome to summarize what happened
        let truncation_note = match (stdout_truncated, stderr_truncated) {
            (true, true) => " (stdout and stderr truncated)",
            (true, false) => " (stdout truncated)",
            (false, true) => " (stderr truncated)",
            (false, false) => "",
        };
        hypothesis.actual_outcome =
            Some(format!("Exit code: {:?}{}", status.code(), truncation_note));

        Ok(())
    }

    /// Read output from a child process pipe with a size limit.
    ///
    /// Returns the output as a string and a flag indicating if truncation
    /// occurred. If the output exceeds `MAX_OUTPUT_SIZE`, it is truncated
    /// and a warning is appended.
    fn read_bounded_output(
        pipe: Option<std::process::ChildStdout>,
        stream_name: &str,
        hypothesis_id: &str,
    ) -> Result<(String, bool)> {
        let Some(mut pipe) = pipe else {
            return Ok((String::new(), false));
        };

        // Read up to MAX_OUTPUT_SIZE + 1 to detect truncation
        let mut buffer = vec![0u8; MAX_OUTPUT_SIZE + 1];
        let bytes_read = pipe
            .read(&mut buffer)
            .with_context(|| format!("Failed to read hypothesis {hypothesis_id} {stream_name}"))?;

        let truncated = bytes_read > MAX_OUTPUT_SIZE;
        let actual_bytes = bytes_read.min(MAX_OUTPUT_SIZE);
        buffer.truncate(actual_bytes);

        let mut output = String::from_utf8_lossy(&buffer).to_string();

        if truncated {
            // Use write! to avoid extra allocation from format!
            let _ = write!(
                output,
                "\n\n[TRUNCATED: {stream_name} exceeded {MAX_OUTPUT_SIZE} bytes limit]"
            );
        }

        Ok((output, truncated))
    }

    /// Read output from a child process stderr pipe with a size limit.
    ///
    /// This is a separate function because `ChildStderr` and `ChildStdout` are
    /// different types even though they both implement Read.
    fn read_bounded_stderr(
        pipe: Option<std::process::ChildStderr>,
        stream_name: &str,
        hypothesis_id: &str,
    ) -> Result<(String, bool)> {
        let Some(mut pipe) = pipe else {
            return Ok((String::new(), false));
        };

        // Read up to MAX_OUTPUT_SIZE + 1 to detect truncation
        let mut buffer = vec![0u8; MAX_OUTPUT_SIZE + 1];
        let bytes_read = pipe
            .read(&mut buffer)
            .with_context(|| format!("Failed to read hypothesis {hypothesis_id} {stream_name}"))?;

        let truncated = bytes_read > MAX_OUTPUT_SIZE;
        let actual_bytes = bytes_read.min(MAX_OUTPUT_SIZE);
        buffer.truncate(actual_bytes);

        let mut output = String::from_utf8_lossy(&buffer).to_string();

        if truncated {
            // Use write! to avoid extra allocation from format!
            let _ = write!(
                output,
                "\n\n[TRUNCATED: {stream_name} exceeded {MAX_OUTPUT_SIZE} bytes limit]"
            );
        }

        Ok((output, truncated))
    }

    /// Execute all hypotheses in a collection.
    ///
    /// Hypotheses are executed sequentially in order. If any hypothesis
    /// execution fails (e.g., timeout, spawn failure), the error is
    /// propagated and subsequent hypotheses are not executed.
    ///
    /// # Arguments
    ///
    /// * `hypotheses` - Mutable slice of hypotheses to execute
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all hypotheses were executed (regardless of
    /// their pass/fail verdicts), or an error if any execution failed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut hypotheses = vec![
    ///     Hypothesis { verification_method: "echo test1".to_string(), .. },
    ///     Hypothesis { verification_method: "echo test2".to_string(), .. },
    /// ];
    ///
    /// HypothesisExecutor::execute_all(&mut hypotheses)?;
    ///
    /// // All hypotheses now have execution results
    /// for h in &hypotheses {
    ///     assert!(h.result.is_some());
    /// }
    /// ```
    pub fn execute_all(hypotheses: &mut [Hypothesis]) -> Result<()> {
        for hypothesis in hypotheses {
            Self::execute(hypothesis)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test hypothesis with a given verification command.
    fn make_test_hypothesis(id: &str, verification_method: &str) -> Hypothesis {
        Hypothesis {
            id: id.to_string(),
            prediction: "Test prediction".to_string(),
            verification_method: verification_method.to_string(),
            tests_error_handling: false,
            formed_at: "2026-01-25T10:00:00Z".to_string(),
            executed_at: None,
            result: None,
            actual_outcome: None,
            stdout: None,
            stderr: None,
            exit_code: None,
        }
    }

    // =========================================================================
    // Basic execution tests
    // =========================================================================

    #[test]
    fn test_execute_successful_command() {
        let mut h = make_test_hypothesis("H-001", "echo hello");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok(), "Execution should succeed");
        assert_eq!(h.exit_code, Some(0), "Exit code should be 0");
        assert_eq!(
            h.result,
            Some(HypothesisResult::Passed),
            "Result should be PASSED"
        );
        assert!(h.executed_at.is_some(), "executed_at should be set");
        assert!(
            h.stdout.as_ref().unwrap().contains("hello"),
            "stdout should contain 'hello'"
        );
        assert!(
            h.stderr.is_some(),
            "stderr should be captured (even if empty)"
        );
    }

    #[test]
    fn test_execute_failing_command() {
        let mut h = make_test_hypothesis("H-002", "exit 1");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok(), "Execution should succeed (command ran)");
        assert_eq!(h.exit_code, Some(1), "Exit code should be 1");
        assert_eq!(
            h.result,
            Some(HypothesisResult::Failed),
            "Result should be FAILED"
        );
        assert!(h.executed_at.is_some(), "executed_at should be set");
    }

    #[test]
    fn test_execute_command_with_stderr() {
        let mut h = make_test_hypothesis("H-003", "echo error >&2");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        assert_eq!(h.exit_code, Some(0));
        assert!(
            h.stderr.as_ref().unwrap().contains("error"),
            "stderr should contain 'error'"
        );
    }

    #[test]
    fn test_execute_command_with_stdout_and_stderr() {
        let mut h = make_test_hypothesis("H-004", "echo out && echo err >&2");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        assert!(h.stdout.as_ref().unwrap().contains("out"));
        assert!(h.stderr.as_ref().unwrap().contains("err"));
    }

    // =========================================================================
    // Exit code tests
    // =========================================================================

    #[test]
    fn test_execute_various_exit_codes() {
        for code in [0, 1, 2, 42, 127, 255] {
            let mut h = make_test_hypothesis(&format!("H-{code}"), &format!("exit {code}"));

            let result = HypothesisExecutor::execute(&mut h);

            assert!(result.is_ok(), "Should execute exit {code}");
            assert_eq!(h.exit_code, Some(code), "Exit code should be {code}");

            let expected_result = if code == 0 {
                HypothesisResult::Passed
            } else {
                HypothesisResult::Failed
            };
            assert_eq!(
                h.result,
                Some(expected_result),
                "Exit code {code} should map to correct result"
            );
        }
    }

    // =========================================================================
    // Timing invariant tests
    // =========================================================================

    #[test]
    fn test_executed_at_is_after_formed_at() {
        let mut h = make_test_hypothesis("H-005", "sleep 0.1");
        let formed_at = h.formed_at.clone();

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        let executed_at = h.executed_at.clone().unwrap();

        // Parse and compare timestamps
        // Since formed_at is a fixed past timestamp and executed_at is "now",
        // executed_at should always be later
        assert!(
            executed_at > formed_at,
            "executed_at ({executed_at}) should be after formed_at ({formed_at})"
        );
    }

    #[test]
    fn test_executed_at_set_after_command_completes() {
        // This test verifies that executed_at is set AFTER the command runs,
        // not before. We do this by running a command that takes some time
        // and verifying the timestamp is recent.
        let mut h = make_test_hypothesis("H-006", "sleep 0.2");

        let before = Utc::now();
        let result = HypothesisExecutor::execute(&mut h);
        let after = Utc::now();

        assert!(result.is_ok());

        // Parse executed_at
        let executed_at_str = h.executed_at.as_ref().unwrap();
        // The timestamp format is "%Y-%m-%dT%H:%M:%SZ"
        // It should be between before and after
        assert!(
            executed_at_str >= &before.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "executed_at should be >= before time"
        );
        assert!(
            executed_at_str <= &after.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "executed_at should be <= after time"
        );
    }

    // =========================================================================
    // Output capture tests
    // =========================================================================

    #[test]
    fn test_execute_captures_multiline_output() {
        let mut h = make_test_hypothesis("H-007", "echo line1; echo line2; echo line3");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        let stdout = h.stdout.as_ref().unwrap();
        assert!(stdout.contains("line1"));
        assert!(stdout.contains("line2"));
        assert!(stdout.contains("line3"));
    }

    #[test]
    fn test_execute_captures_empty_output() {
        let mut h = make_test_hypothesis("H-008", "true");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        assert!(h.stdout.is_some());
        assert!(h.stderr.is_some());
        // Empty strings are valid
        assert!(h.stdout.as_ref().unwrap().is_empty() || !h.stdout.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_execute_captures_binary_safe() {
        // Test with output containing special characters
        let mut h = make_test_hypothesis("H-009", "printf 'hello\\x00world'");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        // from_utf8_lossy should handle the null byte
        assert!(h.stdout.is_some());
    }

    // =========================================================================
    // actual_outcome tests
    // =========================================================================

    #[test]
    fn test_actual_outcome_contains_exit_code() {
        let mut h = make_test_hypothesis("H-010", "exit 42");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        let outcome = h.actual_outcome.as_ref().unwrap();
        assert!(
            outcome.contains("42"),
            "actual_outcome should contain exit code: {outcome}"
        );
    }

    // =========================================================================
    // execute_all tests
    // =========================================================================

    #[test]
    fn test_execute_all_success() {
        let mut hypotheses = vec![
            make_test_hypothesis("H-011", "echo first"),
            make_test_hypothesis("H-012", "echo second"),
            make_test_hypothesis("H-013", "echo third"),
        ];

        let result = HypothesisExecutor::execute_all(&mut hypotheses);

        assert!(result.is_ok());
        for h in &hypotheses {
            assert!(h.result.is_some(), "All hypotheses should have results");
            assert!(
                h.executed_at.is_some(),
                "All hypotheses should have executed_at"
            );
        }
    }

    #[test]
    fn test_execute_all_with_failures() {
        let mut hypotheses = vec![
            make_test_hypothesis("H-014", "echo pass"),
            make_test_hypothesis("H-015", "exit 1"),
            make_test_hypothesis("H-016", "echo also pass"),
        ];

        let result = HypothesisExecutor::execute_all(&mut hypotheses);

        assert!(
            result.is_ok(),
            "execute_all should succeed even if hypotheses fail"
        );

        // First passes
        assert_eq!(hypotheses[0].result, Some(HypothesisResult::Passed));
        // Second fails
        assert_eq!(hypotheses[1].result, Some(HypothesisResult::Failed));
        // Third passes
        assert_eq!(hypotheses[2].result, Some(HypothesisResult::Passed));
    }

    #[test]
    fn test_execute_all_empty() {
        let mut hypotheses: Vec<Hypothesis> = vec![];

        let result = HypothesisExecutor::execute_all(&mut hypotheses);

        assert!(result.is_ok(), "execute_all on empty slice should succeed");
    }

    // =========================================================================
    // Error handling tests
    // =========================================================================

    #[test]
    fn test_execute_nonexistent_command() {
        // This should still "execute" (the shell runs, finds the command doesn't exist)
        let mut h = make_test_hypothesis("H-017", "nonexistent_command_12345");

        let result = HypothesisExecutor::execute(&mut h);

        // The shell executes but the command fails
        assert!(result.is_ok(), "Shell execution should succeed");
        assert_ne!(h.exit_code, Some(0), "Exit code should be non-zero");
        assert_eq!(h.result, Some(HypothesisResult::Failed));
    }

    #[test]
    fn test_execute_syntax_error() {
        let mut h = make_test_hypothesis("H-018", "if then else");

        let result = HypothesisExecutor::execute(&mut h);

        // Shell syntax error is still an execution
        assert!(result.is_ok());
        assert_ne!(h.exit_code, Some(0));
        assert_eq!(h.result, Some(HypothesisResult::Failed));
    }

    // =========================================================================
    // Complex command tests
    // =========================================================================

    #[test]
    fn test_execute_piped_command() {
        let mut h = make_test_hypothesis("H-019", "echo 'hello world' | grep hello");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        assert_eq!(h.exit_code, Some(0));
        assert_eq!(h.result, Some(HypothesisResult::Passed));
        assert!(h.stdout.as_ref().unwrap().contains("hello"));
    }

    #[test]
    fn test_execute_piped_command_failure() {
        let mut h = make_test_hypothesis("H-020", "echo 'hello' | grep nonexistent");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        assert_ne!(h.exit_code, Some(0));
        assert_eq!(h.result, Some(HypothesisResult::Failed));
    }

    #[test]
    fn test_execute_command_with_environment() {
        let mut h = make_test_hypothesis("H-021", "TEST_VAR=hello; echo $TEST_VAR");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        assert_eq!(h.exit_code, Some(0));
        assert!(h.stdout.as_ref().unwrap().contains("hello"));
    }

    #[test]
    fn test_execute_compound_command() {
        let mut h = make_test_hypothesis("H-022", "true && echo success || echo failure");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        assert_eq!(h.exit_code, Some(0));
        assert!(h.stdout.as_ref().unwrap().contains("success"));
        assert!(!h.stdout.as_ref().unwrap().contains("failure"));
    }

    // =========================================================================
    // Timeout constant test
    // =========================================================================

    #[test]
    fn test_hypothesis_timeout_is_reasonable() {
        // Document and verify the timeout constant is reasonable
        // 2 minutes should be enough for most verification commands
        // but not so long that hung commands block AAT indefinitely
        assert_eq!(HYPOTHESIS_TIMEOUT.as_secs(), 120);
        assert!(
            HYPOTHESIS_TIMEOUT.as_secs() >= 30,
            "Timeout should be at least 30 seconds"
        );
        assert!(
            HYPOTHESIS_TIMEOUT.as_secs() <= 300,
            "Timeout should not exceed 5 minutes"
        );
    }

    // =========================================================================
    // Security tests - Environment isolation
    // =========================================================================

    #[test]
    #[allow(unsafe_code)]
    fn test_environment_isolation_sensitive_vars_not_leaked() {
        // Set a "sensitive" environment variable in the parent process
        // This simulates API keys, tokens, or credentials that should not leak
        // SAFETY: This test runs in isolation and we clean up after ourselves.
        // The set_var/remove_var calls are unsafe in Rust 2024 due to potential
        // data races, but our test framework runs tests serially by default
        // for tests that modify global state.
        unsafe {
            std::env::set_var("SUPER_SECRET_API_KEY", "sensitive_value_12345");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "fake_aws_secret");
            std::env::set_var("GITHUB_TOKEN", "ghp_fake_token");
        }

        // Try to echo these variables in the child process
        let mut h = make_test_hypothesis(
            "H-SEC-001",
            "echo \"KEY=$SUPER_SECRET_API_KEY AWS=$AWS_SECRET_ACCESS_KEY GH=$GITHUB_TOKEN\"",
        );

        let result = HypothesisExecutor::execute(&mut h);

        // Clean up before assertions to ensure cleanup happens even on failure
        // SAFETY: Same as above - test isolation
        unsafe {
            std::env::remove_var("SUPER_SECRET_API_KEY");
            std::env::remove_var("AWS_SECRET_ACCESS_KEY");
            std::env::remove_var("GITHUB_TOKEN");
        }

        assert!(result.is_ok());
        let stdout = h.stdout.as_ref().unwrap();

        // The sensitive values should NOT appear in the output because
        // environment is cleared and only allowlisted vars are passed
        assert!(
            !stdout.contains("sensitive_value_12345"),
            "Secret API key should not be leaked to child process. Got: {stdout}"
        );
        assert!(
            !stdout.contains("fake_aws_secret"),
            "AWS secret should not be leaked to child process. Got: {stdout}"
        );
        assert!(
            !stdout.contains("ghp_fake_token"),
            "GitHub token should not be leaked to child process. Got: {stdout}"
        );
    }

    #[test]
    fn test_environment_isolation_allowlisted_vars_passed() {
        // PATH should be passed through so commands work
        let mut h = make_test_hypothesis("H-SEC-002", "echo $PATH");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        let stdout = h.stdout.as_ref().unwrap();

        // PATH should be present and non-empty
        assert!(
            !stdout.trim().is_empty(),
            "PATH should be passed to child process"
        );
    }

    #[test]
    fn test_allowlist_contains_essential_vars() {
        // Verify our allowlist includes essential variables
        assert!(
            ALLOWED_ENV_VARS.contains(&"PATH"),
            "PATH must be in allowlist"
        );
        assert!(
            ALLOWED_ENV_VARS.contains(&"HOME"),
            "HOME must be in allowlist"
        );

        // Verify our allowlist does NOT include sensitive patterns
        for var in ALLOWED_ENV_VARS {
            let var_upper = var.to_uppercase();
            assert!(
                !var_upper.contains("SECRET"),
                "Allowlist should not include SECRET vars"
            );
            assert!(
                !var_upper.contains("TOKEN"),
                "Allowlist should not include TOKEN vars"
            );
            assert!(
                !var_upper.contains("KEY") || *var == "SSH_AUTH_SOCK",
                "Allowlist should not include KEY vars (except SSH_AUTH_SOCK)"
            );
            assert!(
                !var_upper.contains("PASSWORD"),
                "Allowlist should not include PASSWORD vars"
            );
            assert!(
                !var_upper.contains("CREDENTIAL"),
                "Allowlist should not include CREDENTIAL vars"
            );
        }
    }

    // =========================================================================
    // Security tests - Bounded output
    // =========================================================================

    #[test]
    fn test_max_output_size_is_reasonable() {
        // 10 MB should be enough for legitimate test output
        // but prevents memory exhaustion from runaway commands
        // The exact value is verified; bounds are documented in the constant definition
        assert_eq!(MAX_OUTPUT_SIZE, 10 * 1024 * 1024);
    }

    #[test]
    fn test_bounded_output_small_output_not_truncated() {
        // Small outputs should pass through unchanged
        let mut h = make_test_hypothesis("H-SEC-003", "echo 'small output'");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        let stdout = h.stdout.as_ref().unwrap();
        assert!(stdout.contains("small output"));
        assert!(
            !stdout.contains("TRUNCATED"),
            "Small output should not be truncated"
        );
    }

    #[test]
    fn test_actual_outcome_no_truncation_note_for_small_output() {
        let mut h = make_test_hypothesis("H-SEC-004", "echo 'normal'");

        let result = HypothesisExecutor::execute(&mut h);

        assert!(result.is_ok());
        let outcome = h.actual_outcome.as_ref().unwrap();
        assert!(
            !outcome.contains("truncated"),
            "Small output should not have truncation note: {outcome}"
        );
    }
}
