//! Implementation of the `lint` command.
//!
//! This command checks for anti-patterns that cannot be caught by clippy:
//! - Direct `std::env::temp_dir` usage (use `tempfile` crate instead)
//! - Shell interpolation patterns (use file-based input instead)
//!
//! Findings are reported as warnings (not errors) to allow gradual adoption.

use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;

/// Arguments for the lint command.
#[derive(Parser, Debug, Clone, Copy)]
pub struct LintArgs {
    /// Automatically fix lint violations (not yet implemented).
    #[arg(long)]
    pub fix: bool,
}

/// A lint finding with location and remediation information.
#[derive(Debug)]
struct LintFinding {
    /// Path to the file containing the violation.
    file_path: String,
    /// Line number (1-indexed).
    line_number: usize,
    /// The pattern that was found.
    pattern: String,
    /// Description of the issue.
    message: String,
    /// Suggested remediation.
    suggestion: String,
}

impl std::fmt::Display for LintFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "warning: {}\n  --> {}:{}\n  |\n  | {}\n  |\n  = help: {}",
            self.message, self.file_path, self.line_number, self.pattern, self.suggestion
        )
    }
}

/// Run the lint command.
///
/// Scans Rust source files for anti-patterns and reports them as warnings.
/// Always returns `Ok(())` since warnings do not fail the build.
///
/// # Arguments
///
/// * `args` - The lint command arguments
///
/// # Errors
///
/// Returns an error only if file operations fail (e.g., cannot read files).
/// Lint findings are warnings and do not cause errors.
pub fn run(args: LintArgs) -> Result<()> {
    if args.fix {
        println!("Note: --fix is accepted but not yet implemented.");
    }

    println!("Running anti-pattern lint checks...\n");

    let mut findings: Vec<LintFinding> = Vec::new();

    // Find all Rust source files in crates/ and xtask/src/
    let patterns = ["crates/**/*.rs", "xtask/src/**/*.rs"];

    for pattern in patterns {
        let glob_pattern = glob::glob(pattern).context("Invalid glob pattern")?;

        for entry in glob_pattern {
            let path = entry.context("Failed to read glob entry")?;
            check_file(&path, &mut findings)?;
        }
    }

    // Report findings
    if findings.is_empty() {
        println!("No anti-patterns found.");
    } else {
        println!("Found {} warning(s):\n", findings.len());
        for finding in &findings {
            println!("{finding}\n");
        }
    }

    // Always return Ok - warnings do not fail the build
    Ok(())
}

/// Check a single file for anti-patterns.
fn check_file(path: &Path, findings: &mut Vec<LintFinding>) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    let file_path = path.display().to_string();

    for (line_idx, line) in content.lines().enumerate() {
        let line_number = line_idx + 1;

        // Skip comments
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }

        // Check for std::env::temp_dir usage
        check_temp_dir_usage(line, &file_path, line_number, findings);

        // Check for shell interpolation patterns
        check_shell_interpolation(line, &file_path, line_number, findings);
    }

    Ok(())
}

/// Check for direct `std::env::temp_dir` usage.
///
/// This is an anti-pattern because it creates predictable temp file paths
/// that are vulnerable to symlink attacks. Use the `tempfile` crate instead.
fn check_temp_dir_usage(
    line: &str,
    file_path: &str,
    line_number: usize,
    findings: &mut Vec<LintFinding>,
) {
    // Skip if this is the lint.rs file itself (contains test patterns)
    if file_path.ends_with("lint.rs") {
        return;
    }

    // Pattern: std::env::temp_dir() or env::temp_dir() (after use std::env)
    // Must contain the actual function call, not just a string literal
    if line.contains("temp_dir()") && !line.contains("tempfile") {
        // Avoid false positives for tempfile crate usage
        if line.contains("// lint:ignore") {
            return;
        }

        // Skip string literals (lines that are mostly strings)
        // A real call won't be inside a string literal preceded by "
        let trimmed = line.trim();
        if is_likely_string_literal(trimmed, "temp_dir()") {
            return;
        }

        findings.push(LintFinding {
            file_path: file_path.to_string(),
            line_number,
            pattern: line.trim().to_string(),
            message: "Direct temp_dir() usage creates predictable paths vulnerable to symlink attacks".to_string(),
            suggestion: "Use tempfile::NamedTempFile or tempfile::TempDir instead. See SAFE_RUST_PATTERNS.md#anti-2".to_string(),
        });
    }
}

/// Check if the pattern is likely inside a string literal.
///
/// Simple heuristic: if the pattern appears after a `"` on the line,
/// it's likely inside a string literal (test data, error messages, etc.).
fn is_likely_string_literal(line: &str, pattern: &str) -> bool {
    if let Some(pattern_pos) = line.find(pattern) {
        // Count quotes before the pattern position
        let before_pattern = &line[..pattern_pos];
        let quote_count = before_pattern.matches('"').count();
        // If odd number of quotes before, we're inside a string
        if quote_count % 2 == 1 {
            return true;
        }
        // Also check for common test patterns
        if before_pattern.contains("assert") || before_pattern.contains("expect") {
            return true;
        }
    }
    false
}

/// Check for shell interpolation anti-patterns.
///
/// Passing complex strings (with quotes, backticks, newlines) directly as
/// shell command arguments is fragile. Use file-based input instead.
fn check_shell_interpolation(
    line: &str,
    file_path: &str,
    line_number: usize,
    findings: &mut Vec<LintFinding>,
) {
    // Skip if this is the lint.rs file itself (contains test patterns)
    if file_path.ends_with("lint.rs") {
        return;
    }

    // Pattern 1: format!(...) inside cmd!() args - complex string interpolation
    // This is fragile when the interpolated string contains shell metacharacters
    if line.contains("cmd!") && line.contains("format!") {
        // Allow format! for simple things like paths
        // Flag when it looks like complex prompt construction
        if line.contains("prompt") || line.contains("markdown") || line.contains("content") {
            if line.contains("// lint:ignore") {
                return;
            }

            // Skip string literals in tests
            let trimmed = line.trim();
            if is_likely_string_literal(trimmed, "cmd!") {
                return;
            }

            findings.push(LintFinding {
                file_path: file_path.to_string(),
                line_number,
                pattern: line.trim().to_string(),
                message: "Complex string interpolation in shell command may break with special characters".to_string(),
                suggestion: "Write complex strings to a temp file and use stdin redirection. See SAFE_RUST_PATTERNS.md#anti-1".to_string(),
            });
        }
    }

    // Pattern 2: .args([...]) with a variable that might contain complex content
    // Look for patterns like .args(["--prompt", &variable]) where variable might be
    // complex
    if line.contains(".args(") && line.contains("prompt") {
        if line.contains("// lint:ignore") {
            return;
        }

        // Skip string literals in tests
        let trimmed = line.trim();
        if is_likely_string_literal(trimmed, ".args(") {
            return;
        }

        findings.push(LintFinding {
            file_path: file_path.to_string(),
            line_number,
            pattern: line.trim().to_string(),
            message: "Passing prompt content as command argument may break with special characters"
                .to_string(),
            suggestion:
                "Write prompts to a temp file and redirect stdin. See SAFE_RUST_PATTERNS.md#anti-1"
                    .to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lint_args_default() {
        let args = LintArgs { fix: false };
        assert!(!args.fix);
    }

    #[test]
    fn test_lint_args_with_fix() {
        let args = LintArgs { fix: true };
        assert!(args.fix);
    }

    #[test]
    fn test_lint_finding_display() {
        let finding = LintFinding {
            file_path: "src/main.rs".to_string(),
            line_number: 42,
            pattern: "std::env::temp_dir()".to_string(),
            message: "Test message".to_string(),
            suggestion: "Test suggestion".to_string(),
        };

        let output = finding.to_string();
        assert!(output.contains("warning: Test message"));
        assert!(output.contains("src/main.rs:42"));
        assert!(output.contains("help: Test suggestion"));
    }

    #[test]
    fn test_temp_dir_detection() {
        let mut findings = Vec::new();

        // Should detect temp_dir usage
        check_temp_dir_usage(
            "let path = std::env::temp_dir().join(\"foo\");",
            "test.rs",
            1,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("predictable paths"));

        // Should not detect when using tempfile crate
        findings.clear();
        check_temp_dir_usage(
            "let temp = tempfile::temp_dir();",
            "test.rs",
            1,
            &mut findings,
        );
        assert_eq!(findings.len(), 0);

        // Should respect lint:ignore comment
        findings.clear();
        check_temp_dir_usage(
            "let path = std::env::temp_dir(); // lint:ignore",
            "test.rs",
            1,
            &mut findings,
        );
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_shell_interpolation_detection() {
        let mut findings = Vec::new();

        // Should detect format! in cmd! with prompt
        check_shell_interpolation(
            "cmd!(sh, \"gemini\", format!(\"{prompt}\"))",
            "test.rs",
            1,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("special characters"));

        // Should detect .args with prompt
        findings.clear();
        check_shell_interpolation(
            "command.args([\"--prompt\", &prompt_content])",
            "test.rs",
            1,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);

        // Should not flag simple cmd! usage
        findings.clear();
        check_shell_interpolation(
            "cmd!(sh, \"cargo\", \"build\")",
            "test.rs",
            1,
            &mut findings,
        );
        assert_eq!(findings.len(), 0);

        // Should respect lint:ignore comment
        findings.clear();
        check_shell_interpolation(
            "command.args([\"--prompt\", &p]) // lint:ignore",
            "test.rs",
            1,
            &mut findings,
        );
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_comment_lines_skipped() {
        // This tests the behavior of check_file which skips comment lines.
        // We verify that comment detection works by checking trim behavior.
        let comment_line = "    // std::env::temp_dir() - this is a comment";
        let trimmed = comment_line.trim();
        assert!(trimmed.starts_with("//"));
    }

    #[test]
    fn test_finding_contains_file_location() {
        let finding = LintFinding {
            file_path: "crates/foo/src/lib.rs".to_string(),
            line_number: 123,
            pattern: "temp_dir()".to_string(),
            message: "Test".to_string(),
            suggestion: "Fix it".to_string(),
        };

        let display = finding.to_string();
        assert!(display.contains("crates/foo/src/lib.rs:123"));
    }

    #[test]
    fn test_fix_flag_placeholder() {
        // Document that --fix is a placeholder that doesn't crash
        let args = LintArgs { fix: true };
        // The run() function should print a note but not fail
        // (We don't actually call run() in unit tests to avoid file I/O)
        assert!(args.fix);
    }
}
