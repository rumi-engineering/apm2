//! Implementation of the `lint` command.
//!
//! This command checks for anti-patterns that cannot be caught by clippy:
//! - Direct `std::env::temp_dir` usage (use `tempfile` crate instead)
//! - Shell interpolation patterns (use file-based input instead)
//! - Unquoted shell paths in format!() calls
//! - Insecure temp file patterns
//!
//! When `--include-docs` is passed, also scans markdown files for code blocks
//! and checks them for the same anti-patterns.
//!
//! Findings are reported as warnings (not errors) to allow gradual adoption.

use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use pulldown_cmark::{CodeBlockKind, Event, Parser as MdParser, Tag, TagEnd};

/// Arguments for the lint command.
#[derive(Parser, Debug, Clone, Copy)]
pub struct LintArgs {
    /// Automatically fix lint violations (not yet implemented).
    #[arg(long)]
    pub fix: bool,

    /// Include documentation markdown files in lint checks.
    ///
    /// When enabled, scans markdown files in documents/skills/ and
    /// documents/rfcs/ for Rust code blocks and checks them for
    /// anti-patterns.
    #[arg(long)]
    pub include_docs: bool,
}

/// A lint finding with location and remediation information.
#[derive(Debug, Clone)]
pub struct LintFinding {
    /// Path to the file containing the violation.
    pub file_path: String,
    /// Line number (1-indexed).
    pub line_number: usize,
    /// The pattern that was found.
    pub pattern: String,
    /// Description of the issue.
    pub message: String,
    /// Suggested remediation.
    pub suggestion: String,
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

/// A code block extracted from a markdown file.
#[derive(Debug, Clone)]
struct CodeBlock {
    /// The language tag (e.g., "rust", "").
    language: String,
    /// The content of the code block.
    content: String,
    /// The starting line number in the markdown file (1-indexed).
    start_line: usize,
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

    let findings = scan_workspace(args)?;

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

/// Scan the workspace for lint findings.
///
/// This is the main entry point for programmatic lint checking. It scans
/// Rust source files and optionally markdown documentation for anti-patterns.
///
/// # Arguments
///
/// * `args` - The lint command arguments controlling what to scan
///
/// # Returns
///
/// A vector of `LintFinding` structs describing each violation found.
///
/// # Errors
///
/// Returns an error only if file operations fail (e.g., cannot read files).
pub fn scan_workspace(args: LintArgs) -> Result<Vec<LintFinding>> {
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

    // Check markdown files if --include-docs is passed
    if args.include_docs {
        check_markdown_examples(&mut findings)?;
    }

    Ok(findings)
}

/// Check markdown files in documentation directories for anti-patterns.
///
/// Scans markdown files in `documents/skills/` and `documents/rfcs/`
/// directories, extracts Rust code blocks, and checks them for the same
/// anti-patterns as regular Rust source files.
fn check_markdown_examples(findings: &mut Vec<LintFinding>) -> Result<()> {
    let md_patterns = ["documents/skills/**/*.md", "documents/rfcs/**/*.md"];

    for pattern in md_patterns {
        let glob_pattern = glob::glob(pattern).context("Invalid glob pattern for markdown")?;

        for entry in glob_pattern {
            let path = entry.context("Failed to read markdown glob entry")?;
            check_markdown_file(&path, findings)?;
        }
    }

    Ok(())
}

/// Check a single markdown file for anti-patterns in its Rust code blocks.
fn check_markdown_file(path: &Path, findings: &mut Vec<LintFinding>) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read markdown file: {}", path.display()))?;

    let file_path = path.display().to_string();
    let code_blocks = extract_code_blocks(&content);

    for block in code_blocks {
        // Only check Rust code blocks (or untagged blocks that might be Rust)
        if block.language != "rust" && !block.language.is_empty() {
            continue;
        }

        // Check each line of the code block
        for (line_offset, line) in block.content.lines().enumerate() {
            let line_number = block.start_line + line_offset;

            // Skip comments within the code block
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            // Check for temp_dir usage in docs
            check_temp_dir_usage_in_doc(line, &file_path, line_number, findings);

            // Check for unquoted shell paths in docs
            check_unquoted_shell_paths(line, &file_path, line_number, findings);

            // Check for shell interpolation in docs
            check_shell_interpolation_in_doc(line, &file_path, line_number, findings);
        }
    }

    Ok(())
}

/// Extract code blocks from markdown content.
///
/// Uses `pulldown-cmark` to parse the markdown and extract fenced code blocks.
/// Returns a vector of `CodeBlock` structs with language, content, and line
/// number.
fn extract_code_blocks(markdown: &str) -> Vec<CodeBlock> {
    let parser = MdParser::new(markdown);
    let mut blocks = Vec::new();
    let mut current_block: Option<CodeBlock> = None;

    // Track line numbers by counting newlines in the source
    let line_offsets: Vec<usize> = std::iter::once(0)
        .chain(markdown.match_indices('\n').map(|(i, _)| i + 1))
        .collect();

    // Helper to convert byte offset to line number
    let byte_to_line = |byte_offset: usize| -> usize {
        line_offsets
            .iter()
            .position(|&offset| offset > byte_offset)
            .unwrap_or(line_offsets.len())
    };

    for (event, range) in parser.into_offset_iter() {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(lang))) => {
                let start_line = byte_to_line(range.start);
                current_block = Some(CodeBlock {
                    language: lang.to_string(),
                    content: String::new(),
                    // Add 1 because the content starts on the line after the fence
                    start_line: start_line + 1,
                });
            },
            Event::Text(text) => {
                if let Some(ref mut block) = current_block {
                    block.content.push_str(&text);
                }
            },
            Event::End(TagEnd::CodeBlock) => {
                if let Some(block) = current_block.take() {
                    blocks.push(block);
                }
            },
            _ => {},
        }
    }

    blocks
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
            suggestion: "Use tempfile::NamedTempFile or tempfile::TempDir instead. See documents/skills/rust-textbook/26_apm2_safe_patterns_and_anti_patterns.md#anti-2".to_string(),
        });
    }
}

/// Check for `std::env::temp_dir` usage in documentation examples.
///
/// Same as `check_temp_dir_usage` but specifically for documentation code
/// blocks.
fn check_temp_dir_usage_in_doc(
    line: &str,
    file_path: &str,
    line_number: usize,
    findings: &mut Vec<LintFinding>,
) {
    // Pattern: std::env::temp_dir() - this is insecure in documentation examples
    if line.contains("std::env::temp_dir") {
        // Allow if explicitly marked with lint:ignore comment
        if line.contains("// lint:ignore") {
            return;
        }

        // Allow if it's in a comment showing what NOT to do (anti-pattern section)
        if line.contains("UNSAFE") || line.contains("BROKEN") || line.contains("VULNERABLE") {
            return;
        }

        findings.push(LintFinding {
            file_path: file_path.to_string(),
            line_number,
            pattern: line.trim().to_string(),
            message:
                "Documentation example uses std::env::temp_dir which teaches insecure patterns"
                    .to_string(),
            suggestion: "Use tempfile::NamedTempFile in examples. See documents/skills/rust-textbook/26_apm2_safe_patterns_and_anti_patterns.md#anti-2"
                .to_string(),
        });
    }
}

/// Check for unquoted shell paths in format!() calls.
///
/// When constructing shell commands with format!(), paths should be quoted
/// using a safe quoting function to prevent shell injection.
fn check_unquoted_shell_paths(
    line: &str,
    file_path: &str,
    line_number: usize,
    findings: &mut Vec<LintFinding>,
) {
    // Pattern: format!(...path.display()...) without quote_path()
    // This is risky because paths with spaces/special chars can break shell
    // commands
    if line.contains("format!") && line.contains(".display()") {
        // Allow if using quote_path() or similar
        if line.contains("quote_path") || line.contains("shell_escape") {
            return;
        }

        // Allow if explicitly marked with lint:ignore
        if line.contains("// lint:ignore") {
            return;
        }

        // Allow if it's in an anti-pattern section showing what NOT to do
        if line.contains("UNSAFE") || line.contains("BROKEN") || line.contains("VULNERABLE") {
            return;
        }

        // Check if this looks like a shell command context
        // Look for shell-related keywords in the surrounding context
        let shell_indicators = ["sh", "bash", "cmd", "Command", "script", "shell"];
        let has_shell_context = shell_indicators.iter().any(|ind| line.contains(ind));

        if has_shell_context {
            findings.push(LintFinding {
                file_path: file_path.to_string(),
                line_number,
                pattern: line.trim().to_string(),
                message: "Unquoted path in shell command format string may break with special characters".to_string(),
                suggestion: "Use quote_path() or shell_escape() for paths in shell commands. See documents/skills/rust-textbook/26_apm2_safe_patterns_and_anti_patterns.md#anti-1".to_string(),
            });
        }
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
                suggestion: "Write complex strings to a temp file and use stdin redirection. See documents/skills/rust-textbook/26_apm2_safe_patterns_and_anti_patterns.md#anti-1".to_string(),
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
                "Write prompts to a temp file and redirect stdin. See documents/skills/rust-textbook/26_apm2_safe_patterns_and_anti_patterns.md#anti-1"
                    .to_string(),
        });
    }
}

/// Check for shell interpolation anti-patterns in documentation examples.
///
/// Similar to `check_shell_interpolation` but adapted for documentation
/// context.
fn check_shell_interpolation_in_doc(
    line: &str,
    file_path: &str,
    line_number: usize,
    findings: &mut Vec<LintFinding>,
) {
    // Check for Command::new("sh").args(["-c", &format!()]) without escaping
    if line.contains("Command::new")
        && line.contains("sh")
        && line.contains("format!")
        && !line.contains("quote")
    {
        // Allow if it's in an anti-pattern section
        if line.contains("UNSAFE") || line.contains("BROKEN") || line.contains("VULNERABLE") {
            return;
        }

        // Allow if explicitly marked
        if line.contains("// lint:ignore") {
            return;
        }

        findings.push(LintFinding {
            file_path: file_path.to_string(),
            line_number,
            pattern: line.trim().to_string(),
            message: "Documentation example shows shell command with unescaped format!()"
                .to_string(),
            suggestion:
                "Show safe pattern using temp file and stdin redirection. See documents/skills/rust-textbook/26_apm2_safe_patterns_and_anti_patterns.md#anti-1"
                    .to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lint_args_default() {
        let args = LintArgs {
            fix: false,
            include_docs: false,
        };
        assert!(!args.fix);
        assert!(!args.include_docs);
    }

    #[test]
    fn test_lint_args_with_fix() {
        let args = LintArgs {
            fix: true,
            include_docs: false,
        };
        assert!(args.fix);
    }

    #[test]
    fn test_lint_args_with_include_docs() {
        let args = LintArgs {
            fix: false,
            include_docs: true,
        };
        assert!(args.include_docs);
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
    fn test_temp_dir_detection_in_doc() {
        let mut findings = Vec::new();

        // Should detect std::env::temp_dir in doc examples
        check_temp_dir_usage_in_doc(
            "let temp_path = std::env::temp_dir().join(\"file.txt\");",
            "documents/skills/coding/SAFE_RUST.md",
            10,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("insecure patterns"));

        // Should allow if marked as anti-pattern example
        findings.clear();
        check_temp_dir_usage_in_doc(
            "// VULNERABLE: std::env::temp_dir() is predictable",
            "documents/skills/coding/SAFE_RUST.md",
            10,
            &mut findings,
        );
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_unquoted_shell_paths() {
        let mut findings = Vec::new();

        // Should detect unquoted path in shell command
        check_unquoted_shell_paths(
            "cmd!(sh, \"-c\", format!(\"script < '{}'\", temp_path.display()))",
            "test.md",
            5,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Unquoted path"));

        // Should allow if using quote_path()
        findings.clear();
        check_unquoted_shell_paths(
            "cmd!(sh, \"-c\", format!(\"script < '{}'\", quote_path(temp_path.display())))",
            "test.md",
            5,
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
        let args = LintArgs {
            fix: true,
            include_docs: false,
        };
        // The run() function should print a note but not fail
        // (We don't actually call run() in unit tests to avoid file I/O)
        assert!(args.fix);
    }

    #[test]
    fn test_extract_code_blocks_basic() {
        let markdown = "# Example

Here is some code:

```rust
let x = 1;
let y = 2;
```

And more text.
";
        let blocks = extract_code_blocks(markdown);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].language, "rust");
        assert!(blocks[0].content.contains("let x = 1;"));
        assert!(blocks[0].content.contains("let y = 2;"));
    }

    #[test]
    fn test_extract_code_blocks_multiple() {
        let markdown = "# Examples

```rust
fn foo() {}
```

Some text.

```python
def bar():
    pass
```

More text.

```rust
fn baz() {}
```
";
        let blocks = extract_code_blocks(markdown);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].language, "rust");
        assert_eq!(blocks[1].language, "python");
        assert_eq!(blocks[2].language, "rust");
    }

    #[test]
    fn test_extract_code_blocks_no_language() {
        let markdown = "# Example

```
let x = 1;
```
";
        let blocks = extract_code_blocks(markdown);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].language.is_empty());
    }

    #[test]
    fn test_code_block_line_numbers() {
        let markdown = "Line 1
Line 2
Line 3

```rust
code line 1
code line 2
```
";
        let blocks = extract_code_blocks(markdown);
        assert_eq!(blocks.len(), 1);
        // The code block starts on line 5 (after ```rust)
        // So content starts on line 6
        assert!(blocks[0].start_line >= 5);
    }

    #[test]
    fn test_shell_interpolation_in_doc() {
        let mut findings = Vec::new();

        // Should detect Command::new("sh") with format! and no quote
        check_shell_interpolation_in_doc(
            "Command::new(\"sh\").args([\"-c\", &format!(\"cat {}\", path)])",
            "doc.md",
            10,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("unescaped format"));

        // Should allow if using quote
        findings.clear();
        check_shell_interpolation_in_doc(
            "Command::new(\"sh\").args([\"-c\", &format!(\"cat {}\", quote_path(path))])",
            "doc.md",
            10,
            &mut findings,
        );
        assert_eq!(findings.len(), 0);

        // Should allow anti-pattern examples
        findings.clear();
        check_shell_interpolation_in_doc(
            "// BROKEN: Command::new(\"sh\").args([\"-c\", &format!(\"cat {}\", path)])",
            "doc.md",
            10,
            &mut findings,
        );
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_finding_with_doc_path() {
        let finding = LintFinding {
            file_path: "documents/skills/rust-textbook/26_apm2_safe_patterns_and_anti_patterns.md"
                .to_string(),
            line_number: 50,
            pattern: "std::env::temp_dir()".to_string(),
            message: "Documentation example uses insecure pattern".to_string(),
            suggestion: "Use tempfile crate instead".to_string(),
        };

        let display = finding.to_string();
        assert!(display.contains(
            "documents/skills/rust-textbook/26_apm2_safe_patterns_and_anti_patterns.md:50"
        ));
        assert!(display.contains("Documentation example"));
    }
}
