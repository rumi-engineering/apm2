//! Implementation of the `lint` command.
//!
//! This command checks for anti-patterns that cannot be caught by clippy:
//! - Direct `std::env::temp_dir` usage (use `tempfile` crate instead)
//! - Shell interpolation patterns (use file-based input instead)
//! - Unquoted shell paths in format!() calls
//! - Insecure temp file patterns
//! - LINT-0013: New modules without RFC justification
//! - LINT-0014: Cousin abstractions (similar struct/trait definitions)
//! - LINT-0015: New pub items without deletion/migration plans
//! - LINT-0016: HTF human-time units in normative documents
//!
//! When `--include-docs` is passed, also scans markdown files for code blocks
//! and checks them for the same anti-patterns.
//!
//! Findings are reported as warnings (not errors) to allow gradual adoption.

use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use clap::Parser;
use pulldown_cmark::{CodeBlockKind, Event, Parser as MdParser, Tag, TagEnd};
use regex::Regex;
use serde::Deserialize;

// =============================================================================
// YAML Schema Definitions for RFC files
// =============================================================================

/// Root structure for `06_ticket_decomposition.yaml` files.
#[derive(Debug, Deserialize)]
struct TicketDecompositionFile {
    rfc_ticket_decomposition: Option<TicketDecomposition>,
}

/// Ticket decomposition schema.
#[derive(Debug, Deserialize)]
struct TicketDecomposition {
    #[serde(default)]
    tickets: Vec<Ticket>,
    #[serde(default)]
    ticket_plan: Option<TicketPlan>,
}

/// Ticket plan containing tickets.
#[derive(Debug, Deserialize)]
struct TicketPlan {
    #[serde(default)]
    tickets: Vec<Ticket>,
}

/// Individual ticket definition.
#[derive(Debug, Deserialize)]
struct Ticket {
    #[serde(default)]
    files_to_create: Vec<String>,
    // Note: files_to_modify is parsed but not currently used by lint rules.
    // Kept for schema completeness and potential future use.
    #[serde(default)]
    #[allow(dead_code)]
    files_to_modify: Vec<String>,
}

/// Root structure for `05_rollout_and_ops.yaml` files.
#[derive(Debug, Deserialize)]
struct RolloutAndOpsFile {
    rfc_rollout_and_ops: Option<RolloutAndOps>,
}

/// Rollout and ops schema.
#[derive(Debug, Deserialize)]
struct RolloutAndOps {
    #[serde(default)]
    deletion_plan: Vec<DeletionPlanItem>,
}

/// Individual deletion plan item.
#[derive(Debug, Deserialize)]
struct DeletionPlanItem {
    item: String,
    plan: String,
}

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

    /// Run HTF (Holonic Time Fabric) human-time lint on normative documents.
    ///
    /// When enabled, scans normative documents (PRDs, RFCs, skills, laws) for
    /// human-time units (minutes, hours, days, etc.) that violate HTF policy.
    /// Human-time units are only allowed with explicit `EXTERNAL_TIME:` prefix.
    #[arg(long)]
    pub include_htf: bool,
}

/// Severity level for lint findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    /// Warning - does not fail the build.
    Warning,
    /// Error - fails the build.
    Error,
}

impl std::fmt::Display for LintSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
        }
    }
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
    /// Severity level (warning or error).
    pub severity: LintSeverity,
    /// Lint rule ID (e.g., "LINT-0013").
    pub lint_id: Option<String>,
}

impl std::fmt::Display for LintFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lint_id_suffix = self
            .lint_id
            .as_ref()
            .map_or(String::new(), |id| format!(" [{id}]"));
        write!(
            f,
            "{}{}: {}\n  --> {}:{}\n  |\n  | {}\n  |\n  = help: {}",
            self.severity,
            lint_id_suffix,
            self.message,
            self.file_path,
            self.line_number,
            self.pattern,
            self.suggestion
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

    // Run clutter prevention lint checks (LINT-0013, LINT-0014, LINT-0015)
    check_no_new_module_without_justification(&mut findings)?;
    check_cousin_abstractions(&mut findings)?;
    check_deletion_plan_required(&mut findings)?;

    // Run HTF human-time lint on normative documents (LINT-0016)
    if args.include_htf {
        check_htf_human_time_units(&mut findings)?;
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
            // Some repos may contain directories that end with `.md` (e.g., skill bundles).
            // Only attempt to parse real markdown files.
            if !path.is_file() {
                continue;
            }
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
            suggestion: "Use tempfile::NamedTempFile or tempfile::TempDir instead. See documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md#anti-2".to_string(),
            severity: LintSeverity::Warning,
            lint_id: None,
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
            suggestion: "Use tempfile::NamedTempFile in examples. See documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md#anti-2"
                .to_string(),
            severity: LintSeverity::Warning,
            lint_id: None,
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
                suggestion: "Use quote_path() or shell_escape() for paths in shell commands. See documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md#anti-1".to_string(),
                severity: LintSeverity::Warning,
                lint_id: None,
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
                suggestion: "Write complex strings to a temp file and use stdin redirection. See documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md#anti-1".to_string(),
                severity: LintSeverity::Warning,
                lint_id: None,
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
                "Write prompts to a temp file and redirect stdin. See documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md#anti-1"
                    .to_string(),
            severity: LintSeverity::Warning,
            lint_id: None,
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
                "Show safe pattern using temp file and stdin redirection. See documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md#anti-1"
                    .to_string(),
            severity: LintSeverity::Warning,
            lint_id: None,
        });
    }
}

// =============================================================================
// LINT-0013: no-new-module-without-justification
// =============================================================================

/// A struct or trait definition extracted from a Rust source file.
#[derive(Debug, Clone)]
struct TypeDefinition {
    /// Name of the type.
    name: String,
    /// File path where defined.
    file_path: String,
    /// Line number in the file.
    line_number: usize,
    /// Field names for structs (empty for traits).
    field_names: Vec<String>,
    /// Whether this is a struct or trait.
    kind: TypeKind,
}

/// Kind of type definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeKind {
    Struct,
    Trait,
}

/// Check for new modules without RFC justification (LINT-0013).
///
/// Scans for mod.rs files that are not tracked in git HEAD and verifies
/// they have justification in an RFC. Currently implements a simplified
/// check that flags any new mod.rs files.
fn check_no_new_module_without_justification(findings: &mut Vec<LintFinding>) -> Result<()> {
    // Get list of new (untracked or staged) mod.rs files
    let new_mod_files = get_new_mod_files()?;

    // Load RFC justifications from ticket decomposition files
    let justified_paths = load_rfc_justified_paths()?;

    for mod_file in new_mod_files {
        // Check if this module path is justified in any RFC
        // Use strict path matching: the justified path must end with the mod_file path
        // or be an exact match. This prevents overly broad justifications like "mod.rs"
        // from bypassing clutter checks for all modules.
        let mod_path = Path::new(&mod_file);
        let is_justified = justified_paths.iter().any(|justified| {
            let justified_path = Path::new(justified);
            // Exact match or justified path ends with the mod_file components
            justified_path == mod_path || justified_path.ends_with(mod_path)
        });

        if !is_justified {
            findings.push(LintFinding {
                file_path: mod_file.clone(),
                line_number: 1,
                pattern: "mod.rs".to_string(),
                message: "New module lacks RFC justification".to_string(),
                suggestion: "Add this module path to files_to_create in an RFC's 06_ticket_decomposition.yaml".to_string(),
                severity: LintSeverity::Error,
                lint_id: Some("LINT-0013".to_string()),
            });
        }
    }

    Ok(())
}

/// Get list of new mod.rs files (not in git HEAD).
fn get_new_mod_files() -> Result<Vec<String>> {
    use std::process::Command;

    // Get untracked files
    let output = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard"])
        .output()
        .context("Failed to run git ls-files")?;

    let untracked = String::from_utf8_lossy(&output.stdout);

    // Get staged new files
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=A"])
        .output()
        .context("Failed to run git diff --cached")?;

    let staged = String::from_utf8_lossy(&output.stdout);

    // Combine and filter for mod.rs files in crates/ or xtask/
    let mut new_mods: Vec<String> = untracked
        .lines()
        .chain(staged.lines())
        .filter(|path| {
            path.ends_with("mod.rs") && (path.starts_with("crates/") || path.starts_with("xtask/"))
        })
        .map(String::from)
        .collect();

    new_mods.sort();
    new_mods.dedup();

    Ok(new_mods)
}

/// Load justified file paths from RFC ticket decomposition files.
///
/// Uses `serde_yaml` to parse the YAML structure and extract `files_to_create`
/// entries from all tickets.
fn load_rfc_justified_paths() -> Result<Vec<String>> {
    let mut justified = Vec::new();

    // Scan RFC ticket decomposition files
    let pattern = "documents/rfcs/*/06_ticket_decomposition.yaml";
    let glob_pattern = glob::glob(pattern).context("Invalid RFC glob pattern")?;

    for entry in glob_pattern.flatten() {
        let file_path = entry.display().to_string();
        match std::fs::read_to_string(&entry) {
            Ok(content) => {
                match serde_yaml::from_str::<TicketDecompositionFile>(&content) {
                    Ok(decomp_file) => {
                        if let Some(decomp) = decomp_file.rfc_ticket_decomposition {
                            // Extract from top-level tickets
                            for ticket in &decomp.tickets {
                                for path in &ticket.files_to_create {
                                    if std::path::Path::new(path)
                                        .extension()
                                        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                                    {
                                        justified.push(path.clone());
                                    }
                                }
                            }
                            // Extract from ticket_plan.tickets if present
                            if let Some(plan) = &decomp.ticket_plan {
                                for ticket in &plan.tickets {
                                    for path in &ticket.files_to_create {
                                        if std::path::Path::new(path)
                                            .extension()
                                            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                                        {
                                            justified.push(path.clone());
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("warning: Failed to parse YAML in {file_path}: {e}");
                    },
                }
            },
            Err(e) => {
                eprintln!("warning: Failed to read file {file_path}: {e}");
            },
        }
    }

    Ok(justified)
}

// =============================================================================
// LINT-0014: cousin-abstraction-detector
// =============================================================================

/// Default similarity threshold for cousin abstraction detection.
const COUSIN_SIMILARITY_THRESHOLD: f64 = 0.8;

/// Check for cousin abstractions - similar struct/trait definitions
/// (LINT-0014).
///
/// Parses all struct and trait definitions in the workspace and computes
/// similarity scores based on name similarity (Levenshtein) and structural
/// similarity (field overlap). Warns when similarity exceeds threshold.
fn check_cousin_abstractions(findings: &mut Vec<LintFinding>) -> Result<()> {
    let type_defs = collect_type_definitions()?;

    // Compare all pairs
    for i in 0..type_defs.len() {
        for j in (i + 1)..type_defs.len() {
            let def_a = &type_defs[i];
            let def_b = &type_defs[j];

            // Only compare same kinds (struct-struct or trait-trait)
            if def_a.kind != def_b.kind {
                continue;
            }

            let similarity = compute_type_similarity(def_a, def_b);

            if similarity >= COUSIN_SIMILARITY_THRESHOLD {
                findings.push(LintFinding {
                    file_path: def_a.file_path.clone(),
                    line_number: def_a.line_number,
                    pattern: format!("{} vs {}", def_a.name, def_b.name),
                    message: format!(
                        "Potential cousin abstraction: '{}' and '{}' have {:.0}% similarity",
                        def_a.name,
                        def_b.name,
                        similarity * 100.0
                    ),
                    suggestion: format!(
                        "Consider unifying these types or documenting why they are distinct. See also: {}:{}",
                        def_b.file_path, def_b.line_number
                    ),
                    severity: LintSeverity::Warning,
                    lint_id: Some("LINT-0014".to_string()),
                });
            }
        }
    }

    Ok(())
}

/// Collect all struct and trait definitions from workspace Rust files.
fn collect_type_definitions() -> Result<Vec<TypeDefinition>> {
    let mut definitions = Vec::new();

    let patterns = ["crates/**/*.rs", "xtask/src/**/*.rs"];

    for pattern in patterns {
        let glob_pattern = glob::glob(pattern).context("Invalid glob pattern")?;

        for entry in glob_pattern.flatten() {
            let file_path = entry.display().to_string();
            match std::fs::read_to_string(&entry) {
                Ok(content) => {
                    extract_type_definitions(&content, &file_path, &mut definitions);
                },
                Err(e) => {
                    eprintln!("warning: Failed to read file {file_path}: {e}");
                },
            }
        }
    }

    Ok(definitions)
}

/// Extract struct and trait definitions from Rust source code.
///
/// Uses the `syn` crate to parse the source and extract type definitions.
fn extract_type_definitions(content: &str, file_path: &str, definitions: &mut Vec<TypeDefinition>) {
    // Try to parse the file with syn
    let Ok(syntax) = syn::parse_file(content) else {
        // If parsing fails, skip this file (might have syntax errors)
        return;
    };

    for item in &syntax.items {
        match item {
            syn::Item::Struct(item_struct) => {
                let name = item_struct.ident.to_string();
                let line_number = item_struct.ident.span().start().line;

                let field_names: Vec<String> = match &item_struct.fields {
                    syn::Fields::Named(fields) => fields
                        .named
                        .iter()
                        .filter_map(|f| f.ident.as_ref().map(std::string::ToString::to_string))
                        .collect(),
                    syn::Fields::Unnamed(fields) => {
                        (0..fields.unnamed.len()).map(|i| format!("_{i}")).collect()
                    },
                    syn::Fields::Unit => Vec::new(),
                };

                definitions.push(TypeDefinition {
                    name,
                    file_path: file_path.to_string(),
                    line_number,
                    field_names,
                    kind: TypeKind::Struct,
                });
            },
            syn::Item::Trait(item_trait) => {
                let name = item_trait.ident.to_string();
                let line_number = item_trait.ident.span().start().line;

                // For traits, extract method names as "fields" for comparison
                let field_names: Vec<String> = item_trait
                    .items
                    .iter()
                    .filter_map(|item| {
                        if let syn::TraitItem::Fn(method) = item {
                            Some(method.sig.ident.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();

                definitions.push(TypeDefinition {
                    name,
                    file_path: file_path.to_string(),
                    line_number,
                    field_names,
                    kind: TypeKind::Trait,
                });
            },
            _ => {},
        }
    }
}

/// Compute similarity between two type definitions.
///
/// Returns a score between 0.0 and 1.0 based on:
/// - Name similarity (Levenshtein distance)
/// - Field/method overlap (Jaccard similarity)
fn compute_type_similarity(a: &TypeDefinition, b: &TypeDefinition) -> f64 {
    // Name similarity using normalized Levenshtein
    let name_similarity = strsim::normalized_levenshtein(&a.name, &b.name);

    // Field/method overlap using Jaccard similarity
    let field_similarity = if a.field_names.is_empty() && b.field_names.is_empty() {
        // If both have no fields, consider them structurally similar
        1.0
    } else if a.field_names.is_empty() || b.field_names.is_empty() {
        // If one has fields and other doesn't, not similar
        0.0
    } else {
        let set_a: std::collections::HashSet<_> = a.field_names.iter().collect();
        let set_b: std::collections::HashSet<_> = b.field_names.iter().collect();
        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();
        if union == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let ratio = intersection as f64 / union as f64;
            ratio
        }
    };

    // Weight name similarity more heavily (60% name, 40% structure)
    0.6f64.mul_add(name_similarity, 0.4 * field_similarity)
}

// =============================================================================
// LINT-0015: deletion-migration-plan-required
// =============================================================================

/// Check for new pub items without deletion/migration plans (LINT-0015).
///
/// Scans for new public items (fn, struct, trait, mod) in staged/untracked
/// files and verifies they have corresponding deletion plans in the RFC.
fn check_deletion_plan_required(findings: &mut Vec<LintFinding>) -> Result<()> {
    // Get list of new or modified Rust files
    let new_files = get_new_rust_files()?;

    // Load deletion plans from RFCs
    let deletion_plans = load_rfc_deletion_plans()?;

    for file_path in new_files {
        match std::fs::read_to_string(&file_path) {
            Ok(content) => {
                check_pub_items_for_deletion_plan(&content, &file_path, &deletion_plans, findings);
            },
            Err(e) => {
                eprintln!("warning: Failed to read file {file_path}: {e}");
            },
        }
    }

    Ok(())
}

/// Get list of new or modified Rust files.
fn get_new_rust_files() -> Result<Vec<String>> {
    use std::process::Command;

    // Get untracked files
    let output = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard"])
        .output()
        .context("Failed to run git ls-files")?;

    let untracked = String::from_utf8_lossy(&output.stdout);

    // Get staged new files only (not modified)
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=A"])
        .output()
        .context("Failed to run git diff --cached")?;

    let staged = String::from_utf8_lossy(&output.stdout);

    // Combine and filter for .rs files in crates/ or xtask/
    let mut new_files: Vec<String> = untracked
        .lines()
        .chain(staged.lines())
        .filter(|path| {
            std::path::Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                && (path.starts_with("crates/") || path.starts_with("xtask/"))
        })
        .map(String::from)
        .collect();

    new_files.sort();
    new_files.dedup();

    Ok(new_files)
}

/// A deletion plan entry with optional scope information.
#[derive(Debug, Clone)]
struct DeletionPlanEntry {
    /// The item name (e.g., "init", `MyStruct`).
    item_name: String,
    /// Optional file path scope (e.g., "crates/foo/src/lib.rs").
    /// If None, the plan applies globally (with ambiguity warning).
    file_scope: Option<String>,
    /// The deletion/migration plan description.
    /// Stored for logging/debugging but not used in matching logic.
    #[allow(dead_code)]
    plan: String,
}

/// Load deletion plans from RFC files.
///
/// Uses `serde_yaml` to parse the YAML structure and extract `deletion_plan`
/// entries. Returns a list of deletion plan entries with optional scope.
///
/// Deletion plan items can be specified as:
/// - Simple name: `init` (global, may trigger ambiguity warning)
/// - Scoped name: `crates/foo/src/lib.rs::init` (file-scoped, preferred)
fn load_rfc_deletion_plans() -> Result<Vec<DeletionPlanEntry>> {
    let mut plans = Vec::new();

    // Scan RFC rollout/ops files for deletion_plan sections
    let pattern = "documents/rfcs/*/05_rollout_and_ops.yaml";
    let glob_pattern = glob::glob(pattern).context("Invalid RFC glob pattern")?;

    for entry in glob_pattern.flatten() {
        let file_path = entry.display().to_string();
        match std::fs::read_to_string(&entry) {
            Ok(content) => match serde_yaml::from_str::<RolloutAndOpsFile>(&content) {
                Ok(rollout_file) => {
                    if let Some(rollout) = rollout_file.rfc_rollout_and_ops {
                        for plan_item in &rollout.deletion_plan {
                            // Check if the item is scoped (contains "::")
                            let entry =
                                if let Some((scope, name)) = plan_item.item.rsplit_once("::") {
                                    DeletionPlanEntry {
                                        item_name: name.to_string(),
                                        file_scope: Some(scope.to_string()),
                                        plan: plan_item.plan.clone(),
                                    }
                                } else {
                                    DeletionPlanEntry {
                                        item_name: plan_item.item.clone(),
                                        file_scope: None,
                                        plan: plan_item.plan.clone(),
                                    }
                                };
                            plans.push(entry);
                        }
                    }
                },
                Err(e) => {
                    eprintln!("warning: Failed to parse YAML in {file_path}: {e}");
                },
            },
            Err(e) => {
                eprintln!("warning: Failed to read file {file_path}: {e}");
            },
        }
    }

    Ok(plans)
}

/// Check if a deletion plan matches an item, considering scope.
///
/// Returns `Some(is_scoped)` if the plan matches, where `is_scoped` indicates
/// whether the match was file-scoped (true) or global/unscoped (false).
fn deletion_plan_matches(
    plan: &DeletionPlanEntry,
    item_name: &str,
    file_path: &str,
) -> Option<bool> {
    if plan.item_name != item_name {
        return None;
    }

    plan.file_scope.as_ref().map_or(Some(false), |scope| {
        // Scoped match: file path must end with the scope
        let file_path_obj = Path::new(file_path);
        let scope_path = Path::new(scope);
        if file_path_obj == scope_path || file_path_obj.ends_with(scope_path) {
            Some(true) // Scoped match
        } else {
            None // Scope doesn't match
        }
    })
}

/// Check public items in a file for corresponding deletion plans.
fn check_pub_items_for_deletion_plan(
    content: &str,
    file_path: &str,
    deletion_plans: &[DeletionPlanEntry],
    findings: &mut Vec<LintFinding>,
) {
    // Parse with syn to find pub items
    let Ok(syntax) = syn::parse_file(content) else {
        return;
    };

    for item in &syntax.items {
        let (name, line_number, item_kind) = match item {
            syn::Item::Fn(item_fn) if matches!(item_fn.vis, syn::Visibility::Public(_)) => {
                let name = item_fn.sig.ident.to_string();
                let line = item_fn.sig.ident.span().start().line;
                (name, line, "function")
            },
            syn::Item::Struct(item_struct)
                if matches!(item_struct.vis, syn::Visibility::Public(_)) =>
            {
                let name = item_struct.ident.to_string();
                let line = item_struct.ident.span().start().line;
                (name, line, "struct")
            },
            syn::Item::Trait(item_trait)
                if matches!(item_trait.vis, syn::Visibility::Public(_)) =>
            {
                let name = item_trait.ident.to_string();
                let line = item_trait.ident.span().start().line;
                (name, line, "trait")
            },
            syn::Item::Mod(item_mod) if matches!(item_mod.vis, syn::Visibility::Public(_)) => {
                let name = item_mod.ident.to_string();
                let line = item_mod.ident.span().start().line;
                (name, line, "module")
            },
            syn::Item::Enum(item_enum) if matches!(item_enum.vis, syn::Visibility::Public(_)) => {
                let name = item_enum.ident.to_string();
                let line = item_enum.ident.span().start().line;
                (name, line, "enum")
            },
            syn::Item::Const(item_const)
                if matches!(item_const.vis, syn::Visibility::Public(_)) =>
            {
                let name = item_const.ident.to_string();
                let line = item_const.ident.span().start().line;
                (name, line, "constant")
            },
            syn::Item::Static(item_static)
                if matches!(item_static.vis, syn::Visibility::Public(_)) =>
            {
                let name = item_static.ident.to_string();
                let line = item_static.ident.span().start().line;
                (name, line, "static")
            },
            syn::Item::Type(item_type) if matches!(item_type.vis, syn::Visibility::Public(_)) => {
                let name = item_type.ident.to_string();
                let line = item_type.ident.span().start().line;
                (name, line, "type alias")
            },
            _ => continue,
        };

        // Check if this item has a deletion plan
        // Prefer scoped matches over unscoped ones
        let mut has_scoped_match = false;
        let mut has_unscoped_match = false;

        for plan in deletion_plans {
            if let Some(is_scoped) = deletion_plan_matches(plan, &name, file_path) {
                if is_scoped {
                    has_scoped_match = true;
                    break; // Scoped match is definitive
                }
                has_unscoped_match = true;
            }
        }

        if has_scoped_match {
            // Item has a properly scoped deletion plan - no finding
            continue;
        }

        if has_unscoped_match {
            // Item matched by unscoped plan - warn about ambiguity
            findings.push(LintFinding {
                file_path: file_path.to_string(),
                line_number,
                pattern: format!("pub {item_kind} {name}"),
                message: format!(
                    "Public {item_kind} '{name}' has unscoped deletion plan (ambiguous match)"
                ),
                suggestion: format!(
                    "Use scoped deletion plan: '{file_path}::{name}' in 05_rollout_and_ops.yaml"
                ),
                severity: LintSeverity::Warning,
                lint_id: Some("LINT-0015".to_string()),
            });
        } else {
            // No deletion plan at all
            findings.push(LintFinding {
                file_path: file_path.to_string(),
                line_number,
                pattern: format!("pub {item_kind} {name}"),
                message: format!("New public {item_kind} '{name}' lacks a deletion/migration plan"),
                suggestion:
                    "Add a deletion_plan entry in the RFC's 05_rollout_and_ops.yaml for this item"
                        .to_string(),
                severity: LintSeverity::Error,
                lint_id: Some("LINT-0015".to_string()),
            });
        }
    }
}

// =============================================================================
// LINT-0016: HTF human-time units in normative documents
// =============================================================================

/// Regex patterns for detecting human time units that violate HTF policy.
///
/// These patterns match:
/// - Numeric durations: "5 minutes", "24 hours", "30 days", etc.
/// - Business time codes: "ASAP", "EOD", "EOW", "EOY"
/// - Relative time phrases: "next week", "next month", "next quarter"
static HTF_TIME_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // Numeric time units: "5 minutes", "24 hours", "30 days", etc.
        Regex::new(r"(?i)\b\d+\s*(seconds?|minutes?|hours?|days?|weeks?|months?|years?)\b")
            .unwrap(),
        // Business time codes (case-insensitive)
        Regex::new(r"(?i)\b(ASAP|EOD|EOW|EOY)\b").unwrap(),
        // Relative time phrases
        Regex::new(r"(?i)\bnext\s+(week|month|quarter|year)\b").unwrap(),
    ]
});

/// Directories containing normative documents subject to HTF human-time lint.
const HTF_SCOPED_PATHS: &[&str] = &[
    "documents/prds/",
    "documents/rfcs/",
    "documents/skills/",
    "documents/laws/",
];

/// Escape hatch prefix for explicitly external-facing time references.
const HTF_ESCAPE_PREFIX: &str = "EXTERNAL_TIME:";

/// Check for human time units in normative documents (LINT-0016).
///
/// Scans normative documents (PRDs, RFCs, skills, laws) for human-time units
/// that violate HTF (Holonic Time Fabric) policy. Human-time units are only
/// allowed with explicit `EXTERNAL_TIME:` prefix to indicate external-facing
/// contexts (user notifications, SLAs, display formatting).
fn check_htf_human_time_units(findings: &mut Vec<LintFinding>) -> Result<()> {
    // Scan YAML and Markdown files in scoped directories
    let file_patterns = [
        "documents/prds/**/*.yaml",
        "documents/prds/**/*.md",
        "documents/rfcs/**/*.yaml",
        "documents/rfcs/**/*.md",
        "documents/skills/**/*.yaml",
        "documents/skills/**/*.md",
        "documents/laws/**/*.yaml",
        "documents/laws/**/*.md",
    ];

    for pattern in file_patterns {
        let glob_pattern = glob::glob(pattern).context("Invalid HTF glob pattern")?;

        for entry in glob_pattern {
            let path = entry.context("Failed to read HTF glob entry")?;
            if !path.is_file() {
                continue;
            }
            check_htf_file(&path, findings)?;
        }
    }

    Ok(())
}

/// Check a single file for HTF human-time violations.
fn check_htf_file(path: &Path, findings: &mut Vec<LintFinding>) -> Result<()> {
    let file_path = path.display().to_string();

    // Skip template files (they may contain examples with human time)
    if file_path.contains("/template/") {
        return Ok(());
    }

    // Verify this file is in a scoped directory
    if !HTF_SCOPED_PATHS
        .iter()
        .any(|scope| file_path.starts_with(scope))
    {
        return Ok(());
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read file for HTF lint: {file_path}"))?;

    for (line_idx, line) in content.lines().enumerate() {
        let line_number = line_idx + 1;

        // Skip lines with the escape hatch prefix
        if line.contains(HTF_ESCAPE_PREFIX) {
            continue;
        }

        // Skip YAML comments (starting with #)
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        // Check each pattern - use find_iter to capture all matches per line
        for pattern in HTF_TIME_PATTERNS.iter() {
            for mat in pattern.find_iter(line) {
                let matched_text = mat.as_str();

                // Additional check: skip if this looks like a schema version (e.g.,
                // "2026-01-30") or an ID pattern (e.g., "REQ-0001")
                if is_likely_version_or_id(matched_text, line) {
                    continue;
                }

                findings.push(LintFinding {
                    file_path: file_path.clone(),
                    line_number,
                    pattern: matched_text.to_string(),
                    message: format!(
                        "Human time unit '{matched_text}' in normative document violates HTF policy (REQ-HTF-0006)"
                    ),
                    suggestion: format!(
                        "Use tick-based or ledger-based time instead. For external-facing contexts, prefix with '{HTF_ESCAPE_PREFIX}'"
                    ),
                    severity: LintSeverity::Error,
                    lint_id: Some("LINT-0016".to_string()),
                });
            }
        }
    }

    Ok(())
}

/// Regex pattern for YAML keys that indicate version/schema/date fields.
/// Used to avoid false positives on lines like `schema_version: "2026-01-30"`.
static VERSION_KEY_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(schema_version|template_version|version|created_date|last_updated_date|date)\s*:").unwrap()
});

/// Regex pattern for ISO date formats (YYYY-MM-DD).
static DATE_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d{4}-\d{2}-\d{2}").unwrap());

/// Regex pattern for YAML keys ending in _id or named id.
static ID_KEY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(\w+_id|id)\s*:").unwrap());

/// Check if matched text is likely a version number or ID rather than a time
/// reference.
///
/// This helps avoid false positives for patterns like:
/// - Schema versions: "2026-01-30" (matches "30 days" pattern without context)
/// - ID fields: "REQ-0001" where numbers might match time patterns
fn is_likely_version_or_id(matched_text: &str, line: &str) -> bool {
    // Check if the line starts with a version/schema/date YAML key
    if VERSION_KEY_PATTERN.is_match(line) {
        return true;
    }

    // Check if the line starts with an ID YAML key
    if ID_KEY_PATTERN.is_match(line) {
        return true;
    }

    // If the matched text is part of a date pattern (YYYY-MM-DD), skip it
    if line.contains('-') {
        if let Some(date_match) = DATE_PATTERN.find(line) {
            if date_match.as_str().contains(matched_text) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lint_args_default() {
        let args = LintArgs {
            fix: false,
            include_docs: false,
            include_htf: false,
        };
        assert!(!args.fix);
        assert!(!args.include_docs);
        assert!(!args.include_htf);
    }

    #[test]
    fn test_lint_args_with_fix() {
        let args = LintArgs {
            fix: true,
            include_docs: false,
            include_htf: false,
        };
        assert!(args.fix);
    }

    #[test]
    fn test_lint_args_with_include_docs() {
        let args = LintArgs {
            fix: false,
            include_docs: true,
            include_htf: false,
        };
        assert!(args.include_docs);
    }

    #[test]
    fn test_lint_args_with_include_htf() {
        let args = LintArgs {
            fix: false,
            include_docs: false,
            include_htf: true,
        };
        assert!(args.include_htf);
    }

    #[test]
    fn test_lint_finding_display() {
        let finding = LintFinding {
            file_path: "src/main.rs".to_string(),
            line_number: 42,
            pattern: "std::env::temp_dir()".to_string(),
            message: "Test message".to_string(),
            suggestion: "Test suggestion".to_string(),
            severity: LintSeverity::Warning,
            lint_id: None,
        };

        let output = finding.to_string();
        assert!(output.contains("warning: Test message"));
        assert!(output.contains("src/main.rs:42"));
        assert!(output.contains("help: Test suggestion"));
    }

    #[test]
    fn test_lint_finding_display_with_id() {
        let finding = LintFinding {
            file_path: "src/main.rs".to_string(),
            line_number: 42,
            pattern: "pub struct Foo".to_string(),
            message: "Test error message".to_string(),
            suggestion: "Test suggestion".to_string(),
            severity: LintSeverity::Error,
            lint_id: Some("LINT-0013".to_string()),
        };

        let output = finding.to_string();
        assert!(output.contains("error [LINT-0013]: Test error message"));
        assert!(output.contains("src/main.rs:42"));
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
            "documents/security/SECURITY_CHECKLIST.cac.json",
            10,
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("insecure patterns"));

        // Should allow if marked as anti-pattern example
        findings.clear();
        check_temp_dir_usage_in_doc(
            "// VULNERABLE: std::env::temp_dir() is predictable",
            "documents/security/SECURITY_CHECKLIST.cac.json",
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
            severity: LintSeverity::Warning,
            lint_id: None,
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
            include_htf: false,
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
            file_path: "documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md"
                .to_string(),
            line_number: 50,
            pattern: "std::env::temp_dir()".to_string(),
            message: "Documentation example uses insecure pattern".to_string(),
            suggestion: "Use tempfile crate instead".to_string(),
            severity: LintSeverity::Warning,
            lint_id: None,
        };

        let display = finding.to_string();
        assert!(display.contains(
            "documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md:50"
        ));
        assert!(display.contains("Documentation example"));
    }

    // =========================================================================
    // Tests for LINT-0013, LINT-0014, LINT-0015 (clutter prevention)
    // =========================================================================

    #[test]
    fn test_lint_severity_display() {
        assert_eq!(LintSeverity::Warning.to_string(), "warning");
        assert_eq!(LintSeverity::Error.to_string(), "error");
    }

    #[test]
    fn test_type_kind_equality() {
        assert_eq!(TypeKind::Struct, TypeKind::Struct);
        assert_eq!(TypeKind::Trait, TypeKind::Trait);
        assert_ne!(TypeKind::Struct, TypeKind::Trait);
    }

    #[test]
    fn test_extract_type_definitions_struct() {
        let content = r"
pub struct Foo {
    pub name: String,
    pub value: i32,
}
";
        let mut definitions = Vec::new();
        extract_type_definitions(content, "test.rs", &mut definitions);

        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].name, "Foo");
        assert_eq!(definitions[0].kind, TypeKind::Struct);
        assert!(definitions[0].field_names.contains(&"name".to_string()));
        assert!(definitions[0].field_names.contains(&"value".to_string()));
    }

    #[test]
    fn test_extract_type_definitions_trait() {
        let content = r"
pub trait Bar {
    fn method_one(&self);
    fn method_two(&self) -> i32;
}
";
        let mut definitions = Vec::new();
        extract_type_definitions(content, "test.rs", &mut definitions);

        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].name, "Bar");
        assert_eq!(definitions[0].kind, TypeKind::Trait);
        assert!(
            definitions[0]
                .field_names
                .contains(&"method_one".to_string())
        );
        assert!(
            definitions[0]
                .field_names
                .contains(&"method_two".to_string())
        );
    }

    #[test]
    fn test_compute_type_similarity_identical_names() {
        let a = TypeDefinition {
            name: "FooBar".to_string(),
            file_path: "a.rs".to_string(),
            line_number: 1,
            field_names: vec!["x".to_string(), "y".to_string()],
            kind: TypeKind::Struct,
        };
        let b = TypeDefinition {
            name: "FooBar".to_string(),
            file_path: "b.rs".to_string(),
            line_number: 1,
            field_names: vec!["x".to_string(), "y".to_string()],
            kind: TypeKind::Struct,
        };

        let similarity = compute_type_similarity(&a, &b);
        assert!(
            (similarity - 1.0).abs() < 0.001,
            "Expected 1.0, got {similarity}"
        );
    }

    #[test]
    fn test_compute_type_similarity_similar_names() {
        let a = TypeDefinition {
            name: "UserData".to_string(),
            file_path: "a.rs".to_string(),
            line_number: 1,
            field_names: vec!["id".to_string(), "name".to_string()],
            kind: TypeKind::Struct,
        };
        let b = TypeDefinition {
            name: "UserInfo".to_string(),
            file_path: "b.rs".to_string(),
            line_number: 1,
            field_names: vec!["id".to_string(), "name".to_string()],
            kind: TypeKind::Struct,
        };

        let similarity = compute_type_similarity(&a, &b);
        // Names are similar (User* prefix), fields identical
        assert!(similarity >= 0.7, "Expected >= 0.7, got {similarity}");
    }

    #[test]
    fn test_compute_type_similarity_different() {
        let a = TypeDefinition {
            name: "Apple".to_string(),
            file_path: "a.rs".to_string(),
            line_number: 1,
            field_names: vec!["color".to_string()],
            kind: TypeKind::Struct,
        };
        let b = TypeDefinition {
            name: "Banana".to_string(),
            file_path: "b.rs".to_string(),
            line_number: 1,
            field_names: vec!["length".to_string()],
            kind: TypeKind::Struct,
        };

        let similarity = compute_type_similarity(&a, &b);
        // Names and fields are completely different
        assert!(similarity < 0.5, "Expected < 0.5, got {similarity}");
    }

    #[test]
    fn test_cousin_similarity_threshold() {
        // Verify the threshold constant is reasonable
        // Using const block to silence clippy::assertions_on_constants
        const { assert!(COUSIN_SIMILARITY_THRESHOLD > 0.5) };
        const { assert!(COUSIN_SIMILARITY_THRESHOLD <= 1.0) };
    }

    #[test]
    fn test_check_pub_items_for_deletion_plan() {
        let content = r"
pub fn public_function() {}
fn private_function() {}
pub struct PublicStruct { pub x: i32 }
struct PrivateStruct { x: i32 }
";
        let mut findings = Vec::new();
        let deletion_plans: Vec<DeletionPlanEntry> = Vec::new(); // Empty - no plans

        check_pub_items_for_deletion_plan(content, "test.rs", &deletion_plans, &mut findings);

        // Should flag pub items but not private ones
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern.contains("public_function"))
        );
        assert!(findings.iter().any(|f| f.pattern.contains("PublicStruct")));
        assert!(!findings.iter().any(|f| f.pattern.contains("private")));
    }

    #[test]
    fn test_check_pub_items_with_scoped_deletion_plan() {
        let content = r"
pub fn public_function() {}
pub struct PublicStruct { pub x: i32 }
";
        let mut findings = Vec::new();
        let deletion_plans = vec![
            DeletionPlanEntry {
                item_name: "public_function".to_string(),
                file_scope: Some("test.rs".to_string()),
                plan: "Will be removed in v2.0".to_string(),
            },
            DeletionPlanEntry {
                item_name: "PublicStruct".to_string(),
                file_scope: Some("test.rs".to_string()),
                plan: "Deprecated, use NewStruct".to_string(),
            },
        ];

        check_pub_items_for_deletion_plan(content, "test.rs", &deletion_plans, &mut findings);

        // Should not flag items that have scoped deletion plans
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_check_pub_items_with_unscoped_deletion_plan_warns() {
        let content = r"
pub fn init() {}
";
        let mut findings = Vec::new();
        let deletion_plans = vec![DeletionPlanEntry {
            item_name: "init".to_string(),
            file_scope: None, // Unscoped - global match
            plan: "Will be removed".to_string(),
        }];

        check_pub_items_for_deletion_plan(
            content,
            "crates/foo/src/lib.rs",
            &deletion_plans,
            &mut findings,
        );

        // Should warn about ambiguous unscoped match
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, LintSeverity::Warning);
        assert!(findings[0].message.contains("unscoped"));
    }

    #[test]
    fn test_check_pub_items_scoped_plan_wrong_file() {
        let content = r"
pub fn init() {}
";
        let mut findings = Vec::new();
        let deletion_plans = vec![DeletionPlanEntry {
            item_name: "init".to_string(),
            file_scope: Some("crates/bar/src/lib.rs".to_string()), // Wrong file
            plan: "Will be removed".to_string(),
        }];

        check_pub_items_for_deletion_plan(
            content,
            "crates/foo/src/lib.rs",
            &deletion_plans,
            &mut findings,
        );

        // Should flag as missing (scoped plan doesn't match this file)
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, LintSeverity::Error);
        assert!(findings[0].message.contains("lacks a deletion"));
    }

    #[test]
    fn test_deletion_plan_matches_scoped() {
        let plan = DeletionPlanEntry {
            item_name: "init".to_string(),
            file_scope: Some("crates/foo/src/lib.rs".to_string()),
            plan: "test".to_string(),
        };

        // Exact match
        assert_eq!(
            deletion_plan_matches(&plan, "init", "crates/foo/src/lib.rs"),
            Some(true)
        );

        // Ends with match
        assert_eq!(
            deletion_plan_matches(&plan, "init", "/home/user/project/crates/foo/src/lib.rs"),
            Some(true)
        );

        // Wrong name
        assert_eq!(
            deletion_plan_matches(&plan, "other", "crates/foo/src/lib.rs"),
            None
        );

        // Wrong file
        assert_eq!(
            deletion_plan_matches(&plan, "init", "crates/bar/src/lib.rs"),
            None
        );
    }

    #[test]
    fn test_deletion_plan_matches_unscoped() {
        let plan = DeletionPlanEntry {
            item_name: "init".to_string(),
            file_scope: None,
            plan: "test".to_string(),
        };

        // Matches any file with the same name
        assert_eq!(
            deletion_plan_matches(&plan, "init", "crates/foo/src/lib.rs"),
            Some(false) // false indicates unscoped match
        );
        assert_eq!(
            deletion_plan_matches(&plan, "init", "crates/bar/src/lib.rs"),
            Some(false)
        );

        // Wrong name still doesn't match
        assert_eq!(
            deletion_plan_matches(&plan, "other", "crates/foo/src/lib.rs"),
            None
        );
    }

    // =========================================================================
    // Tests for LINT-0016: HTF human-time units
    // =========================================================================

    /// Helper function to check HTF violations in a content string.
    fn check_htf_content(content: &str, file_path: &str) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for (line_idx, line) in content.lines().enumerate() {
            let line_number = line_idx + 1;

            // Skip lines with the escape hatch prefix
            if line.contains(HTF_ESCAPE_PREFIX) {
                continue;
            }

            // Skip YAML comments
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }

            for pattern in HTF_TIME_PATTERNS.iter() {
                for mat in pattern.find_iter(line) {
                    let matched_text = mat.as_str();
                    if is_likely_version_or_id(matched_text, line) {
                        continue;
                    }
                    findings.push(LintFinding {
                        file_path: file_path.to_string(),
                        line_number,
                        pattern: matched_text.to_string(),
                        message: format!("Human time unit '{matched_text}' in normative document"),
                        suggestion: "Use tick-based time".to_string(),
                        severity: LintSeverity::Error,
                        lint_id: Some("LINT-0016".to_string()),
                    });
                }
            }
        }
        findings
    }

    #[test]
    fn test_htf_detects_numeric_time_units() {
        let content = r"
statement: |
  The timeout is set to 5 minutes for initial connection.
  Retries happen every 30 seconds.
  Leases expire after 24 hours.
  Cleanup runs every 7 days.
";
        let findings = check_htf_content(content, "documents/rfcs/RFC-0001/test.yaml");
        assert!(
            findings.len() >= 4,
            "Expected at least 4 findings, got {}",
            findings.len()
        );

        // Check that we found the expected patterns
        let patterns: Vec<_> = findings.iter().map(|f| f.pattern.as_str()).collect();
        assert!(
            patterns.iter().any(|p| p.contains("minutes")),
            "Should detect '5 minutes'"
        );
        assert!(
            patterns.iter().any(|p| p.contains("seconds")),
            "Should detect '30 seconds'"
        );
        assert!(
            patterns.iter().any(|p| p.contains("hours")),
            "Should detect '24 hours'"
        );
        assert!(
            patterns.iter().any(|p| p.contains("days")),
            "Should detect '7 days'"
        );
    }

    #[test]
    fn test_htf_detects_business_time_codes() {
        let content = r"
deadline: ASAP
completion: EOD
review: EOW
delivery: EOY
";
        let findings = check_htf_content(content, "documents/prds/PRD-0001/test.yaml");
        assert_eq!(findings.len(), 4, "Should detect all 4 business time codes");

        let patterns: Vec<_> = findings.iter().map(|f| f.pattern.as_str()).collect();
        assert!(patterns.contains(&"ASAP"));
        assert!(patterns.contains(&"EOD"));
        assert!(patterns.contains(&"EOW"));
        assert!(patterns.contains(&"EOY"));
    }

    #[test]
    fn test_htf_detects_relative_time_phrases() {
        let content = r"
planning: We will address this next week.
roadmap: Implementation scheduled for next month.
goals: Complete by next quarter.
";
        let findings = check_htf_content(content, "documents/skills/test/test.md");
        assert_eq!(
            findings.len(),
            3,
            "Should detect all 3 relative time phrases"
        );

        let patterns: Vec<_> = findings.iter().map(|f| f.pattern.as_str()).collect();
        assert!(
            patterns.iter().any(|p| p.contains("next week")),
            "Should detect 'next week'"
        );
        assert!(
            patterns.iter().any(|p| p.contains("next month")),
            "Should detect 'next month'"
        );
        assert!(
            patterns.iter().any(|p| p.contains("next quarter")),
            "Should detect 'next quarter'"
        );
    }

    #[test]
    fn test_htf_escape_hatch_works() {
        let content = r"
external_notification: |
  EXTERNAL_TIME: Users will receive a reminder 24 hours before the deadline.
  EXTERNAL_TIME: The SLA guarantees response within 4 hours.
normal_statement: |
  Internal processing takes 5 minutes.
";
        let findings = check_htf_content(content, "documents/rfcs/RFC-0001/test.yaml");

        // Should only detect the internal "5 minutes", not the EXTERNAL_TIME prefixed
        // ones
        assert_eq!(
            findings.len(),
            1,
            "Should only detect 1 violation (not escaped)"
        );
        assert!(findings[0].pattern.contains("5 minutes"));
    }

    #[test]
    fn test_htf_skips_yaml_comments() {
        let content = r"
# This comment mentions 5 minutes but should be skipped
  # Indented comment: 30 seconds
statement: This is the actual content with 10 hours timeout.
";
        let findings = check_htf_content(content, "documents/prds/PRD-0001/test.yaml");

        // Should only detect "10 hours" from the non-comment line
        assert_eq!(
            findings.len(),
            1,
            "Should only detect 1 violation (not in comments)"
        );
        assert!(findings[0].pattern.contains("10 hours"));
    }

    #[test]
    fn test_htf_skips_version_and_schema_lines() {
        let content = r#"
schema_version: "2026-01-30"
template_version: "2026-01-26"
created_date: "2026-01-30"
"#;
        let findings = check_htf_content(content, "documents/rfcs/RFC-0001/00_meta.yaml");

        // Should not flag version/schema lines even if they contain date-like patterns
        assert_eq!(
            findings.len(),
            0,
            "Should not flag version/schema/date lines"
        );
    }

    #[test]
    fn test_htf_lint_finding_format() {
        let finding = LintFinding {
            file_path: "documents/rfcs/RFC-0016/02_design.yaml".to_string(),
            line_number: 42,
            pattern: "5 minutes".to_string(),
            message: "Human time unit '5 minutes' in normative document violates HTF policy (REQ-HTF-0006)"
                .to_string(),
            suggestion: "Use tick-based time instead. For external-facing contexts, prefix with 'EXTERNAL_TIME:'"
                .to_string(),
            severity: LintSeverity::Error,
            lint_id: Some("LINT-0016".to_string()),
        };

        let output = finding.to_string();
        assert!(output.contains("error [LINT-0016]"));
        assert!(output.contains("documents/rfcs/RFC-0016/02_design.yaml:42"));
        assert!(output.contains("5 minutes"));
    }

    #[test]
    fn test_htf_case_insensitive_time_units() {
        let content = r"
timeout: 5 MINUTES
delay: 30 Seconds
expiry: 24 Hours
";
        let findings = check_htf_content(content, "documents/rfcs/RFC-0001/test.yaml");
        assert_eq!(
            findings.len(),
            3,
            "Should detect time units regardless of case"
        );
    }

    #[test]
    fn test_htf_singular_and_plural_forms() {
        let content = r"
one_second: 1 second
one_minute: 1 minute
one_hour: 1 hour
one_day: 1 day
one_week: 1 week
one_month: 1 month
one_year: 1 year
";
        let findings = check_htf_content(content, "documents/prds/PRD-0001/test.yaml");
        assert_eq!(
            findings.len(),
            7,
            "Should detect both singular and plural forms"
        );
    }

    #[test]
    fn test_htf_patterns_compiled() {
        // Verify patterns compile and can match
        assert!(!HTF_TIME_PATTERNS.is_empty(), "Should have HTF patterns");

        for pattern in HTF_TIME_PATTERNS.iter() {
            // Each pattern should be valid regex
            assert!(
                pattern.is_match("test 5 minutes test")
                    || pattern.is_match("ASAP")
                    || pattern.is_match("next week"),
                "Pattern should match at least one expected string"
            );
        }
    }

    #[test]
    fn test_htf_scoped_paths() {
        // Verify scoped paths are configured
        assert!(!HTF_SCOPED_PATHS.is_empty(), "Should have scoped paths");
        assert!(
            HTF_SCOPED_PATHS.contains(&"documents/prds/"),
            "Should include PRDs"
        );
        assert!(
            HTF_SCOPED_PATHS.contains(&"documents/rfcs/"),
            "Should include RFCs"
        );
        assert!(
            HTF_SCOPED_PATHS.contains(&"documents/skills/"),
            "Should include skills"
        );
        assert!(
            HTF_SCOPED_PATHS.contains(&"documents/laws/"),
            "Should include laws"
        );
    }

    #[test]
    fn test_is_likely_version_or_id() {
        // Version lines should be skipped (YAML key starts with version-related key)
        assert!(is_likely_version_or_id("30", "schema_version: 2026-01-30"));
        assert!(is_likely_version_or_id(
            "26",
            "template_version: 2026-01-26"
        ));
        assert!(is_likely_version_or_id("30", "version: 1.2.30"));
        assert!(is_likely_version_or_id("30", "created_date: 2026-01-30"));

        // ID lines should be skipped (YAML key ends with _id or is "id:")
        assert!(is_likely_version_or_id("1", "requirement_id: REQ-0001"));
        assert!(is_likely_version_or_id("5", "ticket_id: TCK-00005"));
        assert!(is_likely_version_or_id("1", "id: 1"));

        // Regular content should NOT be skipped
        assert!(!is_likely_version_or_id("5 minutes", "timeout: 5 minutes"));
        assert!(!is_likely_version_or_id("ASAP", "deadline: ASAP"));

        // Lines with "version" in the VALUE (not the key) should NOT be skipped
        assert!(!is_likely_version_or_id(
            "30 days",
            "description: The system version 2.0 will be ready in 30 days"
        ));

        // Lines with "id" in the VALUE (not the key) should NOT be skipped
        assert!(!is_likely_version_or_id(
            "5 minutes",
            "note: The user id lookup takes 5 minutes"
        ));
    }

    #[test]
    fn test_htf_detects_multiple_violations_per_line() {
        let content = r"
statement: Processing takes 5 minutes and retries every 30 seconds.
";
        let findings = check_htf_content(content, "documents/rfcs/RFC-0001/test.yaml");

        // Should detect both "5 minutes" and "30 seconds" on the same line
        assert_eq!(
            findings.len(),
            2,
            "Should detect 2 violations on same line, got {}",
            findings.len()
        );

        let patterns: Vec<_> = findings.iter().map(|f| f.pattern.as_str()).collect();
        assert!(
            patterns.iter().any(|p| p.contains("5 minutes")),
            "Should detect '5 minutes'"
        );
        assert!(
            patterns.iter().any(|p| p.contains("30 seconds")),
            "Should detect '30 seconds'"
        );
    }

    #[test]
    fn test_htf_does_not_skip_version_in_value() {
        let content = r"
description: The system version 2.0 will be ready in 30 days and reviewed within 48 hours.
";
        let findings = check_htf_content(content, "documents/rfcs/RFC-0001/test.yaml");

        // Should detect both "30 days" and "48 hours" - not skipped because "version"
        // is in value
        assert_eq!(
            findings.len(),
            2,
            "Should detect 2 violations, got {}",
            findings.len()
        );
    }
}
