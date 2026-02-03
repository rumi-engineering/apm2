//! Implementation of the `aat` command.
//!
//! This command runs Agent Acceptance Testing (AAT) on a PR to verify
//! it meets acceptance criteria through hypothesis-driven testing.
//!
//! # Usage
//!
//! ```bash
//! cargo xtask aat <PR_URL>
//! cargo xtask aat https://github.com/owner/repo/pull/123 --dry-run
//! ```
//!
//! # Process
//!
//! 1. Parse PR URL to extract owner/repo/number
//! 2. Fetch PR description and diff via `gh` CLI
//! 3. Parse PR description for required sections
//! 4. Run anti-gaming analysis on the diff
//! 5. Invoke AAT skill for hypothesis generation and execution
//! 6. Generate evidence bundle
//! 7. Set GitHub status check (unless --dry-run)
//!
//! # Exit Codes
//!
//! - 0: Success (all hypotheses passed, no anti-gaming violations)
//! - 1: Failure (hypothesis failed or anti-gaming violation)
//! - 2: Invalid arguments or missing PR sections

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use regex::Regex;
use tempfile::NamedTempFile;
use wait_timeout::ChildExt;
use xshell::{Shell, cmd};

/// Maximum time allowed for AI tool execution (5 minutes).
/// This prevents hung AI tools from blocking CI runners indefinitely.
const AI_TOOL_TIMEOUT: Duration = Duration::from_secs(300);

use crate::aat::anti_gaming::analyze_diff;
use crate::aat::evidence::EvidenceBundleBuilder;
use crate::aat::executor::HypothesisExecutor;
use crate::aat::parser::parse_pr_description;
use crate::aat::tool_config::{AatToolConfig, AiTool};
use crate::aat::types::{Hypothesis, HypothesisResult, ParsedPRDescription, Verdict};
use crate::aat::validation::validate_pr_description;
use crate::aat::variation::InputVariationGenerator;
use crate::reviewer_state::select_review_model;
use crate::shell_escape::build_script_command;
use crate::util::print_non_authoritative_banner;

// =============================================================================
// PR URL Parsing
// =============================================================================

/// Parsed PR URL components.
#[derive(Debug, Clone)]
pub struct PrInfo {
    /// Repository owner (e.g., "Anveio")
    pub owner: String,
    /// Repository name (e.g., "apm2")
    pub repo: String,
    /// PR number
    pub number: u64,
}

impl PrInfo {
    /// Format as owner/repo
    pub fn owner_repo(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }
}

/// Parse a GitHub PR URL to extract owner, repo, and PR number.
///
/// Handles URLs like:
/// - `https://github.com/owner/repo/pull/123`
/// - `github.com/owner/repo/pull/123`
///
/// # Errors
///
/// Returns an error if the URL format is invalid.
pub fn parse_pr_url(url: &str) -> Result<PrInfo> {
    let url = url.trim();

    // Remove protocol if present
    let path = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Remove github.com prefix
    let path = path
        .strip_prefix("github.com/")
        .ok_or_else(|| anyhow::anyhow!("Invalid PR URL: must be a GitHub URL"))?;

    // Split into parts: owner/repo/pull/number
    let parts: Vec<&str> = path.split('/').collect();

    if parts.len() < 4 || parts[2] != "pull" {
        bail!(
            "Invalid PR URL format. Expected: https://github.com/owner/repo/pull/123\n\
             Got: {url}"
        );
    }

    let owner = parts[0].to_string();
    let repo = parts[1].to_string();
    let number: u64 = parts[3].parse().context("Invalid PR number in URL")?;

    Ok(PrInfo {
        owner,
        repo,
        number,
    })
}

// =============================================================================
// GitHub API Interactions
// =============================================================================

/// Fetch PR description via gh CLI.
pub fn fetch_pr_description(sh: &Shell, pr_info: &PrInfo) -> Result<String> {
    let owner_repo = pr_info.owner_repo();
    let number = pr_info.number.to_string();

    let body = cmd!(
        sh,
        "gh pr view {number} --repo {owner_repo} --json body -q .body"
    )
    .read()
    .context("Failed to fetch PR description")?;

    Ok(body)
}

/// Fetch PR diff via gh CLI.
pub fn fetch_pr_diff(sh: &Shell, pr_info: &PrInfo) -> Result<String> {
    let owner_repo = pr_info.owner_repo();
    let number = pr_info.number.to_string();

    let diff = cmd!(sh, "gh pr diff {number} --repo {owner_repo}")
        .read()
        .context("Failed to fetch PR diff")?;

    Ok(diff)
}

/// Fetch PR head commit SHA via gh CLI.
pub fn fetch_pr_sha(sh: &Shell, pr_info: &PrInfo) -> Result<String> {
    let owner_repo = pr_info.owner_repo();
    let number = pr_info.number.to_string();

    let sha = cmd!(
        sh,
        "gh pr view {number} --repo {owner_repo} --json headRefOid -q .headRefOid"
    )
    .read()
    .context("Failed to fetch PR head SHA")?;

    let sha = sha.trim().to_string();
    if sha.is_empty() {
        bail!("Could not get HEAD SHA for PR #{number}");
    }

    Ok(sha)
}

/// Set GitHub status check.
///
/// # NON-AUTHORITATIVE OUTPUT
///
/// This function writes GitHub status checks as DEVELOPMENT SCAFFOLDING only.
/// Per RFC-0018 REQ-HEF-0001, these statuses are NOT the source of truth for
/// the HEF evidence pipeline. A NON-AUTHORITATIVE banner is printed to stderr
/// before each status write to make this explicit.
///
/// # Arguments
///
/// * `sh` - Shell instance
/// * `pr_info` - PR information
/// * `sha` - Commit SHA to set status on
/// * `state` - Status state (success, failure, pending)
/// * `description` - Human-readable description
/// * `target_url` - Optional URL to evidence bundle
pub fn set_status_check(
    sh: &Shell,
    pr_info: &PrInfo,
    sha: &str,
    state: &str,
    description: &str,
    target_url: Option<&str>,
) -> Result<()> {
    // TCK-00309: Gate writes on HEF projection flag
    // When HEF projection is enabled, the daemon is responsible for updating
    // GitHub status based on ledger events. xtask MUST NOT write directly.
    if crate::util::use_hef_projection() {
        println!("  [HEF] Skipping direct GitHub status write (USE_HEF_PROJECTION=true)");
        println!("  [HEF] Status would be: {state} - {description}");
        return Ok(());
    }

    // TCK-00294: Print NON-AUTHORITATIVE banner before status writes
    print_non_authoritative_banner();

    let owner_repo = pr_info.owner_repo();
    let endpoint = format!("/repos/{owner_repo}/statuses/{sha}");
    let context = "aat/acceptance";

    if let Some(url) = target_url {
        cmd!(
            sh,
            "gh api --method POST {endpoint} -f state={state} -f context={context} -f description={description} -f target_url={url}"
        )
        .run()
        .context("Failed to set status check")?;
    } else {
        cmd!(
            sh,
            "gh api --method POST {endpoint} -f state={state} -f context={context} -f description={description}"
        )
        .run()
        .context("Failed to set status check")?;
    }

    Ok(())
}

// =============================================================================
// Hypothesis Generation
// =============================================================================

/// Minimum number of hypotheses required for a valid AAT run.
const MIN_HYPOTHESES: usize = 3;

/// Path to the hypothesis generation prompt template.
const HYPOTHESIS_PROMPT_PATH: &str = "documents/reviews/AAT_HYPOTHESIS_PROMPT.md";

/// Raw hypothesis from AI response before transformation.
///
/// This intermediate struct captures the JSON schema returned by the AI tool,
/// which uses slightly different field types than our internal `Hypothesis`
/// type.
///
/// Note: We use `deny_unknown_fields` to ensure strict parsing of AI responses.
/// This prevents silent failures where the AI returns unexpected fields that
/// could indicate a misunderstood prompt or malformed output.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHypothesis {
    id: String,
    prediction: String,
    verification_method: String,
    tests_error_handling: bool,
}

/// Generate hypotheses by invoking the configured AI tool.
///
/// This function:
/// 1. Loads the hypothesis prompt template from `AAT_HYPOTHESIS_PROMPT.md`
/// 2. Substitutes `$PR_DESCRIPTION` and `$DIFF_SUMMARY` placeholders
/// 3. Invokes the configured AI tool with the prompt
/// 4. Parses the JSON response into hypotheses
/// 5. Validates minimum hypothesis count and error handling coverage
///
/// # Arguments
///
/// * `pr_description` - The raw PR description text
/// * `diff` - The PR diff text
/// * `tool_config` - AI tool configuration (gemini or claude-code)
/// * `repo_root` - Repository root path for loading prompt template
///
/// # Returns
///
/// Returns `Ok(Vec<Hypothesis>)` on success, or an error if:
/// - The prompt template cannot be loaded
/// - The AI tool fails to execute
/// - The AI response cannot be parsed as JSON
/// - Validation fails (less than 3 hypotheses or no error handling hypothesis)
fn generate_hypotheses(
    pr_description: &str,
    diff: &str,
    tool_config: &AatToolConfig,
    repo_root: &str,
) -> Result<Vec<Hypothesis>> {
    // Load the prompt template
    let prompt_template_path = format!("{repo_root}/{HYPOTHESIS_PROMPT_PATH}");
    let prompt_template = std::fs::read_to_string(&prompt_template_path).with_context(|| {
        format!(
            "Failed to read hypothesis prompt template from {prompt_template_path}\n\
             Hint: Ensure AAT_HYPOTHESIS_PROMPT.md exists in documents/reviews/"
        )
    })?;

    // Create a summary of the diff (truncate if too large for AI context)
    let diff_summary = create_diff_summary(diff);

    // Substitute placeholders in the prompt template.
    // Note: We replace $DIFF_SUMMARY first, then $PR_DESCRIPTION, to prevent
    // potential injection where a malicious PR description contains
    // "$DIFF_SUMMARY". This order ensures user content ($PR_DESCRIPTION) is
    // substituted last, so it cannot reference other placeholders.
    let prompt = prompt_template
        .replace("$DIFF_SUMMARY", &diff_summary)
        .replace("$PR_DESCRIPTION", pr_description);

    // Write prompt to secure temp file
    let mut prompt_file =
        NamedTempFile::new().context("Failed to create temp file for hypothesis prompt")?;
    prompt_file
        .write_all(prompt.as_bytes())
        .context("Failed to write hypothesis prompt to temp file")?;
    prompt_file
        .flush()
        .context("Failed to flush hypothesis prompt temp file")?;

    let prompt_path = prompt_file.path();

    // Build and execute the AI tool command
    let ai_output = invoke_ai_tool(prompt_path, tool_config)?;

    // Parse the AI response
    let hypotheses = parse_ai_response(&ai_output)?;

    // Validate hypothesis requirements
    validate_hypotheses(&hypotheses)?;

    // Transform raw hypotheses into full Hypothesis structs
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let hypotheses = hypotheses
        .into_iter()
        .map(|raw| Hypothesis {
            id: raw.id,
            prediction: raw.prediction,
            verification_method: raw.verification_method,
            tests_error_handling: raw.tests_error_handling,
            formed_at: now.clone(),
            executed_at: None,
            result: None,
            actual_outcome: None,
            stdout: None,
            stderr: None,
            exit_code: None,
        })
        .collect();

    Ok(hypotheses)
}

/// Create a summary of the diff for inclusion in the prompt.
///
/// If the diff is larger than a reasonable context window, it is truncated
/// with a note indicating the truncation.
fn create_diff_summary(diff: &str) -> String {
    // Limit diff to approximately 50KB to fit in AI context windows
    const MAX_DIFF_BYTES: usize = 50_000;

    if diff.len() <= MAX_DIFF_BYTES {
        diff.to_string()
    } else {
        // Truncate at a line boundary if possible
        let truncated = &diff[..MAX_DIFF_BYTES];
        let last_newline = truncated.rfind('\n').unwrap_or(MAX_DIFF_BYTES);
        format!(
            "{}\n\n[... diff truncated, {} more bytes ...]",
            &diff[..last_newline],
            diff.len() - last_newline
        )
    }
}

/// Invoke the AI tool with the given prompt file.
///
/// Uses the secure `script` wrapper pattern for PTY allocation, which gives
/// the AI tool access to all capabilities including shell tools.
///
/// # Arguments
///
/// * `prompt_path` - Path to the prompt file
/// * `tool_config` - AI tool configuration
///
/// # Returns
///
/// Returns the AI tool's stdout output, or an error if execution fails.
fn invoke_ai_tool(prompt_path: &Path, tool_config: &AatToolConfig) -> Result<String> {
    // Build the command using safe shell escaping
    // For hypothesis generation, we use synchronous execution (no log file)
    let shell_cmd = build_ai_script_command(prompt_path, tool_config);

    // Spawn the command with stdout/stderr capture
    let mut child = std::process::Command::new("sh")
        .args(["-c", &shell_cmd])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "Failed to execute AI tool '{}'\n\
                 Hint: Ensure {} is installed and available in PATH",
                tool_config.ai_tool,
                tool_config.ai_tool.command()
            )
        })?;

    // Wait with timeout to prevent hung AI tools from blocking CI indefinitely
    let Some(status) = child.wait_timeout(AI_TOOL_TIMEOUT)? else {
        // Timeout expired - kill the process and report error
        let _ = child.kill();
        let _ = child.wait(); // Reap the zombie process
        bail!(
            "AI tool '{}' timed out after {} seconds\n\
             Hint: The AI tool may be hung or the prompt may be too complex.\n\
             Consider breaking down the PR into smaller changes.",
            tool_config.ai_tool,
            AI_TOOL_TIMEOUT.as_secs()
        );
    };

    // Read stdout and stderr from the completed process
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();

    if let Some(mut stdout) = child.stdout.take() {
        std::io::Read::read_to_end(&mut stdout, &mut stdout_buf)
            .context("Failed to read AI tool stdout")?;
    }
    if let Some(mut stderr) = child.stderr.take() {
        std::io::Read::read_to_end(&mut stderr, &mut stderr_buf)
            .context("Failed to read AI tool stderr")?;
    }

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_buf);
        let exit_code = status.code().unwrap_or(-1);
        bail!(
            "AI tool '{}' failed with exit code {}\n\
             Stderr: {}\n\
             Hint: Check that the AI tool is properly configured and authenticated",
            tool_config.ai_tool,
            exit_code,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8(stdout_buf).context(
        "AI tool output was not valid UTF-8\n\
         Hint: The AI tool may have produced binary output unexpectedly",
    )?;

    Ok(stdout)
}

/// Build the script command for AI tool invocation.
///
/// This handles the differences between AI tools:
/// - Gemini: Uses `--yolo` flag for non-interactive mode
/// - Claude: Uses standard input without special flags
fn build_ai_script_command(prompt_path: &Path, tool_config: &AatToolConfig) -> String {
    match tool_config.ai_tool {
        AiTool::Gemini => {
            // Gemini uses build_script_command from shell_escape module
            build_script_command(prompt_path, None, Some(select_review_model()))
        },
        AiTool::ClaudeCode => {
            // Claude Code uses similar pattern but different command
            let quoted_prompt = crate::shell_escape::quote_path(prompt_path);
            let inner_cmd = format!("claude --dangerously-skip-permissions < {quoted_prompt}");
            let escaped_inner = inner_cmd.replace('\'', "'\\''");
            format!("script -qec '{escaped_inner}' /dev/null")
        },
    }
}

/// Parse the AI tool's output to extract hypotheses.
///
/// The AI is expected to return a JSON array of hypothesis objects.
/// This function extracts the JSON from the output (which may contain
/// other text like markdown formatting) and parses it.
///
/// Parsing strategy (in order):
/// 1. Try to parse the entire trimmed output as JSON directly
/// 2. Try to extract JSON from a markdown code block
/// 3. Try to find a JSON array in the text (string-aware bracket matching)
fn parse_ai_response(output: &str) -> Result<Vec<RawHypothesis>> {
    let trimmed = output.trim();

    // Strategy 1: Try to parse the entire output as JSON directly
    // This handles the clean case where AI returns raw JSON without any wrapper
    if let Ok(hypotheses) = serde_json::from_str::<Vec<RawHypothesis>>(trimmed) {
        return Ok(hypotheses);
    }

    // Strategy 2 & 3: Extract JSON from wrapped content
    let json_str = extract_json_array(output).with_context(|| {
        format!(
            "Could not find JSON array in AI response\n\
             Expected: A JSON array of hypothesis objects\n\
             Got: {}\n\
             Hint: The AI tool may not have followed the output format instructions",
            truncate_for_error(output)
        )
    })?;

    let hypotheses: Vec<RawHypothesis> = serde_json::from_str(json_str).with_context(|| {
        format!(
            "Failed to parse AI response as JSON\n\
                 JSON: {}\n\
                 Hint: Each hypothesis must have 'id', 'prediction', 'verification_method', \
                 and 'tests_error_handling' fields",
            truncate_for_error(json_str)
        )
    })?;

    Ok(hypotheses)
}

/// Extract a JSON array from text that may contain other content.
///
/// Handles cases where the JSON is:
/// - Wrapped in markdown code blocks (```json ... ```)
/// - Preceded or followed by other text
/// - The entire output
///
/// This function properly handles brackets inside JSON strings by tracking
/// string context (respecting escaped quotes and escape sequences).
fn extract_json_array(text: &str) -> Option<&str> {
    // First, try to find JSON in a markdown code block
    if let Some(json) = extract_from_code_block(text) {
        return Some(json);
    }

    // Otherwise, find the first '[' and matching ']' with string awareness
    let start = text.find('[')?;
    let bytes = &text.as_bytes()[start..];
    let mut depth = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let mut end = None;

    for (i, &byte) in bytes.iter().enumerate() {
        let c = byte as char;

        if escape_next {
            // Skip this character, it's escaped
            escape_next = false;
            continue;
        }

        if c == '\\' && in_string {
            // Next character is escaped
            escape_next = true;
            continue;
        }

        if c == '"' {
            // Toggle string context
            in_string = !in_string;
            continue;
        }

        // Only count brackets outside of strings
        if !in_string {
            match c {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(start + i + 1);
                        break;
                    }
                },
                _ => {},
            }
        }
    }

    end.map(|e| &text[start..e])
}

/// Extract JSON from a markdown code block.
fn extract_from_code_block(text: &str) -> Option<&str> {
    // Look for ```json or just ```
    let patterns = ["```json\n", "```json\r\n", "```\n", "```\r\n"];

    for pattern in patterns {
        if let Some(start) = text.find(pattern) {
            let content_start = start + pattern.len();
            if let Some(end) = text[content_start..].find("```") {
                let json = text[content_start..content_start + end].trim();
                // Verify it starts with '[' (is an array)
                if json.starts_with('[') {
                    return Some(json);
                }
            }
        }
    }

    None
}

/// Validate that hypotheses meet AAT requirements.
///
/// Requirements:
/// - At least 3 hypotheses
/// - At least 1 hypothesis with `tests_error_handling = true`
fn validate_hypotheses(hypotheses: &[RawHypothesis]) -> Result<()> {
    // Check minimum count
    if hypotheses.len() < MIN_HYPOTHESES {
        bail!(
            "AI generated only {} hypotheses, but at least {} are required\n\
             Hint: Re-run the AAT command or manually add hypotheses to meet the minimum",
            hypotheses.len(),
            MIN_HYPOTHESES
        );
    }

    // Check for error handling hypothesis
    let error_handling_count = hypotheses.iter().filter(|h| h.tests_error_handling).count();
    if error_handling_count == 0 {
        bail!(
            "No hypotheses test error handling (tests_error_handling = true)\n\
             At least 1 hypothesis must test error handling scenarios\n\
             Hint: Re-run the AAT command or manually add an error handling hypothesis"
        );
    }

    Ok(())
}

/// Truncate a string for inclusion in error messages.
fn truncate_for_error(s: &str) -> String {
    const MAX_LEN: usize = 500;
    if s.len() <= MAX_LEN {
        s.to_string()
    } else {
        format!("{}...", &s[..MAX_LEN])
    }
}

// =============================================================================
// Input Variation Testing
// =============================================================================

/// Maximum number of commands to extract from a PR description.
///
/// This limit prevents denial-of-service attacks where a malicious PR
/// description contains hundreds of commands, each requiring execution
/// with 3 variations. 10 commands * 3 variations = 30 executions max.
const MAX_COMMANDS_PER_PR: usize = 10;

/// Extract CLI commands from the PR description usage section.
///
/// Parses the usage section to find shell commands in code blocks.
/// Returns a list of commands suitable for input variation testing.
///
/// # Extraction Strategy
///
/// 1. Extract content from fenced code blocks (bash, shell, or plain)
/// 2. Filter to lines that look like CLI commands (start with common prefixes)
/// 3. Skip comment lines and empty lines
/// 4. Limit to `MAX_COMMANDS_PER_PR` to prevent abuse
///
/// # Arguments
///
/// * `parsed_pr` - The parsed PR description
///
/// # Returns
///
/// A vector of command strings extracted from the usage section,
/// limited to `MAX_COMMANDS_PER_PR` entries.
fn extract_commands_from_usage(parsed_pr: &ParsedPRDescription) -> Vec<String> {
    let usage = &parsed_pr.usage;
    let mut commands = Vec::new();

    // Pattern to match fenced code blocks
    let code_block_re = Regex::new(r"(?s)```(?:bash|shell|sh)?\s*\n(.*?)```").expect("valid regex");

    // Extract commands from code blocks
    'outer: for cap in code_block_re.captures_iter(usage) {
        if let Some(block_content) = cap.get(1) {
            for line in block_content.as_str().lines() {
                // SECURITY: Enforce limit to prevent DoS via bloated usage sections
                if commands.len() >= MAX_COMMANDS_PER_PR {
                    break 'outer;
                }

                let line = line.trim();

                // Skip empty lines and comments
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Only include lines that look like CLI commands
                // (start with common command prefixes)
                if is_cli_command(line) {
                    commands.push(line.to_string());
                }
            }
        }
    }

    // If no commands found in code blocks, try to find inline commands
    // (lines starting with $ or common command names)
    if commands.is_empty() {
        for line in usage.lines() {
            // SECURITY: Enforce limit to prevent DoS via bloated usage sections
            if commands.len() >= MAX_COMMANDS_PER_PR {
                break;
            }

            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check for shell prompt prefix
            if let Some(cmd) = line.strip_prefix("$ ") {
                if is_cli_command(cmd) {
                    commands.push(cmd.to_string());
                }
            } else if is_cli_command(line) {
                commands.push(line.to_string());
            }
        }
    }

    commands
}

/// Check if a line looks like a CLI command.
///
/// Returns true if the line starts with a common command prefix.
///
/// # Security
///
/// This allowlist is security-sensitive. The following are intentionally
/// EXCLUDED:
/// - `gh ` - Could expose reviewer tokens via `gh auth token`
/// - `git ` - Could access credentials via `git config` or credential helpers
/// - `./` - Could execute arbitrary scripts from untrusted PR branches
///
/// Commands on this list will be executed in an isolated environment with
/// credential isolation (isolated HOME), but reducing the attack surface
/// is still important.
fn is_cli_command(line: &str) -> bool {
    // Security: DO NOT add `gh `, `git `, or `./` to this list.
    // See security review findings for rationale:
    // - gh: Could expose tokens via `gh auth token`
    // - git: Could access credentials via git-credential helpers
    // - ./: Could execute arbitrary scripts from untrusted PR branches
    let command_prefixes = [
        "cargo ", "cargo-", "rustc ", "rustup ", "npm ", "npx ", "yarn ", "pnpm ", "python ",
        "python3 ", "pip ", "pip3 ", "make ", "cmake ", "docker ", "kubectl ",
    ];

    // Strip leading $ if present
    let cmd = line.strip_prefix("$ ").unwrap_or(line);

    command_prefixes
        .iter()
        .any(|prefix| cmd.starts_with(prefix))
}

// =============================================================================
// Main AAT Command
// =============================================================================

/// Result of running the AAT command.
#[derive(Debug)]
#[allow(dead_code)] // Fields are part of public API
pub struct AatResult {
    /// The final verdict
    pub verdict: Verdict,
    /// Path to the evidence bundle (if written)
    pub evidence_path: Option<std::path::PathBuf>,
    /// Human-readable summary
    pub summary: String,
}

/// Run the AAT command.
///
/// # Arguments
///
/// * `pr_url` - GitHub PR URL
/// * `dry_run` - If true, don't set status check or write evidence
/// * `ai_tool_override` - Optional AI tool override from CLI flag
///
/// # Returns
///
/// Returns `Ok(AatResult)` with the verdict and evidence path,
/// or an error if the AAT process fails.
///
/// # Exit Codes
///
/// The caller should use these exit codes:
/// - 0: Success (PASSED verdict)
/// - 1: Failure (FAILED verdict)
/// - 2: Invalid arguments or `NEEDS_ADJUDICATION`
pub fn run(
    pr_url: &str,
    dry_run: bool,
    ai_tool_override: Option<AiTool>,
    emit_internal: bool,
) -> Result<AatResult> {
    let sh = Shell::new().context("Failed to create shell")?;

    // TCK-00295: Check if internal emission is enabled (flag or env var)
    let should_emit_internal = emit_internal || crate::util::emit_internal_from_env();

    // Configure AI tool backend
    let tool_config = AatToolConfig::from_env().with_override(ai_tool_override);

    println!("Running AAT for: {pr_url}");
    println!(
        "  AI Tool: {} ({})",
        tool_config.ai_tool,
        tool_config.ai_tool.command()
    );
    if dry_run {
        println!("  (dry-run mode - no status check will be set)");
    }
    if should_emit_internal {
        println!("  [TCK-00295] Internal receipt emission enabled");
    }
    println!();

    // Step 1: Parse PR URL
    println!("[1/8] Parsing PR URL...");
    let pr_info = parse_pr_url(pr_url)?;
    println!("  Owner: {}", pr_info.owner);
    println!("  Repo: {}", pr_info.repo);
    println!("  PR #: {}", pr_info.number);

    // Step 2: Fetch PR data
    println!("\n[2/8] Fetching PR data...");
    let description = fetch_pr_description(&sh, &pr_info)?;
    println!("  Description: {} bytes", description.len());

    let diff = fetch_pr_diff(&sh, &pr_info)?;
    println!("  Diff: {} bytes", diff.len());

    let sha = fetch_pr_sha(&sh, &pr_info)?;
    println!("  HEAD SHA: {sha}");

    // Step 3: Parse PR description
    println!("\n[3/8] Parsing PR description...");
    let parsed_pr = match parse_pr_description(&description) {
        Ok(parsed) => {
            println!("  Usage: found ({} chars)", parsed.usage.len());
            println!(
                "  Expected Outcomes: {} items",
                parsed.expected_outcomes.len()
            );
            println!(
                "  Evidence Script: {}",
                parsed.evidence_script.as_deref().unwrap_or("not found")
            );
            println!(
                "  Known Limitations: {} items",
                parsed.known_limitations.len()
            );
            parsed
        },
        Err(e) => {
            let summary = format!("PR description parsing failed: {e}");
            println!("  ERROR: {e}");

            if !dry_run {
                set_status_check(&sh, &pr_info, &sha, "failure", &summary, None)?;
            }

            return Ok(AatResult {
                verdict: Verdict::Failed,
                evidence_path: None,
                summary,
            });
        },
    };

    // Step 4: Validate PR description format
    println!("\n[4/8] Validating PR description...");

    // Get repository root for evidence script validation
    let repo_root = cmd!(sh, "git rev-parse --show-toplevel")
        .read()
        .context("Failed to get repository root")?
        .trim()
        .to_string();
    let repo_root_path = Path::new(&repo_root);

    let validation_errors = validate_pr_description(&parsed_pr, repo_root_path);

    if validation_errors.is_empty() {
        println!("  Validation: PASSED");
    } else {
        println!("  Validation: FAILED ({} errors)", validation_errors.len());
        for error in &validation_errors {
            println!("  ERROR: {}", error.message().replace('\n', "\n         "));
        }

        // Build summary with all validation errors
        let error_summary = validation_errors
            .iter()
            .map(|e| e.to_string().lines().next().unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join("; ");
        let summary = format!("PR description validation failed: {error_summary}");

        if !dry_run {
            set_status_check(&sh, &pr_info, &sha, "failure", &summary, None)?;
        }

        return Ok(AatResult {
            verdict: Verdict::Failed,
            evidence_path: None,
            summary,
        });
    }

    // Step 5: Run anti-gaming analysis (static analysis + input variation)
    println!("\n[5/8] Running anti-gaming analysis...");
    let anti_gaming_result = analyze_diff(&diff, &parsed_pr.known_limitations);
    println!(
        "  Static Analysis Violations: {}",
        anti_gaming_result.violations.len()
    );

    for violation in &anti_gaming_result.violations {
        println!("    - {violation:?}");
    }

    // Run input variation testing on commands from usage section
    println!("  Running input variation testing...");
    let commands = extract_commands_from_usage(&parsed_pr);
    let input_variation_results = if commands.is_empty() {
        println!("    No CLI commands found in Usage section, skipping variation testing");
        Vec::new()
    } else {
        println!("    Found {} commands to test", commands.len());
        let results = InputVariationGenerator::test_commands(commands.iter().map(String::as_str));
        let invariant_count = results.iter().filter(|r| r.invariance_detected).count();
        println!(
            "    Tested {} commands, {} with invariance detected",
            results.len(),
            invariant_count
        );
        for result in &results {
            let status = if result.invariance_detected {
                "INVARIANT (violation)"
            } else {
                "OK"
            };
            println!(
                "      - {}: {} variations, {}",
                result.base_command, result.variations_tested, status
            );
        }
        results
    };

    // Determine overall anti-gaming result
    let input_variation_failed = input_variation_results
        .iter()
        .any(|r| r.invariance_detected);
    let overall_anti_gaming_passed = anti_gaming_result.passed && !input_variation_failed;

    println!(
        "  Overall Anti-Gaming Result: {}",
        if overall_anti_gaming_passed {
            "PASSED"
        } else {
            "FAILED"
        }
    );

    // Step 6: Generate hypotheses
    println!("\n[6/8] Generating hypotheses via AI...");
    println!(
        "  Using AI tool: {} ({})",
        tool_config.ai_tool,
        tool_config.ai_tool.command()
    );
    let hypotheses = match generate_hypotheses(&description, &diff, &tool_config, &repo_root) {
        Ok(h) => {
            println!("  Generated: {} hypotheses", h.len());
            h
        },
        Err(e) => {
            let summary = format!("Hypothesis generation failed: {e}");
            println!("  ERROR: {e}");

            if !dry_run {
                set_status_check(&sh, &pr_info, &sha, "failure", &summary, None)?;
            }

            return Ok(AatResult {
                verdict: Verdict::Failed,
                evidence_path: None,
                summary,
            });
        },
    };

    for h in &hypotheses {
        println!("    - {}: {} (PENDING)", h.id, h.prediction);
    }

    // Step 7: Execute hypotheses
    println!("\n[7/8] Executing hypothesis verification commands...");
    let mut hypotheses = hypotheses; // Make mutable for execution
    match HypothesisExecutor::execute_all(&mut hypotheses) {
        Ok(()) => {
            let passed = hypotheses
                .iter()
                .filter(|h| h.result == Some(HypothesisResult::Passed))
                .count();
            let failed = hypotheses
                .iter()
                .filter(|h| h.result == Some(HypothesisResult::Failed))
                .count();
            println!(
                "  Executed: {} hypotheses ({} passed, {} failed)",
                hypotheses.len(),
                passed,
                failed
            );
        },
        Err(e) => {
            let summary = format!("Hypothesis execution failed: {e}");
            println!("  ERROR: {e}");

            if !dry_run {
                set_status_check(&sh, &pr_info, &sha, "failure", &summary, None)?;
            }

            return Ok(AatResult {
                verdict: Verdict::Failed,
                evidence_path: None,
                summary,
            });
        },
    }

    for h in &hypotheses {
        let result_str = match h.result {
            Some(HypothesisResult::Passed) => "PASSED",
            Some(HypothesisResult::Failed) => "FAILED",
            None => "UNVERIFIED",
        };
        println!("    - {}: {} ({})", h.id, h.prediction, result_str);
    }

    // Step 8: Generate evidence bundle
    println!("\n[8/8] Generating evidence bundle...");
    let bundle = EvidenceBundleBuilder::new(pr_info.number, &sha)
        .set_pr_description_parse(&parsed_pr)
        .add_hypotheses(hypotheses)
        .set_anti_gaming_result(&anti_gaming_result)
        .set_input_variation_results(&input_variation_results)
        .build();

    let verdict = bundle.verdict;
    let verdict_reason = bundle.verdict_reason.clone();

    println!("  Verdict: {verdict:?}");
    println!("  Reason: {verdict_reason}");

    // Write evidence bundle and set status
    let evidence_path = if dry_run {
        println!("\n[DRY RUN] Would write evidence bundle and set status check");
        None
    } else {
        let path = bundle
            .write_to_file(repo_root_path)
            .context("Failed to write evidence bundle")?;

        println!("  Evidence written to: {}", path.display());

        // Set status check
        let state = match verdict {
            Verdict::Passed => "success",
            Verdict::Failed => "failure",
            Verdict::NeedsAdjudication => "pending",
        };

        let description = match verdict {
            Verdict::Passed => format!(
                "AAT passed: {}/{}",
                bundle.hypotheses.len(),
                bundle.hypotheses.len()
            ),
            Verdict::Failed => format!("AAT failed: {verdict_reason}"),
            Verdict::NeedsAdjudication => format!("Needs adjudication: {verdict_reason}"),
        };

        // Create target URL (placeholder - in real deployment this would be a real URL)
        let target_url = format!("file://{}", path.display());

        set_status_check(&sh, &pr_info, &sha, state, &description, Some(&target_url))?;
        println!("  Status check set: aat/acceptance = {state}");

        Some(path)
    };

    let summary = format!("AAT {verdict:?}: {verdict_reason}");
    println!("\n{summary}");

    // TCK-00295: Optionally emit internal receipt (non-blocking)
    if should_emit_internal && !dry_run {
        println!("\n  [EMIT_INTERNAL] Attempting internal receipt emission...");
        let payload = serde_json::json!({
            "pr_url": pr_url,
            "owner_repo": pr_info.owner_repo(),
            "pr_number": pr_info.number,
            "head_sha": sha,
            "verdict": format!("{:?}", verdict),
            "verdict_reason": verdict_reason,
            "evidence_path": evidence_path.as_ref().map(|p| p.display().to_string()),
            "non_authoritative": true,
        });
        let correlation_id = format!("aat-{}-{}", pr_info.number, sha);

        // Non-blocking: errors are logged but don't fail the command
        if let Err(e) = crate::util::try_emit_internal_receipt(
            "aat.evidence.published",
            payload.to_string().as_bytes(),
            &correlation_id,
        ) {
            eprintln!("  [EMIT_INTERNAL] Warning: Failed to emit internal receipt: {e}");
        }
    }

    Ok(AatResult {
        verdict,
        evidence_path,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // parse_pr_url tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_pr_url_https() {
        let pr_info = parse_pr_url("https://github.com/owner/repo/pull/123").unwrap();
        assert_eq!(pr_info.owner, "owner");
        assert_eq!(pr_info.repo, "repo");
        assert_eq!(pr_info.number, 123);
    }

    #[test]
    fn test_parse_pr_url_no_protocol() {
        let pr_info = parse_pr_url("github.com/owner/repo/pull/456").unwrap();
        assert_eq!(pr_info.owner, "owner");
        assert_eq!(pr_info.repo, "repo");
        assert_eq!(pr_info.number, 456);
    }

    #[test]
    fn test_parse_pr_url_with_trailing_path() {
        let pr_info = parse_pr_url("https://github.com/owner/repo/pull/789/files").unwrap();
        assert_eq!(pr_info.owner, "owner");
        assert_eq!(pr_info.repo, "repo");
        assert_eq!(pr_info.number, 789);
    }

    #[test]
    fn test_parse_pr_url_invalid_not_github() {
        let result = parse_pr_url("https://gitlab.com/owner/repo/pull/123");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pr_url_invalid_not_pull() {
        let result = parse_pr_url("https://github.com/owner/repo/issues/123");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pr_url_invalid_no_number() {
        let result = parse_pr_url("https://github.com/owner/repo/pull/abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_pr_info_owner_repo() {
        let pr_info = PrInfo {
            owner: "Anveio".to_string(),
            repo: "apm2".to_string(),
            number: 42,
        };
        assert_eq!(pr_info.owner_repo(), "Anveio/apm2");
    }

    // -------------------------------------------------------------------------
    // Hypothesis generation helper tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_json_array_simple() {
        let input = r#"[{"id": "H-001", "prediction": "test"}]"#;
        let result = extract_json_array(input);
        assert!(result.is_some());
        assert!(result.unwrap().starts_with('['));
    }

    #[test]
    fn test_extract_json_array_with_markdown() {
        let input = r#"Here is the JSON:

```json
[
  {"id": "H-001", "prediction": "test", "verification_method": "cmd", "tests_error_handling": false}
]
```

Done!"#;
        let result = extract_json_array(input);
        assert!(result.is_some());
        let json = result.unwrap();
        assert!(json.starts_with('['));
        assert!(json.contains("H-001"));
    }

    #[test]
    fn test_extract_json_array_with_surrounding_text() {
        let input = r#"Based on the PR, here are my hypotheses:
[{"id": "H-001", "prediction": "test", "verification_method": "cmd", "tests_error_handling": true}]
These hypotheses cover the main scenarios."#;
        let result = extract_json_array(input);
        assert!(result.is_some());
        let json = result.unwrap();
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
    }

    #[test]
    fn test_extract_json_array_nested_brackets() {
        let input = r#"[{"id": "H-001", "nested": {"key": ["value"]}}]"#;
        let result = extract_json_array(input);
        assert!(result.is_some());
        let json = result.unwrap();
        // Should extract the entire outer array
        assert_eq!(json, input);
    }

    #[test]
    fn test_extract_json_array_no_array() {
        let input = "No JSON here, just text.";
        let result = extract_json_array(input);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ai_response_valid() {
        let input = r#"[
            {"id": "H-001", "prediction": "test 1", "verification_method": "cargo test", "tests_error_handling": false},
            {"id": "H-002", "prediction": "test 2", "verification_method": "cargo build", "tests_error_handling": false},
            {"id": "H-003", "prediction": "error test", "verification_method": "cargo test fail", "tests_error_handling": true}
        ]"#;
        let result = parse_ai_response(input);
        assert!(result.is_ok());
        let hypotheses = result.unwrap();
        assert_eq!(hypotheses.len(), 3);
        assert_eq!(hypotheses[0].id, "H-001");
        assert!(hypotheses[2].tests_error_handling);
    }

    #[test]
    fn test_parse_ai_response_missing_field() {
        // Missing tests_error_handling field
        let input = r#"[{"id": "H-001", "prediction": "test", "verification_method": "cmd"}]"#;
        let result = parse_ai_response(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hypotheses_success() {
        let hypotheses = vec![
            RawHypothesis {
                id: "H-001".to_string(),
                prediction: "test 1".to_string(),
                verification_method: "cargo test".to_string(),
                tests_error_handling: false,
            },
            RawHypothesis {
                id: "H-002".to_string(),
                prediction: "test 2".to_string(),
                verification_method: "cargo build".to_string(),
                tests_error_handling: false,
            },
            RawHypothesis {
                id: "H-003".to_string(),
                prediction: "error test".to_string(),
                verification_method: "cargo test fail".to_string(),
                tests_error_handling: true,
            },
        ];
        let result = validate_hypotheses(&hypotheses);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_hypotheses_too_few() {
        let hypotheses = vec![
            RawHypothesis {
                id: "H-001".to_string(),
                prediction: "test 1".to_string(),
                verification_method: "cargo test".to_string(),
                tests_error_handling: true,
            },
            RawHypothesis {
                id: "H-002".to_string(),
                prediction: "test 2".to_string(),
                verification_method: "cargo build".to_string(),
                tests_error_handling: false,
            },
        ];
        let result = validate_hypotheses(&hypotheses);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least 3"));
    }

    #[test]
    fn test_validate_hypotheses_no_error_handling() {
        let hypotheses = vec![
            RawHypothesis {
                id: "H-001".to_string(),
                prediction: "test 1".to_string(),
                verification_method: "cargo test".to_string(),
                tests_error_handling: false,
            },
            RawHypothesis {
                id: "H-002".to_string(),
                prediction: "test 2".to_string(),
                verification_method: "cargo build".to_string(),
                tests_error_handling: false,
            },
            RawHypothesis {
                id: "H-003".to_string(),
                prediction: "test 3".to_string(),
                verification_method: "cargo check".to_string(),
                tests_error_handling: false,
            },
        ];
        let result = validate_hypotheses(&hypotheses);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("error handling"));
    }

    #[test]
    fn test_create_diff_summary_small() {
        let small_diff = "diff --git a/file.rs b/file.rs\n+line";
        let summary = create_diff_summary(small_diff);
        assert_eq!(summary, small_diff);
    }

    #[test]
    fn test_create_diff_summary_large() {
        // Create a diff larger than 50KB
        let large_diff = "a".repeat(60_000);
        let summary = create_diff_summary(&large_diff);
        assert!(summary.len() < large_diff.len());
        assert!(summary.contains("truncated"));
    }

    #[test]
    fn test_truncate_for_error_short() {
        let short = "short message";
        assert_eq!(truncate_for_error(short), short);
    }

    #[test]
    fn test_truncate_for_error_long() {
        let long = "a".repeat(1000);
        let truncated = truncate_for_error(&long);
        assert!(truncated.len() < 510); // 500 + "..."
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_extract_from_code_block_json() {
        let input = "```json\n[{\"id\": \"H-001\"}]\n```";
        let result = extract_from_code_block(input);
        assert!(result.is_some());
        assert!(result.unwrap().starts_with('['));
    }

    #[test]
    fn test_extract_from_code_block_plain() {
        let input = "```\n[{\"id\": \"H-001\"}]\n```";
        let result = extract_from_code_block(input);
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_from_code_block_no_array() {
        let input = "```json\n{\"not\": \"array\"}\n```";
        let result = extract_from_code_block(input);
        assert!(result.is_none()); // Not an array
    }

    // -------------------------------------------------------------------------
    // Edge case tests for JSON extraction (brackets in strings)
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_json_array_brackets_in_string() {
        // This tests the case where brackets appear inside a JSON string value
        // The old implementation would fail on this because it didn't track string
        // context
        let input = r#"[{"id": "H-001", "pattern": "[a-z]+", "tests_error_handling": false}]"#;
        let result = extract_json_array(input);
        assert!(result.is_some(), "Should handle brackets inside strings");
        let json = result.unwrap();
        assert_eq!(json, input, "Should extract the entire array");
    }

    #[test]
    fn test_extract_json_array_single_bracket_in_string() {
        // Edge case: single '[' in a string should not break parsing
        let input = r#"["["]"#;
        let result = extract_json_array(input);
        assert!(result.is_some(), "Should handle single bracket in string");
        assert_eq!(result.unwrap(), input);
    }

    #[test]
    fn test_extract_json_array_escaped_quote_in_string() {
        // Test that escaped quotes inside strings are handled properly
        let input =
            r#"[{"id": "H-001", "text": "He said \"hello\"", "tests_error_handling": false}]"#;
        let result = extract_json_array(input);
        assert!(result.is_some(), "Should handle escaped quotes in strings");
        assert_eq!(result.unwrap(), input);
    }

    #[test]
    fn test_extract_json_array_backslash_before_bracket() {
        // Test backslash handling: backslash before bracket inside string
        let input = r#"[{"path": "C:\\Users\\[test]"}]"#;
        let result = extract_json_array(input);
        assert!(result.is_some(), "Should handle backslash sequences");
        assert_eq!(result.unwrap(), input);
    }

    #[test]
    fn test_parse_ai_response_direct_json() {
        // Test that clean JSON without any wrapper is parsed correctly
        let input = r#"[
            {"id": "H-001", "prediction": "test", "verification_method": "cmd", "tests_error_handling": true},
            {"id": "H-002", "prediction": "test2", "verification_method": "cmd2", "tests_error_handling": false},
            {"id": "H-003", "prediction": "test3", "verification_method": "cmd3", "tests_error_handling": false}
        ]"#;
        let result = parse_ai_response(input);
        assert!(result.is_ok(), "Should parse clean JSON directly");
        assert_eq!(result.unwrap().len(), 3);
    }

    #[test]
    fn test_parse_ai_response_with_whitespace() {
        // Test that JSON with leading/trailing whitespace is parsed correctly
        let input = "  \n\n  [{\"id\": \"H-001\", \"prediction\": \"test\", \"verification_method\": \"cmd\", \"tests_error_handling\": true}, {\"id\": \"H-002\", \"prediction\": \"test2\", \"verification_method\": \"cmd2\", \"tests_error_handling\": false}, {\"id\": \"H-003\", \"prediction\": \"test3\", \"verification_method\": \"cmd3\", \"tests_error_handling\": false}]  \n\n  ";
        let result = parse_ai_response(input);
        assert!(
            result.is_ok(),
            "Should parse JSON with surrounding whitespace"
        );
    }

    #[test]
    fn test_parse_ai_response_brackets_in_verification_method() {
        // Test that brackets in verification_method (e.g., regex) don't break parsing
        let input = r#"[
            {"id": "H-001", "prediction": "Pattern matches", "verification_method": "grep '[0-9]+' file.txt", "tests_error_handling": false},
            {"id": "H-002", "prediction": "Error on invalid", "verification_method": "echo '[error]'", "tests_error_handling": true},
            {"id": "H-003", "prediction": "Build works", "verification_method": "cargo build", "tests_error_handling": false}
        ]"#;
        let result = parse_ai_response(input);
        assert!(
            result.is_ok(),
            "Should handle brackets in verification_method"
        );
        let hypotheses = result.unwrap();
        assert_eq!(hypotheses[0].verification_method, "grep '[0-9]+' file.txt");
    }

    #[test]
    fn test_ai_tool_timeout_is_reasonable() {
        // Document and verify the timeout constant is reasonable
        // 5 minutes should be enough for most AI tool invocations
        // but not so long that hung processes block CI indefinitely
        assert_eq!(AI_TOOL_TIMEOUT.as_secs(), 300);
        assert!(
            AI_TOOL_TIMEOUT.as_secs() >= 60,
            "Timeout should be at least 1 minute"
        );
        assert!(
            AI_TOOL_TIMEOUT.as_secs() <= 600,
            "Timeout should not exceed 10 minutes"
        );
    }

    #[test]
    fn test_raw_hypothesis_rejects_unknown_fields() {
        // Verify that RawHypothesis with deny_unknown_fields rejects extra fields
        let input_with_extra = r#"{"id": "H-001", "prediction": "test", "verification_method": "cmd", "tests_error_handling": true, "extra_field": "should fail"}"#;
        let result: Result<RawHypothesis, _> = serde_json::from_str(input_with_extra);
        assert!(result.is_err(), "Should reject unknown fields");
        assert!(
            result.unwrap_err().to_string().contains("unknown field"),
            "Error should mention unknown field"
        );
    }

    // -------------------------------------------------------------------------
    // Input variation helper tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_cli_command_cargo() {
        assert!(is_cli_command("cargo test"));
        assert!(is_cli_command("cargo build --release"));
        assert!(is_cli_command("cargo xtask aat <PR_URL>"));
    }

    #[test]
    fn test_is_cli_command_git_excluded() {
        // SECURITY: git is excluded from allowlist to prevent credential access
        // via git-credential helpers and git config
        assert!(!is_cli_command("git status"));
        assert!(!is_cli_command("git commit -m 'message'"));
    }

    #[test]
    fn test_is_cli_command_shell_prompt() {
        assert!(is_cli_command("$ cargo test"));
        // SECURITY: git is excluded even with shell prompt prefix
        assert!(!is_cli_command("$ git status"));
    }

    #[test]
    fn test_is_cli_command_relative_path_excluded() {
        // SECURITY: ./ paths are excluded to prevent RCE via local scripts
        // from untrusted PR branches
        assert!(!is_cli_command("./run_tests.sh"));
        assert!(!is_cli_command("./scripts/verify.sh"));
    }

    #[test]
    fn test_is_cli_command_gh_excluded() {
        // SECURITY: gh is excluded to prevent token exfiltration via `gh auth token`
        assert!(!is_cli_command("gh auth token"));
        assert!(!is_cli_command("gh pr view 123"));
    }

    #[test]
    fn test_is_cli_command_not_command() {
        assert!(!is_cli_command("This is just text"));
        assert!(!is_cli_command("Output: success"));
        assert!(!is_cli_command("# Comment"));
    }

    #[test]
    fn test_extract_commands_from_usage_code_block() {
        use crate::aat::types::ParsedPRDescription;

        let parsed = ParsedPRDescription {
            usage: r"
Run the command:

```bash
cargo xtask aat https://github.com/owner/repo/pull/123
cargo test --lib
```

Then verify the output.
"
            .to_string(),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let commands = extract_commands_from_usage(&parsed);
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("cargo xtask aat"));
        assert!(commands[1].contains("cargo test"));
    }

    #[test]
    fn test_extract_commands_from_usage_skips_comments() {
        use crate::aat::types::ParsedPRDescription;

        let parsed = ParsedPRDescription {
            usage: r"
```bash
# This is a comment
cargo build
# Another comment
```
"
            .to_string(),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let commands = extract_commands_from_usage(&parsed);
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0], "cargo build");
    }

    #[test]
    fn test_extract_commands_from_usage_empty() {
        use crate::aat::types::ParsedPRDescription;

        let parsed = ParsedPRDescription {
            usage: "No code blocks here, just prose explaining the feature.".to_string(),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let commands = extract_commands_from_usage(&parsed);
        assert!(commands.is_empty());
    }

    #[test]
    fn test_extract_commands_from_usage_inline_commands() {
        use crate::aat::types::ParsedPRDescription;

        let parsed = ParsedPRDescription {
            usage: r"
To run, use:
$ cargo build
$ cargo test
"
            .to_string(),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let commands = extract_commands_from_usage(&parsed);
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("cargo build"));
        assert!(commands[1].contains("cargo test"));
    }

    #[test]
    fn test_extract_commands_enforces_limit() {
        use crate::aat::types::ParsedPRDescription;

        // Create a usage section with more commands than MAX_COMMANDS_PER_PR
        // to test DoS protection
        let many_commands: String = (0..20)
            .map(|i| format!("cargo test --test test_{i}"))
            .collect::<Vec<_>>()
            .join("\n");

        let parsed = ParsedPRDescription {
            usage: format!(
                r"
Run the tests:

```bash
{many_commands}
```
"
            ),
            expected_outcomes: vec![],
            evidence_script: None,
            known_limitations: vec![],
        };

        let commands = extract_commands_from_usage(&parsed);

        // Should be limited to MAX_COMMANDS_PER_PR
        assert_eq!(
            commands.len(),
            MAX_COMMANDS_PER_PR,
            "Should enforce limit of {} commands, got {}",
            MAX_COMMANDS_PER_PR,
            commands.len()
        );
    }

    /// Compile-time assertion that `MAX_COMMANDS_PER_PR` is reasonable.
    const _: () = {
        assert!(MAX_COMMANDS_PER_PR >= 5); // Allow reasonable use cases
        assert!(MAX_COMMANDS_PER_PR <= 20); // Prevent excessive execution
    };

    #[test]
    fn test_max_commands_constant_value() {
        // Document and verify the constant value at runtime:
        // 10 commands * 3 variations * 30s timeout = 15 minutes max execution
        assert_eq!(MAX_COMMANDS_PER_PR, 10);
    }
}
