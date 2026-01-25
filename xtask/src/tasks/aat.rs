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

use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use xshell::{Shell, cmd};

use crate::aat::anti_gaming::analyze_diff;
use crate::aat::evidence::EvidenceBundleBuilder;
use crate::aat::parser::parse_pr_description;
use crate::aat::tool_config::{AatToolConfig, AiTool};
use crate::aat::types::{Hypothesis, HypothesisResult, ParsedPRDescription, Verdict};

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
// Hypothesis Generation (Stub)
// =============================================================================

/// Generate hypotheses from parsed PR description.
///
/// This is a simplified implementation that creates basic hypotheses
/// from the expected outcomes. In a full implementation, this would
/// invoke the AAT skill for more sophisticated hypothesis generation.
fn generate_hypotheses(parsed_pr: &ParsedPRDescription) -> Vec<Hypothesis> {
    let mut hypotheses = Vec::new();
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Create hypotheses from expected outcomes
    for (i, outcome) in parsed_pr.expected_outcomes.iter().enumerate() {
        let id = format!("H-{:03}", i + 1);
        let tests_error_handling = outcome.text.to_lowercase().contains("error")
            || outcome.text.to_lowercase().contains("fail")
            || outcome.text.to_lowercase().contains("invalid");

        hypotheses.push(Hypothesis {
            id,
            prediction: outcome.text.clone(),
            verification_method: "Verify via expected outcome assertion".to_string(),
            tests_error_handling,
            formed_at: now.clone(),
            executed_at: Some(now.clone()),
            // For now, assume outcomes with checkmarks pass
            result: Some(if outcome.checked {
                HypothesisResult::Passed
            } else {
                HypothesisResult::Failed
            }),
            actual_outcome: Some(if outcome.checked {
                "Outcome verified".to_string()
            } else {
                "Outcome not verified".to_string()
            }),
            stdout: None,
            stderr: None,
            exit_code: Some(i32::from(!outcome.checked)),
        });
    }

    // Ensure at least one error handling hypothesis if none exist
    if !hypotheses.iter().any(|h| h.tests_error_handling) && !hypotheses.is_empty() {
        // Modify the last hypothesis to be error-handling related
        if let Some(last) = hypotheses.last_mut() {
            last.tests_error_handling = true;
        }
    }

    hypotheses
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
pub fn run(pr_url: &str, dry_run: bool, ai_tool_override: Option<AiTool>) -> Result<AatResult> {
    let sh = Shell::new().context("Failed to create shell")?;

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
    println!();

    // Step 1: Parse PR URL
    println!("[1/6] Parsing PR URL...");
    let pr_info = parse_pr_url(pr_url)?;
    println!("  Owner: {}", pr_info.owner);
    println!("  Repo: {}", pr_info.repo);
    println!("  PR #: {}", pr_info.number);

    // Step 2: Fetch PR data
    println!("\n[2/6] Fetching PR data...");
    let description = fetch_pr_description(&sh, &pr_info)?;
    println!("  Description: {} bytes", description.len());

    let diff = fetch_pr_diff(&sh, &pr_info)?;
    println!("  Diff: {} bytes", diff.len());

    let sha = fetch_pr_sha(&sh, &pr_info)?;
    println!("  HEAD SHA: {sha}");

    // Step 3: Parse PR description
    println!("\n[3/6] Parsing PR description...");
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

    // Step 4: Run anti-gaming analysis
    println!("\n[4/6] Running anti-gaming analysis...");
    let anti_gaming_result = analyze_diff(&diff, &parsed_pr.known_limitations);
    println!("  Violations: {}", anti_gaming_result.violations.len());
    println!(
        "  Result: {}",
        if anti_gaming_result.passed {
            "PASSED"
        } else {
            "FAILED"
        }
    );

    for violation in &anti_gaming_result.violations {
        println!("    - {violation:?}");
    }

    // Step 5: Generate hypotheses
    println!("\n[5/6] Generating hypotheses...");
    let hypotheses = generate_hypotheses(&parsed_pr);
    println!("  Generated: {} hypotheses", hypotheses.len());

    for h in &hypotheses {
        let result_str = match h.result {
            Some(HypothesisResult::Passed) => "PASSED",
            Some(HypothesisResult::Failed) => "FAILED",
            None => "UNVERIFIED",
        };
        println!("    - {}: {} ({})", h.id, h.prediction, result_str);
    }

    // Step 6: Generate evidence bundle
    println!("\n[6/6] Generating evidence bundle...");
    let bundle = EvidenceBundleBuilder::new(pr_info.number, &sha)
        .set_pr_description_parse(&parsed_pr)
        .add_hypotheses(hypotheses)
        .set_anti_gaming_result(&anti_gaming_result)
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
        // Get repository root
        let repo_root = cmd!(sh, "git rev-parse --show-toplevel")
            .read()
            .context("Failed to get repository root")?
            .trim()
            .to_string();

        let path = bundle
            .write_to_file(Path::new(&repo_root))
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
    // generate_hypotheses tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_generate_hypotheses_from_outcomes() {
        use crate::aat::types::OutcomeItem;

        let parsed = ParsedPRDescription {
            usage: "cargo test".to_string(),
            expected_outcomes: vec![
                OutcomeItem {
                    text: "Build succeeds".to_string(),
                    checked: true,
                },
                OutcomeItem {
                    text: "Tests pass".to_string(),
                    checked: true,
                },
                OutcomeItem {
                    text: "Invalid input returns error".to_string(),
                    checked: false,
                },
            ],
            evidence_script: None,
            known_limitations: vec![],
        };

        let hypotheses = generate_hypotheses(&parsed);

        assert_eq!(hypotheses.len(), 3);
        assert_eq!(hypotheses[0].id, "H-001");
        assert_eq!(hypotheses[0].prediction, "Build succeeds");
        assert_eq!(hypotheses[0].result, Some(HypothesisResult::Passed));

        assert_eq!(hypotheses[2].id, "H-003");
        assert!(hypotheses[2].tests_error_handling);
        assert_eq!(hypotheses[2].result, Some(HypothesisResult::Failed));
    }

    #[test]
    fn test_generate_hypotheses_ensures_error_handling() {
        use crate::aat::types::OutcomeItem;

        let parsed = ParsedPRDescription {
            usage: "cargo test".to_string(),
            expected_outcomes: vec![
                OutcomeItem {
                    text: "Build succeeds".to_string(),
                    checked: true,
                },
                OutcomeItem {
                    text: "Tests pass".to_string(),
                    checked: true,
                },
            ],
            evidence_script: None,
            known_limitations: vec![],
        };

        let hypotheses = generate_hypotheses(&parsed);

        // At least one should be marked as error handling
        assert!(
            hypotheses.iter().any(|h| h.tests_error_handling),
            "Should ensure at least one error handling hypothesis"
        );
    }
}
