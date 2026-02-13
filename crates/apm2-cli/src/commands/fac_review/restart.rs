//! Intelligent pipeline restart: uses local authoritative FAC artifacts to
//! re-enter the DAG at the optimal point (evidence gates, review dispatch, or
//! noop).

use serde::Serialize;

use super::barrier::fetch_pr_head_sha_local;
use super::dispatch::dispatch_single_review;
use super::evidence::run_evidence_gates_with_status;
use super::projection_store;
use super::state::load_review_run_completion_receipt;
use super::target::resolve_pr_target;
use super::types::{DispatchReviewResult, ReviewKind, validate_expected_head_sha};
use crate::exit_codes::codes as exit_codes;

// ── Strategy ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartStrategy {
    /// Re-run everything: evidence gates + review dispatch.
    FullRestart,
    /// Re-run evidence gates (some failed or still running), then dispatch
    /// reviews if gates pass.
    EvidenceRestart,
    /// Everything already passed — nothing to do.
    Noop,
}

impl RestartStrategy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::FullRestart => "full_restart",
            Self::EvidenceRestart => "evidence_restart",
            Self::Noop => "noop",
        }
    }
}

// ── Summary ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct RestartSummary {
    pub repo: String,
    pub pr_number: u32,
    pub pr_url: String,
    pub head_sha: String,
    pub strategy: RestartStrategy,
    pub evidence_passed: Option<bool>,
    pub reviews_dispatched: Option<Vec<DispatchReviewResult>>,
}

// ── PR context resolution ───────────────────────────────────────────────────

struct PrContext {
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
}

fn resolve_pr_context(repo: &str, pr: Option<u32>) -> Result<PrContext, String> {
    let (owner_repo, pr_number) = resolve_pr_target(repo, pr)?;
    let head_sha = resolve_head_sha_for_restart(&owner_repo, pr_number)?;

    Ok(PrContext {
        owner_repo,
        pr_number,
        head_sha,
    })
}

fn resolve_head_sha_for_restart(owner_repo: &str, pr_number: u32) -> Result<String, String> {
    let head_sha = fetch_pr_head_sha_local(pr_number)?;
    if let Some(identity) = projection_store::load_pr_identity(owner_repo, pr_number)? {
        validate_expected_head_sha(&identity.head_sha)?;
        if !identity.head_sha.eq_ignore_ascii_case(&head_sha) {
            return Err(format!(
                "local PR identity head {} is stale relative to authoritative PR head {head_sha}; refresh local FAC projection first",
                identity.head_sha
            ));
        }
    }
    validate_expected_head_sha(&head_sha)?;
    Ok(head_sha.to_ascii_lowercase())
}

fn receipt_approves_head(
    receipt: Option<&super::state::ReviewRunCompletionReceipt>,
    owner_repo: &str,
    head_sha: &str,
) -> bool {
    let Some(receipt) = receipt else {
        return false;
    };
    receipt.repo.eq_ignore_ascii_case(owner_repo)
        && receipt.head_sha.eq_ignore_ascii_case(head_sha)
        && receipt.decision.eq_ignore_ascii_case("approve")
}

fn determine_restart_strategy(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    force: bool,
) -> Result<RestartStrategy, String> {
    if force {
        return Ok(RestartStrategy::FullRestart);
    }

    let security_receipt = load_review_run_completion_receipt(pr_number, "security")?;
    let quality_receipt = load_review_run_completion_receipt(pr_number, "quality")?;

    if receipt_approves_head(security_receipt.as_ref(), owner_repo, head_sha)
        && receipt_approves_head(quality_receipt.as_ref(), owner_repo, head_sha)
    {
        return Ok(RestartStrategy::Noop);
    }

    Ok(RestartStrategy::EvidenceRestart)
}

// ── Execution ───────────────────────────────────────────────────────────────

fn execute_strategy(
    strategy: RestartStrategy,
    ctx: &PrContext,
) -> Result<(Option<bool>, Option<Vec<DispatchReviewResult>>), String> {
    match strategy {
        RestartStrategy::Noop => Ok((None, None)),

        RestartStrategy::EvidenceRestart | RestartStrategy::FullRestart => {
            let workspace_root =
                std::env::current_dir().map_err(|e| format!("failed to resolve cwd: {e}"))?;

            let passed = run_evidence_gates_with_status(
                &workspace_root,
                &ctx.head_sha,
                &ctx.owner_repo,
                ctx.pr_number,
                None,
            )?;

            if passed {
                let reviews = dispatch_reviews(&ctx.owner_repo, ctx.pr_number, &ctx.head_sha)?;
                Ok((Some(true), Some(reviews)))
            } else {
                Ok((Some(false), None))
            }
        },
    }
}

fn dispatch_reviews(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<Vec<DispatchReviewResult>, String> {
    let dispatch_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut results = Vec::with_capacity(2);
    for kind in [ReviewKind::Security, ReviewKind::Quality] {
        let result = dispatch_single_review(owner_repo, pr_number, kind, head_sha, dispatch_epoch)?;
        results.push(result);
    }
    Ok(results)
}

// ── Public entry point ──────────────────────────────────────────────────────

pub fn run_restart(repo: &str, pr: Option<u32>, force: bool, json_output: bool) -> u8 {
    match run_restart_inner(repo, pr, force) {
        Ok(summary) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("FAC Restart");
                println!("  Repo:          {}", summary.repo);
                println!("  PR:            #{}", summary.pr_number);
                println!("  Head SHA:      {}", summary.head_sha);
                println!("  Strategy:      {}", summary.strategy.label());
                if let Some(passed) = summary.evidence_passed {
                    println!("  Evidence:      {}", if passed { "PASS" } else { "FAIL" });
                }
                if let Some(ref reviews) = summary.reviews_dispatched {
                    for r in reviews {
                        println!(
                            "  Review:        {} ({}{}{})",
                            r.review_type,
                            r.mode,
                            r.pid.map_or_else(String::new, |p| format!(", pid={p}")),
                            r.log_file
                                .as_ref()
                                .map_or_else(String::new, |l| format!(", log={l}")),
                        );
                    }
                }
            }

            let failed = summary.evidence_passed == Some(false);
            if failed {
                exit_codes::GENERIC_ERROR
            } else {
                exit_codes::SUCCESS
            }
        },
        Err(err) => {
            if json_output {
                let payload = serde_json::json!({
                    "error": "fac_restart_failed",
                    "message": err,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
            } else {
                eprintln!("ERROR: {err}");
            }
            exit_codes::GENERIC_ERROR
        },
    }
}

fn run_restart_inner(repo: &str, pr: Option<u32>, force: bool) -> Result<RestartSummary, String> {
    let ctx = resolve_pr_context(repo, pr)?;

    eprintln!(
        "fac restart: pr=#{} sha={} repo={}",
        ctx.pr_number, ctx.head_sha, ctx.owner_repo
    );

    let strategy =
        determine_restart_strategy(&ctx.owner_repo, ctx.pr_number, &ctx.head_sha, force)?;
    eprintln!("fac restart: strategy={}", strategy.label());

    let (evidence_passed, reviews_dispatched) = execute_strategy(strategy, &ctx)?;
    let pr_url = format!(
        "https://github.com/{}/pull/{}",
        ctx.owner_repo, ctx.pr_number
    );

    Ok(RestartSummary {
        repo: ctx.owner_repo.clone(),
        pr_number: ctx.pr_number,
        pr_url,
        head_sha: ctx.head_sha,
        strategy,
        evidence_passed,
        reviews_dispatched,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::fac_review::state::ReviewRunCompletionReceipt;

    fn sample_completion(decision: &str, head_sha: &str) -> ReviewRunCompletionReceipt {
        ReviewRunCompletionReceipt {
            schema: super::super::state::COMPLETION_RECEIPT_SCHEMA.to_string(),
            emitted_at: "2026-02-13T00:00:00Z".to_string(),
            repo: "guardian-intelligence/apm2".to_string(),
            pr_number: 1,
            review_type: "security".to_string(),
            run_id: "pr1-security-s1-01234567".to_string(),
            head_sha: head_sha.to_string(),
            decision: decision.to_string(),
            decision_comment_id: 1,
            decision_author: "reviewer".to_string(),
            decision_summary: "security:approve|code-quality:approve".to_string(),
            integrity_hmac: "abcd".to_string(),
        }
    }

    #[test]
    fn test_receipt_approves_head_requires_matching_sha_and_approve() {
        let head = "0123456789abcdef0123456789abcdef01234567";
        let approve = sample_completion("approve", head);
        assert!(receipt_approves_head(
            Some(&approve),
            "guardian-intelligence/apm2",
            head
        ));

        let deny = sample_completion("deny", head);
        assert!(!receipt_approves_head(
            Some(&deny),
            "guardian-intelligence/apm2",
            head
        ));

        let mismatch = sample_completion("approve", "fedcba9876543210fedcba9876543210fedcba98");
        assert!(!receipt_approves_head(
            Some(&mismatch),
            "guardian-intelligence/apm2",
            head
        ));

        assert!(!receipt_approves_head(Some(&approve), "other/repo", head));
    }
}
