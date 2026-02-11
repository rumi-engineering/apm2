//! Intelligent pipeline restart: reads CI state and re-enters the DAG at the
//! optimal point (evidence gates, review dispatch, or noop).

use serde::Serialize;

use super::barrier::{fetch_pr_head_sha, resolve_authenticated_gh_login};
use super::ci_status::{CiStatus, find_status_comment};
use super::dispatch::dispatch_single_review;
use super::evidence::run_evidence_gates_with_status;
use super::target::resolve_pr_target;
use super::types::{DispatchReviewResult, ReviewKind};
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
    /// All evidence gates passed; only dispatch reviews.
    ReviewsOnly,
    /// Everything already passed — nothing to do.
    Noop,
}

impl RestartStrategy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::FullRestart => "full_restart",
            Self::EvidenceRestart => "evidence_restart",
            Self::ReviewsOnly => "reviews_only",
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
    pr_url: String,
    head_sha: String,
}

fn resolve_pr_context(
    repo: &str,
    pr: Option<u32>,
    pr_url: Option<&str>,
) -> Result<PrContext, String> {
    let (owner_repo, pr_number) = resolve_pr_target(repo, pr, pr_url)?;

    let pr_url_resolved = format!("https://github.com/{owner_repo}/pull/{pr_number}");
    let head_sha = fetch_pr_head_sha(&owner_repo, pr_number)?;

    Ok(PrContext {
        owner_repo,
        pr_number,
        pr_url: pr_url_resolved,
        head_sha,
    })
}

// ── Strategy determination ──────────────────────────────────────────────────

fn determine_restart_strategy(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    force: bool,
) -> Result<RestartStrategy, String> {
    if force {
        return Ok(RestartStrategy::FullRestart);
    }

    let expected_author_login = resolve_authenticated_gh_login();
    let Some(expected_author_login) = expected_author_login else {
        return Ok(RestartStrategy::FullRestart);
    };

    let status_opt = find_status_comment(
        owner_repo,
        pr_number,
        head_sha,
        Some(&expected_author_login),
    )?;
    let Some((_comment_id, status)) = status_opt else {
        // No status comment for this SHA — either never ran or SHA changed.
        return Ok(RestartStrategy::FullRestart);
    };

    Ok(analyze_ci_status(&status))
}

fn analyze_ci_status(status: &CiStatus) -> RestartStrategy {
    if status.gates.is_empty() {
        return RestartStrategy::FullRestart;
    }

    // Evidence gate names (must match evidence.rs gate definitions).
    let evidence_gates = [
        "merge_conflict_main",
        "rustfmt",
        "clippy",
        "doc",
        "test",
        "test_safety_guard",
        "workspace_integrity",
        "review_artifact_lint",
    ];

    let mut all_evidence_pass = true;
    let mut has_any_evidence = false;

    for gate_name in &evidence_gates {
        if let Some(gate) = status.gates.get(*gate_name) {
            has_any_evidence = true;
            if gate.status != "PASS" {
                all_evidence_pass = false;
                break;
            }
        }
    }

    if !has_any_evidence {
        // Status comment exists but no evidence gates recorded — full restart.
        return RestartStrategy::FullRestart;
    }

    if !all_evidence_pass {
        return RestartStrategy::EvidenceRestart;
    }

    // All evidence gates passed. Check review status.
    let review_gates = ["security_review", "quality_review"];
    let mut all_reviews_pass = true;
    let mut has_any_review = false;

    for gate_name in &review_gates {
        if let Some(gate) = status.gates.get(*gate_name) {
            has_any_review = true;
            if gate.status != "PASS" {
                all_reviews_pass = false;
            }
        }
    }

    if has_any_review && all_reviews_pass {
        return RestartStrategy::Noop;
    }

    // Evidence passed, reviews incomplete → dispatch reviews only.
    RestartStrategy::ReviewsOnly
}

// ── Execution ───────────────────────────────────────────────────────────────

fn execute_strategy(
    strategy: RestartStrategy,
    ctx: &PrContext,
) -> Result<(Option<bool>, Option<Vec<DispatchReviewResult>>), String> {
    match strategy {
        RestartStrategy::Noop => Ok((None, None)),

        RestartStrategy::ReviewsOnly => {
            let reviews =
                dispatch_reviews(&ctx.pr_url, &ctx.owner_repo, ctx.pr_number, &ctx.head_sha)?;
            Ok((None, Some(reviews)))
        },

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
                let reviews =
                    dispatch_reviews(&ctx.pr_url, &ctx.owner_repo, ctx.pr_number, &ctx.head_sha)?;
                Ok((Some(true), Some(reviews)))
            } else {
                Ok((Some(false), None))
            }
        },
    }
}

fn dispatch_reviews(
    pr_url: &str,
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
        let result = dispatch_single_review(
            pr_url,
            owner_repo,
            pr_number,
            kind,
            head_sha,
            dispatch_epoch,
        )?;
        results.push(result);
    }
    Ok(results)
}

// ── Public entry point ──────────────────────────────────────────────────────

pub fn run_restart(
    repo: &str,
    pr: Option<u32>,
    pr_url: Option<&str>,
    force: bool,
    json_output: bool,
) -> u8 {
    match run_restart_inner(repo, pr, pr_url, force) {
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

fn run_restart_inner(
    repo: &str,
    pr: Option<u32>,
    pr_url: Option<&str>,
    force: bool,
) -> Result<RestartSummary, String> {
    let ctx = resolve_pr_context(repo, pr, pr_url)?;

    eprintln!(
        "fac restart: pr=#{} sha={} repo={}",
        ctx.pr_number, ctx.head_sha, ctx.owner_repo
    );

    let strategy =
        determine_restart_strategy(&ctx.owner_repo, ctx.pr_number, &ctx.head_sha, force)?;
    eprintln!("fac restart: strategy={}", strategy.label());

    let (evidence_passed, reviews_dispatched) = execute_strategy(strategy, &ctx)?;

    Ok(RestartSummary {
        repo: ctx.owner_repo,
        pr_number: ctx.pr_number,
        pr_url: ctx.pr_url,
        head_sha: ctx.head_sha,
        strategy,
        evidence_passed,
        reviews_dispatched,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::commands::fac_review::ci_status::GateStatus;

    fn gate(status: &str) -> GateStatus {
        GateStatus {
            status: status.to_string(),
            duration_secs: Some(10),
            tokens_used: None,
            model: None,
        }
    }

    #[test]
    fn test_analyze_empty_gates_returns_full_restart() {
        let status = CiStatus {
            sha: "abc".to_string(),
            pr: 1,
            updated_at: "2025-01-01T00:00:00Z".to_string(),
            gates: BTreeMap::new(),
        };
        assert_eq!(analyze_ci_status(&status), RestartStrategy::FullRestart);
    }

    #[test]
    fn test_analyze_all_evidence_pass_no_reviews_returns_reviews_only() {
        let mut gates = BTreeMap::new();
        gates.insert("rustfmt".to_string(), gate("PASS"));
        gates.insert("clippy".to_string(), gate("PASS"));
        gates.insert("doc".to_string(), gate("PASS"));
        gates.insert("test".to_string(), gate("PASS"));
        let status = CiStatus {
            sha: "abc".to_string(),
            pr: 1,
            updated_at: "2025-01-01T00:00:00Z".to_string(),
            gates,
        };
        assert_eq!(analyze_ci_status(&status), RestartStrategy::ReviewsOnly);
    }

    #[test]
    fn test_analyze_evidence_fail_returns_evidence_restart() {
        let mut gates = BTreeMap::new();
        gates.insert("rustfmt".to_string(), gate("PASS"));
        gates.insert("clippy".to_string(), gate("FAIL"));
        gates.insert("doc".to_string(), gate("PASS"));
        gates.insert("test".to_string(), gate("PASS"));
        let status = CiStatus {
            sha: "abc".to_string(),
            pr: 1,
            updated_at: "2025-01-01T00:00:00Z".to_string(),
            gates,
        };
        assert_eq!(analyze_ci_status(&status), RestartStrategy::EvidenceRestart);
    }

    #[test]
    fn test_analyze_evidence_running_returns_evidence_restart() {
        let mut gates = BTreeMap::new();
        gates.insert("rustfmt".to_string(), gate("PASS"));
        gates.insert("clippy".to_string(), gate("RUNNING"));
        let status = CiStatus {
            sha: "abc".to_string(),
            pr: 1,
            updated_at: "2025-01-01T00:00:00Z".to_string(),
            gates,
        };
        assert_eq!(analyze_ci_status(&status), RestartStrategy::EvidenceRestart);
    }

    #[test]
    fn test_analyze_all_pass_returns_noop() {
        let mut gates = BTreeMap::new();
        gates.insert("rustfmt".to_string(), gate("PASS"));
        gates.insert("clippy".to_string(), gate("PASS"));
        gates.insert("doc".to_string(), gate("PASS"));
        gates.insert("test".to_string(), gate("PASS"));
        gates.insert("security_review".to_string(), gate("PASS"));
        gates.insert("quality_review".to_string(), gate("PASS"));
        let status = CiStatus {
            sha: "abc".to_string(),
            pr: 1,
            updated_at: "2025-01-01T00:00:00Z".to_string(),
            gates,
        };
        assert_eq!(analyze_ci_status(&status), RestartStrategy::Noop);
    }
}
