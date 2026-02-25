//! PR-scoped repair cycle: uses local authoritative FAC artifacts to
//! re-enter the review DAG at the optimal point (evidence gates, review
//! dispatch, or noop).

use serde::Serialize;

use super::dispatch::resolve_worktree_for_sha;
use super::evidence::run_evidence_gates_with_status;
use super::projection::fetch_pr_head_sha_authoritative;
use super::state::load_review_run_completion_receipt;
use super::target::resolve_pr_target;
use super::types::{DispatchReviewResult, validate_expected_head_sha};
use super::{lifecycle, projection_store};

// ── Strategy ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairStrategy {
    /// Re-run everything: evidence gates + review dispatch.
    FullRepair,
    /// Re-run evidence gates (some failed or still running), then dispatch
    /// reviews if gates pass.
    EvidenceRepair,
    /// Re-dispatch reviewers without rerunning evidence gates.
    ///
    /// Used for projection-gap convergence when evidence receipts already
    /// approve the current head SHA, but projection-side artifacts (for
    /// example remote comment binding) require bounded repair.
    DispatchRepair,
    /// Everything already passed — nothing to do.
    Noop,
}

impl RepairStrategy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::FullRepair => "full_repair",
            Self::EvidenceRepair => "evidence_repair",
            Self::DispatchRepair => "dispatch_repair",
            Self::Noop => "noop",
        }
    }
}

// ── Summary ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct RepairCycleSummary {
    pub repo: String,
    pub pr_number: u32,
    pub pr_url: String,
    pub head_sha: String,
    pub refreshed_identity: bool,
    pub strategy: RepairStrategy,
    pub evidence_passed: Option<bool>,
    pub reviews_dispatched: Option<Vec<DispatchReviewResult>>,
}

// ── PR context resolution ───────────────────────────────────────────────────

struct PrContext {
    owner_repo: String,
    pr_number: u32,
    head_sha: String,
    refreshed_identity: bool,
}

fn resolve_pr_context(
    repo: &str,
    pr: Option<u32>,
    refresh_identity: bool,
) -> Result<PrContext, String> {
    let (owner_repo, pr_number) = resolve_pr_target(repo, pr)?;
    let (head_sha, refreshed_identity) =
        resolve_head_sha_for_repair(&owner_repo, pr_number, refresh_identity)?;

    Ok(PrContext {
        owner_repo,
        pr_number,
        head_sha,
        refreshed_identity,
    })
}

fn resolve_head_sha_for_repair(
    owner_repo: &str,
    pr_number: u32,
    refresh_identity: bool,
) -> Result<(String, bool), String> {
    let head_sha = fetch_pr_head_sha_authoritative(owner_repo, pr_number)?;
    let mut refreshed_identity = false;
    if refresh_identity {
        let should_refresh = match projection_store::load_pr_identity(owner_repo, pr_number)? {
            Some(identity) => !identity.head_sha.eq_ignore_ascii_case(&head_sha),
            None => true,
        };
        if should_refresh {
            projection_store::save_identity_with_context(
                owner_repo,
                pr_number,
                &head_sha,
                "doctor_fix.refresh_identity",
            )
            .map_err(|err| format!("failed to refresh local projection identity: {err}"))?;
            refreshed_identity = true;
        }
    }
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
    Ok((head_sha.to_ascii_lowercase(), refreshed_identity))
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

fn determine_repair_strategy(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    force: bool,
) -> Result<RepairStrategy, String> {
    let security_receipt = load_review_run_completion_receipt(pr_number, "security")?;
    let quality_receipt = load_review_run_completion_receipt(pr_number, "quality")?;

    let strategy = determine_repair_strategy_from_receipts(
        owner_repo,
        head_sha,
        force,
        security_receipt.as_ref(),
        quality_receipt.as_ref(),
    );
    if strategy != RepairStrategy::Noop {
        return Ok(strategy);
    }

    let projection_snapshot = super::verdict_projection::load_verdict_projection_snapshot(
        owner_repo, pr_number, head_sha,
    )?;
    Ok(promote_noop_strategy_for_projection_gap(
        strategy,
        projection_snapshot.as_ref(),
    ))
}

fn determine_repair_strategy_from_receipts(
    owner_repo: &str,
    head_sha: &str,
    force: bool,
    security_receipt: Option<&super::state::ReviewRunCompletionReceipt>,
    quality_receipt: Option<&super::state::ReviewRunCompletionReceipt>,
) -> RepairStrategy {
    if force {
        return RepairStrategy::FullRepair;
    }

    if receipt_approves_head(security_receipt, owner_repo, head_sha)
        && receipt_approves_head(quality_receipt, owner_repo, head_sha)
    {
        return RepairStrategy::Noop;
    }

    RepairStrategy::EvidenceRepair
}

fn projection_has_dimension_approve(
    snapshot: &super::verdict_projection::VerdictProjectionSnapshot,
    dimension: &str,
) -> bool {
    snapshot.dimensions.iter().any(|entry| {
        entry.dimension.eq_ignore_ascii_case(dimension)
            && entry.decision.eq_ignore_ascii_case("approve")
    })
}

fn projection_has_remote_comment_binding(
    snapshot: &super::verdict_projection::VerdictProjectionSnapshot,
) -> bool {
    super::verdict_projection::has_remote_comment_binding(
        snapshot.source_comment_id,
        snapshot.source_comment_url.as_deref(),
    )
}

fn projection_snapshot_requires_dispatch_repair(
    snapshot: Option<&super::verdict_projection::VerdictProjectionSnapshot>,
) -> bool {
    let Some(snapshot) = snapshot else {
        return true;
    };
    if snapshot.fail_closed {
        return true;
    }
    if !projection_has_dimension_approve(snapshot, "security")
        || !projection_has_dimension_approve(snapshot, "code-quality")
    {
        return true;
    }
    !projection_has_remote_comment_binding(snapshot)
}

fn promote_noop_strategy_for_projection_gap(
    strategy: RepairStrategy,
    snapshot: Option<&super::verdict_projection::VerdictProjectionSnapshot>,
) -> RepairStrategy {
    if strategy != RepairStrategy::Noop {
        return strategy;
    }
    if projection_snapshot_requires_dispatch_repair(snapshot) {
        RepairStrategy::DispatchRepair
    } else {
        RepairStrategy::Noop
    }
}

fn apply_repair_gate_lifecycle_events_with<F>(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    passed: bool,
    mut apply_event_fn: F,
) -> Result<(), String>
where
    F: FnMut(lifecycle::LifecycleEventKind) -> Result<(), String>,
{
    let final_event = if passed {
        lifecycle::LifecycleEventKind::GatesPassed
    } else {
        lifecycle::LifecycleEventKind::GatesFailed
    };
    for (event_name, event) in [
        ("push_observed", lifecycle::LifecycleEventKind::PushObserved),
        ("gates_started", lifecycle::LifecycleEventKind::GatesStarted),
        (
            if passed {
                "gates_passed"
            } else {
                "gates_failed"
            },
            final_event,
        ),
    ] {
        apply_event_fn(event).map_err(|err| {
            format!(
                "failed to record repair lifecycle event {event_name} for PR #{pr_number} SHA {head_sha} repo {owner_repo}: {err}"
            )
        })?;
    }
    Ok(())
}

fn apply_repair_gate_lifecycle_events(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    passed: bool,
) -> Result<(), String> {
    apply_repair_gate_lifecycle_events_with(owner_repo, pr_number, head_sha, passed, |event| {
        lifecycle::apply_event(owner_repo, pr_number, head_sha, &event).map(|_| ())
    })
}

// ── Execution ───────────────────────────────────────────────────────────────

fn execute_strategy(
    strategy: RepairStrategy,
    ctx: &PrContext,
    emit_human_logs: bool,
) -> Result<(Option<bool>, Option<Vec<DispatchReviewResult>>), String> {
    match strategy {
        RepairStrategy::Noop => Ok((None, None)),
        RepairStrategy::DispatchRepair => {
            let projection_repair = lifecycle::reconcile_projection_gap_for_head(
                &ctx.owner_repo,
                ctx.pr_number,
                &ctx.head_sha,
                "doctor_fix_projection_gap",
            )?;

            if projection_repair.converged() {
                return Ok((None, None));
            }

            let reviews = dispatch_reviews(
                &ctx.owner_repo,
                ctx.pr_number,
                &ctx.head_sha,
                strategy_forces_dispatch_retry(strategy),
            )?;
            Ok((None, Some(reviews)))
        },

        RepairStrategy::EvidenceRepair | RepairStrategy::FullRepair => {
            let workspace_root = resolve_worktree_for_sha(&ctx.head_sha)?;

            let (passed, _) = run_evidence_gates_with_status(
                &workspace_root,
                &ctx.head_sha,
                &ctx.owner_repo,
                ctx.pr_number,
                None,
                emit_human_logs,
                None,
            )?;

            apply_repair_gate_lifecycle_events(
                &ctx.owner_repo,
                ctx.pr_number,
                &ctx.head_sha,
                passed,
            )?;

            if passed {
                let reviews = dispatch_reviews(
                    &ctx.owner_repo,
                    ctx.pr_number,
                    &ctx.head_sha,
                    strategy_forces_dispatch_retry(strategy),
                )?;
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
    force_same_sha_retry: bool,
) -> Result<Vec<DispatchReviewResult>, String> {
    super::dispatch_reviews_with_lifecycle(owner_repo, pr_number, head_sha, force_same_sha_retry)
}

const fn strategy_forces_dispatch_retry(strategy: RepairStrategy) -> bool {
    matches!(
        strategy,
        RepairStrategy::FullRepair | RepairStrategy::DispatchRepair
    )
}

fn run_repair_inner(
    repo: &str,
    pr: Option<u32>,
    force: bool,
    refresh_identity: bool,
) -> Result<RepairCycleSummary, String> {
    let ctx = resolve_pr_context(repo, pr, refresh_identity)?;

    let strategy = determine_repair_strategy(&ctx.owner_repo, ctx.pr_number, &ctx.head_sha, force)?;

    let (evidence_passed, reviews_dispatched) = execute_strategy(strategy, &ctx, false)?;
    let pr_url = format!(
        "https://github.com/{}/pull/{}",
        ctx.owner_repo, ctx.pr_number
    );

    Ok(RepairCycleSummary {
        repo: ctx.owner_repo.clone(),
        pr_number: ctx.pr_number,
        pr_url,
        head_sha: ctx.head_sha,
        refreshed_identity: ctx.refreshed_identity,
        strategy,
        evidence_passed,
        reviews_dispatched,
    })
}

pub(super) fn run_repair_for_doctor_fix(
    repo: &str,
    pr_number: u32,
    force: bool,
    refresh_identity: bool,
) -> Result<RepairCycleSummary, String> {
    run_repair_inner(repo, Some(pr_number), force, refresh_identity)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::fac_review::state::ReviewRunCompletionReceipt;
    use crate::commands::fac_review::verdict_projection::{
        VerdictProjectionDimensionSnapshot, VerdictProjectionSnapshot,
    };

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

    #[test]
    fn repair_lifecycle_events_success_sequence() {
        let mut seen = Vec::new();
        apply_repair_gate_lifecycle_events_with(
            "guardian-intelligence/apm2",
            767,
            "0123456789abcdef0123456789abcdef01234567",
            true,
            |event| {
                let name = match event {
                    lifecycle::LifecycleEventKind::PushObserved => "push_observed",
                    lifecycle::LifecycleEventKind::GatesStarted => "gates_started",
                    lifecycle::LifecycleEventKind::GatesPassed => "gates_passed",
                    _ => "unexpected",
                };
                seen.push(name.to_string());
                Ok(())
            },
        )
        .expect("repair lifecycle success sequence should apply");
        assert_eq!(seen, vec!["push_observed", "gates_started", "gates_passed"]);
    }

    #[test]
    fn repair_lifecycle_events_failure_sequence() {
        let mut seen = Vec::new();
        apply_repair_gate_lifecycle_events_with(
            "guardian-intelligence/apm2",
            767,
            "0123456789abcdef0123456789abcdef01234567",
            false,
            |event| {
                let name = match event {
                    lifecycle::LifecycleEventKind::PushObserved => "push_observed",
                    lifecycle::LifecycleEventKind::GatesStarted => "gates_started",
                    lifecycle::LifecycleEventKind::GatesFailed => "gates_failed",
                    _ => "unexpected",
                };
                seen.push(name.to_string());
                Ok(())
            },
        )
        .expect("repair lifecycle failure sequence should apply");
        assert_eq!(seen, vec!["push_observed", "gates_started", "gates_failed"]);
    }

    #[test]
    fn repair_lifecycle_events_propagate_transition_errors() {
        let err = apply_repair_gate_lifecycle_events_with(
            "guardian-intelligence/apm2",
            767,
            "0123456789abcdef0123456789abcdef01234567",
            true,
            |event| {
                if matches!(event, lifecycle::LifecycleEventKind::GatesStarted) {
                    Err("illegal transition: pushed + gates_started".to_string())
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("transition failure should bubble");
        assert!(err.contains("gates_started"));
        assert!(err.contains("illegal transition"));
    }

    #[test]
    fn determine_repair_strategy_uses_force_to_trigger_full_repair() {
        let head = "0123456789abcdef0123456789abcdef01234567";
        let strategy = determine_repair_strategy_from_receipts(
            "guardian-intelligence/apm2",
            head,
            true,
            None,
            None,
        );
        assert_eq!(strategy, RepairStrategy::FullRepair);
    }

    #[test]
    fn determine_repair_strategy_noops_when_both_receipts_approve_current_head() {
        let head = "0123456789abcdef0123456789abcdef01234567";
        let security = sample_completion("approve", head);
        let mut quality = sample_completion("approve", head);
        quality.review_type = "quality".to_string();

        let strategy = determine_repair_strategy_from_receipts(
            "guardian-intelligence/apm2",
            head,
            false,
            Some(&security),
            Some(&quality),
        );
        assert_eq!(strategy, RepairStrategy::Noop);
    }

    #[test]
    fn determine_repair_strategy_repairs_when_any_receipt_missing_or_non_approve() {
        let head = "0123456789abcdef0123456789abcdef01234567";
        let security = sample_completion("approve", head);
        let mut quality = sample_completion("deny", head);
        quality.review_type = "quality".to_string();

        let denied = determine_repair_strategy_from_receipts(
            "guardian-intelligence/apm2",
            head,
            false,
            Some(&security),
            Some(&quality),
        );
        assert_eq!(denied, RepairStrategy::EvidenceRepair);

        let missing = determine_repair_strategy_from_receipts(
            "guardian-intelligence/apm2",
            head,
            false,
            Some(&security),
            None,
        );
        assert_eq!(missing, RepairStrategy::EvidenceRepair);
    }

    #[test]
    fn strategy_forces_dispatch_retry_for_full_and_dispatch_repair() {
        assert!(strategy_forces_dispatch_retry(RepairStrategy::FullRepair));
        assert!(strategy_forces_dispatch_retry(
            RepairStrategy::DispatchRepair
        ));
        assert!(!strategy_forces_dispatch_retry(
            RepairStrategy::EvidenceRepair
        ));
        assert!(!strategy_forces_dispatch_retry(RepairStrategy::Noop));
    }

    fn sample_projection_snapshot(
        fail_closed: bool,
        security_decision: &str,
        quality_decision: &str,
        comment_id: Option<u64>,
        comment_url: Option<&str>,
    ) -> VerdictProjectionSnapshot {
        VerdictProjectionSnapshot {
            schema: "apm2.review.decision.v1".to_string(),
            pr_number: 42,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            overall_decision: "approve".to_string(),
            fail_closed,
            dimensions: vec![
                VerdictProjectionDimensionSnapshot {
                    dimension: "security".to_string(),
                    decision: security_decision.to_string(),
                    reviewed_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
                    reason: String::new(),
                    reviewed_by: "reviewer-security".to_string(),
                    reviewed_at: "2026-02-14T00:00:00Z".to_string(),
                    model_id: None,
                    backend_id: None,
                },
                VerdictProjectionDimensionSnapshot {
                    dimension: "code-quality".to_string(),
                    decision: quality_decision.to_string(),
                    reviewed_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
                    reason: String::new(),
                    reviewed_by: "reviewer-quality".to_string(),
                    reviewed_at: "2026-02-14T00:00:00Z".to_string(),
                    model_id: None,
                    backend_id: None,
                },
            ],
            errors: Vec::new(),
            source_comment_id: comment_id,
            source_comment_url: comment_url.map(ToString::to_string),
            updated_at: "2026-02-14T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn promote_noop_strategy_for_projection_gap_requires_snapshot() {
        let strategy = promote_noop_strategy_for_projection_gap(RepairStrategy::Noop, None);
        assert_eq!(strategy, RepairStrategy::DispatchRepair);
    }

    #[test]
    fn promote_noop_strategy_for_projection_gap_requires_remote_comment_binding() {
        let projection = sample_projection_snapshot(
            false,
            "approve",
            "approve",
            Some(321),
            Some("local://fac_projection/guardian-intelligence/apm2/pr-42/issue_comments#321"),
        );
        let strategy =
            promote_noop_strategy_for_projection_gap(RepairStrategy::Noop, Some(&projection));
        assert_eq!(strategy, RepairStrategy::DispatchRepair);
    }

    #[test]
    fn promote_noop_strategy_for_projection_gap_accepts_authoritative_projection() {
        let projection = sample_projection_snapshot(
            false,
            "approve",
            "approve",
            Some(654_321),
            Some("https://github.com/guardian-intelligence/apm2/pull/42#issuecomment-654321"),
        );
        let strategy =
            promote_noop_strategy_for_projection_gap(RepairStrategy::Noop, Some(&projection));
        assert_eq!(strategy, RepairStrategy::Noop);
    }

    #[test]
    fn promote_noop_strategy_for_projection_gap_repairs_on_non_approve_dimension() {
        let projection = sample_projection_snapshot(
            false,
            "approve",
            "pending",
            Some(654_321),
            Some("https://github.com/guardian-intelligence/apm2/pull/42#issuecomment-654321"),
        );
        let strategy =
            promote_noop_strategy_for_projection_gap(RepairStrategy::Noop, Some(&projection));
        assert_eq!(strategy, RepairStrategy::DispatchRepair);
    }
}
