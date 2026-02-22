/// Unified error taxonomy for worker orchestration.
///
/// Every error path either:
/// - Requeues job safely (Recoverable)
/// - Leaves for runtime claimed reconcile (`NeedsReconcile`)
/// - Quarantines lane/job with explicit reason (`CorruptLane`, `QuarantineJob`)
/// - Reports a fatal startup/config error (Fatal)
#[derive(Debug)]
pub(super) enum OrchestrationError {
    /// Transient failure; job should be requeued to pending.
    Recoverable(String),
    /// Torn state requiring runtime claimed reconcile repair.
    NeedsReconcile(String),
    /// Lane is corrupt; mark with corrupt marker and skip.
    CorruptLane { lane_id: String, reason: String },
    /// Job should be quarantined with explicit reason.
    QuarantineJob { job_id: String, reason: String },
    /// Fatal startup/configuration error; worker should exit.
    Fatal(String),
}

impl std::fmt::Display for OrchestrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Recoverable(reason) => write!(f, "recoverable: {reason}"),
            Self::NeedsReconcile(reason) => write!(f, "needs_reconcile: {reason}"),
            Self::CorruptLane { lane_id, reason } => {
                write!(f, "corrupt_lane({lane_id}): {reason}")
            },
            Self::QuarantineJob { job_id, reason } => {
                write!(f, "quarantine_job({job_id}): {reason}")
            },
            Self::Fatal(reason) => write!(f, "fatal: {reason}"),
        }
    }
}

pub(super) fn classify_job_outcome_for_orchestration(
    job_id: &str,
    outcome: &super::types::JobOutcome,
) -> OrchestrationError {
    use super::types::{JobOutcome, JobSkipDisposition};

    match outcome {
        JobOutcome::Quarantined { reason } => OrchestrationError::QuarantineJob {
            job_id: job_id.to_string(),
            reason: reason.clone(),
        },
        JobOutcome::Denied { reason } => OrchestrationError::Recoverable(reason.clone()),
        JobOutcome::Completed { .. } => OrchestrationError::Recoverable("completed".to_string()),
        JobOutcome::Aborted { reason } => OrchestrationError::Fatal(reason.clone()),
        JobOutcome::Skipped {
            reason,
            disposition,
        } => match disposition {
            JobSkipDisposition::Generic => OrchestrationError::Recoverable(reason.clone()),
            JobSkipDisposition::NoLaneAvailable => OrchestrationError::CorruptLane {
                lane_id: "unassigned".to_string(),
                reason: reason.clone(),
            },
            JobSkipDisposition::PipelineCommitFailed => {
                OrchestrationError::NeedsReconcile(reason.clone())
            },
        },
    }
}
