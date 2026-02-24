//! Effect idempotency fence contracts for orchestrator execution.

/// Durable effect execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectExecutionState {
    /// Effect has not been dispatched.
    NotStarted,
    /// Effect dispatch started but is not known complete.
    Started,
    /// Effect completion was durably recorded.
    Completed,
    /// Crash-window ambiguity: started without known completion.
    Unknown,
}

/// Resolution of an in-doubt (`Unknown`) effect state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InDoubtResolution {
    /// Explicit deny (fail-closed).
    Deny {
        /// Diagnostic reason.
        reason: String,
    },
    /// Explicit allow for re-execution.
    AllowReExecution,
}

/// Durable effect journal contract used by the Execute phase.
#[allow(async_fn_in_trait)]
pub trait EffectJournal<Key>: Send + Sync {
    /// Journal-specific error type.
    type Error;

    /// Queries the current execution state for `key`.
    async fn query_state(&self, key: &Key) -> Result<EffectExecutionState, Self::Error>;

    /// Durably records that execution started for `key`.
    async fn record_started(&self, key: &Key) -> Result<(), Self::Error>;

    /// Durably records that execution completed for `key`.
    async fn record_completed(&self, key: &Key) -> Result<(), Self::Error>;

    /// Durably clears a pre-dispatch started fence for `key` when execute
    /// exits with `Retry` before any external side effect dispatch.
    ///
    /// Implementations MUST fail-closed if `key` is not in a retryable
    /// pre-dispatch state.
    async fn record_retryable(&self, key: &Key) -> Result<(), Self::Error>;

    /// Resolves in-doubt state for `key`.
    ///
    /// Implementations MUST be explicit and fail-closed on ambiguity.
    async fn resolve_in_doubt(&self, key: &Key) -> Result<InDoubtResolution, Self::Error>;
}

/// Output release policy at the orchestration boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputReleasePolicy {
    /// Deny output release on ambiguity (`Unknown`).
    FailClosed,
    /// Monitor-only mode.
    Monitor,
}

/// Output release denial.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("output release denied: {reason}")]
pub struct OutputReleaseDenied {
    /// Diagnostic reason.
    pub reason: String,
}

/// Fail-closed output release helper.
#[allow(clippy::missing_errors_doc)]
pub fn check_output_release_permitted(
    state: EffectExecutionState,
    policy: OutputReleasePolicy,
) -> Result<(), OutputReleaseDenied> {
    match (state, policy) {
        (EffectExecutionState::Unknown, OutputReleasePolicy::FailClosed) => {
            Err(OutputReleaseDenied {
                reason:
                    "effect execution state is unknown; explicit in-doubt resolution is required"
                        .to_string(),
            })
        },
        (EffectExecutionState::Started, OutputReleasePolicy::FailClosed) => {
            Err(OutputReleaseDenied {
                reason:
                    "effect execution is still started; output release is held until completion"
                        .to_string(),
            })
        },
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_policy_denies_unknown() {
        let result = check_output_release_permitted(
            EffectExecutionState::Unknown,
            OutputReleasePolicy::FailClosed,
        );
        assert!(result.is_err());
    }

    #[test]
    fn monitor_policy_allows_unknown() {
        let result = check_output_release_permitted(
            EffectExecutionState::Unknown,
            OutputReleasePolicy::Monitor,
        );
        assert!(result.is_ok());
    }
}
