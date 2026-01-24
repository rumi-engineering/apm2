//! Episode result types for holon execution.
//!
//! The [`EpisodeResult`] represents the outcome of a single episode of
//! holon execution. It captures what was produced, how much was consumed,
//! and whether the episode completed successfully.

use serde::{Deserialize, Serialize};

/// The result of a single episode of holon execution.
///
/// An episode result captures:
/// - The outcome (completed, needs continuation, failed, escalated)
/// - Any output produced
/// - Resource consumption (tokens, time)
/// - Progress updates
///
/// # Type Parameter
///
/// - `T`: The output type produced by the holon
///
/// # Example
///
/// ```rust
/// use apm2_holon::EpisodeResult;
///
/// // A completed episode with output
/// let result: EpisodeResult<String> =
///     EpisodeResult::completed("Task done!".to_string());
/// assert!(result.is_completed());
///
/// // An episode that needs to continue
/// let result: EpisodeResult<String> = EpisodeResult::continuation();
/// assert!(result.needs_continuation());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpisodeResult<T> {
    /// The outcome of this episode.
    outcome: EpisodeOutcome,

    /// The output produced (if any).
    output: Option<T>,

    /// Tokens consumed in this episode.
    tokens_consumed: u64,

    /// Time consumed in this episode (milliseconds).
    time_consumed_ms: u64,

    /// Updated progress state.
    progress_update: Option<String>,

    /// Artifacts produced in this episode.
    artifact_count: u64,
}

/// The outcome of an episode execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpisodeOutcome {
    /// The work is complete, no more episodes needed.
    Completed,

    /// The episode finished but more work is needed.
    NeedsContinuation,

    /// The episode failed with a recoverable error.
    Failed,

    /// The work is being escalated to a supervisor.
    Escalated,

    /// The episode was interrupted (e.g., budget exhausted).
    Interrupted,
}

impl<T> EpisodeResult<T> {
    /// Creates a completed result with the given output.
    #[must_use]
    pub const fn completed(output: T) -> Self {
        Self {
            outcome: EpisodeOutcome::Completed,
            output: Some(output),
            tokens_consumed: 0,
            time_consumed_ms: 0,
            progress_update: None,
            artifact_count: 0,
        }
    }

    /// Creates a result indicating more episodes are needed.
    #[must_use]
    pub const fn continuation() -> Self {
        Self {
            outcome: EpisodeOutcome::NeedsContinuation,
            output: None,
            tokens_consumed: 0,
            time_consumed_ms: 0,
            progress_update: None,
            artifact_count: 0,
        }
    }

    /// Creates a result indicating more episodes are needed with progress
    /// update.
    #[must_use]
    pub fn continue_with_progress(progress: impl Into<String>) -> Self {
        Self {
            outcome: EpisodeOutcome::NeedsContinuation,
            output: None,
            tokens_consumed: 0,
            time_consumed_ms: 0,
            progress_update: Some(progress.into()),
            artifact_count: 0,
        }
    }

    /// Creates a failed result.
    #[must_use]
    pub const fn failed() -> Self {
        Self {
            outcome: EpisodeOutcome::Failed,
            output: None,
            tokens_consumed: 0,
            time_consumed_ms: 0,
            progress_update: None,
            artifact_count: 0,
        }
    }

    /// Creates an escalated result.
    #[must_use]
    pub const fn escalated() -> Self {
        Self {
            outcome: EpisodeOutcome::Escalated,
            output: None,
            tokens_consumed: 0,
            time_consumed_ms: 0,
            progress_update: None,
            artifact_count: 0,
        }
    }

    /// Creates an interrupted result.
    #[must_use]
    pub const fn interrupted() -> Self {
        Self {
            outcome: EpisodeOutcome::Interrupted,
            output: None,
            tokens_consumed: 0,
            time_consumed_ms: 0,
            progress_update: None,
            artifact_count: 0,
        }
    }

    /// Returns the outcome of this episode.
    #[must_use]
    pub const fn outcome(&self) -> EpisodeOutcome {
        self.outcome
    }

    /// Returns the output, if any.
    #[must_use]
    pub const fn output(&self) -> Option<&T> {
        self.output.as_ref()
    }

    /// Consumes the result and returns the output.
    #[must_use]
    pub fn into_output(self) -> Option<T> {
        self.output
    }

    /// Returns the number of tokens consumed.
    #[must_use]
    pub const fn tokens_consumed(&self) -> u64 {
        self.tokens_consumed
    }

    /// Returns the time consumed in milliseconds.
    #[must_use]
    pub const fn time_consumed_ms(&self) -> u64 {
        self.time_consumed_ms
    }

    /// Returns the progress update, if any.
    #[must_use]
    pub fn progress_update(&self) -> Option<&str> {
        self.progress_update.as_deref()
    }

    /// Returns the number of artifacts produced.
    #[must_use]
    pub const fn artifact_count(&self) -> u64 {
        self.artifact_count
    }

    /// Returns `true` if the episode completed successfully.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self.outcome, EpisodeOutcome::Completed)
    }

    /// Returns `true` if more episodes are needed.
    #[must_use]
    pub const fn needs_continuation(&self) -> bool {
        matches!(self.outcome, EpisodeOutcome::NeedsContinuation)
    }

    /// Returns `true` if the episode failed.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self.outcome, EpisodeOutcome::Failed)
    }

    /// Returns `true` if the work was escalated.
    #[must_use]
    pub const fn is_escalated(&self) -> bool {
        matches!(self.outcome, EpisodeOutcome::Escalated)
    }

    /// Returns `true` if the episode was interrupted.
    #[must_use]
    pub const fn is_interrupted(&self) -> bool {
        matches!(self.outcome, EpisodeOutcome::Interrupted)
    }

    /// Returns `true` if this is a terminal outcome (no more episodes will
    /// run).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.outcome,
            EpisodeOutcome::Completed | EpisodeOutcome::Failed | EpisodeOutcome::Escalated
        )
    }

    /// Sets the token consumption.
    #[must_use]
    pub const fn with_tokens_consumed(mut self, tokens: u64) -> Self {
        self.tokens_consumed = tokens;
        self
    }

    /// Sets the time consumption.
    #[must_use]
    pub const fn with_time_consumed_ms(mut self, ms: u64) -> Self {
        self.time_consumed_ms = ms;
        self
    }

    /// Sets the progress update.
    #[must_use]
    pub fn with_progress(mut self, progress: impl Into<String>) -> Self {
        self.progress_update = Some(progress.into());
        self
    }

    /// Sets the artifact count.
    #[must_use]
    pub const fn with_artifact_count(mut self, count: u64) -> Self {
        self.artifact_count = count;
        self
    }
}

impl EpisodeOutcome {
    /// Returns the outcome as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::NeedsContinuation => "needs_continuation",
            Self::Failed => "failed",
            Self::Escalated => "escalated",
            Self::Interrupted => "interrupted",
        }
    }
}

impl std::fmt::Display for EpisodeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_completed_result() {
        let result: EpisodeResult<String> = EpisodeResult::completed("output".to_string());
        assert!(result.is_completed());
        assert!(!result.needs_continuation());
        assert!(!result.is_failed());
        assert!(result.is_terminal());
        assert_eq!(result.output(), Some(&"output".to_string()));
    }

    #[test]
    fn test_continuation_result() {
        let result: EpisodeResult<String> = EpisodeResult::continuation();
        assert!(!result.is_completed());
        assert!(result.needs_continuation());
        assert!(!result.is_terminal());
        assert!(result.output().is_none());
    }

    #[test]
    fn test_continue_with_progress() {
        let result: EpisodeResult<String> = EpisodeResult::continue_with_progress("Step 1 done");
        assert!(result.needs_continuation());
        assert_eq!(result.progress_update(), Some("Step 1 done"));
    }

    #[test]
    fn test_failed_result() {
        let result: EpisodeResult<String> = EpisodeResult::failed();
        assert!(result.is_failed());
        assert!(result.is_terminal());
    }

    #[test]
    fn test_escalated_result() {
        let result: EpisodeResult<String> = EpisodeResult::escalated();
        assert!(result.is_escalated());
        assert!(result.is_terminal());
    }

    #[test]
    fn test_interrupted_result() {
        let result: EpisodeResult<String> = EpisodeResult::interrupted();
        assert!(result.is_interrupted());
        assert!(!result.is_terminal()); // Interrupted is not terminal, might retry
    }

    #[test]
    fn test_with_consumption() {
        let result: EpisodeResult<String> = EpisodeResult::completed("done".to_string())
            .with_tokens_consumed(100)
            .with_time_consumed_ms(5000)
            .with_artifact_count(2);

        assert_eq!(result.tokens_consumed(), 100);
        assert_eq!(result.time_consumed_ms(), 5000);
        assert_eq!(result.artifact_count(), 2);
    }

    #[test]
    fn test_into_output() {
        let result: EpisodeResult<String> = EpisodeResult::completed("output".to_string());
        let output = result.into_output();
        assert_eq!(output, Some("output".to_string()));
    }

    #[test]
    fn test_outcome_display() {
        assert_eq!(EpisodeOutcome::Completed.to_string(), "completed");
        assert_eq!(
            EpisodeOutcome::NeedsContinuation.to_string(),
            "needs_continuation"
        );
        assert_eq!(EpisodeOutcome::Failed.to_string(), "failed");
        assert_eq!(EpisodeOutcome::Escalated.to_string(), "escalated");
        assert_eq!(EpisodeOutcome::Interrupted.to_string(), "interrupted");
    }

    #[test]
    fn test_outcome_as_str() {
        assert_eq!(EpisodeOutcome::Completed.as_str(), "completed");
        assert_eq!(
            EpisodeOutcome::NeedsContinuation.as_str(),
            "needs_continuation"
        );
    }
}
