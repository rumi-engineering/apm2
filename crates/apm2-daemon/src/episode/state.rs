//! Episode state machine implementation.
//!
//! This module defines the episode state machine per AD-EPISODE-002:
//! - CREATED: Envelope accepted, resources not allocated
//! - RUNNING: Harness process spawned, I/O streaming active
//! - TERMINATED: Normal completion (success or failure), evidence finalized
//! - QUARANTINED: Abnormal termination, evidence pinned for investigation
//!
//! # Invariants
//!
//! - [INV-ES001] No transitions from TERMINATED or QUARANTINED (terminal
//!   states)
//! - [INV-ES002] All transitions emit events
//! - [INV-ES003] RUNNING requires valid lease
//! - [INV-ES004] State timestamps are monotonically increasing

use std::fmt;

use serde::{Deserialize, Serialize};

use super::error::EpisodeError;

/// Classification of how an episode terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum TerminationClass {
    /// Episode completed successfully - goal was satisfied.
    Success,
    /// Episode failed with a recoverable error.
    Failure,
    /// Episode budget was exhausted.
    BudgetExhausted,
    /// Episode timed out.
    Timeout,
    /// Episode was cancelled by external request.
    Cancelled,
    /// Episode crashed unexpectedly.
    Crashed,
    /// Episode was killed (SIGKILL or equivalent).
    Killed,
}

impl TerminationClass {
    /// Returns the classification as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Failure => "FAILURE",
            Self::BudgetExhausted => "BUDGET_EXHAUSTED",
            Self::Timeout => "TIMEOUT",
            Self::Cancelled => "CANCELLED",
            Self::Crashed => "CRASHED",
            Self::Killed => "KILLED",
        }
    }

    /// Returns `true` if this represents a successful completion.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

impl fmt::Display for TerminationClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Reason for quarantining an episode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct QuarantineReason {
    /// Short code for the quarantine reason.
    pub code: String,
    /// Human-readable description.
    pub description: String,
    /// References to evidence artifacts (CAS hashes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<[u8; 32]>,
}

impl QuarantineReason {
    /// Creates a new quarantine reason.
    #[must_use]
    pub fn new(code: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            description: description.into(),
            evidence_refs: Vec::new(),
        }
    }

    /// Adds an evidence reference.
    #[must_use]
    pub fn with_evidence(mut self, hash: [u8; 32]) -> Self {
        self.evidence_refs.push(hash);
        self
    }

    /// Creates a quarantine reason for policy violation.
    #[must_use]
    pub fn policy_violation(policy: &str) -> Self {
        Self::new("POLICY_VIOLATION", format!("Policy violated: {policy}"))
    }

    /// Creates a quarantine reason for crash detection.
    #[must_use]
    pub fn crash(details: &str) -> Self {
        Self::new("CRASH", format!("Episode crashed: {details}"))
    }

    /// Creates a quarantine reason for security incident.
    #[must_use]
    pub fn security_incident(details: &str) -> Self {
        Self::new("SECURITY_INCIDENT", format!("Security incident: {details}"))
    }
}

/// The state of an episode in the lifecycle state machine.
///
/// Per AD-EPISODE-002, episodes transition through these states:
/// CREATED -> RUNNING -> (TERMINATED | QUARANTINED)
///
/// # Invariants
///
/// - [INV-ES001] Terminal states (TERMINATED, QUARANTINED) have no outgoing
///   transitions
/// - [INV-ES004] Timestamps are monotonically increasing within an episode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum EpisodeState {
    /// Episode created but not yet started.
    ///
    /// In this state, the envelope has been accepted and validated,
    /// but resources have not been allocated and the harness has not spawned.
    #[non_exhaustive]
    Created {
        /// Timestamp when the episode was created (nanoseconds since epoch).
        created_at_ns: u64,
        /// Hash of the episode envelope.
        envelope_hash: [u8; 32],
    },

    /// Episode is actively running.
    ///
    /// In this state, the harness process has been spawned and I/O streaming
    /// is active. Budget is being consumed.
    #[non_exhaustive]
    Running {
        /// Timestamp when the episode was created (nanoseconds since epoch).
        created_at_ns: u64,
        /// Timestamp when the episode started (nanoseconds since epoch).
        started_at_ns: u64,
        /// Hash of the episode envelope.
        envelope_hash: [u8; 32],
        /// Lease ID authorizing this episode.
        lease_id: String,
        /// Session ID for the running episode.
        session_id: String,
    },

    /// Episode has terminated normally.
    ///
    /// This is a terminal state - no further transitions are possible.
    /// Evidence has been finalized.
    #[non_exhaustive]
    Terminated {
        /// Timestamp when the episode was created (nanoseconds since epoch).
        created_at_ns: u64,
        /// Timestamp when the episode started (nanoseconds since epoch).
        started_at_ns: u64,
        /// Timestamp when the episode terminated (nanoseconds since epoch).
        terminated_at_ns: u64,
        /// Hash of the episode envelope.
        envelope_hash: [u8; 32],
        /// How the episode terminated.
        termination_class: TerminationClass,
    },

    /// Episode has been quarantined for investigation.
    ///
    /// This is a terminal state - no further transitions are possible.
    /// Evidence has been pinned and cannot be garbage collected.
    #[non_exhaustive]
    Quarantined {
        /// Timestamp when the episode was created (nanoseconds since epoch).
        created_at_ns: u64,
        /// Timestamp when the episode started (nanoseconds since epoch).
        started_at_ns: u64,
        /// Timestamp when the episode was quarantined (nanoseconds since
        /// epoch).
        quarantined_at_ns: u64,
        /// Hash of the episode envelope.
        envelope_hash: [u8; 32],
        /// Reason for quarantine.
        reason: QuarantineReason,
    },
}

impl EpisodeState {
    /// Returns the state name as a string.
    #[must_use]
    pub const fn state_name(&self) -> &'static str {
        match self {
            Self::Created { .. } => "Created",
            Self::Running { .. } => "Running",
            Self::Terminated { .. } => "Terminated",
            Self::Quarantined { .. } => "Quarantined",
        }
    }

    /// Returns `true` if this is an active (non-terminal) state.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Created { .. } | Self::Running { .. })
    }

    /// Returns `true` if this is a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated { .. } | Self::Quarantined { .. })
    }

    /// Returns `true` if the episode is currently running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Returns the envelope hash for this episode.
    #[must_use]
    pub const fn envelope_hash(&self) -> &[u8; 32] {
        match self {
            Self::Created { envelope_hash, .. }
            | Self::Running { envelope_hash, .. }
            | Self::Terminated { envelope_hash, .. }
            | Self::Quarantined { envelope_hash, .. } => envelope_hash,
        }
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at_ns(&self) -> u64 {
        match self {
            Self::Created { created_at_ns, .. }
            | Self::Running { created_at_ns, .. }
            | Self::Terminated { created_at_ns, .. }
            | Self::Quarantined { created_at_ns, .. } => *created_at_ns,
        }
    }

    /// Returns the session ID if the episode is running.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        match self {
            Self::Running { session_id, .. } => Some(session_id),
            _ => None,
        }
    }

    /// Returns the lease ID if the episode is running.
    #[must_use]
    pub fn lease_id(&self) -> Option<&str> {
        match self {
            Self::Running { lease_id, .. } => Some(lease_id),
            _ => None,
        }
    }
}

impl fmt::Display for EpisodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.state_name())
    }
}

/// Validates a state transition.
///
/// Returns `Ok(())` if the transition is valid, or an error describing
/// why the transition is invalid.
///
/// # Valid Transitions
///
/// - Created -> Running (via start)
/// - Running -> Terminated (via stop)
/// - Running -> Quarantined (via quarantine)
///
/// # Invalid Transitions
///
/// - Any transition from Terminated (terminal state)
/// - Any transition from Quarantined (terminal state)
/// - Created -> Terminated (must go through Running)
/// - Created -> Quarantined (must go through Running)
/// - Running -> Created (backwards transition)
pub fn validate_transition(
    episode_id: &str,
    from: &EpisodeState,
    to_state_name: &'static str,
) -> Result<(), EpisodeError> {
    let from_name = from.state_name();

    // Terminal states have no outgoing transitions (INV-ES001)
    if from.is_terminal() {
        return Err(EpisodeError::InvalidTransition {
            id: episode_id.to_string(),
            from: from_name,
            to: to_state_name,
        });
    }

    // Valid transitions from each state
    let valid = match from {
        EpisodeState::Created { .. } => to_state_name == "Running",
        EpisodeState::Running { .. } => {
            to_state_name == "Terminated" || to_state_name == "Quarantined"
        },
        // Terminal states handled above
        EpisodeState::Terminated { .. } | EpisodeState::Quarantined { .. } => false,
    };

    if valid {
        Ok(())
    } else {
        Err(EpisodeError::InvalidTransition {
            id: episode_id.to_string(),
            from: from_name,
            to: to_state_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn created_state() -> EpisodeState {
        EpisodeState::Created {
            created_at_ns: 1_000_000_000,
            envelope_hash: [1u8; 32],
        }
    }

    fn running_state() -> EpisodeState {
        EpisodeState::Running {
            created_at_ns: 1_000_000_000,
            started_at_ns: 2_000_000_000,
            envelope_hash: [1u8; 32],
            lease_id: "lease-123".to_string(),
            session_id: "session-456".to_string(),
        }
    }

    fn terminated_state() -> EpisodeState {
        EpisodeState::Terminated {
            created_at_ns: 1_000_000_000,
            started_at_ns: 2_000_000_000,
            terminated_at_ns: 3_000_000_000,
            envelope_hash: [1u8; 32],
            termination_class: TerminationClass::Success,
        }
    }

    fn quarantined_state() -> EpisodeState {
        EpisodeState::Quarantined {
            created_at_ns: 1_000_000_000,
            started_at_ns: 2_000_000_000,
            quarantined_at_ns: 3_000_000_000,
            envelope_hash: [1u8; 32],
            reason: QuarantineReason::crash("test crash"),
        }
    }

    #[test]
    fn test_state_name() {
        assert_eq!(created_state().state_name(), "Created");
        assert_eq!(running_state().state_name(), "Running");
        assert_eq!(terminated_state().state_name(), "Terminated");
        assert_eq!(quarantined_state().state_name(), "Quarantined");
    }

    #[test]
    fn test_is_active() {
        assert!(created_state().is_active());
        assert!(running_state().is_active());
        assert!(!terminated_state().is_active());
        assert!(!quarantined_state().is_active());
    }

    #[test]
    fn test_is_terminal() {
        assert!(!created_state().is_terminal());
        assert!(!running_state().is_terminal());
        assert!(terminated_state().is_terminal());
        assert!(quarantined_state().is_terminal());
    }

    #[test]
    fn test_is_running() {
        assert!(!created_state().is_running());
        assert!(running_state().is_running());
        assert!(!terminated_state().is_running());
        assert!(!quarantined_state().is_running());
    }

    #[test]
    fn test_envelope_hash() {
        let expected = [1u8; 32];
        assert_eq!(created_state().envelope_hash(), &expected);
        assert_eq!(running_state().envelope_hash(), &expected);
        assert_eq!(terminated_state().envelope_hash(), &expected);
        assert_eq!(quarantined_state().envelope_hash(), &expected);
    }

    #[test]
    fn test_session_and_lease_id() {
        assert!(created_state().session_id().is_none());
        assert!(created_state().lease_id().is_none());

        assert_eq!(running_state().session_id(), Some("session-456"));
        assert_eq!(running_state().lease_id(), Some("lease-123"));

        assert!(terminated_state().session_id().is_none());
        assert!(terminated_state().lease_id().is_none());
    }

    // Transition validation tests

    #[test]
    fn test_valid_transition_created_to_running() {
        let result = validate_transition("ep-1", &created_state(), "Running");
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_transition_running_to_terminated() {
        let result = validate_transition("ep-1", &running_state(), "Terminated");
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_transition_running_to_quarantined() {
        let result = validate_transition("ep-1", &running_state(), "Quarantined");
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_transition_terminated_to_running() {
        let result = validate_transition("ep-1", &terminated_state(), "Running");
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidTransition {
                from: "Terminated",
                to: "Running",
                ..
            })
        ));
    }

    #[test]
    fn test_invalid_transition_quarantined_to_running() {
        let result = validate_transition("ep-1", &quarantined_state(), "Running");
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidTransition {
                from: "Quarantined",
                to: "Running",
                ..
            })
        ));
    }

    #[test]
    fn test_invalid_transition_created_to_terminated() {
        let result = validate_transition("ep-1", &created_state(), "Terminated");
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidTransition {
                from: "Created",
                to: "Terminated",
                ..
            })
        ));
    }

    #[test]
    fn test_invalid_transition_running_to_created() {
        let result = validate_transition("ep-1", &running_state(), "Created");
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidTransition {
                from: "Running",
                to: "Created",
                ..
            })
        ));
    }

    // Termination class tests

    #[test]
    fn test_termination_class_is_success() {
        assert!(TerminationClass::Success.is_success());
        assert!(!TerminationClass::Failure.is_success());
        assert!(!TerminationClass::BudgetExhausted.is_success());
        assert!(!TerminationClass::Timeout.is_success());
        assert!(!TerminationClass::Cancelled.is_success());
        assert!(!TerminationClass::Crashed.is_success());
        assert!(!TerminationClass::Killed.is_success());
    }

    #[test]
    fn test_termination_class_as_str() {
        assert_eq!(TerminationClass::Success.as_str(), "SUCCESS");
        assert_eq!(TerminationClass::Failure.as_str(), "FAILURE");
        assert_eq!(
            TerminationClass::BudgetExhausted.as_str(),
            "BUDGET_EXHAUSTED"
        );
    }

    // Quarantine reason tests

    #[test]
    fn test_quarantine_reason_new() {
        let reason = QuarantineReason::new("TEST", "Test description");
        assert_eq!(reason.code, "TEST");
        assert_eq!(reason.description, "Test description");
        assert!(reason.evidence_refs.is_empty());
    }

    #[test]
    fn test_quarantine_reason_with_evidence() {
        let hash = [42u8; 32];
        let reason = QuarantineReason::new("TEST", "Test").with_evidence(hash);
        assert_eq!(reason.evidence_refs.len(), 1);
        assert_eq!(reason.evidence_refs[0], hash);
    }

    #[test]
    fn test_quarantine_reason_factories() {
        let pv = QuarantineReason::policy_violation("DENY_WRITE");
        assert_eq!(pv.code, "POLICY_VIOLATION");

        let crash = QuarantineReason::crash("segfault");
        assert_eq!(crash.code, "CRASH");

        let sec = QuarantineReason::security_incident("unauthorized access");
        assert_eq!(sec.code, "SECURITY_INCIDENT");
    }

    // Serialization tests

    #[test]
    fn test_state_serialization_roundtrip() {
        let states = vec![
            created_state(),
            running_state(),
            terminated_state(),
            quarantined_state(),
        ];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: EpisodeState = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, state);
        }
    }

    /// SECURITY TEST: Verify `EpisodeState` rejects unknown fields.
    #[test]
    fn test_state_rejects_unknown_fields() {
        let json_with_unknown = r#"{
            "state": "CREATED",
            "created_at_ns": 1000,
            "envelope_hash": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
            "malicious_field": "should_fail"
        }"#;

        let result: Result<EpisodeState, _> = serde_json::from_str(json_with_unknown);
        assert!(
            result.is_err(),
            "EpisodeState should reject JSON with unknown fields"
        );
    }

    /// SECURITY TEST: Verify `QuarantineReason` rejects unknown fields.
    #[test]
    fn test_quarantine_reason_rejects_unknown_fields() {
        let json_with_unknown = r#"{
            "code": "TEST",
            "description": "Test",
            "evil_field": "attack"
        }"#;

        let result: Result<QuarantineReason, _> = serde_json::from_str(json_with_unknown);
        assert!(
            result.is_err(),
            "QuarantineReason should reject JSON with unknown fields"
        );
    }
}
