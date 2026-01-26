//! Exit signal handling for session cleanup.
//!
//! This module provides the integration point between agent exit signals and
//! session lifecycle management. When an agent emits a valid exit signal, this
//! module coordinates:
//!
//! 1. Exit signal validation
//! 2. `AgentSessionCompleted` event emission
//! 3. Work item phase transition
//! 4. Lease release
//!
//! # Security
//!
//! **CRITICAL**: The system MUST verify that `phase_completed` matches the
//! session's active work phase before accepting an exit signal. This prevents
//! protocol phase confusion attacks.
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::agent::exit::ExitSignal;
//! use apm2_core::session::exit_handler::{
//!     ExitHandlerContext, ExitHandlerResult, handle_exit_signal,
//! };
//!
//! let json = r#"{"protocol":"apm2_agent_exit","version":"1.0.0",...}"#;
//! let ctx = ExitHandlerContext {
//!     session_id: "session-123".to_string(),
//!     actor_id: "actor-456".to_string(),
//!     active_work_phase: Some(WorkPhase::Implementation),
//! };
//!
//! match handle_exit_signal(json, &ctx) {
//!     Ok(result) => {
//!         // Emit result.event to ledger
//!         // Transition work item to result.next_phase
//!         // Release lease
//!     }
//!     Err(e) => {
//!         // Log error, do not modify state
//!     }
//! }
//! ```

use thiserror::Error;

use crate::agent::exit::{AgentSessionCompleted, ExitSignal, ExitSignalError, WorkPhase};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur when handling an exit signal.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ExitHandlerError {
    /// Exit signal validation failed.
    #[error("exit signal validation failed: {0}")]
    ValidationFailed(#[from] ExitSignalError),

    /// Phase mismatch between exit signal and session's active phase.
    #[error("phase mismatch: exit signal claims '{claimed}' but session is in '{actual}'")]
    PhaseMismatch {
        /// Phase claimed in the exit signal.
        claimed: WorkPhase,
        /// Actual active phase of the session.
        actual: WorkPhase,
    },

    /// Session has no active work phase (already terminated or not started).
    #[error("session has no active work phase")]
    NoActivePhase,
}

// ============================================================================
// Context and Result Types
// ============================================================================

/// Context required for handling an exit signal.
///
/// This provides the session-specific information needed to validate and
/// process an exit signal.
#[derive(Debug, Clone)]
pub struct ExitHandlerContext {
    /// The session ID that emitted the exit signal.
    pub session_id: String,

    /// The actor ID (agent identity) for this session.
    pub actor_id: String,

    /// The session's currently active work phase.
    ///
    /// This is `None` if the session is not in an active state (already
    /// terminated, quarantined, or not yet started).
    pub active_work_phase: Option<WorkPhase>,
}

/// Result of successfully handling an exit signal.
///
/// Contains all the information needed to complete the session cleanup:
/// - The event to emit to the ledger
/// - The next work phase for the work item
/// - The validated exit signal
#[derive(Debug, Clone)]
pub struct ExitHandlerResult {
    /// The `AgentSessionCompleted` event to emit to the ledger.
    pub event: AgentSessionCompleted,

    /// The next work phase for the work item.
    pub next_phase: WorkPhase,

    /// The validated exit signal (for audit/logging purposes).
    pub exit_signal: ExitSignal,
}

// ============================================================================
// Handler Function
// ============================================================================

/// Handles an agent exit signal, performing validation and preparing cleanup.
///
/// This is the primary entry point for processing exit signals from agents.
/// It performs all necessary validation and returns the information needed
/// to complete session cleanup.
///
/// # Security
///
/// This function enforces server-side phase verification:
/// - The `phase_completed` in the exit signal MUST match the session's active
///   phase
/// - Mismatches are rejected with `ExitHandlerError::PhaseMismatch`
/// - Sessions without an active phase are rejected with
///   `ExitHandlerError::NoActivePhase`
///
/// # Workflow
///
/// After calling this function successfully, the caller should:
/// 1. Emit `result.event` to the ledger
/// 2. Transition the work item to `result.next_phase`
/// 3. Release the session's lease
///
/// # Errors
///
/// Returns `ExitHandlerError::ValidationFailed` if the exit signal is invalid.
/// Returns `ExitHandlerError::PhaseMismatch` if the claimed phase doesn't match
/// the session's active phase.
/// Returns `ExitHandlerError::NoActivePhase` if the session has no active work
/// phase.
///
/// # Example
///
/// ```rust,ignore
/// let result = handle_exit_signal(json, &ctx)?;
///
/// // 1. Emit event to ledger
/// ledger.append(result.event)?;
///
/// // 2. Transition work item phase
/// work_store.transition(work_id, result.next_phase)?;
///
/// // 3. Release lease
/// lease_store.release(lease_id)?;
/// ```
pub fn handle_exit_signal(
    json: &str,
    ctx: &ExitHandlerContext,
) -> Result<ExitHandlerResult, ExitHandlerError> {
    // 1. Parse and validate the exit signal
    let exit_signal = ExitSignal::from_json(json)?;

    // 2. Verify phase matches session's active phase (CRITICAL for security)
    let active_phase = ctx
        .active_work_phase
        .ok_or(ExitHandlerError::NoActivePhase)?;

    if exit_signal.phase_completed != active_phase {
        return Err(ExitHandlerError::PhaseMismatch {
            claimed: exit_signal.phase_completed,
            actual: active_phase,
        });
    }

    // 3. Compute next phase
    let next_phase = exit_signal.next_expected_phase();

    // 4. Create the completion event
    let event = AgentSessionCompleted::from_exit_signal(
        &ctx.session_id,
        &ctx.actor_id,
        exit_signal.clone(),
    );

    Ok(ExitHandlerResult {
        event,
        next_phase,
        exit_signal,
    })
}

/// Stub for lease release.
///
/// This function documents the integration point for releasing a session's
/// lease when handling an exit signal. The actual implementation depends on
/// the `LeaseStore` interface.
///
/// # Arguments
///
/// * `lease_id` - The ID of the lease to release.
///
/// # Returns
///
/// Returns `Ok(())` if the lease was released successfully, or an error if
/// the release failed.
///
/// # Errors
///
/// Returns `Err(String)` if the lease cannot be released. In the current stub
/// implementation, this never occurs.
///
/// # Note
///
/// This is a placeholder/stub. The actual implementation should:
/// 1. Look up the lease by ID
/// 2. Verify the lease belongs to the session
/// 3. Mark the lease as released
/// 4. Allow other agents to claim the work
#[allow(unused_variables)]
pub const fn release_lease_stub(lease_id: &str) -> Result<(), String> {
    // TODO: Integrate with LeaseStore when available
    // This stub documents the expected interface
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::exit::ExitReason;

    fn valid_exit_signal_json(phase: &str) -> String {
        format!(
            r#"{{
                "protocol": "apm2_agent_exit",
                "version": "1.0.0",
                "phase_completed": "{phase}",
                "exit_reason": "completed",
                "pr_url": "https://github.com/org/repo/pull/123"
            }}"#
        )
    }

    fn test_context(active_phase: Option<WorkPhase>) -> ExitHandlerContext {
        ExitHandlerContext {
            session_id: "session-123".to_string(),
            actor_id: "actor-456".to_string(),
            active_work_phase: active_phase,
        }
    }

    #[test]
    fn test_handle_exit_signal_success() {
        let json = valid_exit_signal_json("IMPLEMENTATION");
        let ctx = test_context(Some(WorkPhase::Implementation));

        let result = handle_exit_signal(&json, &ctx).unwrap();

        assert_eq!(
            result.exit_signal.phase_completed,
            WorkPhase::Implementation
        );
        assert_eq!(result.exit_signal.exit_reason, ExitReason::Completed);
        assert_eq!(result.next_phase, WorkPhase::CiPending);
        assert_eq!(result.event.session_id, "session-123");
        assert_eq!(result.event.actor_id, "actor-456");
        assert_eq!(result.event.phase_completed, WorkPhase::Implementation);
        assert_eq!(result.event.next_phase, WorkPhase::CiPending);
    }

    #[test]
    fn test_handle_exit_signal_phase_mismatch() {
        // Agent claims REVIEW but session is in IMPLEMENTATION
        let json = valid_exit_signal_json("REVIEW");
        let ctx = test_context(Some(WorkPhase::Implementation));

        let result = handle_exit_signal(&json, &ctx);

        assert!(matches!(
            result,
            Err(ExitHandlerError::PhaseMismatch {
                claimed: WorkPhase::Review,
                actual: WorkPhase::Implementation,
            })
        ));
    }

    #[test]
    fn test_handle_exit_signal_no_active_phase() {
        let json = valid_exit_signal_json("IMPLEMENTATION");
        let ctx = test_context(None);

        let result = handle_exit_signal(&json, &ctx);

        assert!(matches!(result, Err(ExitHandlerError::NoActivePhase)));
    }

    #[test]
    fn test_handle_exit_signal_invalid_json() {
        let json = "not valid json";
        let ctx = test_context(Some(WorkPhase::Implementation));

        let result = handle_exit_signal(json, &ctx);

        assert!(matches!(result, Err(ExitHandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_exit_signal_wrong_protocol() {
        let json = r#"{
            "protocol": "wrong_protocol",
            "version": "1.0.0",
            "phase_completed": "IMPLEMENTATION",
            "exit_reason": "completed"
        }"#;
        let ctx = test_context(Some(WorkPhase::Implementation));

        let result = handle_exit_signal(json, &ctx);

        assert!(matches!(
            result,
            Err(ExitHandlerError::ValidationFailed(
                ExitSignalError::UnknownProtocol(_)
            ))
        ));
    }

    #[test]
    fn test_handle_exit_signal_blocked_reason() {
        let json = r#"{
            "protocol": "apm2_agent_exit",
            "version": "1.0.0",
            "phase_completed": "IMPLEMENTATION",
            "exit_reason": "blocked",
            "notes": "Waiting for API credentials"
        }"#;
        let ctx = test_context(Some(WorkPhase::Implementation));

        let result = handle_exit_signal(json, &ctx).unwrap();

        assert_eq!(result.exit_signal.exit_reason, ExitReason::Blocked);
        assert_eq!(result.next_phase, WorkPhase::Blocked);
    }

    #[test]
    fn test_release_lease_stub() {
        // Just verify the stub doesn't panic and returns Ok
        let result = release_lease_stub("lease-123");
        assert!(result.is_ok());
    }
}
