//! Event emitter for webhook-triggered CI events.
//!
//! This module provides the [`CIEventEmitter`] which handles:
//! - Idempotency checking via delivery ID
//! - Event creation from webhook payloads
//! - Event persistence to the ledger
//! - Feature flag checking
//!
//! # Thread Safety
//!
//! The event emitter is thread-safe and can be shared across handler instances.
//!
//! # Contracts
//!
//! - [CTR-EE001] Duplicate delivery IDs are rejected before event creation.
//! - [CTR-EE002] Events are persisted atomically.
//! - [CTR-EE003] Feature flag is checked before processing.

use std::sync::Arc;

use super::error::WebhookError;
use super::payload::WorkflowRunCompleted;
use crate::events::ci::{
    CIConclusion, CIWorkflowCompleted, CIWorkflowPayload, DeliveryIdStore, EventStore,
    InMemoryDeliveryIdStore, InMemoryEventStore, is_ci_events_enabled,
};

/// Result of attempting to emit a CI event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitResult {
    /// Event was successfully emitted and persisted.
    Emitted {
        /// The event ID that was assigned.
        event_id: uuid::Uuid,
    },
    /// Event emission was skipped because the feature flag is disabled.
    Disabled,
    /// Event was not emitted because the delivery ID was already seen.
    Duplicate,
}

/// Emits CI workflow events from validated webhook payloads.
///
/// This struct orchestrates the event emission pipeline:
/// 1. Check feature flag
/// 2. Check idempotency (delivery ID)
/// 3. Create event
/// 4. Persist to ledger
///
/// # Example
///
/// ```rust
/// use apm2_core::webhook::event_emitter::CIEventEmitter;
///
/// let emitter = CIEventEmitter::new();
///
/// // After validating a webhook...
/// // let result = emitter.emit(&completed, true, "delivery-123");
/// ```
pub struct CIEventEmitter {
    delivery_store: Arc<dyn DeliveryIdStore>,
    event_store: Arc<dyn EventStore>,
}

impl CIEventEmitter {
    /// Creates a new event emitter with default in-memory stores.
    #[must_use]
    pub fn new() -> Self {
        Self {
            delivery_store: Arc::new(InMemoryDeliveryIdStore::new()),
            event_store: Arc::new(InMemoryEventStore::new()),
        }
    }

    /// Creates a new event emitter with custom stores.
    ///
    /// This is useful for testing or when persistence is needed.
    #[must_use]
    pub fn with_stores(
        delivery_store: Arc<dyn DeliveryIdStore>,
        event_store: Arc<dyn EventStore>,
    ) -> Self {
        Self {
            delivery_store,
            event_store,
        }
    }

    /// Attempts to emit a CI workflow completed event.
    ///
    /// # Arguments
    ///
    /// * `completed` - The validated workflow run completion data
    /// * `signature_verified` - Whether the webhook signature was verified
    /// * `delivery_id` - GitHub's delivery ID for idempotency
    ///
    /// # Returns
    ///
    /// - `Ok(EmitResult::Emitted { event_id })` if the event was successfully created
    /// - `Ok(EmitResult::Disabled)` if CI events are disabled
    /// - `Ok(EmitResult::Duplicate)` if the delivery ID was already seen
    /// - `Err(WebhookError)` if event persistence failed
    ///
    /// # Errors
    ///
    /// Returns `WebhookError::Internal` if event persistence fails.
    pub fn emit(
        &self,
        completed: &WorkflowRunCompleted,
        signature_verified: bool,
        delivery_id: &str,
    ) -> Result<EmitResult, WebhookError> {
        // 1. Check feature flag (CTR-EE003)
        if !is_ci_events_enabled() {
            tracing::debug!("CI events disabled, skipping event emission");
            return Ok(EmitResult::Disabled);
        }

        // 2. Check idempotency (CTR-EE001)
        if !self.delivery_store.check_and_mark(delivery_id) {
            tracing::info!(
                delivery_id = %delivery_id,
                "duplicate delivery ID, skipping event emission"
            );
            return Ok(EmitResult::Duplicate);
        }

        // 3. Create event
        let payload = CIWorkflowPayload {
            pr_number: completed.pull_request_numbers.first().copied(),
            commit_sha: completed.commit_sha.clone(),
            conclusion: CIConclusion::from(completed.conclusion),
            workflow_name: "workflow".to_string(), // GitHub doesn't include name in basic payload
            workflow_run_id: completed.workflow_run_id,
            checks: vec![], // Individual check results require additional API calls
        };

        let event = CIWorkflowCompleted::new(payload, signature_verified, delivery_id.to_string());
        let event_id = event.event_id;

        // 4. Persist event (CTR-EE002)
        self.event_store
            .persist(&event)
            .map_err(|e| WebhookError::Internal(format!("failed to persist event: {e}")))?;

        tracing::info!(
            event_id = %event_id,
            delivery_id = %delivery_id,
            pr_number = ?event.payload.pr_number,
            conclusion = %event.payload.conclusion,
            "CI workflow event emitted"
        );

        Ok(EmitResult::Emitted { event_id })
    }

    /// Returns a reference to the event store for querying.
    #[must_use]
    pub fn event_store(&self) -> &Arc<dyn EventStore> {
        &self.event_store
    }

    /// Returns a reference to the delivery ID store.
    #[must_use]
    pub fn delivery_store(&self) -> &Arc<dyn DeliveryIdStore> {
        &self.delivery_store
    }
}

impl Default for CIEventEmitter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhook::WorkflowConclusion;

    fn sample_completed() -> WorkflowRunCompleted {
        WorkflowRunCompleted {
            workflow_run_id: 12345,
            commit_sha: "abc123def456".to_string(),
            branch: "feature/test".to_string(),
            conclusion: WorkflowConclusion::Success,
            pull_request_numbers: vec![42],
        }
    }

    #[test]
    fn test_emit_success() {
        let emitter = CIEventEmitter::new();
        let completed = sample_completed();

        let result = emitter.emit(&completed, true, "delivery-123").unwrap();

        match result {
            EmitResult::Emitted { event_id } => {
                // Verify event was persisted
                let stored = emitter.event_store().get(event_id);
                assert!(stored.is_some());

                let event = stored.unwrap();
                assert_eq!(event.payload.pr_number, Some(42));
                assert_eq!(event.payload.commit_sha, "abc123def456");
                assert_eq!(event.payload.conclusion, CIConclusion::Success);
                assert!(event.signature_verified);
            }
            _ => panic!("Expected Emitted result"),
        }
    }

    #[test]
    fn test_emit_duplicate_rejected() {
        let emitter = CIEventEmitter::new();
        let completed = sample_completed();

        // First emission succeeds
        let result1 = emitter.emit(&completed, true, "delivery-123").unwrap();
        assert!(matches!(result1, EmitResult::Emitted { .. }));

        // Second emission with same delivery_id is duplicate
        let result2 = emitter.emit(&completed, true, "delivery-123").unwrap();
        assert_eq!(result2, EmitResult::Duplicate);

        // Only one event should be stored
        assert_eq!(emitter.event_store().count(), 1);
    }

    #[test]
    fn test_emit_different_delivery_ids() {
        let emitter = CIEventEmitter::new();
        let completed = sample_completed();

        let result1 = emitter.emit(&completed, true, "delivery-1").unwrap();
        let result2 = emitter.emit(&completed, true, "delivery-2").unwrap();

        assert!(matches!(result1, EmitResult::Emitted { .. }));
        assert!(matches!(result2, EmitResult::Emitted { .. }));
        assert_eq!(emitter.event_store().count(), 2);
    }

    #[test]
    fn test_emit_failure_conclusion() {
        let emitter = CIEventEmitter::new();
        let mut completed = sample_completed();
        completed.conclusion = WorkflowConclusion::Failure;

        let result = emitter.emit(&completed, true, "delivery-123").unwrap();

        match result {
            EmitResult::Emitted { event_id } => {
                let event = emitter.event_store().get(event_id).unwrap();
                assert_eq!(event.payload.conclusion, CIConclusion::Failure);
            }
            _ => panic!("Expected Emitted result"),
        }
    }

    #[test]
    fn test_emit_no_pr_number() {
        let emitter = CIEventEmitter::new();
        let mut completed = sample_completed();
        completed.pull_request_numbers = vec![];

        let result = emitter.emit(&completed, true, "delivery-123").unwrap();

        match result {
            EmitResult::Emitted { event_id } => {
                let event = emitter.event_store().get(event_id).unwrap();
                assert_eq!(event.payload.pr_number, None);
            }
            _ => panic!("Expected Emitted result"),
        }
    }

    #[test]
    fn test_emit_unverified_signature() {
        let emitter = CIEventEmitter::new();
        let completed = sample_completed();

        let result = emitter.emit(&completed, false, "delivery-123").unwrap();

        match result {
            EmitResult::Emitted { event_id } => {
                let event = emitter.event_store().get(event_id).unwrap();
                assert!(!event.signature_verified);
            }
            _ => panic!("Expected Emitted result"),
        }
    }

    #[test]
    fn test_default_impl() {
        let emitter = CIEventEmitter::default();
        assert_eq!(emitter.event_store().count(), 0);
        assert!(emitter.delivery_store().is_empty());
    }
}
