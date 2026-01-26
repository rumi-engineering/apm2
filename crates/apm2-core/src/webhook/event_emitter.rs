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
    CIConclusion, CIEventsConfig, CIWorkflowCompleted, CIWorkflowPayload, DeliveryIdStore,
    EventStore, InMemoryDeliveryIdStore, InMemoryEventStore,
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
    config: CIEventsConfig,
    delivery_store: Arc<dyn DeliveryIdStore>,
    event_store: Arc<dyn EventStore>,
}

impl CIEventEmitter {
    /// Creates a new event emitter with default in-memory stores.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: CIEventsConfig::default(),
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
            config: CIEventsConfig::default(),
            delivery_store,
            event_store,
        }
    }

    /// Creates a new event emitter with custom configuration and stores.
    ///
    /// This allows injecting a `CIEventsConfig` for testing without
    /// modifying global environment variables.
    #[must_use]
    pub fn with_config(
        config: CIEventsConfig,
        delivery_store: Arc<dyn DeliveryIdStore>,
        event_store: Arc<dyn EventStore>,
    ) -> Self {
        Self {
            config,
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
    /// - `Ok(EmitResult::Emitted { event_id })` if the event was successfully
    ///   created
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
        if !self.config.enabled {
            tracing::debug!("CI events disabled, skipping event emission");
            return Ok(EmitResult::Disabled);
        }

        // 2. Check idempotency (read-only) (CTR-EE001)
        // We check first without marking to ensure atomicity: if persistence
        // fails, we haven't marked the delivery ID, allowing retries.
        if self.delivery_store.contains(delivery_id) {
            tracing::info!(
                delivery_id = %delivery_id,
                "duplicate delivery ID, skipping event emission"
            );
            return Ok(EmitResult::Duplicate);
        }

        // 3. Create event
        let payload = CIWorkflowPayload {
            pr_numbers: completed.pull_request_numbers.clone(),
            commit_sha: completed.commit_sha.clone(),
            conclusion: CIConclusion::from(completed.conclusion),
            workflow_name: completed.workflow_name.clone(),
            workflow_run_id: completed.workflow_run_id,
            checks: vec![], // Individual check results require additional API calls (out of scope)
        };

        let event = CIWorkflowCompleted::new(payload, signature_verified, delivery_id.to_string());
        let event_id = event.event_id;

        // 4. Persist event (CTR-EE002)
        // Persistence happens BEFORE marking the delivery ID. This ensures:
        // - If persist fails, the delivery ID is NOT marked -> retry is allowed
        // - If persist succeeds but mark fails, worst case is a duplicate event (which
        //   is better than losing the event entirely)
        self.event_store
            .persist(&event)
            .map_err(|e| WebhookError::Internal(format!("failed to persist event: {e}")))?;

        // 5. Mark delivery ID as seen (after successful persist)
        // This ensures idempotency for future requests.
        self.delivery_store.mark(delivery_id);

        tracing::info!(
            event_id = %event_id,
            delivery_id = %delivery_id,
            pr_numbers = ?event.payload.pr_numbers,
            workflow_name = %event.payload.workflow_name,
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
    use crate::events::ci::{CIEventsConfig, EventStore};
    use crate::webhook::WorkflowConclusion;

    fn sample_completed() -> WorkflowRunCompleted {
        WorkflowRunCompleted {
            workflow_run_id: 12345,
            workflow_name: "CI".to_string(),
            commit_sha: "abc123def456".to_string(),
            branch: "feature/test".to_string(),
            conclusion: WorkflowConclusion::Success,
            pull_request_numbers: vec![42],
        }
    }

    /// Creates an enabled emitter for testing.
    ///
    /// Note: `CIEventEmitter::new()` uses the default config which is disabled
    /// (fail-closed security). Tests that need events enabled must use this
    /// helper.
    fn enabled_emitter() -> CIEventEmitter {
        CIEventEmitter::with_config(
            CIEventsConfig::enabled(),
            Arc::new(InMemoryDeliveryIdStore::new()),
            Arc::new(InMemoryEventStore::new()),
        )
    }

    #[test]
    fn test_emit_success() {
        let emitter = enabled_emitter();
        let completed = sample_completed();

        let result = emitter.emit(&completed, true, "delivery-123").unwrap();

        match result {
            EmitResult::Emitted { event_id } => {
                // Verify event was persisted
                let stored = emitter.event_store().get(event_id);
                assert!(stored.is_some());

                let event = stored.unwrap();
                assert_eq!(event.payload.pr_numbers, vec![42]);
                assert_eq!(event.payload.commit_sha, "abc123def456");
                assert_eq!(event.payload.conclusion, CIConclusion::Success);
                assert!(event.signature_verified);
            },
            _ => panic!("Expected Emitted result"),
        }
    }

    #[test]
    fn test_emit_duplicate_rejected() {
        let emitter = enabled_emitter();
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
        let emitter = enabled_emitter();
        let completed = sample_completed();

        let result1 = emitter.emit(&completed, true, "delivery-1").unwrap();
        let result2 = emitter.emit(&completed, true, "delivery-2").unwrap();

        assert!(matches!(result1, EmitResult::Emitted { .. }));
        assert!(matches!(result2, EmitResult::Emitted { .. }));
        assert_eq!(emitter.event_store().count(), 2);
    }

    #[test]
    fn test_emit_failure_conclusion() {
        let emitter = enabled_emitter();
        let mut completed = sample_completed();
        completed.conclusion = WorkflowConclusion::Failure;

        let result = emitter.emit(&completed, true, "delivery-123").unwrap();

        match result {
            EmitResult::Emitted { event_id } => {
                let event = emitter.event_store().get(event_id).unwrap();
                assert_eq!(event.payload.conclusion, CIConclusion::Failure);
            },
            _ => panic!("Expected Emitted result"),
        }
    }

    #[test]
    fn test_emit_no_pr_number() {
        let emitter = enabled_emitter();
        let mut completed = sample_completed();
        completed.pull_request_numbers = vec![];

        let result = emitter.emit(&completed, true, "delivery-123").unwrap();

        match result {
            EmitResult::Emitted { event_id } => {
                let event = emitter.event_store().get(event_id).unwrap();
                assert!(event.payload.pr_numbers.is_empty());
            },
            _ => panic!("Expected Emitted result"),
        }
    }

    #[test]
    fn test_emit_multiple_pr_numbers() {
        let emitter = enabled_emitter();
        let mut completed = sample_completed();
        completed.pull_request_numbers = vec![42, 43, 44];

        let result = emitter.emit(&completed, true, "delivery-123").unwrap();

        match result {
            EmitResult::Emitted { event_id } => {
                let event = emitter.event_store().get(event_id).unwrap();
                assert_eq!(event.payload.pr_numbers, vec![42, 43, 44]);
            },
            _ => panic!("Expected Emitted result"),
        }
    }

    #[test]
    fn test_emit_workflow_name() {
        let emitter = enabled_emitter();
        let mut completed = sample_completed();
        completed.workflow_name = "Build and Test".to_string();

        let result = emitter.emit(&completed, true, "delivery-123").unwrap();

        match result {
            EmitResult::Emitted { event_id } => {
                let event = emitter.event_store().get(event_id).unwrap();
                assert_eq!(event.payload.workflow_name, "Build and Test");
            },
            _ => panic!("Expected Emitted result"),
        }
    }

    #[test]
    fn test_emit_unverified_signature() {
        let emitter = enabled_emitter();
        let completed = sample_completed();

        let result = emitter.emit(&completed, false, "delivery-123").unwrap();

        match result {
            EmitResult::Emitted { event_id } => {
                let event = emitter.event_store().get(event_id).unwrap();
                assert!(!event.signature_verified);
            },
            _ => panic!("Expected Emitted result"),
        }
    }

    #[test]
    fn test_default_impl() {
        let emitter = CIEventEmitter::default();
        assert_eq!(emitter.event_store().count(), 0);
        assert!(emitter.delivery_store().is_empty());
    }

    #[test]
    fn test_emit_disabled_via_config() {
        let emitter = CIEventEmitter::with_config(
            CIEventsConfig::disabled(),
            Arc::new(InMemoryDeliveryIdStore::new()),
            Arc::new(InMemoryEventStore::new()),
        );
        let completed = sample_completed();

        let result = emitter.emit(&completed, true, "delivery-123").unwrap();
        assert_eq!(result, EmitResult::Disabled);

        // No event should be stored
        assert_eq!(emitter.event_store().count(), 0);
        // Delivery ID should not be marked (since we returned early)
        assert!(emitter.delivery_store().is_empty());
    }

    /// A failing event store for testing atomicity guarantees.
    struct FailingEventStore;

    impl EventStore for FailingEventStore {
        fn persist(
            &self,
            _event: &CIWorkflowCompleted,
        ) -> Result<(), crate::events::ci::EventStoreError> {
            Err(crate::events::ci::EventStoreError::Storage(
                "simulated failure".to_string(),
            ))
        }

        fn query(&self, _query: &crate::events::ci::EventQuery) -> Vec<CIWorkflowCompleted> {
            vec![]
        }

        fn get(&self, _event_id: uuid::Uuid) -> Option<CIWorkflowCompleted> {
            None
        }

        fn count(&self) -> usize {
            0
        }
    }

    #[test]
    fn test_persistence_failure_allows_retry() {
        // This test verifies the atomicity guarantee:
        // If persistence fails, the delivery ID should NOT be marked,
        // allowing subsequent retries to succeed.
        let delivery_store: Arc<dyn DeliveryIdStore> = Arc::new(InMemoryDeliveryIdStore::new());
        let emitter = CIEventEmitter::with_config(
            CIEventsConfig::enabled(),
            Arc::clone(&delivery_store),
            Arc::new(FailingEventStore),
        );
        let completed = sample_completed();

        // First attempt fails due to persistence error
        let result1 = emitter.emit(&completed, true, "delivery-123");
        assert!(result1.is_err());

        // Critically: the delivery ID should NOT be marked
        // This allows retries to succeed once the store is fixed
        assert!(!delivery_store.contains("delivery-123"));
        assert!(delivery_store.is_empty());

        // Now create an emitter with a working store
        let working_emitter = enabled_emitter();

        // Retry with the same delivery ID should succeed
        // (In a real scenario, this would be the same emitter after recovery)
        let result2 = working_emitter.emit(&completed, true, "delivery-123");
        assert!(matches!(result2, Ok(EmitResult::Emitted { .. })));
    }
}
