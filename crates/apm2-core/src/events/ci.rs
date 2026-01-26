//! CI workflow ledger events.
//!
//! This module defines ledger event types for CI workflow completions,
//! providing a structured event log for CI/CD pipeline monitoring and
//! auditing.
//!
//! # Event Schema
//!
//! The [`CIWorkflowCompleted`] event captures the completion of a GitHub
//! workflow run, including:
//!
//! - Event metadata (id, type, timestamp, source)
//! - Payload (PR number, commit SHA, conclusion, workflow details)
//! - Security context (signature verification status)
//! - Idempotency key (`delivery_id` from GitHub)
//!
//! # Idempotency
//!
//! The [`DeliveryIdStore`] trait and [`InMemoryDeliveryIdStore`] implementation
//! provide idempotency tracking using GitHub's `X-GitHub-Delivery` header.
//! Duplicate webhook deliveries (e.g., retries) are detected and skipped.
//!
//! # Persistence
//!
//! The [`EventStore`] trait defines a pluggable persistence layer for events.
//! [`InMemoryEventStore`] provides an in-memory implementation suitable for
//! testing and development.
//!
//! # Feature Flag
//!
//! Event emission can be controlled via the `CI_EVENTS_ENABLED` environment
//! variable. When disabled (default: enabled), webhook handlers skip event
//! emission.
//!
//! # Contracts
//!
//! - [CTR-CI001] Events are immutable once persisted.
//! - [CTR-CI002] Delivery IDs are checked before event emission.
//! - [CTR-CI003] Event IDs are unique (UUID v4).
//! - [CTR-CI004] Timestamps use UTC.
//!
//! # Invariants
//!
//! - [INV-CI001] Delivery ID store is thread-safe.
//! - [INV-CI002] Event store is thread-safe.
//! - [INV-CI003] TTL cleanup bounds memory usage.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::webhook::WorkflowConclusion;

// ============================================================================
// Event Types
// ============================================================================

/// A CI workflow completion ledger event.
///
/// This event is emitted when a GitHub `workflow_run.completed` webhook is
/// successfully processed. It captures all relevant information for auditing
/// and downstream processing.
///
/// # Example
///
/// ```rust
/// use apm2_core::events::ci::{CIWorkflowCompleted, CIWorkflowPayload, CIConclusion};
/// use chrono::Utc;
/// use uuid::Uuid;
///
/// let event = CIWorkflowCompleted::new(
///     CIWorkflowPayload {
///         pr_number: Some(42),
///         commit_sha: "abc123def456".to_string(),
///         conclusion: CIConclusion::Success,
///         workflow_name: "CI".to_string(),
///         workflow_run_id: 12345,
///         checks: vec![],
///     },
///     true, // signature_verified
///     "delivery-uuid-from-github".to_string(),
/// );
///
/// assert_eq!(event.event_type, "CIWorkflowCompleted");
/// assert_eq!(event.source, "github_webhook");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CIWorkflowCompleted {
    /// Unique identifier for this event (UUID v4).
    pub event_id: Uuid,

    /// The type of event (always `CIWorkflowCompleted`).
    pub event_type: String,

    /// When the event was created (UTC).
    pub timestamp: DateTime<Utc>,

    /// The source of the event (always `github_webhook`).
    pub source: String,

    /// The event payload containing workflow details.
    pub payload: CIWorkflowPayload,

    /// Whether the webhook signature was verified.
    pub signature_verified: bool,

    /// GitHub's delivery ID for idempotency tracking.
    pub delivery_id: String,
}

impl CIWorkflowCompleted {
    /// The constant event type string.
    pub const EVENT_TYPE: &'static str = "CIWorkflowCompleted";

    /// The constant source string.
    pub const SOURCE: &'static str = "github_webhook";

    /// Creates a new `CIWorkflowCompleted` event.
    ///
    /// Generates a new UUID v4 for the event ID and captures the current
    /// UTC timestamp.
    #[must_use]
    pub fn new(payload: CIWorkflowPayload, signature_verified: bool, delivery_id: String) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            event_type: Self::EVENT_TYPE.to_string(),
            timestamp: Utc::now(),
            source: Self::SOURCE.to_string(),
            payload,
            signature_verified,
            delivery_id,
        }
    }

    /// Creates a new event with a specific timestamp (for testing).
    #[cfg(test)]
    #[must_use]
    pub fn with_timestamp(
        payload: CIWorkflowPayload,
        signature_verified: bool,
        delivery_id: String,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            event_type: Self::EVENT_TYPE.to_string(),
            timestamp,
            source: Self::SOURCE.to_string(),
            payload,
            signature_verified,
            delivery_id,
        }
    }
}

/// The payload of a CI workflow completion event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CIWorkflowPayload {
    /// The pull request number, if any.
    pub pr_number: Option<u64>,

    /// The commit SHA that triggered the workflow.
    pub commit_sha: String,

    /// The conclusion of the workflow run.
    pub conclusion: CIConclusion,

    /// The name of the workflow.
    pub workflow_name: String,

    /// GitHub's workflow run ID.
    pub workflow_run_id: u64,

    /// Individual check results within the workflow.
    pub checks: Vec<CheckResult>,
}

/// The conclusion of a CI workflow run.
///
/// This mirrors GitHub's workflow run conclusions but is defined separately
/// for the ledger event schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CIConclusion {
    /// The workflow completed successfully.
    Success,
    /// The workflow failed.
    Failure,
    /// The workflow was cancelled.
    Cancelled,
}

impl std::fmt::Display for CIConclusion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl From<WorkflowConclusion> for CIConclusion {
    fn from(wc: WorkflowConclusion) -> Self {
        match wc {
            WorkflowConclusion::Success => Self::Success,
            WorkflowConclusion::Failure => Self::Failure,
            WorkflowConclusion::Cancelled
            | WorkflowConclusion::Skipped
            | WorkflowConclusion::TimedOut
            | WorkflowConclusion::ActionRequired
            | WorkflowConclusion::Stale
            | WorkflowConclusion::Neutral => Self::Cancelled,
        }
    }
}

/// The conclusion of an individual check within a workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckConclusion {
    /// The check completed successfully.
    Success,
    /// The check failed.
    Failure,
    /// The check was skipped.
    Skipped,
}

impl std::fmt::Display for CheckConclusion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Skipped => write!(f, "skipped"),
        }
    }
}

/// The result of an individual check within a workflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    /// The name of the check.
    pub name: String,

    /// The conclusion of the check.
    pub conclusion: CheckConclusion,

    /// When the check started.
    pub started_at: DateTime<Utc>,

    /// When the check completed.
    pub completed_at: DateTime<Utc>,
}

// ============================================================================
// Idempotency Tracking
// ============================================================================

/// Configuration for delivery ID tracking.
#[derive(Debug, Clone)]
pub struct DeliveryIdConfig {
    /// Time-to-live for delivery IDs (default: 24 hours).
    pub ttl: Duration,

    /// Maximum number of delivery IDs to track (memory bound).
    pub max_entries: usize,

    /// How often to run cleanup (every N checks).
    pub cleanup_interval: u64,
}

impl Default for DeliveryIdConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(24 * 60 * 60), // 24 hours
            max_entries: 100_000,                   // ~10MB memory bound
            cleanup_interval: 1000,
        }
    }
}

/// Trait for delivery ID stores (idempotency tracking).
///
/// Implementations must be thread-safe ([INV-CI001]).
pub trait DeliveryIdStore: Send + Sync {
    /// Checks if a delivery ID has been seen.
    ///
    /// Returns `true` if the delivery ID is new (not seen before),
    /// `false` if it's a duplicate.
    fn check_and_mark(&self, delivery_id: &str) -> bool;

    /// Returns the number of tracked delivery IDs.
    fn len(&self) -> usize;

    /// Returns whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Entry in the delivery ID store with timestamp for TTL.
struct DeliveryIdEntry {
    inserted_at: Instant,
}

/// In-memory delivery ID store with TTL support.
///
/// Thread-safe implementation using `RwLock` ([INV-CI001]).
/// Memory is bounded by `max_entries` and TTL cleanup ([INV-CI003]).
pub struct InMemoryDeliveryIdStore {
    config: DeliveryIdConfig,
    entries: RwLock<HashMap<String, DeliveryIdEntry>>,
    check_count: std::sync::atomic::AtomicU64,
}

impl InMemoryDeliveryIdStore {
    /// Creates a new in-memory delivery ID store with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(DeliveryIdConfig::default())
    }

    /// Creates a new in-memory delivery ID store with custom configuration.
    #[must_use]
    pub fn with_config(config: DeliveryIdConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
            check_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Removes expired entries from the store.
    fn cleanup(&self) {
        let now = Instant::now();
        let ttl = self.config.ttl;

        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        entries.retain(|_, entry| now.duration_since(entry.inserted_at) < ttl);
    }
}

impl Default for InMemoryDeliveryIdStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliveryIdStore for InMemoryDeliveryIdStore {
    fn check_and_mark(&self, delivery_id: &str) -> bool {
        let now = Instant::now();

        // Probabilistic cleanup
        let count = self
            .check_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count > 0 && count % self.config.cleanup_interval == 0 {
            self.cleanup();
        }

        // Check if already exists (read lock)
        {
            let entries = self
                .entries
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            if let Some(entry) = entries.get(delivery_id) {
                // Check if still within TTL
                if now.duration_since(entry.inserted_at) < self.config.ttl {
                    return false; // Duplicate
                }
                // Expired, will be replaced below
            }
        }

        // Insert new entry (write lock)
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Double-check after acquiring write lock (race condition)
        if let Some(entry) = entries.get(delivery_id) {
            if now.duration_since(entry.inserted_at) < self.config.ttl {
                return false; // Another thread inserted it
            }
        }

        // Enforce max_entries limit
        if entries.len() >= self.config.max_entries {
            // Remove oldest entry
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, e)| e.inserted_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }

        entries.insert(
            delivery_id.to_string(),
            DeliveryIdEntry { inserted_at: now },
        );

        true // New entry
    }

    fn len(&self) -> usize {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

// ============================================================================
// Event Store
// ============================================================================

/// Query parameters for retrieving events.
#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    /// Filter by event type.
    pub event_type: Option<String>,

    /// Filter by time range start (inclusive).
    pub from: Option<DateTime<Utc>>,

    /// Filter by time range end (exclusive).
    pub to: Option<DateTime<Utc>>,

    /// Filter by PR number.
    pub pr_number: Option<u64>,

    /// Maximum number of results to return.
    pub limit: Option<usize>,
}

impl EventQuery {
    /// Creates a new empty query.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters by event type.
    #[must_use]
    pub fn with_event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type = Some(event_type.into());
        self
    }

    /// Filters by time range.
    #[must_use]
    pub const fn with_time_range(mut self, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        self.from = Some(from);
        self.to = Some(to);
        self
    }

    /// Filters by PR number.
    #[must_use]
    pub const fn with_pr_number(mut self, pr_number: u64) -> Self {
        self.pr_number = Some(pr_number);
        self
    }

    /// Limits the number of results.
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Error type for event store operations.
#[derive(Debug, thiserror::Error)]
pub enum EventStoreError {
    /// The event already exists (duplicate `event_id`).
    #[error("event already exists: {0}")]
    DuplicateEvent(Uuid),

    /// Internal storage error.
    #[error("storage error: {0}")]
    Storage(String),
}

/// Trait for event persistence.
///
/// Implementations must be thread-safe ([INV-CI002]).
pub trait EventStore: Send + Sync {
    /// Persists an event to the store.
    ///
    /// # Errors
    ///
    /// Returns `EventStoreError::DuplicateEvent` if an event with the same
    /// `event_id` already exists.
    fn persist(&self, event: &CIWorkflowCompleted) -> Result<(), EventStoreError>;

    /// Queries events matching the given criteria.
    fn query(&self, query: &EventQuery) -> Vec<CIWorkflowCompleted>;

    /// Retrieves an event by its ID.
    fn get(&self, event_id: Uuid) -> Option<CIWorkflowCompleted>;

    /// Returns the total number of events in the store.
    fn count(&self) -> usize;
}

/// In-memory event store implementation.
///
/// Thread-safe using `RwLock` ([INV-CI002]).
/// Events are stored in insertion order.
pub struct InMemoryEventStore {
    events: RwLock<Vec<CIWorkflowCompleted>>,
    index_by_id: RwLock<HashMap<Uuid, usize>>,
}

impl InMemoryEventStore {
    /// Creates a new in-memory event store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: RwLock::new(Vec::new()),
            index_by_id: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryEventStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EventStore for InMemoryEventStore {
    fn persist(&self, event: &CIWorkflowCompleted) -> Result<(), EventStoreError> {
        let mut events = self
            .events
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let mut index = self
            .index_by_id
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Check for duplicate
        if index.contains_key(&event.event_id) {
            return Err(EventStoreError::DuplicateEvent(event.event_id));
        }

        // Insert event
        let idx = events.len();
        events.push(event.clone());
        index.insert(event.event_id, idx);

        Ok(())
    }

    fn query(&self, query: &EventQuery) -> Vec<CIWorkflowCompleted> {
        let events = self
            .events
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let mut results: Vec<CIWorkflowCompleted> = events
            .iter()
            .filter(|event| {
                // Filter by event type
                if let Some(ref event_type) = query.event_type {
                    if &event.event_type != event_type {
                        return false;
                    }
                }

                // Filter by time range
                if let Some(ref from) = query.from {
                    if &event.timestamp < from {
                        return false;
                    }
                }
                if let Some(ref to) = query.to {
                    if &event.timestamp >= to {
                        return false;
                    }
                }

                // Filter by PR number
                if let Some(pr_number) = query.pr_number {
                    if event.payload.pr_number != Some(pr_number) {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect();

        // Apply limit
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        results
    }

    fn get(&self, event_id: Uuid) -> Option<CIWorkflowCompleted> {
        let events = self
            .events
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let index = self
            .index_by_id
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        index.get(&event_id).map(|&idx| events[idx].clone())
    }

    fn count(&self) -> usize {
        self.events
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

// ============================================================================
// Feature Flag
// ============================================================================

/// Environment variable name for the CI events feature flag.
pub const CI_EVENTS_ENABLED_ENV: &str = "CI_EVENTS_ENABLED";

/// Checks if CI event emission is enabled.
///
/// Reads the `CI_EVENTS_ENABLED` environment variable.
/// Returns `true` if the variable is set to "true", "1", or "yes" (case-insensitive).
/// Returns `true` by default if the variable is not set.
#[must_use]
pub fn is_ci_events_enabled() -> bool {
    match std::env::var(CI_EVENTS_ENABLED_ENV) {
        Ok(val) => {
            let val_lower = val.to_lowercase();
            // Explicitly disabled
            if val_lower == "false" || val_lower == "0" || val_lower == "no" {
                return false;
            }
            // Any other value (including empty) is considered enabled
            true
        }
        Err(_) => true, // Enabled by default
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> CIWorkflowPayload {
        CIWorkflowPayload {
            pr_number: Some(42),
            commit_sha: "abc123def456".to_string(),
            conclusion: CIConclusion::Success,
            workflow_name: "CI".to_string(),
            workflow_run_id: 12345,
            checks: vec![CheckResult {
                name: "build".to_string(),
                conclusion: CheckConclusion::Success,
                started_at: Utc::now(),
                completed_at: Utc::now(),
            }],
        }
    }

    mod event_tests {
        use super::*;

        #[test]
        fn test_event_creation() {
            let event =
                CIWorkflowCompleted::new(sample_payload(), true, "delivery-123".to_string());

            assert_eq!(event.event_type, CIWorkflowCompleted::EVENT_TYPE);
            assert_eq!(event.source, CIWorkflowCompleted::SOURCE);
            assert!(event.signature_verified);
            assert_eq!(event.delivery_id, "delivery-123");
            assert_eq!(event.payload.pr_number, Some(42));
            assert_eq!(event.payload.conclusion, CIConclusion::Success);
        }

        #[test]
        fn test_event_serialization() {
            let event =
                CIWorkflowCompleted::new(sample_payload(), true, "delivery-123".to_string());

            let json = serde_json::to_string(&event).unwrap();
            let deserialized: CIWorkflowCompleted = serde_json::from_str(&json).unwrap();

            assert_eq!(event.event_id, deserialized.event_id);
            assert_eq!(event.event_type, deserialized.event_type);
            assert_eq!(event.delivery_id, deserialized.delivery_id);
            assert_eq!(event.payload.pr_number, deserialized.payload.pr_number);
        }

        #[test]
        fn test_event_json_schema() {
            let event =
                CIWorkflowCompleted::new(sample_payload(), true, "delivery-123".to_string());

            let json = serde_json::to_value(&event).unwrap();

            // Verify required fields exist
            assert!(json.get("event_id").is_some());
            assert_eq!(json["event_type"], "CIWorkflowCompleted");
            assert!(json.get("timestamp").is_some());
            assert_eq!(json["source"], "github_webhook");
            assert!(json.get("payload").is_some());
            assert_eq!(json["signature_verified"], true);
            assert_eq!(json["delivery_id"], "delivery-123");

            // Verify payload structure
            let payload = &json["payload"];
            assert_eq!(payload["pr_number"], 42);
            assert_eq!(payload["commit_sha"], "abc123def456");
            assert_eq!(payload["conclusion"], "success");
            assert_eq!(payload["workflow_name"], "CI");
            assert_eq!(payload["workflow_run_id"], 12345);
        }

        #[test]
        fn test_ci_conclusion_conversion() {
            assert_eq!(
                CIConclusion::from(WorkflowConclusion::Success),
                CIConclusion::Success
            );
            assert_eq!(
                CIConclusion::from(WorkflowConclusion::Failure),
                CIConclusion::Failure
            );
            assert_eq!(
                CIConclusion::from(WorkflowConclusion::Cancelled),
                CIConclusion::Cancelled
            );
            assert_eq!(
                CIConclusion::from(WorkflowConclusion::Skipped),
                CIConclusion::Cancelled
            );
            assert_eq!(
                CIConclusion::from(WorkflowConclusion::TimedOut),
                CIConclusion::Cancelled
            );
        }

        #[test]
        fn test_conclusion_display() {
            assert_eq!(format!("{}", CIConclusion::Success), "success");
            assert_eq!(format!("{}", CIConclusion::Failure), "failure");
            assert_eq!(format!("{}", CIConclusion::Cancelled), "cancelled");
        }

        #[test]
        fn test_check_conclusion_display() {
            assert_eq!(format!("{}", CheckConclusion::Success), "success");
            assert_eq!(format!("{}", CheckConclusion::Failure), "failure");
            assert_eq!(format!("{}", CheckConclusion::Skipped), "skipped");
        }
    }

    mod idempotency_tests {
        use super::*;
        use std::thread;

        #[test]
        fn test_new_delivery_id_accepted() {
            let store = InMemoryDeliveryIdStore::new();

            assert!(store.check_and_mark("delivery-1"));
            assert_eq!(store.len(), 1);
        }

        #[test]
        fn test_duplicate_delivery_id_rejected() {
            let store = InMemoryDeliveryIdStore::new();

            assert!(store.check_and_mark("delivery-1"));
            assert!(!store.check_and_mark("delivery-1")); // Duplicate
            assert_eq!(store.len(), 1);
        }

        #[test]
        fn test_different_delivery_ids_accepted() {
            let store = InMemoryDeliveryIdStore::new();

            assert!(store.check_and_mark("delivery-1"));
            assert!(store.check_and_mark("delivery-2"));
            assert!(store.check_and_mark("delivery-3"));
            assert_eq!(store.len(), 3);
        }

        #[test]
        fn test_expired_delivery_id_accepted() {
            let config = DeliveryIdConfig {
                ttl: Duration::from_millis(50),
                max_entries: 1000,
                cleanup_interval: 1000,
            };
            let store = InMemoryDeliveryIdStore::with_config(config);

            assert!(store.check_and_mark("delivery-1"));
            assert!(!store.check_and_mark("delivery-1")); // Still valid

            // Wait for TTL to expire
            thread::sleep(Duration::from_millis(60));

            assert!(store.check_and_mark("delivery-1")); // Now accepted
        }

        #[test]
        fn test_max_entries_enforcement() {
            let config = DeliveryIdConfig {
                ttl: Duration::from_secs(3600),
                max_entries: 3,
                cleanup_interval: 1000,
            };
            let store = InMemoryDeliveryIdStore::with_config(config);

            assert!(store.check_and_mark("delivery-1"));
            assert!(store.check_and_mark("delivery-2"));
            assert!(store.check_and_mark("delivery-3"));
            assert_eq!(store.len(), 3);

            // Adding 4th should evict oldest
            assert!(store.check_and_mark("delivery-4"));
            assert_eq!(store.len(), 3);

            // First delivery should have been evicted
            assert!(store.check_and_mark("delivery-1")); // Accepted as new
        }

        #[test]
        fn test_concurrent_access() {
            use std::sync::Arc;

            let store = Arc::new(InMemoryDeliveryIdStore::new());
            let mut handles = vec![];

            // Spawn multiple threads trying to mark the same delivery ID
            for _ in 0..10 {
                let store_clone = Arc::clone(&store);
                handles.push(thread::spawn(move || {
                    store_clone.check_and_mark("same-delivery-id")
                }));
            }

            let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            // Exactly one thread should succeed
            let accepted_count = results.iter().filter(|&&r| r).count();
            assert_eq!(accepted_count, 1, "Only one thread should mark the ID");
            assert_eq!(store.len(), 1);
        }

        #[test]
        fn test_is_empty() {
            let store = InMemoryDeliveryIdStore::new();
            assert!(store.is_empty());

            store.check_and_mark("delivery-1");
            assert!(!store.is_empty());
        }
    }

    mod event_store_tests {
        use super::*;

        #[test]
        fn test_persist_and_get() {
            let store = InMemoryEventStore::new();
            let event =
                CIWorkflowCompleted::new(sample_payload(), true, "delivery-123".to_string());

            store.persist(&event).unwrap();

            let retrieved = store.get(event.event_id).unwrap();
            assert_eq!(retrieved.event_id, event.event_id);
            assert_eq!(retrieved.delivery_id, "delivery-123");
        }

        #[test]
        fn test_duplicate_event_rejected() {
            let store = InMemoryEventStore::new();
            let event =
                CIWorkflowCompleted::new(sample_payload(), true, "delivery-123".to_string());

            store.persist(&event).unwrap();
            let result = store.persist(&event);

            assert!(matches!(result, Err(EventStoreError::DuplicateEvent(_))));
        }

        #[test]
        fn test_query_by_event_type() {
            let store = InMemoryEventStore::new();

            for i in 0..5 {
                let event = CIWorkflowCompleted::new(
                    sample_payload(),
                    true,
                    format!("delivery-{i}"),
                );
                store.persist(&event).unwrap();
            }

            let query = EventQuery::new().with_event_type("CIWorkflowCompleted");
            let results = store.query(&query);
            assert_eq!(results.len(), 5);
        }

        #[test]
        fn test_query_by_pr_number() {
            let store = InMemoryEventStore::new();

            // Create events with different PR numbers
            for i in 0..3 {
                let mut payload = sample_payload();
                payload.pr_number = Some(100 + i);
                let event =
                    CIWorkflowCompleted::new(payload, true, format!("delivery-{i}"));
                store.persist(&event).unwrap();
            }

            let query = EventQuery::new().with_pr_number(101);
            let results = store.query(&query);
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].payload.pr_number, Some(101));
        }

        #[test]
        fn test_query_with_limit() {
            let store = InMemoryEventStore::new();

            for i in 0..10 {
                let event = CIWorkflowCompleted::new(
                    sample_payload(),
                    true,
                    format!("delivery-{i}"),
                );
                store.persist(&event).unwrap();
            }

            let query = EventQuery::new().with_limit(3);
            let results = store.query(&query);
            assert_eq!(results.len(), 3);
        }

        #[test]
        fn test_query_by_time_range() {
            let store = InMemoryEventStore::new();

            let t1 = Utc::now() - chrono::Duration::hours(2);
            let t2 = Utc::now() - chrono::Duration::hours(1);
            let t3 = Utc::now();

            // Create events at different times
            let event1 = CIWorkflowCompleted::with_timestamp(
                sample_payload(),
                true,
                "delivery-1".to_string(),
                t1,
            );
            let event2 = CIWorkflowCompleted::with_timestamp(
                sample_payload(),
                true,
                "delivery-2".to_string(),
                t2,
            );
            let event3 = CIWorkflowCompleted::with_timestamp(
                sample_payload(),
                true,
                "delivery-3".to_string(),
                t3,
            );

            store.persist(&event1).unwrap();
            store.persist(&event2).unwrap();
            store.persist(&event3).unwrap();

            // Query for events between t1 and t2 (exclusive)
            let query = EventQuery::new().with_time_range(t1, t2);
            let results = store.query(&query);
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].delivery_id, "delivery-1");
        }

        #[test]
        fn test_count() {
            let store = InMemoryEventStore::new();
            assert_eq!(store.count(), 0);

            for i in 0..5 {
                let event = CIWorkflowCompleted::new(
                    sample_payload(),
                    true,
                    format!("delivery-{i}"),
                );
                store.persist(&event).unwrap();
            }

            assert_eq!(store.count(), 5);
        }

        #[test]
        fn test_get_nonexistent() {
            let store = InMemoryEventStore::new();
            let result = store.get(Uuid::new_v4());
            assert!(result.is_none());
        }
    }

    // These tests modify environment variables and require unsafe blocks.
    // The unsafe is acceptable here because:
    // 1. Tests run serially by default when touching global state
    // 2. This is test-only code that doesn't affect production
    #[allow(unsafe_code)]
    mod feature_flag_tests {
        use super::*;
        use std::env;

        // Note: These tests modify environment variables and should not run in parallel.
        // In Rust 2024 edition, env::set_var and env::remove_var are unsafe because
        // they can cause data races when run concurrently.

        #[test]
        fn test_feature_flag_default_enabled() {
            // Remove the env var to test default behavior
            // SAFETY: This test runs in isolation (cargo test runs tests serially by default
            // when they touch global state like env vars). The env var is only used by this
            // test module.
            unsafe { env::remove_var(CI_EVENTS_ENABLED_ENV) };
            assert!(is_ci_events_enabled());
        }

        #[test]
        fn test_feature_flag_explicitly_enabled() {
            // SAFETY: See above - test isolation ensures no concurrent access
            unsafe { env::set_var(CI_EVENTS_ENABLED_ENV, "true") };
            assert!(is_ci_events_enabled());

            unsafe { env::set_var(CI_EVENTS_ENABLED_ENV, "1") };
            assert!(is_ci_events_enabled());

            unsafe { env::set_var(CI_EVENTS_ENABLED_ENV, "yes") };
            assert!(is_ci_events_enabled());

            // Cleanup
            unsafe { env::remove_var(CI_EVENTS_ENABLED_ENV) };
        }

        #[test]
        fn test_feature_flag_disabled() {
            // SAFETY: See above - test isolation ensures no concurrent access
            unsafe { env::set_var(CI_EVENTS_ENABLED_ENV, "false") };
            assert!(!is_ci_events_enabled());

            unsafe { env::set_var(CI_EVENTS_ENABLED_ENV, "0") };
            assert!(!is_ci_events_enabled());

            unsafe { env::set_var(CI_EVENTS_ENABLED_ENV, "no") };
            assert!(!is_ci_events_enabled());

            // Cleanup
            unsafe { env::remove_var(CI_EVENTS_ENABLED_ENV) };
        }
    }
}
