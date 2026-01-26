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
//! variable. When disabled (default: disabled for fail-closed security),
//! webhook handlers skip event emission. The flag is cached on first access
//! to avoid hot-path lookups.
//!
//! # Bounded Memory
//!
//! Both [`InMemoryEventStore`] and [`InMemoryDeliveryIdStore`] enforce memory
//! bounds via configurable limits ([CTR-CI005]):
//!
//! - Events use a ring-buffer policy (oldest events are evicted first)
//! - Delivery IDs use O(1) eviction via insertion-order tracking with
//!   `VecDeque`
//!
//! # Contracts
//!
//! - [CTR-CI001] Events are immutable once persisted.
//! - [CTR-CI002] Delivery IDs are checked before event emission.
//! - [CTR-CI003] Event IDs are unique (UUID v4).
//! - [CTR-CI004] Timestamps use UTC.
//! - [CTR-CI005] Memory usage is bounded by configurable limits.
//!
//! # Invariants
//!
//! - [INV-CI001] Delivery ID store is thread-safe.
//! - [INV-CI002] Event store is thread-safe.
//! - [INV-CI003] TTL cleanup bounds memory usage.
//! - [INV-CI004] Eviction is O(1) for both stores.

use std::collections::{HashMap, VecDeque};
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::{OnceLock, RwLock};
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
/// use apm2_core::events::ci::{
///     CIConclusion, CIWorkflowCompleted, CIWorkflowPayload,
/// };
/// use chrono::Utc;
/// use uuid::Uuid;
///
/// let event = CIWorkflowCompleted::new(
///     CIWorkflowPayload {
///         pr_numbers: vec![42],
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct CIWorkflowPayload {
    /// All pull request numbers associated with this workflow run.
    ///
    /// A workflow run can be associated with multiple PRs (e.g., stacked PRs,
    /// merge queues, or commits affecting multiple branches). Storing all PR
    /// numbers ensures no audit information is lost.
    pub pr_numbers: Vec<u64>,

    /// The commit SHA that triggered the workflow.
    ///
    /// # Trust Model
    ///
    /// This value comes from the GitHub webhook payload which is authenticated
    /// via HMAC-SHA256 signature verification. The signature proves the payload
    /// originated from GitHub and was not tampered with in transit. Therefore,
    /// `commit_sha` is trusted data from GitHub and is not independently
    /// validated as a 40-character hex string.
    ///
    /// If you need to use this SHA for security-critical operations (e.g., as a
    /// Git ref), validate the format before use.
    pub commit_sha: String,

    /// The conclusion of the workflow run.
    pub conclusion: CIConclusion,

    /// The name of the workflow.
    pub workflow_name: String,

    /// GitHub's workflow run ID.
    pub workflow_run_id: u64,

    /// Individual check results within the workflow.
    ///
    /// # Note
    ///
    /// Currently populated as an empty list. Resolving individual check results
    /// requires additional GitHub API calls (list check runs for a commit)
    /// which is out of scope for the current implementation. This will be
    /// addressed in a future ticket when detailed check-level auditing is
    /// needed.
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
#[serde(deny_unknown_fields)]
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
// CI-Gated Phase Transition Events
// ============================================================================

/// Event emitted when a work item transitions to a new phase after CI
/// completion.
///
/// This event is the output of the CI-gated queue processing. When a
/// `CIWorkflowCompleted` event is received and matched to a work item, the
/// work item's phase transitions and this event is emitted to record the
/// transition.
///
/// # CI Gating
///
/// The CI-gated workflow transitions are:
/// - CI Success: `CiPending` -> `ReadyForReview`
/// - CI Failure: `CiPending` -> `Blocked`
///
/// # Example
///
/// ```rust
/// use apm2_core::events::ci::WorkReadyForNextPhase;
/// use uuid::Uuid;
///
/// let event = WorkReadyForNextPhase::new(
///     "work-123".to_string(),
///     "CI_PENDING".to_string(),
///     "READY_FOR_REVIEW".to_string(),
///     Uuid::new_v4(), // ID of the CIWorkflowCompleted event
/// );
///
/// assert_eq!(event.event_type, "WorkReadyForNextPhase");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkReadyForNextPhase {
    /// Unique identifier for this event (UUID v4).
    pub event_id: Uuid,

    /// The type of event (always `WorkReadyForNextPhase`).
    pub event_type: String,

    /// When the event was created (UTC).
    pub timestamp: DateTime<Utc>,

    /// The work item ID that transitioned.
    pub work_id: String,

    /// The phase the work item transitioned from.
    pub previous_phase: String,

    /// The phase the work item transitioned to.
    pub next_phase: String,

    /// The event ID of the `CIWorkflowCompleted` event that triggered this
    /// transition.
    pub triggered_by: Uuid,
}

impl WorkReadyForNextPhase {
    /// The constant event type string.
    pub const EVENT_TYPE: &'static str = "WorkReadyForNextPhase";

    /// Creates a new `WorkReadyForNextPhase` event.
    #[must_use]
    pub fn new(
        work_id: String,
        previous_phase: String,
        next_phase: String,
        triggered_by: Uuid,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            event_type: Self::EVENT_TYPE.to_string(),
            timestamp: Utc::now(),
            work_id,
            previous_phase,
            next_phase,
            triggered_by,
        }
    }

    /// Creates a new event with a specific timestamp (for testing).
    #[cfg(test)]
    #[must_use]
    pub fn with_timestamp(
        work_id: String,
        previous_phase: String,
        next_phase: String,
        triggered_by: Uuid,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            event_type: Self::EVENT_TYPE.to_string(),
            timestamp,
            work_id,
            previous_phase,
            next_phase,
            triggered_by,
        }
    }
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
/// Implementations must be thread-safe ([INV-CI001]) and unwind-safe
/// to preserve API compatibility with types that require panic safety.
pub trait DeliveryIdStore: Send + Sync + UnwindSafe + RefUnwindSafe {
    /// Checks if a delivery ID has been seen (read-only).
    ///
    /// Returns `true` if the delivery ID exists in the store (is a duplicate),
    /// `false` if it's new (not seen before).
    fn contains(&self, delivery_id: &str) -> bool;

    /// Marks a delivery ID as seen.
    ///
    /// Should be called after successfully persisting the associated event
    /// to ensure atomicity: if persistence fails, the delivery ID is not
    /// marked, allowing retries.
    fn mark(&self, delivery_id: &str);

    /// Checks if a delivery ID has been seen, and if not, marks it.
    ///
    /// Returns `true` if the delivery ID is new (not seen before),
    /// `false` if it's a duplicate.
    ///
    /// Note: Prefer using `contains()` + `mark()` separately for better
    /// atomicity guarantees when combined with event persistence.
    fn check_and_mark(&self, delivery_id: &str) -> bool {
        if self.contains(delivery_id) {
            false
        } else {
            self.mark(delivery_id);
            true
        }
    }

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

/// Queue entry tracking both key and insertion timestamp for ghost detection.
///
/// When a key is reinserted after expiration, a "ghost" entry remains in the
/// queue with the old timestamp. During eviction, we compare timestamps to
/// detect and skip ghost entries.
struct QueueEntry {
    key: String,
    inserted_at: Instant,
}

/// Internal state for the delivery ID store, protected by `RwLock`.
struct DeliveryIdState {
    /// Map from delivery ID to entry (for O(1) lookup).
    entries: HashMap<String, DeliveryIdEntry>,
    /// Queue tracking insertion order for O(1) eviction ([INV-CI004]).
    /// Entries include timestamps to detect ghost keys.
    insertion_order: VecDeque<QueueEntry>,
}

impl DeliveryIdState {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }
}

/// In-memory delivery ID store with TTL support.
///
/// Thread-safe implementation using `RwLock` ([INV-CI001]).
/// Memory is bounded by `max_entries` and TTL cleanup ([INV-CI003]).
/// Eviction is O(1) using insertion-order tracking ([INV-CI004]).
pub struct InMemoryDeliveryIdStore {
    config: DeliveryIdConfig,
    state: RwLock<DeliveryIdState>,
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
            state: RwLock::new(DeliveryIdState::new()),
            check_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Removes expired entries from the store.
    ///
    /// Uses O(1) eviction by popping entries from the front of the queue
    /// until finding a non-expired entry ([INV-CI004]).
    fn cleanup(&self) {
        let now = Instant::now();
        let ttl = self.config.ttl;

        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // O(1) amortized: pop expired entries from the front of the queue
        // Since entries are inserted in chronological order, expired entries
        // will be at the front. We stop as soon as we find a non-expired entry.
        while let Some(queue_entry) = state.insertion_order.front() {
            if let Some(map_entry) = state.entries.get(&queue_entry.key) {
                // Check if this queue entry matches the current map entry's timestamp
                // (detects ghost entries from reused keys)
                if queue_entry.inserted_at != map_entry.inserted_at {
                    // Ghost entry - different timestamp means key was reinserted
                    state.insertion_order.pop_front();
                    continue;
                }

                // Use checked_duration_since for robustness against clock issues
                let elapsed = now
                    .checked_duration_since(map_entry.inserted_at)
                    .unwrap_or(Duration::ZERO);
                if elapsed >= ttl {
                    // Entry expired, remove it
                    let entry = state.insertion_order.pop_front().unwrap();
                    state.entries.remove(&entry.key);
                } else {
                    // Found a non-expired entry, stop cleanup
                    break;
                }
            } else {
                // Key not in map (already removed), remove ghost from queue
                state.insertion_order.pop_front();
            }
        }
    }
}

impl Default for InMemoryDeliveryIdStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliveryIdStore for InMemoryDeliveryIdStore {
    fn contains(&self, delivery_id: &str) -> bool {
        let now = Instant::now();

        // Probabilistic cleanup
        let count = self
            .check_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.config.cleanup_interval > 0
            && count > 0
            && count % self.config.cleanup_interval == 0
        {
            self.cleanup();
        }

        // Check if already exists (read lock)
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(entry) = state.entries.get(delivery_id) {
            // Check if still within TTL
            // Use checked_duration_since for robustness against clock issues
            let elapsed = now
                .checked_duration_since(entry.inserted_at)
                .unwrap_or(Duration::ZERO);
            if elapsed < self.config.ttl {
                return true; // Exists and not expired
            }
        }

        false // Does not exist or expired
    }

    fn mark(&self, delivery_id: &str) {
        let now = Instant::now();

        // Insert new entry (write lock)
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Check if entry exists and is expired - remove it first
        if let Some(entry) = state.entries.get(delivery_id) {
            let elapsed = now
                .checked_duration_since(entry.inserted_at)
                .unwrap_or(Duration::ZERO);
            if elapsed >= self.config.ttl {
                // Entry expired - remove from entries map.
                // Leave ghost entry in insertion_order - cleanup() and eviction
                // will detect it via timestamp mismatch.
                state.entries.remove(delivery_id);
            } else {
                // Entry exists and not expired - nothing to do
                return;
            }
        }

        // Enforce max_entries limit with O(1) eviction ([INV-CI004])
        // Note: insertion_order may contain "ghost" entries from reused keys.
        // We detect these by comparing timestamps.
        while state.entries.len() >= self.config.max_entries {
            // Pop oldest from the front of the queue
            if let Some(queue_entry) = state.insertion_order.pop_front() {
                // Check if this is a ghost entry (timestamp mismatch) or key removed
                if let Some(map_entry) = state.entries.get(&queue_entry.key) {
                    if queue_entry.inserted_at == map_entry.inserted_at {
                        // Valid entry - remove it
                        state.entries.remove(&queue_entry.key);
                    }
                    // else: ghost entry - skip and continue
                }
                // else: key not in map - skip and continue
            } else {
                break; // Queue empty, shouldn't happen if invariants hold
            }
        }

        // Insert the new entry with timestamp
        state.entries.insert(
            delivery_id.to_string(),
            DeliveryIdEntry { inserted_at: now },
        );
        state.insertion_order.push_back(QueueEntry {
            key: delivery_id.to_string(),
            inserted_at: now,
        });
    }

    fn len(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
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

    /// Filter by PR number (matches if any PR in the event's list matches).
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
/// Implementations must be thread-safe ([INV-CI002]) and unwind-safe
/// to preserve API compatibility with types that require panic safety.
pub trait EventStore: Send + Sync + UnwindSafe + RefUnwindSafe {
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

/// Configuration for the in-memory event store.
#[derive(Debug, Clone)]
pub struct EventStoreConfig {
    /// Maximum number of events to retain (ring-buffer eviction).
    /// Default: 10,000 events.
    pub max_events: usize,
}

impl Default for EventStoreConfig {
    fn default() -> Self {
        Self { max_events: 10_000 }
    }
}

/// Internal state for the event store, protected by a single `RwLock`.
struct EventStoreState {
    /// Events stored as a `VecDeque` for O(1) eviction from front.
    events: VecDeque<CIWorkflowCompleted>,
    /// Index mapping event IDs to their position in the deque.
    /// Note: positions are relative to the logical start (front = 0).
    index_by_id: HashMap<Uuid, usize>,
    /// Counter for total events ever added (used for stable indexing).
    total_added: usize,
    /// Counter for total events evicted (used for stable indexing).
    total_evicted: usize,
}

impl EventStoreState {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            index_by_id: HashMap::new(),
            total_added: 0,
            total_evicted: 0,
        }
    }
}

/// In-memory event store implementation with bounded capacity.
///
/// Thread-safe using `RwLock` ([INV-CI002]).
/// Events are stored in insertion order with ring-buffer eviction
/// when `max_events` is reached ([CTR-CI005], [INV-CI004]).
pub struct InMemoryEventStore {
    config: EventStoreConfig,
    state: RwLock<EventStoreState>,
}

impl InMemoryEventStore {
    /// Creates a new in-memory event store with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(EventStoreConfig::default())
    }

    /// Creates a new in-memory event store with custom configuration.
    #[must_use]
    pub fn with_config(config: EventStoreConfig) -> Self {
        Self {
            config,
            state: RwLock::new(EventStoreState::new()),
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
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Check for duplicate
        if state.index_by_id.contains_key(&event.event_id) {
            return Err(EventStoreError::DuplicateEvent(event.event_id));
        }

        // Enforce max_events limit with O(1) ring-buffer eviction ([CTR-CI005])
        while state.events.len() >= self.config.max_events {
            if let Some(evicted) = state.events.pop_front() {
                state.index_by_id.remove(&evicted.event_id);
                state.total_evicted += 1;
            }
        }

        // Calculate the logical index for this event
        let logical_idx = state.total_added;
        state.events.push_back(event.clone());
        state.index_by_id.insert(event.event_id, logical_idx);
        state.total_added += 1;

        Ok(())
    }

    fn query(&self, query: &EventQuery) -> Vec<CIWorkflowCompleted> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Apply limit BEFORE collect to avoid allocating unlimited results
        // (prevents memory DoS from unbounded queries)
        let limit = query.limit.unwrap_or(usize::MAX);

        state
            .events
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

                // Filter by PR number (matches if any PR in the event's list matches)
                if let Some(pr_number) = query.pr_number {
                    if !event.payload.pr_numbers.contains(&pr_number) {
                        return false;
                    }
                }

                true
            })
            .take(limit)
            .cloned()
            .collect()
    }

    fn get(&self, event_id: Uuid) -> Option<CIWorkflowCompleted> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Look up the logical index
        if let Some(&logical_idx) = state.index_by_id.get(&event_id) {
            // Convert logical index to deque index
            let deque_idx = logical_idx.saturating_sub(state.total_evicted);
            state.events.get(deque_idx).cloned()
        } else {
            None
        }
    }

    fn count(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .events
            .len()
    }
}

// ============================================================================
// Feature Flags
// ============================================================================

/// Environment variable name for the CI events feature flag.
pub const CI_EVENTS_ENABLED_ENV: &str = "CI_EVENTS_ENABLED";

/// Environment variable name for the CI-gated queue feature flag.
pub const CI_GATED_QUEUE_ENABLED_ENV: &str = "CI_GATED_QUEUE_ENABLED";

/// Cached value of the CI events enabled flag.
///
/// Using `OnceLock` to read the environment variable only once,
/// avoiding hot-path `env::var` calls which are relatively expensive.
static CI_EVENTS_ENABLED_CACHE: OnceLock<bool> = OnceLock::new();

/// Cached value of the CI-gated queue enabled flag.
///
/// Using `OnceLock` to read the environment variable only once,
/// avoiding hot-path `env::var` calls which are relatively expensive.
static CI_GATED_QUEUE_ENABLED_CACHE: OnceLock<bool> = OnceLock::new();

/// Parses the CI events enabled flag from an environment variable value.
///
/// Returns `false` (disabled) by default for fail-closed security.
/// Only returns `true` if explicitly set to "true", "1", or "yes".
fn parse_ci_events_enabled(value: Option<&str>) -> bool {
    // Disabled by default (fail-closed security), enabled only if explicitly set
    value.is_some_and(|val| {
        let val_lower = val.to_lowercase();
        val_lower == "true" || val_lower == "1" || val_lower == "yes"
    })
}

/// Checks if CI event emission is enabled.
///
/// Reads and caches the `CI_EVENTS_ENABLED` environment variable on first call.
/// Subsequent calls return the cached value for O(1) performance on hot paths.
///
/// Returns `true` if the variable is set to "true", "1", or "yes"
/// (case-insensitive). Returns `false` by default if the variable is not set
/// (fail-closed security).
#[must_use]
pub fn is_ci_events_enabled() -> bool {
    *CI_EVENTS_ENABLED_CACHE.get_or_init(|| {
        let value = std::env::var(CI_EVENTS_ENABLED_ENV).ok();
        parse_ci_events_enabled(value.as_deref())
    })
}

/// Checks if the CI-gated queue processing is enabled.
///
/// Reads and caches the `CI_GATED_QUEUE_ENABLED` environment variable on first
/// call. Subsequent calls return the cached value for O(1) performance on hot
/// paths.
///
/// Returns `true` if the variable is set to "true", "1", or "yes"
/// (case-insensitive). Returns `false` by default if the variable is not set
/// (fail-closed security).
///
/// # CI Gating
///
/// When enabled, CI workflow completion events trigger automatic phase
/// transitions for work items (e.g., `CiPending` -> `ReadyForReview`).
#[must_use]
pub fn is_ci_gated_queue_enabled() -> bool {
    *CI_GATED_QUEUE_ENABLED_CACHE.get_or_init(|| {
        let value = std::env::var(CI_GATED_QUEUE_ENABLED_ENV).ok();
        parse_ci_events_enabled(value.as_deref())
    })
}

/// Configuration for CI events feature behavior.
///
/// This struct allows injecting configuration for testing without
/// modifying global environment variables (which is unsafe in Rust 2024).
#[derive(Debug, Clone)]
pub struct CIEventsConfig {
    /// Whether CI events are enabled.
    pub enabled: bool,
}

impl Default for CIEventsConfig {
    fn default() -> Self {
        Self {
            enabled: is_ci_events_enabled(),
        }
    }
}

impl CIEventsConfig {
    /// Creates a new config with events enabled.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Creates a new config with events disabled.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }
}

/// Configuration for CI-gated queue feature behavior.
///
/// This struct allows injecting configuration for testing without
/// modifying global environment variables (which is unsafe in Rust 2024).
#[derive(Debug, Clone)]
pub struct CIGatedQueueConfig {
    /// Whether CI-gated queue processing is enabled.
    pub enabled: bool,
}

impl Default for CIGatedQueueConfig {
    fn default() -> Self {
        Self {
            enabled: is_ci_gated_queue_enabled(),
        }
    }
}

impl CIGatedQueueConfig {
    /// Creates a new config with queue processing enabled.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Creates a new config with queue processing disabled.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
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
            pr_numbers: vec![42],
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
            assert_eq!(event.payload.pr_numbers, vec![42]);
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
            assert_eq!(event.payload.pr_numbers, deserialized.payload.pr_numbers);
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
            assert_eq!(payload["pr_numbers"], serde_json::json!([42]));
            assert_eq!(payload["commit_sha"], "abc123def456");
            assert_eq!(payload["conclusion"], "success");
            assert_eq!(payload["workflow_name"], "CI");
            assert_eq!(payload["workflow_run_id"], 12345);
        }

        /// Tests that unknown fields in JSON cause deserialization to fail.
        ///
        /// This ensures that malicious or misconfigured payloads with extra
        /// fields are rejected, preventing potential injection attacks
        /// via unhandled data.
        #[test]
        fn test_deny_unknown_fields_ci_workflow_completed() {
            let json = r#"{
                "event_id": "00000000-0000-0000-0000-000000000000",
                "event_type": "CIWorkflowCompleted",
                "timestamp": "2024-01-01T00:00:00Z",
                "source": "github_webhook",
                "payload": {
                    "pr_numbers": [42],
                    "commit_sha": "abc123",
                    "conclusion": "success",
                    "workflow_name": "CI",
                    "workflow_run_id": 12345,
                    "checks": []
                },
                "signature_verified": true,
                "delivery_id": "test-delivery",
                "unknown_field": "malicious_data"
            }"#;

            let result: Result<CIWorkflowCompleted, _> = serde_json::from_str(json);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("unknown field"),
                "Error should mention unknown field: {err}"
            );
        }

        /// Tests that unknown fields in payload cause deserialization to fail.
        #[test]
        fn test_deny_unknown_fields_ci_workflow_payload() {
            let json = r#"{
                "pr_numbers": [42],
                "commit_sha": "abc123",
                "conclusion": "success",
                "workflow_name": "CI",
                "workflow_run_id": 12345,
                "checks": [],
                "injected_field": "attack_payload"
            }"#;

            let result: Result<CIWorkflowPayload, _> = serde_json::from_str(json);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("unknown field"),
                "Error should mention unknown field: {err}"
            );
        }

        /// Tests that unknown fields in check result cause deserialization to
        /// fail.
        #[test]
        fn test_deny_unknown_fields_check_result() {
            let json = r#"{
                "name": "build",
                "conclusion": "success",
                "started_at": "2024-01-01T00:00:00Z",
                "completed_at": "2024-01-01T00:01:00Z",
                "extra_data": "should_be_rejected"
            }"#;

            let result: Result<CheckResult, _> = serde_json::from_str(json);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("unknown field"),
                "Error should mention unknown field: {err}"
            );
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
        use std::thread;

        use super::*;

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

        #[test]
        fn test_contains_and_mark_separate() {
            let store = InMemoryDeliveryIdStore::new();

            // Initially empty
            assert!(!store.contains("delivery-1"));

            // Mark it
            store.mark("delivery-1");
            assert_eq!(store.len(), 1);

            // Now contains returns true
            assert!(store.contains("delivery-1"));

            // Marking again is idempotent
            store.mark("delivery-1");
            assert_eq!(store.len(), 1);
        }

        #[test]
        fn test_cleanup_interval_zero_safe() {
            // cleanup_interval = 0 should not cause division by zero
            let config = DeliveryIdConfig {
                ttl: Duration::from_secs(3600),
                max_entries: 1000,
                cleanup_interval: 0, // Edge case
            };
            let store = InMemoryDeliveryIdStore::with_config(config);

            // This should not panic
            assert!(store.check_and_mark("delivery-1"));
            assert!(store.check_and_mark("delivery-2"));
            assert!(store.check_and_mark("delivery-3"));
            assert_eq!(store.len(), 3);
        }

        #[test]
        fn test_check_and_mark_uses_contains_and_mark() {
            // Verify that the default check_and_mark uses contains + mark
            let store = InMemoryDeliveryIdStore::new();

            // This should use contains (returns false) + mark
            assert!(store.check_and_mark("delivery-1"));
            assert_eq!(store.len(), 1);

            // This should use contains (returns true) and NOT call mark
            assert!(!store.check_and_mark("delivery-1"));
            assert_eq!(store.len(), 1); // Still 1, not added again
        }

        #[test]
        fn test_reused_key_with_max_entries_eviction() {
            // Regression test for ghost key bug: when a key is reused after
            // expiration, the eviction logic must not remove the new valid entry.
            let config = DeliveryIdConfig {
                ttl: Duration::from_millis(50),
                max_entries: 2,
                cleanup_interval: 1000, // Disable probabilistic cleanup
            };
            let store = InMemoryDeliveryIdStore::with_config(config);

            // Add first entry
            store.mark("key-a");
            assert_eq!(store.len(), 1);

            // Wait for key-a to expire
            thread::sleep(Duration::from_millis(60));

            // Reuse key-a (creates ghost in queue with old timestamp)
            store.mark("key-a");
            assert_eq!(store.len(), 1);

            // Now add key-b - this should NOT evict the new key-a
            store.mark("key-b");
            assert_eq!(store.len(), 2);

            // Both keys should still be present
            assert!(store.contains("key-a"), "key-a should still exist");
            assert!(store.contains("key-b"), "key-b should exist");

            // Add key-c - now we need to evict something
            // The ghost entry for key-a should be skipped, and either
            // the new key-a or key-b should be evicted
            store.mark("key-c");
            assert_eq!(store.len(), 2);

            // key-c is definitely there (just added)
            assert!(store.contains("key-c"), "key-c should exist");
            // And we should have exactly 2 entries
            assert_eq!(store.len(), 2);
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
                let event =
                    CIWorkflowCompleted::new(sample_payload(), true, format!("delivery-{i}"));
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
                payload.pr_numbers = vec![100 + i];
                let event = CIWorkflowCompleted::new(payload, true, format!("delivery-{i}"));
                store.persist(&event).unwrap();
            }

            let query = EventQuery::new().with_pr_number(101);
            let results = store.query(&query);
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].payload.pr_numbers, vec![101]);
        }

        #[test]
        fn test_query_by_pr_number_in_multiple_prs() {
            let store = InMemoryEventStore::new();

            // Create an event with multiple PR numbers
            let mut payload = sample_payload();
            payload.pr_numbers = vec![100, 101, 102];
            let event = CIWorkflowCompleted::new(payload, true, "delivery-1".to_string());
            store.persist(&event).unwrap();

            // Event with a different set of PRs
            let mut payload2 = sample_payload();
            payload2.pr_numbers = vec![200, 201];
            let event2 = CIWorkflowCompleted::new(payload2, true, "delivery-2".to_string());
            store.persist(&event2).unwrap();

            // Query should match event with PR 101
            let query = EventQuery::new().with_pr_number(101);
            let results = store.query(&query);
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].delivery_id, "delivery-1");

            // Query should match event with PR 200
            let query = EventQuery::new().with_pr_number(200);
            let results = store.query(&query);
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].delivery_id, "delivery-2");

            // Query should match no event
            let query = EventQuery::new().with_pr_number(999);
            let results = store.query(&query);
            assert_eq!(results.len(), 0);
        }

        #[test]
        fn test_query_with_limit() {
            let store = InMemoryEventStore::new();

            for i in 0..10 {
                let event =
                    CIWorkflowCompleted::new(sample_payload(), true, format!("delivery-{i}"));
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
                let event =
                    CIWorkflowCompleted::new(sample_payload(), true, format!("delivery-{i}"));
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

        /// Tests that `InMemoryEventStore` enforces `max_events` limit
        /// ([CTR-CI005]).
        #[test]
        fn test_event_store_bounded() {
            let config = EventStoreConfig { max_events: 5 };
            let store = InMemoryEventStore::with_config(config);

            // Add 5 events (at capacity)
            let mut event_ids = Vec::new();
            for i in 0..5 {
                let event =
                    CIWorkflowCompleted::new(sample_payload(), true, format!("delivery-{i}"));
                event_ids.push(event.event_id);
                store.persist(&event).unwrap();
            }
            assert_eq!(store.count(), 5);

            // All 5 events should be retrievable
            for &id in &event_ids {
                assert!(store.get(id).is_some());
            }

            // Add 6th event - should evict the oldest
            let event6 = CIWorkflowCompleted::new(sample_payload(), true, "delivery-5".to_string());
            let event6_id = event6.event_id;
            store.persist(&event6).unwrap();

            // Count should still be 5
            assert_eq!(store.count(), 5);

            // First event should be evicted
            assert!(store.get(event_ids[0]).is_none());

            // Events 2-5 and event 6 should still be present
            for &id in &event_ids[1..] {
                assert!(store.get(id).is_some());
            }
            assert!(store.get(event6_id).is_some());

            // Add 2 more events - should evict events 2 and 3
            let event7 = CIWorkflowCompleted::new(sample_payload(), true, "delivery-6".to_string());
            let event8 = CIWorkflowCompleted::new(sample_payload(), true, "delivery-7".to_string());
            store.persist(&event7).unwrap();
            store.persist(&event8).unwrap();

            assert_eq!(store.count(), 5);
            assert!(store.get(event_ids[1]).is_none()); // Evicted
            assert!(store.get(event_ids[2]).is_none()); // Evicted
            assert!(store.get(event_ids[3]).is_some()); // Still present
            assert!(store.get(event_ids[4]).is_some()); // Still present
        }
    }

    mod feature_flag_tests {
        use super::*;

        // These tests use the parse_ci_events_enabled function directly
        // to avoid unsafe env var manipulation and OnceLock caching issues.

        #[test]
        fn test_parse_feature_flag_default_disabled() {
            // When env var is not set (None), should be disabled by default (fail-closed)
            assert!(!parse_ci_events_enabled(None));
        }

        #[test]
        fn test_parse_feature_flag_explicitly_enabled() {
            assert!(parse_ci_events_enabled(Some("true")));
            assert!(parse_ci_events_enabled(Some("1")));
            assert!(parse_ci_events_enabled(Some("yes")));
            assert!(parse_ci_events_enabled(Some("TRUE")));
            assert!(parse_ci_events_enabled(Some("Yes")));
        }

        #[test]
        fn test_parse_feature_flag_disabled() {
            // Empty string is considered disabled (fail-closed)
            assert!(!parse_ci_events_enabled(Some("")));
            // Unrecognized values are disabled (fail-closed)
            assert!(!parse_ci_events_enabled(Some("maybe")));
        }

        #[test]
        fn test_parse_feature_flag_explicit_disable_values() {
            // These are explicitly disabled, but so is any non-"true/1/yes" value
            assert!(!parse_ci_events_enabled(Some("false")));
            assert!(!parse_ci_events_enabled(Some("0")));
            assert!(!parse_ci_events_enabled(Some("no")));
            assert!(!parse_ci_events_enabled(Some("FALSE")));
            assert!(!parse_ci_events_enabled(Some("No")));
        }

        #[test]
        fn test_ci_events_config() {
            let enabled = CIEventsConfig::enabled();
            assert!(enabled.enabled);

            let disabled = CIEventsConfig::disabled();
            assert!(!disabled.enabled);
        }

        #[test]
        fn test_ci_gated_queue_config() {
            let enabled = CIGatedQueueConfig::enabled();
            assert!(enabled.enabled);

            let disabled = CIGatedQueueConfig::disabled();
            assert!(!disabled.enabled);
        }
    }

    mod work_ready_for_next_phase_tests {
        use super::*;

        #[test]
        fn test_event_creation() {
            let triggered_by = Uuid::new_v4();
            let event = WorkReadyForNextPhase::new(
                "work-123".to_string(),
                "CI_PENDING".to_string(),
                "READY_FOR_REVIEW".to_string(),
                triggered_by,
            );

            assert_eq!(event.event_type, WorkReadyForNextPhase::EVENT_TYPE);
            assert_eq!(event.work_id, "work-123");
            assert_eq!(event.previous_phase, "CI_PENDING");
            assert_eq!(event.next_phase, "READY_FOR_REVIEW");
            assert_eq!(event.triggered_by, triggered_by);
        }

        #[test]
        fn test_event_serialization() {
            let triggered_by = Uuid::new_v4();
            let event = WorkReadyForNextPhase::new(
                "work-123".to_string(),
                "CI_PENDING".to_string(),
                "READY_FOR_REVIEW".to_string(),
                triggered_by,
            );

            let json = serde_json::to_string(&event).unwrap();
            let deserialized: WorkReadyForNextPhase = serde_json::from_str(&json).unwrap();

            assert_eq!(event.event_id, deserialized.event_id);
            assert_eq!(event.work_id, deserialized.work_id);
            assert_eq!(event.previous_phase, deserialized.previous_phase);
            assert_eq!(event.next_phase, deserialized.next_phase);
            assert_eq!(event.triggered_by, deserialized.triggered_by);
        }

        #[test]
        fn test_event_json_schema() {
            let triggered_by = Uuid::new_v4();
            let event = WorkReadyForNextPhase::new(
                "work-123".to_string(),
                "CI_PENDING".to_string(),
                "BLOCKED".to_string(),
                triggered_by,
            );

            let json = serde_json::to_value(&event).unwrap();

            // Verify required fields exist
            assert!(json.get("event_id").is_some());
            assert_eq!(json["event_type"], "WorkReadyForNextPhase");
            assert!(json.get("timestamp").is_some());
            assert_eq!(json["work_id"], "work-123");
            assert_eq!(json["previous_phase"], "CI_PENDING");
            assert_eq!(json["next_phase"], "BLOCKED");
            assert!(json.get("triggered_by").is_some());
        }

        #[test]
        fn test_deny_unknown_fields() {
            let json = r#"{
                "event_id": "00000000-0000-0000-0000-000000000000",
                "event_type": "WorkReadyForNextPhase",
                "timestamp": "2024-01-01T00:00:00Z",
                "work_id": "work-123",
                "previous_phase": "CI_PENDING",
                "next_phase": "READY_FOR_REVIEW",
                "triggered_by": "00000000-0000-0000-0000-000000000001",
                "unknown_field": "malicious_data"
            }"#;

            let result: Result<WorkReadyForNextPhase, _> = serde_json::from_str(json);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("unknown field"),
                "Error should mention unknown field: {err}"
            );
        }
    }
}
