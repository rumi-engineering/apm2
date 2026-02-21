//! Topic derivation for HEF Pulse Plane (RFC-0018, TCK-00305).
//!
//! This module implements deterministic topic derivation for kernel events,
//! mapping Work and Gate events to their respective pulse topics.
//!
//! # Topic Taxonomy (DD-HEF-0001)
//!
//! - `work.<work_id>.events` - Work lifecycle events
//! - `work_graph.<work_id>.edge` - Work graph edge events (TCK-00642)
//! - `gate.<work_id>.<changeset_digest>.<gate_id>` - Gate receipt events
//! - `ledger.head` - System/ledger events
//! - `episode.<episode_id>.<category>` - Episode lifecycle and tool events
//! - `defect.new` - Defect notifications
//!
//! # Multi-Topic Derivation (TCK-00642)
//!
//! Work graph edge events (`work_graph.edge.added/removed/waived`) reference
//! two work IDs (`from_work_id` and `to_work_id`). These events emit **two**
//! topics, one for each work ID, so subscribers to either work item receive
//! the notification. Use [`TopicDeriver::derive_topics`] for these events.
//!
//! # Security Invariants
//!
//! - [INV-TOPIC-001] Topic derivation is deterministic given same inputs
//! - [INV-TOPIC-002] Invalid inputs produce sanitized, valid topics
//! - [INV-TOPIC-003] Changeset lookup uses bounded-size index
//! - [INV-TOPIC-004] All derived topics pass HEF Topic Grammar validation
//! - [INV-TOPIC-005] Work graph event types MUST NOT start with `work.` prefix
//!   to avoid WorkReducer decoding (TCK-00642)
//!
//! # Changeset->Work Mapping (TCK-00305)
//!
//! Gate receipts reference a `changeset_digest` but need to route to topics
//! containing `work_id`. The `ChangesetWorkIndex` maintains this mapping by
//! observing `PolicyResolvedForChangeSet` events, which establish the
//! relationship between changesets and work items.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use apm2_core::events::KernelEvent;
use apm2_core::events::kernel_event::Payload;
use apm2_core::ledger::CommitNotification;
use tracing::{debug, warn};

use super::pulse_topic::{MAX_SEGMENT_LEN, validate_topic};

// ============================================================================
// Constants
// ============================================================================

/// Maximum entries in the changeset->work_id index.
///
/// Prevents unbounded memory growth. When capacity is reached, an entry
/// is evicted to make room for new mappings.
///
/// A typical work session produces ~10-100 changesets, so 10,000 entries
/// provides ample headroom while bounding memory to ~1MB worst case.
pub const MAX_CHANGESET_INDEX_ENTRIES: usize = 10_000;

// ============================================================================
// Topic Derivation Result
// ============================================================================

/// Result of topic derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopicDerivationResult {
    /// Successfully derived a valid topic.
    Success(String),
    /// Topic derivation failed validation.
    ValidationFailed {
        /// The attempted topic string.
        attempted_topic: String,
        /// The validation error message.
        error: String,
    },
    /// No topic could be derived (e.g., missing required data).
    NoTopic,
}

impl TopicDerivationResult {
    /// Returns the topic string if successful.
    #[must_use]
    pub fn topic(&self) -> Option<&str> {
        match self {
            Self::Success(t) => Some(t),
            _ => None,
        }
    }

    /// Returns true if derivation was successful.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }
}

// ============================================================================
// Changeset->Work Index
// ============================================================================

/// Index mapping changeset digests to work IDs.
///
/// This index is populated by observing `PolicyResolvedForChangeSet` events
/// and queried when deriving topics for `GateReceipt` events.
///
/// # Thread Safety
///
/// The index uses interior mutability with `RwLock` for concurrent access.
/// Writers (index updates) are rare compared to readers (topic derivation).
///
/// # Memory Bounds (INV-TOPIC-003)
///
/// The index implements bounded eviction. When capacity is reached,
/// an arbitrary entry is removed to make room for new mappings.
#[derive(Debug, Clone, Default)]
pub struct ChangesetWorkIndex {
    /// The mapping from changeset digest to work ID.
    inner: Arc<RwLock<HashMap<Vec<u8>, String>>>,
}

impl ChangesetWorkIndex {
    /// Creates a new empty index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Inserts a mapping from changeset digest to work ID.
    ///
    /// If the index is at capacity, an arbitrary entry is evicted first.
    pub fn insert(&self, changeset_digest: Vec<u8>, work_id: String) {
        let mut map = self.inner.write().expect("lock poisoned");

        // Bounded eviction: remove an entry if at capacity
        if map.len() >= MAX_CHANGESET_INDEX_ENTRIES {
            if let Some(key_to_remove) = map.keys().next().cloned() {
                map.remove(&key_to_remove);
                debug!(
                    evicted_entries = 1,
                    map_size = map.len(),
                    "Evicted changeset mapping due to capacity limit"
                );
            }
        }

        map.insert(changeset_digest, work_id);
    }

    /// Looks up the work ID for a changeset digest.
    #[must_use]
    pub fn get(&self, changeset_digest: &[u8]) -> Option<String> {
        let map = self.inner.read().expect("lock poisoned");
        map.get(changeset_digest).cloned()
    }

    /// Returns the current number of entries in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        let map = self.inner.read().expect("lock poisoned");
        map.len()
    }

    /// Returns true if the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let map = self.inner.read().expect("lock poisoned");
        map.is_empty()
    }

    /// Updates the index from a kernel event.
    ///
    /// Only `PolicyResolvedForChangeSet` events update the index.
    pub fn update_from_event(&self, event: &KernelEvent) {
        if let Some(Payload::PolicyResolvedForChangeset(p)) = &event.payload {
            self.insert(p.changeset_digest.clone(), p.work_id.clone());
        }
    }
}

// ============================================================================
// Topic Deriver
// ============================================================================

/// Derives pulse topics from kernel events.
///
/// The deriver implements the topic taxonomy defined in DD-HEF-0001:
/// - Work events map to `work.<work_id>.events`
/// - Gate receipts map to `gate.<work_id>.<changeset_digest>.<gate_id>`
/// - Ledger/system events map to `ledger.head`
/// - Episode events map to `episode.<episode_id>.<category>`
/// - Defect events map to `defect.new`
///
/// # Determinism (INV-TOPIC-001)
///
/// Topic derivation is deterministic: given the same event and index state,
/// the same topic is always produced.
#[derive(Debug, Clone)]
pub struct TopicDeriver {
    /// Index for changeset->work_id lookups.
    changeset_index: ChangesetWorkIndex,
}

impl Default for TopicDeriver {
    fn default() -> Self {
        Self::new()
    }
}

impl TopicDeriver {
    /// Creates a new topic deriver with an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            changeset_index: ChangesetWorkIndex::new(),
        }
    }

    /// Creates a topic deriver with a shared index.
    ///
    /// Use this when multiple components need to share the same index.
    #[must_use]
    pub const fn with_index(changeset_index: ChangesetWorkIndex) -> Self {
        Self { changeset_index }
    }

    /// Returns a reference to the changeset index.
    #[must_use]
    pub const fn changeset_index(&self) -> &ChangesetWorkIndex {
        &self.changeset_index
    }

    /// Updates the internal index from an event.
    ///
    /// Call this before `derive_topic` to ensure the index is up-to-date.
    pub fn update_index(&self, event: &KernelEvent) {
        self.changeset_index.update_from_event(event);
    }

    /// Derives a topic from a commit notification and its decoded event.
    ///
    /// # Arguments
    ///
    /// * `notification` - The commit notification with metadata
    /// * `event` - The decoded kernel event
    ///
    /// # Returns
    ///
    /// The derived topic result. On success, contains a validated topic string.
    ///
    /// # Note
    ///
    /// For work graph edge events (`work_graph.edge.*`), this returns only
    /// the first topic (for `from_work_id`). Use
    /// [`derive_topics`](Self::derive_topics) to get topics for both work
    /// IDs.
    ///
    /// # Determinism
    ///
    /// This method is deterministic: the same inputs always produce the same
    /// output.
    #[must_use]
    pub fn derive_topic(
        &self,
        notification: &CommitNotification,
        event: &KernelEvent,
    ) -> TopicDerivationResult {
        let topic = self.derive_topic_internal(notification, event);

        // Validate the derived topic
        match validate_topic(&topic) {
            Ok(()) => TopicDerivationResult::Success(topic),
            Err(e) => {
                warn!(
                    topic = %topic,
                    error = %e,
                    event_type = %notification.event_type,
                    "Derived topic failed validation"
                );
                TopicDerivationResult::ValidationFailed {
                    attempted_topic: topic,
                    error: e.to_string(),
                }
            },
        }
    }

    /// Derives all topics from a commit notification and its decoded event.
    ///
    /// Most event types produce a single topic (returned as a one-element vec).
    /// Work graph edge events (`work_graph.edge.*`) produce two topics: one for
    /// `from_work_id` and one for `to_work_id` (TCK-00642).
    ///
    /// # Arguments
    ///
    /// * `notification` - The commit notification with metadata
    /// * `event` - The decoded kernel event
    ///
    /// # Returns
    ///
    /// A vector of topic derivation results. Empty if no topics could be
    /// derived.
    ///
    /// # Determinism
    ///
    /// This method is deterministic: the same inputs always produce the same
    /// output in the same order.
    #[must_use]
    pub fn derive_topics(
        &self,
        notification: &CommitNotification,
        event: &KernelEvent,
    ) -> Vec<TopicDerivationResult> {
        // Check if this is a multi-topic event (work graph edges)
        match notification.event_type.as_str() {
            "WorkEdgeAdded" | "WorkEdgeRemoved" | "WorkEdgeWaived" => {
                derive_work_graph_topics(event)
            },
            _ => {
                // Single-topic events: delegate to the existing method
                vec![self.derive_topic(notification, event)]
            },
        }
    }

    /// Internal topic derivation without validation.
    fn derive_topic_internal(
        &self,
        notification: &CommitNotification,
        event: &KernelEvent,
    ) -> String {
        let sanitized_namespace = sanitize_segment(&notification.namespace);

        match notification.event_type.as_str() {
            // System events -> ledger.head
            "KernelEvent" | "LedgerEvent" => "ledger.head".to_string(),

            // Work events -> work.<work_id>.events (TCK-00305)
            "WorkOpened" | "WorkTransitioned" | "WorkCompleted" | "WorkAborted"
            | "WorkPrAssociated" => derive_work_topic(event, &sanitized_namespace),

            // Gate receipts -> gate.<work_id>.<changeset_digest>.<gate_id> (TCK-00305)
            "GateReceipt" => self.derive_gate_topic(event, &sanitized_namespace),

            // Session events -> episode.<episode_id>.lifecycle if episode_id present (TCK-00306)
            // Falls back to namespace.lifecycle for non-episode sessions
            "SessionStarted" | "SessionProgress" | "SessionTerminated" | "SessionQuarantined" => {
                derive_session_topic(event, &sanitized_namespace)
            },

            // Episode lifecycle events (legacy compatibility)
            "EpisodeCreated" | "EpisodeStarted" | "EpisodeStopped" => {
                format!("episode.{sanitized_namespace}.lifecycle")
            },

            // Tool events -> episode.<episode_id>.tool if episode_id present (TCK-00306)
            // Falls back to namespace.tool for non-episode sessions
            "ToolRequested" | "ToolDecided" | "ToolExecuted" => {
                derive_tool_topic(event, &sanitized_namespace)
            },

            // IO artifact events -> episode.<episode_id>.io (TCK-00306)
            "IoArtifactPublished" => derive_io_artifact_topic(event, &sanitized_namespace),

            // Defect events (TCK-00307)
            // DefectRecorded ledger events derive to defect.new topic
            "DefectRecorded" => "defect.new".to_string(),

            // PolicyResolvedForChangeSet -> work topic (for observability)
            "PolicyResolvedForChangeSet" => {
                if let Some(Payload::PolicyResolvedForChangeset(p)) = &event.payload {
                    format!("work.{}.policy", sanitize_segment(&p.work_id))
                } else {
                    format!("{sanitized_namespace}.events")
                }
            },

            // Work graph edge events -> work_graph.<from_work_id>.edge (TCK-00642)
            // INV-TOPIC-005: Uses `work_graph.` prefix, NOT `work.`, to avoid
            // WorkReducer decoding.
            // Note: This returns only the from_work_id topic. For multi-topic
            // derivation (both work IDs), use derive_topics().
            "WorkEdgeAdded" | "WorkEdgeRemoved" | "WorkEdgeWaived" => {
                derive_work_graph_primary_topic(event, &sanitized_namespace)
            },

            // Default: namespace-based topic
            _ => format!("{sanitized_namespace}.events"),
        }
    }

    /// Derives a gate topic with `work_id` lookup from the changeset index.
    ///
    /// Format: `gate.<work_id>.<changeset_digest_hex>.<gate_id>`
    ///
    /// If the `work_id` cannot be found in the index, falls back to using
    /// the sanitized namespace.
    fn derive_gate_topic(&self, event: &KernelEvent, fallback_work_id: &str) -> String {
        if let Some(Payload::GateReceipt(g)) = &event.payload {
            // Lookup work_id from changeset_digest
            let work_id = self
                .changeset_index
                .get(&g.changeset_digest)
                .map_or_else(|| fallback_work_id.to_string(), |s| sanitize_segment(&s));

            // Encode changeset digest as hex (truncated for topic length limits)
            let digest_hex = encode_digest_for_topic(&g.changeset_digest);
            let gate_id = sanitize_segment(&g.gate_id);

            format!("gate.{work_id}.{digest_hex}.{gate_id}")
        } else {
            // Fallback if payload doesn't match expected type
            format!("gate.{fallback_work_id}.receipts")
        }
    }
}

// ============================================================================
// Work Topic Derivation (TCK-00305)
// ============================================================================

/// Derives a work topic from a work event.
///
/// Format: `work.<work_id>.events`
///
/// Extracts the `work_id` from the `WorkEvent` payload variants.
fn derive_work_topic(event: &KernelEvent, fallback_namespace: &str) -> String {
    if let Some(Payload::Work(w)) = &event.payload {
        let work_id = match &w.event {
            Some(apm2_core::events::work_event::Event::Opened(e)) => &e.work_id,
            Some(apm2_core::events::work_event::Event::Transitioned(e)) => &e.work_id,
            Some(apm2_core::events::work_event::Event::Completed(e)) => &e.work_id,
            Some(apm2_core::events::work_event::Event::Aborted(e)) => &e.work_id,
            Some(apm2_core::events::work_event::Event::PrAssociated(e)) => &e.work_id,
            None => {
                // Event variant is None, fall back to namespace
                return format!("work.{fallback_namespace}.events");
            },
        };
        format!("work.{}.events", sanitize_segment(work_id))
    } else {
        // Payload is not a Work event, fall back to namespace
        format!("work.{fallback_namespace}.events")
    }
}

// ============================================================================
// Session Topic Derivation (TCK-00306)
// ============================================================================

/// Derives a session topic from a session event.
///
/// Format: `episode.<episode_id>.lifecycle` if `episode_id` is populated
/// Fallback: `<namespace>.lifecycle` for non-episode sessions
///
/// Extracts the `episode_id` from the `SessionEvent` payload variants
/// (RFC-0018).
fn derive_session_topic(event: &KernelEvent, fallback_namespace: &str) -> String {
    if let Some(Payload::Session(s)) = &event.payload {
        let episode_id = match &s.event {
            Some(apm2_core::events::session_event::Event::Started(e)) => &e.episode_id,
            Some(apm2_core::events::session_event::Event::Progress(e)) => &e.episode_id,
            Some(apm2_core::events::session_event::Event::Terminated(e)) => &e.episode_id,
            Some(apm2_core::events::session_event::Event::Quarantined(e)) => &e.episode_id,
            // CrashDetected and RestartScheduled don't have episode_id
            Some(
                apm2_core::events::session_event::Event::CrashDetected(_)
                | apm2_core::events::session_event::Event::RestartScheduled(_),
            )
            | None => {
                return format!("{fallback_namespace}.lifecycle");
            },
        };

        // Use episode_id if populated, otherwise fall back to namespace
        if episode_id.is_empty() {
            format!("{fallback_namespace}.lifecycle")
        } else {
            format!("episode.{}.lifecycle", sanitize_segment(episode_id))
        }
    } else {
        format!("{fallback_namespace}.lifecycle")
    }
}

// ============================================================================
// Tool Topic Derivation (TCK-00306)
// ============================================================================

/// Derives a tool topic from a tool event.
///
/// Format: `episode.<episode_id>.tool` if `episode_id` is populated
/// Fallback: `<namespace>.tool` for non-episode sessions
///
/// Extracts the `episode_id` from the `ToolEvent` payload variants (RFC-0018).
fn derive_tool_topic(event: &KernelEvent, fallback_namespace: &str) -> String {
    if let Some(Payload::Tool(t)) = &event.payload {
        let episode_id = match &t.event {
            Some(apm2_core::events::tool_event::Event::Requested(e)) => &e.episode_id,
            Some(apm2_core::events::tool_event::Event::Decided(e)) => &e.episode_id,
            Some(apm2_core::events::tool_event::Event::Executed(e)) => &e.episode_id,
            None => {
                return format!("{fallback_namespace}.tool");
            },
        };

        // Use episode_id if populated, otherwise fall back to namespace
        if episode_id.is_empty() {
            format!("{fallback_namespace}.tool")
        } else {
            format!("episode.{}.tool", sanitize_segment(episode_id))
        }
    } else {
        format!("{fallback_namespace}.tool")
    }
}

// ============================================================================
// IO Artifact Topic Derivation (TCK-00306)
// ============================================================================

/// Derives an IO artifact topic from an `IoArtifactPublished` event.
///
/// Format: `episode.<episode_id>.io`
/// Fallback: `<namespace>.io` if `episode_id` is missing
///
/// Extracts the `episode_id` from the `IoArtifactPublished` event (RFC-0018).
fn derive_io_artifact_topic(event: &KernelEvent, fallback_namespace: &str) -> String {
    if let Some(Payload::IoArtifactPublished(io)) = &event.payload {
        if io.episode_id.is_empty() {
            format!("{fallback_namespace}.io")
        } else {
            format!("episode.{}.io", sanitize_segment(&io.episode_id))
        }
    } else {
        format!("{fallback_namespace}.io")
    }
}

// ============================================================================
// Work Graph Topic Derivation (TCK-00642)
// ============================================================================

/// Extracts the `from_work_id` and `to_work_id` from a `WorkGraphEvent`.
///
/// Returns `(from_work_id, to_work_id)` if the event payload is a valid
/// `WorkGraphEvent` variant, or `None` if the payload is missing/invalid.
fn extract_work_graph_ids(event: &KernelEvent) -> Option<(String, String)> {
    if let Some(Payload::WorkGraph(wg)) = &event.payload {
        match &wg.event {
            Some(apm2_core::events::work_graph_event::Event::Added(e)) => {
                Some((e.from_work_id.clone(), e.to_work_id.clone()))
            },
            Some(apm2_core::events::work_graph_event::Event::Removed(e)) => {
                Some((e.from_work_id.clone(), e.to_work_id.clone()))
            },
            Some(apm2_core::events::work_graph_event::Event::Waived(e)) => {
                Some((e.from_work_id.clone(), e.to_work_id.clone()))
            },
            None => None,
        }
    } else {
        None
    }
}

/// Derives the primary topic (for `from_work_id`) from a work graph event.
///
/// Format: `work_graph.<from_work_id>.edge`
///
/// INV-TOPIC-005: Uses `work_graph.` prefix, NOT `work.`, to avoid
/// `WorkReducer` decoding collision.
fn derive_work_graph_primary_topic(event: &KernelEvent, fallback_namespace: &str) -> String {
    if let Some((from_work_id, _)) = extract_work_graph_ids(event) {
        format!("work_graph.{}.edge", sanitize_segment(&from_work_id))
    } else {
        format!("{fallback_namespace}.events")
    }
}

/// Derives all topics for a work graph edge event (multi-topic derivation).
///
/// Work graph events produce two topics:
/// - `work_graph.<from_work_id>.edge`
/// - `work_graph.<to_work_id>.edge`
///
/// Both topics are validated and returned. If one or both work IDs are empty
/// or identical, deduplication ensures no duplicate topics are emitted.
///
/// # Determinism
///
/// This function is deterministic: same inputs always produce the same
/// ordered vector of results.
fn derive_work_graph_topics(event: &KernelEvent) -> Vec<TopicDerivationResult> {
    let Some((from_work_id, to_work_id)) = extract_work_graph_ids(event) else {
        return vec![TopicDerivationResult::NoTopic];
    };

    let from_sanitized = sanitize_segment(&from_work_id);
    let to_sanitized = sanitize_segment(&to_work_id);

    let from_topic = format!("work_graph.{from_sanitized}.edge");
    let to_topic = format!("work_graph.{to_sanitized}.edge");

    let mut results = Vec::with_capacity(2);

    // Always add from_work_id topic first (deterministic ordering)
    results.push(validate_topic_result(&from_topic));

    // Add to_work_id topic only if it differs (deduplication)
    if from_topic != to_topic {
        results.push(validate_topic_result(&to_topic));
    }

    results
}

/// Validates a topic string and returns the appropriate result.
fn validate_topic_result(topic: &str) -> TopicDerivationResult {
    match validate_topic(topic) {
        Ok(()) => TopicDerivationResult::Success(topic.to_string()),
        Err(e) => {
            warn!(
                topic = %topic,
                error = %e,
                "Derived work graph topic failed validation"
            );
            TopicDerivationResult::ValidationFailed {
                attempted_topic: topic.to_string(),
                error: e.to_string(),
            }
        },
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Sanitizes a string to be a valid topic segment.
///
/// - Replaces non-ASCII and invalid characters with underscores
/// - Replaces dots (segment separators) with underscores
/// - Truncates to maximum segment length (64 chars)
/// - Ensures non-empty result (uses "_" if input produces empty)
///
/// # Determinism
///
/// This function is deterministic: same input always produces same output.
#[must_use]
pub fn sanitize_segment(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                Some(c)
            } else if c == '.' {
                // Replace dots to avoid creating extra segments
                Some('_')
            } else if c.is_ascii() {
                // Replace other ASCII (spaces, special chars) with underscore
                Some('_')
            } else {
                // Skip non-ASCII characters
                None
            }
        })
        .take(MAX_SEGMENT_LEN)
        .collect();

    if sanitized.is_empty() {
        "_".to_string()
    } else {
        sanitized
    }
}

/// Encodes a digest as hex for use in topic segments.
///
/// Truncates long digests to fit within topic segment limits.
/// Uses first 16 bytes (32 hex chars) which is sufficient for uniqueness.
#[must_use]
pub fn encode_digest_for_topic(digest: &[u8]) -> String {
    // Use first 16 bytes (32 hex chars) for topic segment
    // This provides sufficient uniqueness while staying under MAX_SEGMENT_LEN
    let truncated = if digest.len() > 16 {
        &digest[..16]
    } else {
        digest
    };
    hex::encode(truncated)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use apm2_core::events::{
        GateReceipt, PolicyResolvedForChangeSet, WorkEvent, WorkOpened, WorkTransitioned,
    };
    use apm2_core::ledger::CommitNotification;

    use super::*;

    // ========================================================================
    // Changeset Index Tests
    // ========================================================================

    mod changeset_index {
        use super::*;

        #[test]
        fn empty_index() {
            let index = ChangesetWorkIndex::new();
            assert!(index.is_empty());
            assert_eq!(index.len(), 0);
            assert!(index.get(&[0u8; 32]).is_none());
        }

        #[test]
        fn insert_and_get() {
            let index = ChangesetWorkIndex::new();
            let digest = vec![0xab; 32];

            index.insert(digest.clone(), "W-12345".to_string());

            assert!(!index.is_empty());
            assert_eq!(index.len(), 1);
            assert_eq!(index.get(&digest), Some("W-12345".to_string()));
        }

        #[test]
        fn update_from_policy_resolved_event() {
            let index = ChangesetWorkIndex::new();
            let digest = vec![0xcd; 32];

            let event = KernelEvent {
                payload: Some(Payload::PolicyResolvedForChangeset(
                    PolicyResolvedForChangeSet {
                        changeset_digest: digest.clone(),
                        work_id: "W-policy-test".to_string(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            };

            index.update_from_event(&event);

            assert_eq!(index.get(&digest), Some("W-policy-test".to_string()));
        }

        #[test]
        fn ignores_non_policy_events() {
            let index = ChangesetWorkIndex::new();

            // WorkEvent should not update the index
            let event = KernelEvent {
                payload: Some(Payload::Work(WorkEvent {
                    event: Some(apm2_core::events::work_event::Event::Opened(WorkOpened {
                        work_id: "W-work".to_string(),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            index.update_from_event(&event);

            assert!(index.is_empty());
        }

        #[test]
        fn overwrite_existing_entry() {
            let index = ChangesetWorkIndex::new();
            let digest = vec![0xef; 32];

            index.insert(digest.clone(), "W-first".to_string());
            index.insert(digest.clone(), "W-second".to_string());

            assert_eq!(index.len(), 1);
            assert_eq!(index.get(&digest), Some("W-second".to_string()));
        }
    }

    // ========================================================================
    // Work Topic Derivation Tests (TCK-00305)
    // ========================================================================

    mod work_topics {
        use super::*;

        fn work_opened_event(work_id: &str) -> KernelEvent {
            KernelEvent {
                payload: Some(Payload::Work(WorkEvent {
                    event: Some(apm2_core::events::work_event::Event::Opened(WorkOpened {
                        work_id: work_id.to_string(),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            }
        }

        fn work_transitioned_event(work_id: &str) -> KernelEvent {
            KernelEvent {
                payload: Some(Payload::Work(WorkEvent {
                    event: Some(apm2_core::events::work_event::Event::Transitioned(
                        WorkTransitioned {
                            work_id: work_id.to_string(),
                            from_state: "OPEN".to_string(),
                            to_state: "CLAIMED".to_string(),
                            ..Default::default()
                        },
                    )),
                })),
                ..Default::default()
            }
        }

        #[test]
        fn work_opened_derives_correct_topic() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkOpened", "kernel");
            let event = work_opened_event("W-12345");

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("work.W-12345.events"));
        }

        #[test]
        fn work_transitioned_derives_correct_topic() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkTransitioned", "kernel");
            let event = work_transitioned_event("W-67890");

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("work.W-67890.events"));
        }

        #[test]
        fn work_id_with_special_chars_is_sanitized() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkOpened", "kernel");
            let event = work_opened_event("W@123#456");

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            // Special chars replaced with underscores
            assert_eq!(result.topic(), Some("work.W_123_456.events"));
        }

        #[test]
        fn work_id_with_dots_is_sanitized() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkOpened", "kernel");
            let event = work_opened_event("W.123.456");

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            // Dots replaced with underscores to avoid extra segments
            assert_eq!(result.topic(), Some("work.W_123_456.events"));
        }

        #[test]
        fn empty_work_id_sanitizes_to_underscore() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkOpened", "kernel");
            let event = work_opened_event("");

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("work._.events"));
        }

        #[test]
        fn fallback_to_namespace_when_no_payload() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkOpened", "fallback-ns");
            let event = KernelEvent::default(); // No payload

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("work.fallback-ns.events"));
        }
    }

    // ========================================================================
    // Gate Topic Derivation Tests (TCK-00305)
    // ========================================================================

    mod gate_topics {
        use super::*;

        fn gate_receipt_event(changeset_digest: Vec<u8>, gate_id: &str) -> KernelEvent {
            KernelEvent {
                payload: Some(Payload::GateReceipt(GateReceipt {
                    changeset_digest,
                    gate_id: gate_id.to_string(),
                    receipt_id: "R-001".to_string(),
                    ..Default::default()
                })),
                ..Default::default()
            }
        }

        #[test]
        fn gate_receipt_with_indexed_work_id() {
            let deriver = TopicDeriver::new();
            let digest = vec![0xab; 32];

            // Index the changeset->work mapping
            deriver
                .changeset_index
                .insert(digest.clone(), "W-indexed".to_string());

            let notification = CommitNotification::new(1, [0; 32], "GateReceipt", "kernel");
            let event = gate_receipt_event(digest, "quality-gate");

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            let topic = result.topic().unwrap();

            // Format: gate.<work_id>.<changeset_hex>.<gate_id>
            assert!(topic.starts_with("gate.W-indexed."));
            assert!(topic.contains("abababababababab")); // First 16 bytes hex
            assert!(topic.ends_with(".quality-gate"));
        }

        #[test]
        fn gate_receipt_without_index_uses_namespace() {
            let deriver = TopicDeriver::new();
            let digest = vec![0xcd; 32]; // Not in index

            let notification = CommitNotification::new(1, [0; 32], "GateReceipt", "W-fallback");
            let event = gate_receipt_event(digest, "security-gate");

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            let topic = result.topic().unwrap();

            // Falls back to namespace as work_id
            assert!(topic.starts_with("gate.W-fallback."));
            assert!(topic.ends_with(".security-gate"));
        }

        #[test]
        fn gate_id_with_special_chars_is_sanitized() {
            let deriver = TopicDeriver::new();
            let digest = vec![0xef; 32];

            let notification = CommitNotification::new(1, [0; 32], "GateReceipt", "W-123");
            let event = gate_receipt_event(digest, "gate@123#test");

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            let topic = result.topic().unwrap();

            // Gate ID sanitized
            assert!(topic.ends_with(".gate_123_test"));
        }

        #[test]
        fn changeset_digest_truncated_for_topic() {
            let deriver = TopicDeriver::new();
            let long_digest = vec![0x12; 64]; // Longer than 16 bytes

            let notification = CommitNotification::new(1, [0; 32], "GateReceipt", "W-123");
            let event = gate_receipt_event(long_digest, "gate-001");

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            let topic = result.topic().unwrap();

            // Only first 16 bytes (32 hex chars) used
            assert!(topic.contains("12121212121212121212121212121212"));
        }

        #[test]
        fn empty_changeset_digest_handled() {
            let deriver = TopicDeriver::new();
            let empty_digest = vec![];

            let notification = CommitNotification::new(1, [0; 32], "GateReceipt", "W-123");
            let event = gate_receipt_event(empty_digest, "gate-001");

            let result = deriver.derive_topic(&notification, &event);

            // Empty digest produces empty hex segment, but topic is still valid
            // because we have gate.<work_id>..gate_id which has empty segment
            // This should fail validation
            assert!(!result.is_success() || result.topic().unwrap().contains(".."));
        }
    }

    // ========================================================================
    // Determinism Verification Tests (INV-TOPIC-001)
    // ========================================================================

    mod determinism {
        use super::*;

        #[test]
        fn same_inputs_produce_same_topic() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(42, [0xab; 32], "WorkOpened", "kernel");
            let event = KernelEvent {
                payload: Some(Payload::Work(WorkEvent {
                    event: Some(apm2_core::events::work_event::Event::Opened(WorkOpened {
                        work_id: "W-determinism-test".to_string(),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            // Derive the same topic multiple times
            let results: Vec<_> = (0..10)
                .map(|_| deriver.derive_topic(&notification, &event))
                .collect();

            // All results should be identical
            let first = results[0].topic().unwrap();
            for result in &results {
                assert_eq!(result.topic(), Some(first));
            }
        }

        #[test]
        fn gate_topic_deterministic_with_index() {
            let deriver = TopicDeriver::new();
            let digest = vec![0xde; 32];

            // Populate index
            deriver
                .changeset_index
                .insert(digest.clone(), "W-det".to_string());

            let notification = CommitNotification::new(1, [0; 32], "GateReceipt", "kernel");
            let event = KernelEvent {
                payload: Some(Payload::GateReceipt(GateReceipt {
                    changeset_digest: digest,
                    gate_id: "G-001".to_string(),
                    ..Default::default()
                })),
                ..Default::default()
            };

            // Derive multiple times
            let results: Vec<_> = (0..10)
                .map(|_| deriver.derive_topic(&notification, &event))
                .collect();

            // All should be identical
            let first = results[0].topic().unwrap();
            for result in &results {
                assert_eq!(result.topic(), Some(first));
            }
        }

        #[test]
        fn sanitize_segment_is_deterministic() {
            let inputs = ["W-123", "hello world", "with.dots", "special@#$chars", ""];

            for input in inputs {
                let results: Vec<_> = (0..10).map(|_| sanitize_segment(input)).collect();
                let first = &results[0];
                for result in &results {
                    assert_eq!(result, first, "Non-deterministic for input: {input}");
                }
            }
        }

        #[test]
        fn encode_digest_is_deterministic() {
            let digests = [
                vec![0x00; 32],
                vec![0xff; 32],
                vec![0xab, 0xcd, 0xef],
                vec![],
            ];

            for digest in &digests {
                let results: Vec<_> = (0..10).map(|_| encode_digest_for_topic(digest)).collect();
                let first = &results[0];
                for result in &results {
                    assert_eq!(result, first);
                }
            }
        }
    }

    // ========================================================================
    // Other Topic Types
    // ========================================================================

    mod other_topics {
        use super::*;

        #[test]
        fn ledger_events_map_to_ledger_head() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent::default();

            let notification = CommitNotification::new(1, [0; 32], "LedgerEvent", "kernel");
            let result = deriver.derive_topic(&notification, &event);
            assert_eq!(result.topic(), Some("ledger.head"));

            let notification = CommitNotification::new(1, [0; 32], "KernelEvent", "kernel");
            let result = deriver.derive_topic(&notification, &event);
            assert_eq!(result.topic(), Some("ledger.head"));
        }

        #[test]
        fn episode_lifecycle_events() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent::default();

            for event_type in ["EpisodeCreated", "EpisodeStarted", "EpisodeStopped"] {
                let notification = CommitNotification::new(1, [0; 32], event_type, "EP-12345");
                let result = deriver.derive_topic(&notification, &event);
                assert_eq!(result.topic(), Some("episode.EP-12345.lifecycle"));
            }
        }

        #[test]
        fn episode_tool_events_without_payload_fallback() {
            // When there's no Tool payload in the event, tool events fall back to namespace
            let deriver = TopicDeriver::new();
            let event = KernelEvent::default();

            for event_type in ["ToolRequested", "ToolDecided", "ToolExecuted"] {
                let notification = CommitNotification::new(1, [0; 32], event_type, "EP-67890");
                let result = deriver.derive_topic(&notification, &event);
                // Falls back to namespace.tool when no Tool payload present
                assert_eq!(result.topic(), Some("EP-67890.tool"));
            }
        }

        #[test]
        fn defect_events_map_to_defect_new() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent::default();

            // TCK-00307: DefectRecorded events derive to defect.new topic
            let notification = CommitNotification::new(1, [0; 32], "DefectRecorded", "kernel");
            let result = deriver.derive_topic(&notification, &event);
            assert_eq!(result.topic(), Some("defect.new"));
        }

        #[test]
        fn unknown_events_use_namespace() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent::default();

            let notification = CommitNotification::new(1, [0; 32], "UnknownEventType", "my-ns");
            let result = deriver.derive_topic(&notification, &event);
            assert_eq!(result.topic(), Some("my-ns.events"));
        }
    }

    // ========================================================================
    // Sanitization Tests
    // ========================================================================

    mod sanitization {
        use super::*;

        #[test]
        fn preserves_alphanumeric() {
            assert_eq!(sanitize_segment("abc123XYZ"), "abc123XYZ");
        }

        #[test]
        fn preserves_hyphen_underscore() {
            assert_eq!(sanitize_segment("work-id_123"), "work-id_123");
        }

        #[test]
        fn replaces_dots() {
            assert_eq!(sanitize_segment("a.b.c"), "a_b_c");
        }

        #[test]
        fn replaces_spaces() {
            assert_eq!(sanitize_segment("hello world"), "hello_world");
        }

        #[test]
        fn replaces_special_ascii() {
            assert_eq!(sanitize_segment("a@b#c$d"), "a_b_c_d");
        }

        #[test]
        fn removes_non_ascii() {
            assert_eq!(sanitize_segment("hello\u{00E9}world"), "helloworld");
            assert_eq!(sanitize_segment("\u{1F600}emoji"), "emoji");
        }

        #[test]
        fn truncates_to_max_length() {
            let long_input = "a".repeat(100);
            let result = sanitize_segment(&long_input);
            assert_eq!(result.len(), MAX_SEGMENT_LEN);
        }

        #[test]
        fn empty_input_becomes_underscore() {
            assert_eq!(sanitize_segment(""), "_");
        }

        #[test]
        fn all_invalid_chars_becomes_underscore() {
            // All non-ASCII characters stripped
            assert_eq!(sanitize_segment("\u{1F600}\u{1F601}"), "_");
        }
    }

    // ========================================================================
    // Digest Encoding Tests
    // ========================================================================

    mod digest_encoding {
        use super::*;

        #[test]
        fn encodes_full_32_byte_digest() {
            let digest = vec![0xab; 32];
            let encoded = encode_digest_for_topic(&digest);
            // First 16 bytes -> 32 hex chars
            assert_eq!(encoded, "abababababababababababababababab");
            assert_eq!(encoded.len(), 32);
        }

        #[test]
        fn truncates_long_digest() {
            let digest = vec![0xcd; 64];
            let encoded = encode_digest_for_topic(&digest);
            assert_eq!(encoded, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
            assert_eq!(encoded.len(), 32);
        }

        #[test]
        fn handles_short_digest() {
            let digest = vec![0xef, 0x12];
            let encoded = encode_digest_for_topic(&digest);
            assert_eq!(encoded, "ef12");
            assert_eq!(encoded.len(), 4);
        }

        #[test]
        fn handles_empty_digest() {
            let digest = vec![];
            let encoded = encode_digest_for_topic(&digest);
            assert_eq!(encoded, "");
        }
    }

    // ========================================================================
    // Episode Topic Derivation Tests (TCK-00306)
    // ========================================================================

    mod episode_topics {
        use apm2_core::events::{
            IoArtifactPublished, SessionEvent, SessionProgress, SessionQuarantined, SessionStarted,
            SessionTerminated, ToolDecided, ToolEvent, ToolExecuted, ToolRequested, session_event,
            tool_event,
        };

        use super::*;

        // --------------------------------------------------------------------
        // Session Event Tests
        // --------------------------------------------------------------------

        #[test]
        fn session_started_with_episode_id_derives_episode_lifecycle_topic() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Session(SessionEvent {
                    event: Some(session_event::Event::Started(SessionStarted {
                        session_id: "sess-123".to_string(),
                        episode_id: "EP-456".to_string(),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "SessionStarted", "fallback");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("episode.EP-456.lifecycle"));
        }

        #[test]
        fn session_started_without_episode_id_falls_back_to_namespace() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Session(SessionEvent {
                    event: Some(session_event::Event::Started(SessionStarted {
                        session_id: "sess-123".to_string(),
                        episode_id: String::new(), // Empty = non-episode session
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "SessionStarted", "my-ns");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("my-ns.lifecycle"));
        }

        #[test]
        fn session_progress_with_episode_id_derives_episode_lifecycle_topic() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Session(SessionEvent {
                    event: Some(session_event::Event::Progress(SessionProgress {
                        session_id: "sess-123".to_string(),
                        episode_id: "EP-789".to_string(),
                        progress_sequence: 1,
                        progress_type: "HEARTBEAT".to_string(),
                        entropy_consumed: 100,
                    })),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "SessionProgress", "fallback");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("episode.EP-789.lifecycle"));
        }

        #[test]
        fn session_terminated_with_episode_id_derives_episode_lifecycle_topic() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Session(SessionEvent {
                    event: Some(session_event::Event::Terminated(SessionTerminated {
                        session_id: "sess-123".to_string(),
                        episode_id: "EP-ABC".to_string(),
                        exit_classification: "SUCCESS".to_string(),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "SessionTerminated", "fallback");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("episode.EP-ABC.lifecycle"));
        }

        #[test]
        fn session_quarantined_with_episode_id_derives_episode_lifecycle_topic() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Session(SessionEvent {
                    event: Some(session_event::Event::Quarantined(SessionQuarantined {
                        session_id: "sess-123".to_string(),
                        episode_id: "EP-XYZ".to_string(),
                        reason: "POLICY_VIOLATION".to_string(),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            let notification =
                CommitNotification::new(1, [0; 32], "SessionQuarantined", "fallback");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("episode.EP-XYZ.lifecycle"));
        }

        // --------------------------------------------------------------------
        // Tool Event Tests
        // --------------------------------------------------------------------

        #[test]
        fn tool_requested_with_episode_id_derives_episode_tool_topic() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Tool(ToolEvent {
                    event: Some(tool_event::Event::Requested(ToolRequested {
                        request_id: "req-001".to_string(),
                        session_id: "sess-123".to_string(),
                        tool_name: "Read".to_string(),
                        episode_id: "EP-TOOL-1".to_string(),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "ToolRequested", "fallback");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("episode.EP-TOOL-1.tool"));
        }

        #[test]
        fn tool_requested_without_episode_id_falls_back_to_namespace() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Tool(ToolEvent {
                    event: Some(tool_event::Event::Requested(ToolRequested {
                        request_id: "req-001".to_string(),
                        session_id: "sess-123".to_string(),
                        tool_name: "Read".to_string(),
                        episode_id: String::new(), // Empty = non-episode session
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "ToolRequested", "non-episode");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("non-episode.tool"));
        }

        #[test]
        fn tool_decided_with_episode_id_derives_episode_tool_topic() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Tool(ToolEvent {
                    event: Some(tool_event::Event::Decided(ToolDecided {
                        request_id: "req-001".to_string(),
                        decision: "ALLOW".to_string(),
                        episode_id: "EP-TOOL-2".to_string(),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "ToolDecided", "fallback");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("episode.EP-TOOL-2.tool"));
        }

        #[test]
        fn tool_executed_with_episode_id_derives_episode_tool_topic() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Tool(ToolEvent {
                    event: Some(tool_event::Event::Executed(ToolExecuted {
                        request_id: "req-001".to_string(),
                        outcome: "SUCCESS".to_string(),
                        episode_id: "EP-TOOL-3".to_string(),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "ToolExecuted", "fallback");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("episode.EP-TOOL-3.tool"));
        }

        // --------------------------------------------------------------------
        // IO Artifact Tests
        // --------------------------------------------------------------------

        #[test]
        fn io_artifact_published_with_episode_id_derives_episode_io_topic() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::IoArtifactPublished(IoArtifactPublished {
                    episode_id: "EP-IO-1".to_string(),
                    session_id: "sess-123".to_string(),
                    artifact_type: "STDOUT".to_string(),
                    artifact_hash: vec![0xab; 32],
                    artifact_size: 1024,
                    ..Default::default()
                })),
                ..Default::default()
            };

            let notification =
                CommitNotification::new(1, [0; 32], "IoArtifactPublished", "fallback");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("episode.EP-IO-1.io"));
        }

        #[test]
        fn io_artifact_published_without_episode_id_falls_back_to_namespace() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::IoArtifactPublished(IoArtifactPublished {
                    episode_id: String::new(), // Empty
                    session_id: "sess-123".to_string(),
                    artifact_type: "FILE_WRITE".to_string(),
                    ..Default::default()
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "IoArtifactPublished", "ns-io");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("ns-io.io"));
        }

        // --------------------------------------------------------------------
        // Backward Compatibility Tests (empty episode_id)
        // --------------------------------------------------------------------

        #[test]
        fn backward_compat_session_events_default_to_namespace() {
            // Simulates replaying old events where episode_id defaults to empty string
            let deriver = TopicDeriver::new();

            // SessionStarted with default (empty) episode_id
            let event = KernelEvent {
                payload: Some(Payload::Session(SessionEvent {
                    event: Some(session_event::Event::Started(SessionStarted::default())),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "SessionStarted", "legacy-ns");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            // Falls back to namespace because episode_id is empty
            assert_eq!(result.topic(), Some("legacy-ns.lifecycle"));
        }

        #[test]
        fn backward_compat_tool_events_default_to_namespace() {
            // Simulates replaying old events where episode_id defaults to empty string
            let deriver = TopicDeriver::new();

            // ToolRequested with default (empty) episode_id
            let event = KernelEvent {
                payload: Some(Payload::Tool(ToolEvent {
                    event: Some(tool_event::Event::Requested(ToolRequested::default())),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "ToolRequested", "legacy-ns");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            // Falls back to namespace because episode_id is empty
            assert_eq!(result.topic(), Some("legacy-ns.tool"));
        }

        // --------------------------------------------------------------------
        // Episode ID Sanitization Tests
        // --------------------------------------------------------------------

        #[test]
        fn episode_id_with_special_chars_is_sanitized() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Session(SessionEvent {
                    event: Some(session_event::Event::Started(SessionStarted {
                        session_id: "sess-123".to_string(),
                        episode_id: "EP@123#456".to_string(), // Special chars
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "SessionStarted", "fallback");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            // Special chars replaced with underscores
            assert_eq!(result.topic(), Some("episode.EP_123_456.lifecycle"));
        }

        #[test]
        fn episode_id_with_dots_is_sanitized() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::Tool(ToolEvent {
                    event: Some(tool_event::Event::Decided(ToolDecided {
                        request_id: "req-001".to_string(),
                        episode_id: "EP.123.456".to_string(), // Dots
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "ToolDecided", "fallback");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            // Dots replaced with underscores to avoid extra segments
            assert_eq!(result.topic(), Some("episode.EP_123_456.tool"));
        }
    }

    // ========================================================================
    // Event Serialization Tests (TCK-00306)
    // ========================================================================

    mod event_serialization {
        use apm2_core::events::{
            IoArtifactPublished, SessionProgress, SessionQuarantined, SessionStarted,
            SessionTerminated, ToolDecided, ToolExecuted, ToolRequested,
        };
        use prost::Message;

        #[test]
        fn session_started_serializes_with_episode_id() {
            let event = SessionStarted {
                session_id: "sess-123".to_string(),
                actor_id: "actor-456".to_string(),
                episode_id: "EP-789".to_string(),
                ..Default::default()
            };

            let bytes = event.encode_to_vec();
            let decoded = SessionStarted::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.session_id, "sess-123");
            assert_eq!(decoded.episode_id, "EP-789");
        }

        #[test]
        fn session_started_defaults_episode_id_to_empty() {
            let event = SessionStarted {
                session_id: "sess-123".to_string(),
                ..Default::default()
            };

            assert_eq!(event.episode_id, "");
        }

        #[test]
        fn session_progress_serializes_with_episode_id() {
            let event = SessionProgress {
                session_id: "sess-123".to_string(),
                episode_id: "EP-PROG".to_string(),
                progress_sequence: 5,
                progress_type: "HEARTBEAT".to_string(),
                entropy_consumed: 100,
            };

            let bytes = event.encode_to_vec();
            let decoded = SessionProgress::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.episode_id, "EP-PROG");
        }

        #[test]
        fn session_terminated_serializes_with_episode_id() {
            let event = SessionTerminated {
                session_id: "sess-123".to_string(),
                episode_id: "EP-TERM".to_string(),
                exit_classification: "SUCCESS".to_string(),
                ..Default::default()
            };

            let bytes = event.encode_to_vec();
            let decoded = SessionTerminated::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.episode_id, "EP-TERM");
        }

        #[test]
        fn session_quarantined_serializes_with_episode_id() {
            let event = SessionQuarantined {
                session_id: "sess-123".to_string(),
                episode_id: "EP-QUAR".to_string(),
                reason: "POLICY".to_string(),
                ..Default::default()
            };

            let bytes = event.encode_to_vec();
            let decoded = SessionQuarantined::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.episode_id, "EP-QUAR");
        }

        #[test]
        fn tool_requested_serializes_with_episode_id() {
            let event = ToolRequested {
                request_id: "req-001".to_string(),
                session_id: "sess-123".to_string(),
                tool_name: "Read".to_string(),
                episode_id: "EP-TOOL".to_string(),
                ..Default::default()
            };

            let bytes = event.encode_to_vec();
            let decoded = ToolRequested::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.episode_id, "EP-TOOL");
        }

        #[test]
        fn tool_decided_serializes_with_episode_id() {
            let event = ToolDecided {
                request_id: "req-001".to_string(),
                decision: "ALLOW".to_string(),
                episode_id: "EP-DECIDED".to_string(),
                ..Default::default()
            };

            let bytes = event.encode_to_vec();
            let decoded = ToolDecided::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.episode_id, "EP-DECIDED");
        }

        #[test]
        fn tool_executed_serializes_with_episode_id() {
            let event = ToolExecuted {
                request_id: "req-001".to_string(),
                outcome: "SUCCESS".to_string(),
                episode_id: "EP-EXEC".to_string(),
                ..Default::default()
            };

            let bytes = event.encode_to_vec();
            let decoded = ToolExecuted::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.episode_id, "EP-EXEC");
        }

        #[test]
        fn io_artifact_published_serializes_with_all_fields() {
            let event = IoArtifactPublished {
                episode_id: "EP-IO".to_string(),
                session_id: "sess-123".to_string(),
                artifact_type: "STDOUT".to_string(),
                artifact_hash: vec![0xab; 32],
                artifact_size: 1024,
                path: "/path/to/file".to_string(),
                produced_at: 1_234_567_890,
                classification: "INTERNAL".to_string(),
                ..Default::default()
            };

            let bytes = event.encode_to_vec();
            let decoded = IoArtifactPublished::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.episode_id, "EP-IO");
            assert_eq!(decoded.session_id, "sess-123");
            assert_eq!(decoded.artifact_type, "STDOUT");
            assert_eq!(decoded.artifact_hash.len(), 32);
            assert_eq!(decoded.artifact_size, 1024);
            assert_eq!(decoded.path, "/path/to/file");
            assert_eq!(decoded.classification, "INTERNAL");
        }

        #[test]
        fn backward_compat_old_events_decode_with_empty_episode_id() {
            // Simulate old event bytes without episode_id field
            // (proto defaults string fields to empty)
            let old_event = SessionStarted {
                session_id: "sess-old".to_string(),
                actor_id: "actor-old".to_string(),
                // episode_id not set - defaults to empty
                ..Default::default()
            };

            let bytes = old_event.encode_to_vec();
            let decoded = SessionStarted::decode(bytes.as_slice()).unwrap();

            // episode_id should default to empty string
            assert_eq!(decoded.episode_id, "");
            assert_eq!(decoded.session_id, "sess-old");
        }
    }

    // ========================================================================
    // DefectRecorded Event Tests (TCK-00307)
    // ========================================================================

    mod defect_recorded_tests {
        use apm2_core::events::kernel_event::Payload;
        use apm2_core::events::{DefectRecorded, DefectSource, KernelEvent};
        use apm2_core::ledger::CommitNotification;
        use prost::Message;

        use super::*;

        // --------------------------------------------------------------------
        // DefectRecorded Serialization Tests
        // --------------------------------------------------------------------

        #[test]
        fn defect_recorded_serializes_with_all_fields() {
            let event = DefectRecorded {
                defect_id: "DEF-001".to_string(),
                defect_type: "PROJECTION_DIVERGENCE".to_string(),
                cas_hash: vec![0xab; 32],
                source: DefectSource::DivergenceWatchdog as i32,
                work_id: "work-123".to_string(),
                severity: "S0".to_string(),
                detected_at: 1_234_567_890,
                time_envelope_ref: None,
            };

            let bytes = event.encode_to_vec();
            let decoded = DefectRecorded::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.defect_id, "DEF-001");
            assert_eq!(decoded.defect_type, "PROJECTION_DIVERGENCE");
            assert_eq!(decoded.cas_hash.len(), 32);
            assert_eq!(decoded.source, DefectSource::DivergenceWatchdog as i32);
            assert_eq!(decoded.work_id, "work-123");
            assert_eq!(decoded.severity, "S0");
            assert_eq!(decoded.detected_at, 1_234_567_890);
        }

        #[test]
        fn defect_recorded_with_context_miss_source() {
            let event = DefectRecorded {
                defect_id: "DEF-002".to_string(),
                defect_type: "UNPLANNED_CONTEXT_READ".to_string(),
                cas_hash: vec![0xcd; 32],
                source: DefectSource::ContextMiss as i32,
                work_id: "work-456".to_string(),
                severity: "S2".to_string(),
                detected_at: 1_234_567_891,
                time_envelope_ref: None,
            };

            let bytes = event.encode_to_vec();
            let decoded = DefectRecorded::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.defect_id, "DEF-002");
            assert_eq!(decoded.defect_type, "UNPLANNED_CONTEXT_READ");
            assert_eq!(decoded.source, DefectSource::ContextMiss as i32);
        }

        #[test]
        fn defect_recorded_with_htf_regression_source() {
            let event = DefectRecorded {
                defect_id: "DEF-003".to_string(),
                defect_type: "AAT_FAIL".to_string(),
                cas_hash: vec![0xef; 32],
                source: DefectSource::HtfRegression as i32,
                work_id: "work-789".to_string(),
                severity: "S1".to_string(),
                detected_at: 1_234_567_892,
                time_envelope_ref: None,
            };

            let bytes = event.encode_to_vec();
            let decoded = DefectRecorded::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.source, DefectSource::HtfRegression as i32);
        }

        #[test]
        fn defect_source_enum_values() {
            // Verify all DefectSource enum values are serializable
            assert_eq!(DefectSource::Unspecified as i32, 0);
            assert_eq!(DefectSource::DivergenceWatchdog as i32, 1);
            assert_eq!(DefectSource::ContextMiss as i32, 2);
            assert_eq!(DefectSource::HtfRegression as i32, 3);
            assert_eq!(DefectSource::ProjectionTamper as i32, 4);
            assert_eq!(DefectSource::SchemaReject as i32, 5);
            assert_eq!(DefectSource::AatFail as i32, 6);
            assert_eq!(DefectSource::CapabilityUnavailable as i32, 7);
        }

        // --------------------------------------------------------------------
        // DefectRecorded Topic Derivation Tests
        // --------------------------------------------------------------------

        #[test]
        fn defect_recorded_derives_defect_new_topic() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::DefectRecorded(DefectRecorded {
                    defect_id: "DEF-001".to_string(),
                    defect_type: "PROJECTION_DIVERGENCE".to_string(),
                    cas_hash: vec![0xab; 32],
                    source: DefectSource::DivergenceWatchdog as i32,
                    work_id: "work-123".to_string(),
                    severity: "S0".to_string(),
                    detected_at: 1_234_567_890,
                    time_envelope_ref: None,
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(1, [0; 32], "DefectRecorded", "kernel");
            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("defect.new"));
        }

        #[test]
        fn defect_recorded_topic_derivation_is_deterministic() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent {
                payload: Some(Payload::DefectRecorded(DefectRecorded {
                    defect_id: "DEF-DET".to_string(),
                    defect_type: "CONTEXT_MISS".to_string(),
                    cas_hash: vec![0xcd; 32],
                    source: DefectSource::ContextMiss as i32,
                    work_id: "work-det".to_string(),
                    severity: "S2".to_string(),
                    detected_at: 1_000_000,
                    time_envelope_ref: None,
                })),
                ..Default::default()
            };

            let notification = CommitNotification::new(42, [0xab; 32], "DefectRecorded", "kernel");

            // Derive the same topic multiple times
            let results: Vec<_> = (0..10)
                .map(|_| deriver.derive_topic(&notification, &event))
                .collect();

            // All results should be identical
            let first = results[0].topic().unwrap();
            assert_eq!(first, "defect.new");
            for result in &results {
                assert_eq!(result.topic(), Some(first));
            }
        }

        // --------------------------------------------------------------------
        // KernelEvent with DefectRecorded Payload Tests
        // --------------------------------------------------------------------

        #[test]
        fn kernel_event_with_defect_recorded_payload() {
            let defect_recorded = DefectRecorded {
                defect_id: "DEF-KE".to_string(),
                defect_type: "PROJECTION_TAMPER".to_string(),
                cas_hash: vec![0x11; 32],
                source: DefectSource::ProjectionTamper as i32,
                work_id: "work-ke".to_string(),
                severity: "S1".to_string(),
                detected_at: 2_000_000,
                time_envelope_ref: None,
            };

            let kernel_event = KernelEvent {
                sequence: 100,
                actor_id: "watchdog".to_string(),
                session_id: "session-001".to_string(),
                schema_version: 1,
                payload: Some(Payload::DefectRecorded(defect_recorded)),
                ..Default::default()
            };

            let bytes = kernel_event.encode_to_vec();
            let decoded = KernelEvent::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.sequence, 100);
            assert_eq!(decoded.actor_id, "watchdog");

            if let Some(Payload::DefectRecorded(dr)) = decoded.payload {
                assert_eq!(dr.defect_id, "DEF-KE");
                assert_eq!(dr.defect_type, "PROJECTION_TAMPER");
                assert_eq!(dr.source, DefectSource::ProjectionTamper as i32);
            } else {
                panic!("Expected DefectRecorded payload");
            }
        }
    }

    // ========================================================================
    // WorkGraphEvent Topic Derivation Tests (TCK-00642, drift barrier D1.2)
    // ========================================================================

    mod work_graph_topics {
        use apm2_core::events::kernel_event::Payload;
        use apm2_core::events::{
            KernelEvent, WorkEdgeAdded, WorkEdgeRemoved, WorkEdgeType, WorkEdgeWaived,
            WorkGraphEvent, work_graph_event,
        };
        use apm2_core::ledger::CommitNotification;
        use prost::Message;

        use super::*;

        // ====================================================================
        // Helper constructors
        // ====================================================================

        fn work_edge_added_event(
            from_work_id: &str,
            to_work_id: &str,
            edge_type: WorkEdgeType,
        ) -> KernelEvent {
            KernelEvent {
                payload: Some(Payload::WorkGraph(WorkGraphEvent {
                    event: Some(work_graph_event::Event::Added(WorkEdgeAdded {
                        from_work_id: from_work_id.to_string(),
                        to_work_id: to_work_id.to_string(),
                        edge_type: edge_type as i32,
                        rationale: "test edge".to_string(),
                    })),
                })),
                ..Default::default()
            }
        }

        fn work_edge_removed_event(from_work_id: &str, to_work_id: &str) -> KernelEvent {
            KernelEvent {
                payload: Some(Payload::WorkGraph(WorkGraphEvent {
                    event: Some(work_graph_event::Event::Removed(WorkEdgeRemoved {
                        from_work_id: from_work_id.to_string(),
                        to_work_id: to_work_id.to_string(),
                        reason: "no longer needed".to_string(),
                    })),
                })),
                ..Default::default()
            }
        }

        fn work_edge_waived_event(
            from_work_id: &str,
            to_work_id: &str,
            edge_type: WorkEdgeType,
        ) -> KernelEvent {
            KernelEvent {
                payload: Some(Payload::WorkGraph(WorkGraphEvent {
                    event: Some(work_graph_event::Event::Waived(WorkEdgeWaived {
                        from_work_id: from_work_id.to_string(),
                        to_work_id: to_work_id.to_string(),
                        original_edge_type: edge_type as i32,
                        waiver_justification: "approved override".to_string(),
                        waiver_actor_id: "operator-1".to_string(),
                    })),
                })),
                ..Default::default()
            }
        }

        // ====================================================================
        // WorkEdgeAdded topic derivation tests
        // ====================================================================

        #[test]
        fn work_edge_added_derives_correct_primary_topic() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeAdded", "kernel");
            let event = work_edge_added_event("W-FROM-1", "W-TO-1", WorkEdgeType::Dependency);

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("work_graph.W-FROM-1.edge"));
        }

        #[test]
        fn work_edge_added_derives_two_topics() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeAdded", "kernel");
            let event = work_edge_added_event("W-FROM-2", "W-TO-2", WorkEdgeType::Blocks);

            let results = deriver.derive_topics(&notification, &event);

            assert_eq!(results.len(), 2);
            assert!(results[0].is_success());
            assert!(results[1].is_success());
            assert_eq!(results[0].topic(), Some("work_graph.W-FROM-2.edge"));
            assert_eq!(results[1].topic(), Some("work_graph.W-TO-2.edge"));
        }

        #[test]
        fn work_edge_added_topic_prefix_avoids_work_reducer() {
            // INV-TOPIC-005: work_graph.edge.* MUST NOT start with `work.`
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeAdded", "kernel");
            let event = work_edge_added_event("W-123", "W-456", WorkEdgeType::Enables);

            let results = deriver.derive_topics(&notification, &event);

            for result in &results {
                let topic = result.topic().expect("should be successful");
                assert!(
                    topic.starts_with("work_graph."),
                    "Topic must start with 'work_graph.' not 'work.': got {topic}"
                );
                assert!(
                    !topic.starts_with("work."),
                    "Topic MUST NOT start with 'work.' to avoid WorkReducer collision: got {topic}"
                );
            }
        }

        #[test]
        fn work_edge_added_with_all_edge_types() {
            let deriver = TopicDeriver::new();

            for edge_type in [
                WorkEdgeType::Dependency,
                WorkEdgeType::Blocks,
                WorkEdgeType::Enables,
                WorkEdgeType::Sequence,
            ] {
                let notification = CommitNotification::new(1, [0; 32], "WorkEdgeAdded", "kernel");
                let event = work_edge_added_event("W-A", "W-B", edge_type);

                let results = deriver.derive_topics(&notification, &event);

                assert_eq!(results.len(), 2, "edge_type={edge_type:?}");
                assert_eq!(
                    results[0].topic(),
                    Some("work_graph.W-A.edge"),
                    "edge_type={edge_type:?}"
                );
                assert_eq!(
                    results[1].topic(),
                    Some("work_graph.W-B.edge"),
                    "edge_type={edge_type:?}"
                );
            }
        }

        // ====================================================================
        // WorkEdgeRemoved topic derivation tests
        // ====================================================================

        #[test]
        fn work_edge_removed_derives_correct_primary_topic() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeRemoved", "kernel");
            let event = work_edge_removed_event("W-REM-FROM", "W-REM-TO");

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("work_graph.W-REM-FROM.edge"));
        }

        #[test]
        fn work_edge_removed_derives_two_topics() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeRemoved", "kernel");
            let event = work_edge_removed_event("W-REM-A", "W-REM-B");

            let results = deriver.derive_topics(&notification, &event);

            assert_eq!(results.len(), 2);
            assert!(results[0].is_success());
            assert!(results[1].is_success());
            assert_eq!(results[0].topic(), Some("work_graph.W-REM-A.edge"));
            assert_eq!(results[1].topic(), Some("work_graph.W-REM-B.edge"));
        }

        #[test]
        fn work_edge_removed_topic_prefix_avoids_work_reducer() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeRemoved", "kernel");
            let event = work_edge_removed_event("W-789", "W-012");

            let results = deriver.derive_topics(&notification, &event);

            for result in &results {
                let topic = result.topic().expect("should be successful");
                assert!(
                    topic.starts_with("work_graph."),
                    "Topic must start with 'work_graph.': got {topic}"
                );
                assert!(
                    !topic.starts_with("work."),
                    "Topic MUST NOT start with 'work.': got {topic}"
                );
            }
        }

        // ====================================================================
        // WorkEdgeWaived topic derivation tests
        // ====================================================================

        #[test]
        fn work_edge_waived_derives_correct_primary_topic() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeWaived", "kernel");
            let event = work_edge_waived_event("W-WAI-FROM", "W-WAI-TO", WorkEdgeType::Dependency);

            let result = deriver.derive_topic(&notification, &event);

            assert!(result.is_success());
            assert_eq!(result.topic(), Some("work_graph.W-WAI-FROM.edge"));
        }

        #[test]
        fn work_edge_waived_derives_two_topics() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeWaived", "kernel");
            let event = work_edge_waived_event("W-WAI-A", "W-WAI-B", WorkEdgeType::Blocks);

            let results = deriver.derive_topics(&notification, &event);

            assert_eq!(results.len(), 2);
            assert!(results[0].is_success());
            assert!(results[1].is_success());
            assert_eq!(results[0].topic(), Some("work_graph.W-WAI-A.edge"));
            assert_eq!(results[1].topic(), Some("work_graph.W-WAI-B.edge"));
        }

        #[test]
        fn work_edge_waived_topic_prefix_avoids_work_reducer() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeWaived", "kernel");
            let event = work_edge_waived_event("W-X1", "W-X2", WorkEdgeType::Sequence);

            let results = deriver.derive_topics(&notification, &event);

            for result in &results {
                let topic = result.topic().expect("should be successful");
                assert!(
                    topic.starts_with("work_graph."),
                    "Topic must start with 'work_graph.': got {topic}"
                );
                assert!(
                    !topic.starts_with("work."),
                    "Topic MUST NOT start with 'work.': got {topic}"
                );
            }
        }

        // ====================================================================
        // Edge case and deduplication tests
        // ====================================================================

        #[test]
        fn identical_work_ids_produce_single_topic() {
            // When from_work_id == to_work_id, should deduplicate
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeAdded", "kernel");
            let event = work_edge_added_event("W-SAME", "W-SAME", WorkEdgeType::Dependency);

            let results = deriver.derive_topics(&notification, &event);

            assert_eq!(
                results.len(),
                1,
                "Identical work IDs should deduplicate to 1 topic"
            );
            assert!(results[0].is_success());
            assert_eq!(results[0].topic(), Some("work_graph.W-SAME.edge"));
        }

        #[test]
        fn special_chars_in_work_ids_are_sanitized() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeAdded", "kernel");
            let event = work_edge_added_event("W@from#1", "W.to.2", WorkEdgeType::Enables);

            let results = deriver.derive_topics(&notification, &event);

            assert_eq!(results.len(), 2);
            assert!(results[0].is_success());
            assert!(results[1].is_success());
            // Special chars replaced with underscores, dots replaced with underscores
            assert_eq!(results[0].topic(), Some("work_graph.W_from_1.edge"));
            assert_eq!(results[1].topic(), Some("work_graph.W_to_2.edge"));
        }

        #[test]
        fn empty_work_ids_sanitize_to_underscore() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeAdded", "kernel");
            let event = work_edge_added_event("", "", WorkEdgeType::Dependency);

            let results = deriver.derive_topics(&notification, &event);

            // Both work IDs empty -> sanitized to "_" -> same topic -> deduplicated
            assert_eq!(results.len(), 1);
            assert!(results[0].is_success());
            assert_eq!(results[0].topic(), Some("work_graph._.edge"));
        }

        #[test]
        fn missing_work_graph_payload_returns_no_topic() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeAdded", "kernel");
            // No payload at all
            let event = KernelEvent::default();

            let results = deriver.derive_topics(&notification, &event);

            assert_eq!(results.len(), 1);
            assert_eq!(results[0], TopicDerivationResult::NoTopic);
        }

        #[test]
        fn work_graph_event_none_variant_returns_no_topic() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeAdded", "kernel");
            let event = KernelEvent {
                payload: Some(Payload::WorkGraph(WorkGraphEvent { event: None })),
                ..Default::default()
            };

            let results = deriver.derive_topics(&notification, &event);

            assert_eq!(results.len(), 1);
            assert_eq!(results[0], TopicDerivationResult::NoTopic);
        }

        // ====================================================================
        // Determinism tests
        // ====================================================================

        #[test]
        fn work_graph_topic_derivation_is_deterministic() {
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(42, [0xab; 32], "WorkEdgeAdded", "kernel");
            let event = work_edge_added_event("W-DET-A", "W-DET-B", WorkEdgeType::Dependency);

            // Derive multiple times
            let all_results: Vec<_> = (0..10)
                .map(|_| deriver.derive_topics(&notification, &event))
                .collect();

            // All results should be identical
            let first = &all_results[0];
            for result in &all_results {
                assert_eq!(result.len(), first.len());
                for (a, b) in result.iter().zip(first.iter()) {
                    assert_eq!(a, b);
                }
            }
        }

        #[test]
        fn derive_topics_ordering_is_stable() {
            // from_work_id topic always comes first, to_work_id second
            let deriver = TopicDeriver::new();
            let notification = CommitNotification::new(1, [0; 32], "WorkEdgeAdded", "kernel");
            let event = work_edge_added_event("W-ALPHA", "W-BETA", WorkEdgeType::Sequence);

            for _ in 0..20 {
                let results = deriver.derive_topics(&notification, &event);

                assert_eq!(results.len(), 2);
                assert_eq!(results[0].topic(), Some("work_graph.W-ALPHA.edge"));
                assert_eq!(results[1].topic(), Some("work_graph.W-BETA.edge"));
            }
        }

        // ====================================================================
        // Non-work-graph events use single-topic derivation via derive_topics
        // ====================================================================

        #[test]
        fn non_work_graph_events_return_single_topic_via_derive_topics() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent::default();

            let notification = CommitNotification::new(1, [0; 32], "DefectRecorded", "kernel");
            let results = deriver.derive_topics(&notification, &event);

            assert_eq!(results.len(), 1);
            assert_eq!(results[0].topic(), Some("defect.new"));
        }

        // ====================================================================
        // Proto serialization round-trip tests
        // ====================================================================

        #[test]
        fn work_edge_added_serializes_round_trip() {
            let event = WorkEdgeAdded {
                from_work_id: "W-SER-FROM".to_string(),
                to_work_id: "W-SER-TO".to_string(),
                edge_type: WorkEdgeType::Dependency as i32,
                rationale: "test rationale".to_string(),
            };

            let bytes = event.encode_to_vec();
            let decoded = WorkEdgeAdded::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.from_work_id, "W-SER-FROM");
            assert_eq!(decoded.to_work_id, "W-SER-TO");
            assert_eq!(decoded.edge_type, WorkEdgeType::Dependency as i32);
            assert_eq!(decoded.rationale, "test rationale");
        }

        #[test]
        fn work_edge_removed_serializes_round_trip() {
            let event = WorkEdgeRemoved {
                from_work_id: "W-REM-SER-FROM".to_string(),
                to_work_id: "W-REM-SER-TO".to_string(),
                reason: "completed dependency".to_string(),
            };

            let bytes = event.encode_to_vec();
            let decoded = WorkEdgeRemoved::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.from_work_id, "W-REM-SER-FROM");
            assert_eq!(decoded.to_work_id, "W-REM-SER-TO");
            assert_eq!(decoded.reason, "completed dependency");
        }

        #[test]
        fn work_edge_waived_serializes_round_trip() {
            let event = WorkEdgeWaived {
                from_work_id: "W-WAI-SER-FROM".to_string(),
                to_work_id: "W-WAI-SER-TO".to_string(),
                original_edge_type: WorkEdgeType::Blocks as i32,
                waiver_justification: "emergency override".to_string(),
                waiver_actor_id: "admin-1".to_string(),
            };

            let bytes = event.encode_to_vec();
            let decoded = WorkEdgeWaived::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.from_work_id, "W-WAI-SER-FROM");
            assert_eq!(decoded.to_work_id, "W-WAI-SER-TO");
            assert_eq!(decoded.original_edge_type, WorkEdgeType::Blocks as i32);
            assert_eq!(decoded.waiver_justification, "emergency override");
            assert_eq!(decoded.waiver_actor_id, "admin-1");
        }

        #[test]
        fn work_edge_type_enum_values() {
            assert_eq!(WorkEdgeType::Unspecified as i32, 0);
            assert_eq!(WorkEdgeType::Dependency as i32, 1);
            assert_eq!(WorkEdgeType::Blocks as i32, 2);
            assert_eq!(WorkEdgeType::Enables as i32, 3);
            assert_eq!(WorkEdgeType::Sequence as i32, 4);
        }

        #[test]
        fn kernel_event_with_work_graph_payload_round_trip() {
            let work_graph_event = WorkGraphEvent {
                event: Some(work_graph_event::Event::Added(WorkEdgeAdded {
                    from_work_id: "W-KE-FROM".to_string(),
                    to_work_id: "W-KE-TO".to_string(),
                    edge_type: WorkEdgeType::Enables as i32,
                    rationale: "kernel event test".to_string(),
                })),
            };

            let kernel_event = KernelEvent {
                sequence: 200,
                actor_id: "graph-manager".to_string(),
                schema_version: 1,
                payload: Some(Payload::WorkGraph(work_graph_event)),
                ..Default::default()
            };

            let bytes = kernel_event.encode_to_vec();
            let decoded = KernelEvent::decode(bytes.as_slice()).unwrap();

            assert_eq!(decoded.sequence, 200);
            assert_eq!(decoded.actor_id, "graph-manager");

            if let Some(Payload::WorkGraph(wg)) = decoded.payload {
                if let Some(work_graph_event::Event::Added(added)) = wg.event {
                    assert_eq!(added.from_work_id, "W-KE-FROM");
                    assert_eq!(added.to_work_id, "W-KE-TO");
                    assert_eq!(added.edge_type, WorkEdgeType::Enables as i32);
                } else {
                    panic!("Expected WorkEdgeAdded variant");
                }
            } else {
                panic!("Expected WorkGraph payload");
            }
        }
    }
}
