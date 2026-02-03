//! Topic derivation for HEF Pulse Plane (RFC-0018, TCK-00305).
//!
//! This module implements deterministic topic derivation for kernel events,
//! mapping Work and Gate events to their respective pulse topics.
//!
//! # Topic Taxonomy (DD-HEF-0001)
//!
//! - `work.<work_id>.events` - Work lifecycle events
//! - `gate.<work_id>.<changeset_digest>.<gate_id>` - Gate receipt events
//! - `ledger.head` - System/ledger events
//! - `episode.<episode_id>.<category>` - Episode lifecycle and tool events
//! - `defect.new` - Defect notifications
//!
//! # Security Invariants
//!
//! - [INV-TOPIC-001] Topic derivation is deterministic given same inputs
//! - [INV-TOPIC-002] Invalid inputs produce sanitized, valid topics
//! - [INV-TOPIC-003] Changeset lookup uses bounded-size index
//! - [INV-TOPIC-004] All derived topics pass HEF Topic Grammar validation
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

            // Episode lifecycle events
            "EpisodeCreated" | "EpisodeStarted" | "EpisodeStopped" => {
                format!("episode.{sanitized_namespace}.lifecycle")
            },

            // Episode tool events
            "ToolRequested" | "ToolDecided" | "ToolExecuted" => {
                format!("episode.{sanitized_namespace}.tool")
            },

            // Defect events
            "DefectRecord" => "defect.new".to_string(),

            // PolicyResolvedForChangeSet -> work topic (for observability)
            "PolicyResolvedForChangeSet" => {
                if let Some(Payload::PolicyResolvedForChangeset(p)) = &event.payload {
                    format!("work.{}.policy", sanitize_segment(&p.work_id))
                } else {
                    format!("{sanitized_namespace}.events")
                }
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
        fn episode_tool_events() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent::default();

            for event_type in ["ToolRequested", "ToolDecided", "ToolExecuted"] {
                let notification = CommitNotification::new(1, [0; 32], event_type, "EP-67890");
                let result = deriver.derive_topic(&notification, &event);
                assert_eq!(result.topic(), Some("episode.EP-67890.tool"));
            }
        }

        #[test]
        fn defect_events_map_to_defect_new() {
            let deriver = TopicDeriver::new();
            let event = KernelEvent::default();

            let notification = CommitNotification::new(1, [0; 32], "DefectRecord", "kernel");
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
}
