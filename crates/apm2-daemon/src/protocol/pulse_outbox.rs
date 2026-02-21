//! HEF Pulse Outbox and Publisher (RFC-0018, TCK-00304).
//!
//! This module implements the daemon-owned outbox that receives post-commit
//! notifications from the ledger and publishes `PulseEvent` messages to
//! matching subscribers.
//!
//! # Architecture (DD-HEF-0007)
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │ BftLedgerBackend│     │ PulsePublisher  │     │ Subscribers     │
//! │ (apm2-core)     │     │ (apm2-daemon)   │     │ (connections)   │
//! ├─────────────────┤     ├─────────────────┤     ├─────────────────┤
//! │ on_commit()     │────▶│ drain_channel() │────▶│ ACL Filter      │
//! │ try_send()      │     │ build_envelope()│     │ try_reserve_    │
//! │ (non-blocking)  │     │ fanout()        │     │ enqueue()       │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//! ```
//!
//! # Ordering Invariant (REQ-HEF-0006)
//!
//! Pulse emission order is: CAS persist -> ledger commit -> outbox enqueue ->
//! pulse publish. The `CommitNotification` channel ensures this ordering is
//! maintained.
//!
//! # Security Invariants
//!
//! - [INV-OUTBOX-001] Pulses are emitted ONLY after ledger commit
//! - [INV-OUTBOX-002] ACL filtering applied per DD-HEF-0004 before fanout
//! - [INV-OUTBOX-003] Backpressure via `try_reserve_enqueue()` prevents DoS
//! - [INV-OUTBOX-004] Notification drops never fail the commit path
//!
//! # Resource Governance (DD-HEF-0005)
//!
//! The publisher respects per-subscriber limits enforced via the
//! `SubscriptionRegistry`:
//! - Rate limiting via token bucket
//! - Queue depth bounds
//! - Bytes in-flight limits
//!
//! # Failure Modes (RFC-0018)
//!
//! - **Loss**: Expected; pulses are lossy hints. Consumer reconciles via
//!   ledger.
//! - **Reorder**: Allowed; authoritative ordering is ledger cursor.
//! - **Duplication**: Allowed; consumer dedupes by pulse_id + ledger_cursor.

use std::sync::Arc;

use apm2_core::events::KernelEvent;
use apm2_core::ledger::{CommitNotification, CommitNotificationReceiver, LedgerBackend};
use bytes::Bytes;
use prost::Message;
use tracing::{debug, info, trace, warn};
use uuid::Uuid;

use super::messages::{EntityRef, PulseEnvelopeV1, PulseEvent};
use super::resource_governance::SharedSubscriptionRegistry;
use super::topic_derivation::{TopicDerivationResult, TopicDeriver};

// ============================================================================
// Constants
// ============================================================================

/// Schema version for `PulseEnvelopeV1`.
///
/// Per proto definition: "MUST be 1 for `PulseEnvelopeV1`."
pub const PULSE_ENVELOPE_SCHEMA_VERSION: u32 = 1;

/// Maximum pulse ID length per proto bounds.
pub const MAX_PULSE_ID_LEN: usize = 64;

/// Tag byte for `PulseEvent` messages (server->client).
///
/// Per CTR-PROTO-010: HEF messages use tag range 64-79.
/// - 68 = `PulseEvent` (server->client only)
pub const PULSE_EVENT_TAG: u8 = 68;

/// Maximum entries in the `changeset_to_work_id` map (bounded eviction).
///
/// This prevents unbounded memory growth from accumulated changeset mappings.
/// When the map reaches this limit, the oldest entry is evicted (FIFO-like).
/// A typical work session produces ~10-100 changesets, so 10,000 entries
/// provides ample headroom while bounding memory to ~1MB worst case.
///
/// Security: Prevents `DoS` via unbounded memory growth (TCK-00304 review).
pub const MAX_CHANGESET_MAP_ENTRIES: usize = 10_000;

// ============================================================================
// Pulse Publisher
// ============================================================================

/// Configuration for the pulse publisher.
#[derive(Debug, Clone)]
pub struct PulsePublisherConfig {
    /// Maximum notifications to process per drain cycle.
    ///
    /// Bounds memory usage during burst scenarios.
    pub max_drain_batch: usize,

    /// Whether to skip ACL filtering (for testing only).
    ///
    /// In production, this MUST be false.
    pub skip_acl_filtering: bool,
}

impl Default for PulsePublisherConfig {
    fn default() -> Self {
        Self {
            max_drain_batch: 256,
            skip_acl_filtering: false,
        }
    }
}

impl PulsePublisherConfig {
    /// Creates a configuration for testing with relaxed settings.
    #[must_use]
    pub const fn for_testing() -> Self {
        Self {
            max_drain_batch: 16,
            skip_acl_filtering: false,
        }
    }
}

/// The HEF pulse publisher.
///
/// Drains the commit notification channel and fans out `PulseEvent` messages
/// to matching subscribers with ACL filtering and backpressure.
pub struct PulsePublisher {
    /// Configuration.
    config: PulsePublisherConfig,

    /// Commit notification receiver from ledger.
    receiver: CommitNotificationReceiver,

    /// Ledger backend for reading event payloads (TCK-00305).
    ///
    /// Required to extract `work_id` and `changeset_digest` for topic
    /// derivation.
    ledger: Arc<dyn LedgerBackend>,

    /// Shared subscription registry for ACL filtering and resource governance.
    registry: SharedSubscriptionRegistry,

    /// Connection senders for fanout (`connection_id` -> sender).
    ///
    /// This maps connection IDs to their frame senders. In a real
    /// implementation, this would be wired to the actual connection write
    /// halves.
    ///
    /// NOTE: For TCK-00304, we define the interface. Full wiring to connection
    /// handlers will be completed when the connection lifecycle is integrated.
    connection_senders: Arc<std::sync::RwLock<std::collections::HashMap<String, PulseFrameSender>>>,

    /// Current ledger head (updated as notifications are processed).
    ledger_head: std::sync::atomic::AtomicU64,

    /// Topic deriver for Work and Gate events (TCK-00305).
    ///
    /// Handles the mapping from kernel events to pulse topics, including
    /// the `changeset_digest` -> `work_id` index for gate receipts.
    topic_deriver: TopicDeriver,
}

/// Result of a non-blocking pulse send attempt.
///
/// Per TCK-00304 security review: `send_pulse` must be non-blocking to prevent
/// head-of-line blocking denial of service. A slow consumer on one connection
/// must not stall pulse delivery to other connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrySendResult {
    /// Pulse was successfully queued for delivery.
    Sent,
    /// Per-connection buffer is full; pulse dropped (acceptable per HEF
    /// semantics).
    BufferFull,
    /// Connection is closed; pulse dropped and connection should be cleaned up.
    Disconnected,
}

/// Sender for pulse frames to a connection.
///
/// This trait abstracts the actual frame sending mechanism to allow testing
/// and different transport implementations.
///
/// # Non-Blocking Guarantee (TCK-00304 Security Review)
///
/// Implementations MUST be non-blocking. The `try_send_pulse` method should
/// return immediately, using `try_send` semantics on an internal per-connection
/// buffer/channel. If the buffer is full, return `TrySendResult::BufferFull`
/// rather than blocking.
///
/// This prevents a slow consumer on one connection from blocking pulse delivery
/// to all other connections (head-of-line blocking `DoS`).
pub trait PulseFrameSink: Send + Sync {
    /// Attempts to send a pulse frame to the connection without blocking.
    ///
    /// # Arguments
    ///
    /// * `frame` - The encoded `PulseEvent` frame (tag + protobuf)
    ///
    /// # Returns
    ///
    /// - `TrySendResult::Sent` if the pulse was successfully queued
    /// - `TrySendResult::BufferFull` if the per-connection buffer is full
    ///   (pulse dropped)
    /// - `TrySendResult::Disconnected` if the connection is closed
    ///
    /// # Non-Blocking Guarantee
    ///
    /// This method MUST NOT block. Implementations should use `try_send` on an
    /// internal channel/buffer. Blocking here would cause head-of-line blocking
    /// denial of service across all connections.
    fn try_send_pulse(&self, frame: Bytes) -> TrySendResult;
}

/// Type alias for a boxed pulse frame sink.
pub type PulseFrameSender = Arc<dyn PulseFrameSink>;

impl PulsePublisher {
    /// Creates a new pulse publisher.
    ///
    /// # Arguments
    ///
    /// * `config` - Publisher configuration
    /// * `receiver` - Commit notification receiver from ledger
    /// * `ledger` - Ledger backend for event payload access
    /// * `registry` - Shared subscription registry
    #[must_use]
    pub fn new(
        config: PulsePublisherConfig,
        receiver: CommitNotificationReceiver,
        ledger: Arc<dyn LedgerBackend>,
        registry: SharedSubscriptionRegistry,
    ) -> Self {
        Self {
            config,
            receiver,
            ledger,
            registry,
            connection_senders: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            ledger_head: std::sync::atomic::AtomicU64::new(0),
            topic_deriver: TopicDeriver::new(),
        }
    }

    /// Returns a reference to the topic deriver.
    ///
    /// Allows external access to the changeset index for testing or monitoring.
    #[must_use]
    pub const fn topic_deriver(&self) -> &TopicDeriver {
        &self.topic_deriver
    }

    /// Registers a connection sender for pulse delivery.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Unique connection identifier
    /// * `sender` - The frame sender for this connection
    pub fn register_connection(&self, connection_id: impl Into<String>, sender: PulseFrameSender) {
        let mut senders = self.connection_senders.write().expect("lock poisoned");
        senders.insert(connection_id.into(), sender);
    }

    /// Unregisters a connection (called on disconnect).
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Connection identifier to remove
    pub fn unregister_connection(&self, connection_id: &str) {
        let mut senders = self.connection_senders.write().expect("lock poisoned");
        senders.remove(connection_id);
    }

    /// Runs the publisher loop, draining notifications and publishing pulses.
    ///
    /// This method runs until the receiver is closed (daemon shutdown).
    ///
    /// # Cancel Safety
    ///
    /// This method is cancel-safe. If cancelled, some notifications may be
    /// unprocessed, but this is acceptable per the lossy pulse semantics.
    pub async fn run(&mut self) {
        info!("Pulse publisher started");

        while let Some(notification) = self.receiver.recv().await {
            // Update ledger head
            self.ledger_head
                .store(notification.seq_id, std::sync::atomic::Ordering::Release);

            // Process the notification
            self.process_notification(notification).await;
        }

        info!("Pulse publisher stopped (channel closed)");
    }

    /// Drains available notifications without blocking.
    ///
    /// Returns the number of notifications processed.
    ///
    /// # Arguments
    ///
    /// * `max_batch` - Maximum notifications to drain (0 = use config default)
    pub async fn drain_batch(&mut self, max_batch: usize) -> usize {
        let limit = if max_batch == 0 {
            self.config.max_drain_batch
        } else {
            max_batch
        };

        let mut count = 0;
        while count < limit {
            match self.receiver.try_recv() {
                Ok(notification) => {
                    self.ledger_head
                        .store(notification.seq_id, std::sync::atomic::Ordering::Release);
                    self.process_notification(notification).await;
                    count += 1;
                },
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    break;
                },
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    debug!("Notification channel disconnected during drain");
                    break;
                },
            }
        }

        count
    }

    /// Processes a single commit notification.
    async fn process_notification(&self, notification: CommitNotification) {
        trace!(
            seq_id = notification.seq_id,
            event_type = %notification.event_type,
            namespace = %notification.namespace,
            "Processing commit notification"
        );

        // Read event record from ledger to get payload
        // This is necessary for TCK-00305 topic derivation (Work/Gate events)
        let event_record = match self
            .ledger
            .read_from(&notification.namespace, notification.seq_id, 1)
            .await
        {
            Ok(records) => {
                if let Some(record) = records.into_iter().next() {
                    record
                } else {
                    warn!("Event {} not found in ledger", notification.seq_id);
                    return;
                }
            },
            Err(e) => {
                warn!("Failed to read event {}: {}", notification.seq_id, e);
                return;
            },
        };

        // Decode KernelEvent
        let kernel_event = match KernelEvent::decode(event_record.payload.as_slice()) {
            Ok(event) => event,
            Err(e) => {
                warn!("Failed to decode event {}: {}", notification.seq_id, e);
                return;
            },
        };

        // Update index for TCK-00305 (PolicyResolvedForChangeSet lookup)
        self.topic_deriver.update_index(&kernel_event);

        // Derive topics using multi-topic derivation (TCK-00642).
        // Most events produce a single topic; work graph edge events produce
        // topics for both from_work_id and to_work_id.
        let topic_results = self
            .topic_deriver
            .derive_topics(&notification, &kernel_event);

        // Filter to successful topics only, logging failures
        let topics: Vec<String> = topic_results
            .into_iter()
            .filter_map(|result| match result {
                TopicDerivationResult::Success(t) => Some(t),
                TopicDerivationResult::ValidationFailed {
                    attempted_topic,
                    error,
                } => {
                    debug!(
                        seq_id = notification.seq_id,
                        event_type = %notification.event_type,
                        namespace = %notification.namespace,
                        attempted_topic = %attempted_topic,
                        error = %error,
                        "Derived topic failed validation (skipped)"
                    );
                    None
                },
                TopicDerivationResult::NoTopic => {
                    debug!(
                        seq_id = notification.seq_id,
                        event_type = %notification.event_type,
                        namespace = %notification.namespace,
                        "No topic could be derived (skipped)"
                    );
                    None
                },
            })
            .collect();

        if topics.is_empty() {
            debug!(
                seq_id = notification.seq_id,
                event_type = %notification.event_type,
                "Notification dropped: no valid topics derived"
            );
            return;
        }

        // Fan out to all derived topics
        for topic in &topics {
            self.publish_to_topic(&notification, topic);
        }
    }

    /// Publishes a pulse event for a single topic.
    ///
    /// Builds the envelope, finds matching subscriptions, encodes the pulse
    /// event, and fans out to matching subscribers with backpressure.
    fn publish_to_topic(&self, notification: &CommitNotification, topic: &str) {
        // Build the pulse envelope
        let envelope = self.build_envelope(notification, topic);

        // Find matching subscriptions
        let matches = self.registry.find_matching_subscriptions(topic);

        if matches.is_empty() {
            trace!(topic = %topic, "No matching subscriptions for pulse");
            return;
        }

        // Encode the pulse event once
        let frame = Self::encode_pulse_event(&envelope);
        let payload_size = frame.len();

        // Fan out to matching subscribers with backpressure
        let senders = self.connection_senders.read().expect("lock poisoned");

        for (connection_id, subscription_id) in matches {
            // Try to reserve queue slot with backpressure
            match self
                .registry
                .try_reserve_enqueue(&connection_id, payload_size)
            {
                Ok(()) => {
                    // Reservation successful, attempt non-blocking send
                    if let Some(sender) = senders.get(&connection_id) {
                        match sender.try_send_pulse(frame.clone()) {
                            TrySendResult::Sent => {
                                trace!(
                                    connection_id = %connection_id,
                                    subscription_id = %subscription_id,
                                    topic = %topic,
                                    "Pulse delivered"
                                );
                            },
                            TrySendResult::BufferFull => {
                                // Per-connection buffer full; release reservation and drop pulse
                                self.registry.record_dequeue(&connection_id, payload_size);
                                debug!(
                                    connection_id = %connection_id,
                                    subscription_id = %subscription_id,
                                    topic = %topic,
                                    "Pulse dropped: per-connection buffer full"
                                );
                            },
                            TrySendResult::Disconnected => {
                                // Connection closed, release reservation
                                self.registry.record_dequeue(&connection_id, payload_size);
                                debug!(
                                    connection_id = %connection_id,
                                    "Pulse delivery failed: connection closed"
                                );
                            },
                        }
                    } else {
                        // No sender registered, release reservation
                        self.registry.record_dequeue(&connection_id, payload_size);
                        trace!(
                            connection_id = %connection_id,
                            "No sender registered for connection"
                        );
                    }
                },
                Err(e) => {
                    // Backpressure: drop the pulse for this subscriber
                    warn!(
                        connection_id = %connection_id,
                        subscription_id = %subscription_id,
                        topic = %topic,
                        error = %e,
                        "Pulse dropped due to backpressure"
                    );
                },
            }
        }
    }

    /// Builds a `PulseEnvelopeV1` from a commit notification.
    fn build_envelope(&self, notification: &CommitNotification, topic: &str) -> PulseEnvelopeV1 {
        // Generate pulse ID: seq:hash_prefix:random
        let hash_prefix = hex::encode(&notification.event_hash[..4]);
        let random = Uuid::new_v4().to_string()[..8].to_string();
        let pulse_id = format!("{}:{}:{}", notification.seq_id, hash_prefix, random);

        // Get current ledger head
        let ledger_head = self.ledger_head.load(std::sync::atomic::Ordering::Acquire);

        // Build entity references based on event type
        let entities = self.extract_entities(notification);

        PulseEnvelopeV1 {
            schema_version: PULSE_ENVELOPE_SCHEMA_VERSION,
            pulse_id,
            topic: topic.to_string(),
            ledger_cursor: notification.seq_id,
            ledger_head,
            event_hash: Some(notification.event_hash.to_vec()),
            event_type: notification.event_type.clone(),
            entities,
            cas_refs: vec![], // CAS refs extracted when needed
            time_envelope_hash: None,
            hlc: None,
            wall: None,
        }
    }

    /// Extracts entity references from a notification.
    ///
    /// This is a placeholder that returns minimal entities.
    /// Full entity extraction will be implemented when event schemas are
    /// defined.
    #[allow(clippy::unused_self)] // Will use self for entity extraction config in future
    fn extract_entities(&self, notification: &CommitNotification) -> Vec<EntityRef> {
        // For now, just include namespace as a basic entity
        vec![EntityRef {
            kind: "namespace".to_string(),
            id: notification.namespace.clone(),
            digest: None, // No digest for namespace entities
        }]
    }

    /// Encodes a `PulseEvent` to a frame (tag + protobuf).
    fn encode_pulse_event(envelope: &PulseEnvelopeV1) -> Bytes {
        let event = PulseEvent {
            envelope: Some(envelope.clone()),
        };

        let mut buf = Vec::with_capacity(1 + event.encoded_len());
        buf.push(PULSE_EVENT_TAG);
        event.encode(&mut buf).expect("encode cannot fail");

        Bytes::from(buf)
    }

    /// Returns the current ledger head seen by the publisher.
    #[must_use]
    pub fn ledger_head(&self) -> u64 {
        self.ledger_head.load(std::sync::atomic::Ordering::Acquire)
    }
}

// ============================================================================
// Factory Function
// ============================================================================

/// Creates a commit notification channel and returns both ends.
///
/// This is a convenience function for setting up the HEF outbox pipeline.
///
/// # Returns
///
/// A tuple of (sender, receiver) for commit notifications.
#[must_use]
pub fn create_commit_notification_channel() -> (
    apm2_core::ledger::CommitNotificationSender,
    CommitNotificationReceiver,
) {
    tokio::sync::mpsc::channel(apm2_core::ledger::COMMIT_NOTIFICATION_CHANNEL_CAPACITY)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use apm2_core::ledger::{CommitNotification, EventRecord};

    use super::*;
    use crate::protocol::pulse_topic::TopicPattern;
    use crate::protocol::resource_governance::{
        ResourceQuotaConfig, SubscriptionRegistry, SubscriptionState,
    };

    /// Mock pulse frame sink for testing.
    #[derive(Default)]
    struct MockPulseFrameSink {
        frames: std::sync::Mutex<Vec<Bytes>>,
        failure_mode: std::sync::atomic::AtomicU8,
    }

    impl MockPulseFrameSink {
        /// Disconnected mode - returns `Disconnected`
        const MODE_DISCONNECTED: u8 = 1;
        /// Buffer full mode - returns `BufferFull`
        const MODE_BUFFER_FULL: u8 = 2;

        fn new() -> Self {
            Self::default()
        }

        fn with_failure() -> Self {
            Self {
                frames: std::sync::Mutex::new(Vec::new()),
                failure_mode: std::sync::atomic::AtomicU8::new(Self::MODE_DISCONNECTED),
            }
        }

        fn with_buffer_full() -> Self {
            Self {
                frames: std::sync::Mutex::new(Vec::new()),
                failure_mode: std::sync::atomic::AtomicU8::new(Self::MODE_BUFFER_FULL),
            }
        }

        fn received_frames(&self) -> Vec<Bytes> {
            self.frames.lock().unwrap().clone()
        }
    }

    impl PulseFrameSink for MockPulseFrameSink {
        fn try_send_pulse(&self, frame: Bytes) -> TrySendResult {
            match self.failure_mode.load(std::sync::atomic::Ordering::Relaxed) {
                Self::MODE_DISCONNECTED => TrySendResult::Disconnected,
                Self::MODE_BUFFER_FULL => TrySendResult::BufferFull,
                _ => {
                    self.frames.lock().unwrap().push(frame);
                    TrySendResult::Sent
                },
            }
        }
    }

    fn test_pattern(s: &str) -> TopicPattern {
        TopicPattern::parse(s).expect("valid pattern")
    }

    /// Mock ledger backend for testing.
    struct MockLedgerBackend {
        events: std::sync::Mutex<HashMap<u64, EventRecord>>,
    }

    impl MockLedgerBackend {
        fn new() -> Self {
            Self {
                events: std::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    impl LedgerBackend for MockLedgerBackend {
        fn append<'a>(
            &'a self,
            _namespace: &'a str,
            _event: &'a EventRecord,
        ) -> apm2_core::ledger::BoxFuture<'a, Result<u64, apm2_core::ledger::LedgerError>> {
            Box::pin(async { Ok(0) })
        }

        fn read_from<'a>(
            &'a self,
            _namespace: &'a str,
            cursor: u64,
            _limit: u64,
        ) -> apm2_core::ledger::BoxFuture<
            'a,
            Result<Vec<EventRecord>, apm2_core::ledger::LedgerError>,
        > {
            let events = self.events.lock().unwrap();
            let result = events
                .get(&cursor)
                .map_or_else(Vec::new, |event| vec![event.clone()]);
            Box::pin(async { Ok(result) })
        }

        fn head<'a>(
            &'a self,
            _namespace: &'a str,
        ) -> apm2_core::ledger::BoxFuture<'a, Result<u64, apm2_core::ledger::LedgerError>> {
            Box::pin(async { Ok(0) })
        }

        fn verify_chain<'a>(
            &'a self,
            _namespace: &'a str,
            _from_seq_id: u64,
            _verify_hash_fn: apm2_core::ledger::HashFn<'a>,
            _verify_sig_fn: apm2_core::ledger::VerifyFn<'a>,
        ) -> apm2_core::ledger::BoxFuture<'a, Result<(), apm2_core::ledger::LedgerError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn test_create_channel() {
        let (sender, mut rx) = create_commit_notification_channel();

        let notification = CommitNotification::new(1, [0xab; 32], "TestEvent", "kernel");

        sender.send(notification.clone()).await.unwrap();

        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.seq_id, 1);
        assert_eq!(msg.event_type, "TestEvent");
    }

    #[tokio::test]
    async fn test_publisher_topic_derivation() {
        let (_, receiver) = create_commit_notification_channel();
        let ledger = Arc::new(MockLedgerBackend::new());
        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));

        let publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            ledger,
            registry,
        );

        let event = KernelEvent::default();

        // Test ledger head topic
        let notification = CommitNotification::new(1, [0; 32], "LedgerEvent", "kernel");
        let result = publisher
            .topic_deriver()
            .derive_topic(&notification, &event);
        assert_eq!(result.topic(), Some("ledger.head"));

        // Test work event topic (falls back to namespace when no payload)
        let notification = CommitNotification::new(2, [0; 32], "WorkOpened", "W-123");
        let result = publisher
            .topic_deriver()
            .derive_topic(&notification, &event);
        assert_eq!(result.topic(), Some("work.W-123.events"));

        // Test gate receipt topic (falls back when no payload or index entry)
        let notification = CommitNotification::new(3, [0; 32], "GateReceipt", "W-456");
        let result = publisher
            .topic_deriver()
            .derive_topic(&notification, &event);
        assert_eq!(result.topic(), Some("gate.W-456.receipts"));

        // Test defect topic (TCK-00307)
        let notification = CommitNotification::new(4, [0; 32], "DefectRecorded", "kernel");
        let result = publisher
            .topic_deriver()
            .derive_topic(&notification, &event);
        assert_eq!(result.topic(), Some("defect.new"));
    }

    #[tokio::test]
    async fn test_publisher_topic_derivation_sanitizes_namespace() {
        let (_, receiver) = create_commit_notification_channel();
        let ledger = Arc::new(MockLedgerBackend::new());
        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));

        let publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            ledger,
            registry,
        );

        let event = KernelEvent::default();

        // Test namespace with special characters gets sanitized
        let notification = CommitNotification::new(1, [0; 32], "WorkOpened", "work@id#123");
        let result = publisher
            .topic_deriver()
            .derive_topic(&notification, &event);
        assert!(result.is_success());
        // Special characters replaced with underscores
        assert_eq!(result.topic(), Some("work.work_id_123.events"));

        // Test namespace with dots gets sanitized (dots become underscores)
        let notification = CommitNotification::new(2, [0; 32], "WorkOpened", "ns.sub.id");
        let result = publisher
            .topic_deriver()
            .derive_topic(&notification, &event);
        assert!(result.is_success());
        assert_eq!(result.topic(), Some("work.ns_sub_id.events"));

        // Test empty namespace gets sanitized to underscore
        let notification = CommitNotification::new(3, [0; 32], "WorkOpened", "");
        let result = publisher
            .topic_deriver()
            .derive_topic(&notification, &event);
        assert!(result.is_success());
        assert_eq!(result.topic(), Some("work._.events"));
    }

    #[tokio::test]
    async fn test_publisher_buffer_full_handling() {
        let (sender, receiver) = create_commit_notification_channel();

        // Setup mock ledger with the event
        let mock_ledger = Arc::new(MockLedgerBackend::new());
        let event_record = EventRecord::new(
            "LedgerEvent",
            "session-1",
            "actor-1",
            KernelEvent::default().encode_to_vec(),
        );
        mock_ledger.events.lock().unwrap().insert(1, event_record);

        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));

        registry.register_connection("conn-1").unwrap();
        let sub = SubscriptionState::new(
            "sub-1",
            "client-sub-1",
            vec![test_pattern("ledger.head")],
            0,
        );
        registry.add_subscription("conn-1", sub).unwrap();

        // Register a mock sender that simulates buffer full
        let mock_sink = Arc::new(MockPulseFrameSink::with_buffer_full());

        let mut publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            mock_ledger,
            Arc::clone(&registry),
        );
        publisher.register_connection("conn-1", mock_sink.clone());

        // Send a notification
        let notification = CommitNotification::new(1, [0xab; 32], "LedgerEvent", "kernel");
        sender.send(notification).await.unwrap();

        // Process it - should handle buffer full gracefully (non-blocking)
        let count = publisher.drain_batch(10).await;
        assert_eq!(count, 1);

        // No frames sent due to buffer full
        let frames = mock_sink.received_frames();
        assert_eq!(frames.len(), 0);

        // Verify dequeue was called (reservation released)
        let stats = registry.connection_stats("conn-1").unwrap();
        assert_eq!(stats.queue_depth, 0);
    }

    #[tokio::test]
    async fn test_publisher_build_envelope() {
        let (_, receiver) = create_commit_notification_channel();
        let ledger = Arc::new(MockLedgerBackend::new());
        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));

        let publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            ledger,
            registry,
        );

        let notification = CommitNotification::new(42, [0xab; 32], "TestEvent", "kernel");
        let envelope = publisher.build_envelope(&notification, "test.topic");

        assert_eq!(envelope.schema_version, PULSE_ENVELOPE_SCHEMA_VERSION);
        assert!(envelope.pulse_id.starts_with("42:"));
        assert_eq!(envelope.topic, "test.topic");
        assert_eq!(envelope.ledger_cursor, 42);
        assert_eq!(envelope.event_hash, Some(vec![0xab; 32]));
        assert_eq!(envelope.event_type, "TestEvent");
    }

    #[tokio::test]
    async fn test_publisher_fanout_with_matching_subscription() {
        let (sender, receiver) = create_commit_notification_channel();
        let mock_ledger = Arc::new(MockLedgerBackend::new());
        let event_record = EventRecord::new(
            "LedgerEvent",
            "session-1",
            "actor-1",
            KernelEvent::default().encode_to_vec(),
        );
        mock_ledger.events.lock().unwrap().insert(1, event_record);

        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));

        // Register a connection and subscription
        registry.register_connection("conn-1").unwrap();
        let sub = SubscriptionState::new(
            "sub-1",
            "client-sub-1",
            vec![test_pattern("ledger.head")],
            0,
        );
        registry.add_subscription("conn-1", sub).unwrap();

        let mut publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            mock_ledger,
            Arc::clone(&registry),
        );

        // Register a mock sender
        let mock_sink = Arc::new(MockPulseFrameSink::new());
        publisher.register_connection("conn-1", mock_sink.clone());

        // Send a notification
        let notification = CommitNotification::new(1, [0xab; 32], "LedgerEvent", "kernel");
        sender.send(notification).await.unwrap();

        // Process it
        let count = publisher.drain_batch(10).await;
        assert_eq!(count, 1);

        // Verify the frame was sent
        let frames = mock_sink.received_frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], PULSE_EVENT_TAG);
    }

    #[tokio::test]
    async fn test_publisher_fanout_no_matching_subscription() {
        let (sender, receiver) = create_commit_notification_channel();
        let mock_ledger = Arc::new(MockLedgerBackend::new());
        let event_record = EventRecord::new(
            "LedgerEvent",
            "session-1",
            "actor-1",
            KernelEvent::default().encode_to_vec(),
        );
        mock_ledger.events.lock().unwrap().insert(1, event_record);

        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));

        // Register a connection with a non-matching subscription
        registry.register_connection("conn-1").unwrap();
        let sub = SubscriptionState::new(
            "sub-1",
            "client-sub-1",
            vec![test_pattern("work.*.events")],
            0,
        );
        registry.add_subscription("conn-1", sub).unwrap();

        let mut publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            mock_ledger,
            Arc::clone(&registry),
        );

        // Register a mock sender
        let mock_sink = Arc::new(MockPulseFrameSink::new());
        publisher.register_connection("conn-1", mock_sink.clone());

        // Send a notification
        let notification = CommitNotification::new(1, [0xab; 32], "LedgerEvent", "kernel");
        sender.send(notification).await.unwrap();

        // Process it
        let count = publisher.drain_batch(10).await;
        assert_eq!(count, 1);

        // Verify no frame was sent (topic doesn't match pattern)
        let frames = mock_sink.received_frames();
        assert_eq!(frames.len(), 0);
    }

    #[tokio::test]
    async fn test_publisher_backpressure() {
        let (sender, receiver) = create_commit_notification_channel();
        let mock_ledger = Arc::new(MockLedgerBackend::new());
        for i in 0..5u64 {
            let event_record = EventRecord::new(
                "LedgerEvent",
                "session-1",
                "actor-1",
                KernelEvent::default().encode_to_vec(),
            );
            mock_ledger.events.lock().unwrap().insert(i, event_record);
        }

        // Use very restrictive quotas
        let config = ResourceQuotaConfig {
            max_queue_depth: 1,
            max_bytes_in_flight: 100,
            max_burst_pulses: 1,
            max_pulses_per_sec: 1,
            ..ResourceQuotaConfig::for_testing()
        };
        let registry = Arc::new(SubscriptionRegistry::new(config));

        registry.register_connection("conn-1").unwrap();
        let sub = SubscriptionState::new(
            "sub-1",
            "client-sub-1",
            vec![test_pattern("ledger.head")],
            0,
        );
        registry.add_subscription("conn-1", sub).unwrap();

        let mut publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            mock_ledger,
            Arc::clone(&registry),
        );

        let mock_sink = Arc::new(MockPulseFrameSink::new());
        publisher.register_connection("conn-1", mock_sink.clone());

        // Send multiple notifications
        for i in 0..5u64 {
            let notification = CommitNotification::new(i, [0xab; 32], "LedgerEvent", "kernel");
            sender.send(notification).await.unwrap();
        }

        // Process them - some should be dropped due to backpressure
        let count = publisher.drain_batch(10).await;
        assert_eq!(count, 5);

        // Due to rate limiting (1 pulse burst), only 1 should have been delivered
        let frames = mock_sink.received_frames();
        assert!(
            frames.len() <= 2,
            "Expected 1-2 frames due to backpressure, got {}",
            frames.len()
        );
    }

    #[tokio::test]
    async fn test_publisher_connection_failure() {
        let (sender, receiver) = create_commit_notification_channel();
        let mock_ledger = Arc::new(MockLedgerBackend::new());
        let event_record = EventRecord::new(
            "LedgerEvent",
            "session-1",
            "actor-1",
            KernelEvent::default().encode_to_vec(),
        );
        mock_ledger.events.lock().unwrap().insert(1, event_record);

        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));

        registry.register_connection("conn-1").unwrap();
        let sub = SubscriptionState::new(
            "sub-1",
            "client-sub-1",
            vec![test_pattern("ledger.head")],
            0,
        );
        registry.add_subscription("conn-1", sub).unwrap();

        let mut publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            mock_ledger,
            Arc::clone(&registry),
        );

        // Register a failing mock sender
        let mock_sink = Arc::new(MockPulseFrameSink::with_failure());
        publisher.register_connection("conn-1", mock_sink.clone());

        // Send a notification
        let notification = CommitNotification::new(1, [0xab; 32], "LedgerEvent", "kernel");
        sender.send(notification).await.unwrap();

        // Process it - should handle the failure gracefully
        let count = publisher.drain_batch(10).await;
        assert_eq!(count, 1);

        // No frames sent due to failure
        let frames = mock_sink.received_frames();
        assert_eq!(frames.len(), 0);

        // Verify dequeue was called (reservation released)
        // The stats should show 0 queue depth after failure
        let stats = registry.connection_stats("conn-1").unwrap();
        assert_eq!(stats.queue_depth, 0);
    }

    #[test]
    fn test_encode_pulse_event() {
        let envelope = PulseEnvelopeV1 {
            schema_version: 1,
            pulse_id: "1:abcd:1234".to_string(),
            topic: "ledger.head".to_string(),
            ledger_cursor: 42,
            ledger_head: 100,
            event_hash: Some(vec![0xab; 32]),
            event_type: "TestEvent".to_string(),
            entities: vec![],
            cas_refs: vec![],
            time_envelope_hash: None,
            hlc: None,
            wall: None,
        };

        let frame = PulsePublisher::encode_pulse_event(&envelope);

        // Verify tag byte
        assert_eq!(frame[0], PULSE_EVENT_TAG);

        // Verify we can decode it
        let event = PulseEvent::decode(&frame[1..]).unwrap();
        assert!(event.envelope.is_some());
        let decoded = event.envelope.unwrap();
        assert_eq!(decoded.schema_version, 1);
        assert_eq!(decoded.topic, "ledger.head");
        assert_eq!(decoded.ledger_cursor, 42);
    }

    #[test]
    fn test_config_defaults() {
        let config = PulsePublisherConfig::default();
        assert_eq!(config.max_drain_batch, 256);
        assert!(!config.skip_acl_filtering);

        let test_config = PulsePublisherConfig::for_testing();
        assert_eq!(test_config.max_drain_batch, 16);
    }

    #[tokio::test]
    async fn test_changeset_index_via_topic_deriver() {
        use apm2_core::events::PolicyResolvedForChangeSet;
        use apm2_core::events::kernel_event::Payload;

        let (_, receiver) = create_commit_notification_channel();
        let ledger = Arc::new(MockLedgerBackend::new());
        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));

        let publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            ledger,
            registry,
        );

        // Insert entries up to a test limit (not the full MAX to keep tests fast)
        let test_limit = 100;

        // First, verify the index is empty
        assert!(publisher.topic_deriver().changeset_index().is_empty());
        assert_eq!(publisher.topic_deriver().changeset_index().len(), 0);

        // Insert entries up to the test limit via update_index
        for i in 0..test_limit {
            #[allow(clippy::cast_possible_truncation)]
            let digest_byte = i as u8; // Safe: test_limit is 100, well within u8 range
            let event = KernelEvent {
                payload: Some(Payload::PolicyResolvedForChangeset(
                    PolicyResolvedForChangeSet {
                        changeset_digest: vec![digest_byte; 32],
                        work_id: format!("work-{i}"),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            };
            publisher.topic_deriver().update_index(&event);
        }

        // Verify all entries were inserted
        assert_eq!(
            publisher.topic_deriver().changeset_index().len(),
            test_limit
        );

        // Verify we can look up entries
        assert_eq!(
            publisher.topic_deriver().changeset_index().get(&[50u8; 32]),
            Some("work-50".to_string())
        );
    }

    #[test]
    fn test_max_changeset_map_entries_constant() {
        // Ensure it's > 0 (const assertion validated at compile time)
        const _: () = assert!(MAX_CHANGESET_MAP_ENTRIES > 0);

        // Verify the constant is set to a reasonable value
        assert_eq!(MAX_CHANGESET_MAP_ENTRIES, 10_000);
        // Ensure it's < u32::MAX to prevent overflow issues
        assert!(MAX_CHANGESET_MAP_ENTRIES < u32::MAX as usize);
    }
}
