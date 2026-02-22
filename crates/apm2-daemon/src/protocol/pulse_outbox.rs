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

use apm2_core::events::{
    EvidenceEvent, GateReceipt, IoArtifactPublished, KernelEvent, PolicyResolvedForChangeSet,
    SessionEvent, ToolEvent, WorkEvent, WorkGraphEvent, evidence_event, session_event, tool_event,
    work_event, work_graph_event,
};
use apm2_core::ledger::{
    CommitNotification, CommitNotificationReceiver, EventRecord, LedgerBackend,
};
use bytes::Bytes;
use prost::Message;
use tracing::{debug, info, trace, warn};
use uuid::Uuid;

use super::messages::{EntityRef, PulseEnvelopeV1, PulseEvent};
use super::resource_governance::SharedSubscriptionRegistry;
use super::topic_derivation::{
    BridgeTopicHints, TopicDerivationResult, TopicDeriver, normalize_event_type,
};

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

/// Maximum payload bytes processed by bridge fallback routing.
///
/// Prevents unbounded JSON parsing or hex expansion when extracting minimal
/// routing fields from non-`KernelEvent` payload formats.
pub const MAX_BRIDGE_ROUTING_PAYLOAD_BYTES: usize = 256 * 1024;

/// Maximum hex characters accepted for nested `payload` fields in JSON
/// envelopes.
const MAX_BRIDGE_ROUTING_HEX_CHARS: usize = MAX_BRIDGE_ROUTING_PAYLOAD_BYTES * 2;

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

        // Primary path: decode full KernelEvent.
        // Bridge fallback: extract bounded routing hints from payload when the
        // stored format is not a KernelEvent envelope.
        let topic_results = match KernelEvent::decode(event_record.payload.as_slice()) {
            Ok(kernel_event) => {
                // Update index for TCK-00305 (PolicyResolvedForChangeSet lookup)
                self.topic_deriver.update_index(&kernel_event);

                // Derive topics using multi-topic derivation (TCK-00642).
                // Most events produce a single topic; work graph edge events
                // produce topics for both from_work_id and to_work_id.
                self.topic_deriver
                    .derive_topics(&notification, &kernel_event)
            },
            Err(e) => {
                warn!(
                    seq_id = notification.seq_id,
                    event_type = %notification.event_type,
                    namespace = %notification.namespace,
                    error = %e,
                    "KernelEvent decode failed; using bounded bridge routing hints"
                );

                let hints = Self::derive_bridge_topic_hints(&notification, &event_record);

                // Preserve changeset->work index updates in bridge mode so gate
                // routing remains coherent during mixed payload windows.
                if normalize_event_type(notification.event_type.as_str())
                    == "policy.resolved_for_changeset"
                {
                    if let (Some(changeset_digest), Some(work_id)) =
                        (&hints.changeset_digest, &hints.work_id)
                    {
                        self.topic_deriver
                            .changeset_index()
                            .insert(changeset_digest.clone(), work_id.clone());
                    }
                }

                self.topic_deriver
                    .derive_topics_from_hints(&notification, &hints)
            },
        };

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
                TopicDerivationResult::MultiTopicEventError { event_type } => {
                    // Should never happen: derive_topics() does not return this variant.
                    // Log at warn level as a defensive measure.
                    warn!(
                        seq_id = notification.seq_id,
                        event_type = %event_type,
                        "BUG: MultiTopicEventError in derive_topics path (skipped)"
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

    fn derive_bridge_topic_hints(
        notification: &CommitNotification,
        event_record: &EventRecord,
    ) -> BridgeTopicHints {
        let normalized_event_type = normalize_event_type(notification.event_type.as_str());
        let is_work_scoped_event = Self::is_work_scoped_event_type(normalized_event_type);
        let mut hints = BridgeTopicHints::default();

        if !event_record.session_id.is_empty() {
            hints.session_id = Some(event_record.session_id.clone());
        }

        if event_record.payload.len() > MAX_BRIDGE_ROUTING_PAYLOAD_BYTES {
            warn!(
                event_type = %notification.event_type,
                payload_bytes = event_record.payload.len(),
                max_payload_bytes = MAX_BRIDGE_ROUTING_PAYLOAD_BYTES,
                "Bridge routing skipped payload decode: payload exceeds bound"
            );
            // Last-resort fallback only when payload cannot be inspected.
            if is_work_scoped_event
                && hints.work_id.is_none()
                && !event_record.session_id.is_empty()
            {
                hints.work_id = Some(event_record.session_id.clone());
            }
            return hints;
        }

        if let Ok(payload_json) = serde_json::from_slice::<serde_json::Value>(&event_record.payload)
        {
            Self::populate_hints_from_json(&payload_json, &mut hints);

            let inner_payload = payload_json
                .get("payload")
                .and_then(serde_json::Value::as_str)
                .filter(|hex_payload| {
                    hex_payload.len() <= MAX_BRIDGE_ROUTING_HEX_CHARS && hex_payload.len() % 2 == 0
                })
                .and_then(|hex_payload| hex::decode(hex_payload).ok());

            if let Some(inner_payload) = inner_payload {
                Self::populate_hints_from_payload_bytes(
                    normalized_event_type,
                    inner_payload.as_slice(),
                    &mut hints,
                );
            } else {
                Self::populate_hints_from_payload_bytes(
                    normalized_event_type,
                    event_record.payload.as_slice(),
                    &mut hints,
                );
            }
        } else {
            Self::populate_hints_from_payload_bytes(
                normalized_event_type,
                event_record.payload.as_slice(),
                &mut hints,
            );
        }

        // Lowest-precedence compatibility fallback for legacy records where
        // work_id is carried in session_id and payload extraction failed.
        if is_work_scoped_event && hints.work_id.is_none() && !event_record.session_id.is_empty() {
            hints.work_id = Some(event_record.session_id.clone());
        }

        hints
    }

    fn populate_hints_from_json(payload_json: &serde_json::Value, hints: &mut BridgeTopicHints) {
        if hints.work_id.is_none() {
            hints.work_id = payload_json
                .get("work_id")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
        }

        if hints.session_id.is_none() {
            hints.session_id = payload_json
                .get("session_id")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
        }

        if hints.gate_id.is_none() {
            hints.gate_id = payload_json
                .get("gate_id")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
        }

        if hints.from_work_id.is_none() {
            hints.from_work_id = payload_json
                .get("from_work_id")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
        }

        if hints.to_work_id.is_none() {
            hints.to_work_id = payload_json
                .get("to_work_id")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
        }

        if hints.changeset_digest.is_none() {
            hints.changeset_digest = payload_json
                .get("changeset_digest")
                .and_then(serde_json::Value::as_str)
                .and_then(Self::decode_hex_digest_bounded);
        }
    }

    fn populate_hints_from_payload_bytes(
        normalized_event_type: &str,
        payload: &[u8],
        hints: &mut BridgeTopicHints,
    ) {
        match normalized_event_type {
            "work.opened" | "work.transitioned" | "work.completed" | "work.aborted"
            | "work.pr_associated" => {
                if let Ok(work_event) = WorkEvent::decode(payload) {
                    let work_id = match work_event.event {
                        Some(work_event::Event::Opened(event)) => event.work_id,
                        Some(work_event::Event::Transitioned(event)) => event.work_id,
                        Some(work_event::Event::Completed(event)) => event.work_id,
                        Some(work_event::Event::Aborted(event)) => event.work_id,
                        Some(work_event::Event::PrAssociated(event)) => event.work_id,
                        None => String::new(),
                    };
                    if hints.work_id.is_none() && !work_id.is_empty() {
                        hints.work_id = Some(work_id);
                    }
                }
            },
            "evidence.published" => {
                if let Ok(evidence_event) = EvidenceEvent::decode(payload)
                    && let Some(evidence_event::Event::Published(published)) = evidence_event.event
                    && hints.work_id.is_none()
                    && !published.work_id.is_empty()
                {
                    hints.work_id = Some(published.work_id);
                }
            },
            "gate.receipt" => {
                if let Ok(gate_receipt) = GateReceipt::decode(payload) {
                    if hints.gate_id.is_none() && !gate_receipt.gate_id.is_empty() {
                        hints.gate_id = Some(gate_receipt.gate_id);
                    }
                    if hints.changeset_digest.is_none() && !gate_receipt.changeset_digest.is_empty()
                    {
                        hints.changeset_digest = Some(gate_receipt.changeset_digest);
                    }
                }
            },
            "policy.resolved_for_changeset" => {
                if let Ok(policy_resolved) = PolicyResolvedForChangeSet::decode(payload) {
                    if hints.work_id.is_none() && !policy_resolved.work_id.is_empty() {
                        hints.work_id = Some(policy_resolved.work_id);
                    }
                    if hints.changeset_digest.is_none()
                        && !policy_resolved.changeset_digest.is_empty()
                    {
                        hints.changeset_digest = Some(policy_resolved.changeset_digest);
                    }
                }
            },
            "work_graph.edge.added" | "work_graph.edge.removed" | "work_graph.edge.waived" => {
                if let Ok(work_graph_event) = WorkGraphEvent::decode(payload) {
                    match work_graph_event.event {
                        Some(work_graph_event::Event::Added(event)) => {
                            if hints.from_work_id.is_none() && !event.from_work_id.is_empty() {
                                hints.from_work_id = Some(event.from_work_id);
                            }
                            if hints.to_work_id.is_none() && !event.to_work_id.is_empty() {
                                hints.to_work_id = Some(event.to_work_id);
                            }
                        },
                        Some(work_graph_event::Event::Removed(event)) => {
                            if hints.from_work_id.is_none() && !event.from_work_id.is_empty() {
                                hints.from_work_id = Some(event.from_work_id);
                            }
                            if hints.to_work_id.is_none() && !event.to_work_id.is_empty() {
                                hints.to_work_id = Some(event.to_work_id);
                            }
                        },
                        Some(work_graph_event::Event::Waived(event)) => {
                            if hints.from_work_id.is_none() && !event.from_work_id.is_empty() {
                                hints.from_work_id = Some(event.from_work_id);
                            }
                            if hints.to_work_id.is_none() && !event.to_work_id.is_empty() {
                                hints.to_work_id = Some(event.to_work_id);
                            }
                        },
                        None => {},
                    }
                }
            },
            "session.started"
            | "session.progress"
            | "session.terminated"
            | "session.quarantined" => {
                if let Ok(session_event) = SessionEvent::decode(payload) {
                    let episode_id = match session_event.event {
                        Some(session_event::Event::Started(event)) => event.episode_id,
                        Some(session_event::Event::Progress(event)) => event.episode_id,
                        Some(session_event::Event::Terminated(event)) => event.episode_id,
                        Some(session_event::Event::Quarantined(event)) => event.episode_id,
                        Some(
                            session_event::Event::CrashDetected(_)
                            | session_event::Event::RestartScheduled(_),
                        )
                        | None => String::new(),
                    };
                    if hints.session_id.is_none() && !episode_id.is_empty() {
                        hints.session_id = Some(episode_id);
                    }
                }
            },
            "tool.requested" | "tool.decided" | "tool.executed" => {
                if let Ok(tool_event) = ToolEvent::decode(payload) {
                    let episode_id = match tool_event.event {
                        Some(tool_event::Event::Requested(event)) => event.episode_id,
                        Some(tool_event::Event::Decided(event)) => event.episode_id,
                        Some(tool_event::Event::Executed(event)) => event.episode_id,
                        None => String::new(),
                    };
                    if hints.session_id.is_none() && !episode_id.is_empty() {
                        hints.session_id = Some(episode_id);
                    }
                }
            },
            "io.artifact.published" => {
                if let Ok(io_artifact) = IoArtifactPublished::decode(payload)
                    && hints.session_id.is_none()
                    && !io_artifact.episode_id.is_empty()
                {
                    hints.session_id = Some(io_artifact.episode_id);
                }
            },
            _ => {},
        }
    }

    fn decode_hex_digest_bounded(value: &str) -> Option<Vec<u8>> {
        if value.is_empty() || value.len() > MAX_BRIDGE_ROUTING_HEX_CHARS || value.len() % 2 != 0 {
            return None;
        }
        hex::decode(value).ok()
    }

    fn is_work_scoped_event_type(normalized_event_type: &str) -> bool {
        matches!(
            normalized_event_type,
            "work.opened"
                | "work.transitioned"
                | "work.completed"
                | "work.aborted"
                | "work.pr_associated"
                | "evidence.published"
                | "policy.resolved_for_changeset"
                | "gate.receipt"
                | "work_graph.edge.added"
                | "work_graph.edge.removed"
                | "work_graph.edge.waived"
        )
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

    use apm2_core::events::{WorkEdgeAdded, WorkEdgeType, WorkGraphEvent, work_graph_event};
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

    fn decode_envelope_topic(frame: &Bytes) -> String {
        let event = PulseEvent::decode(&frame[1..]).expect("pulse frame must decode");
        event
            .envelope
            .expect("pulse event must include envelope")
            .topic
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

    #[tokio::test]
    async fn test_bridge_non_kernel_payload_routes_without_drop() {
        let (sender, receiver) = create_commit_notification_channel();
        let mock_ledger = Arc::new(MockLedgerBackend::new());
        let bridge_payload = serde_json::json!({
            "event_type": "work_transitioned",
            "work_id": "W-BRIDGE-001",
            "from_state": "OPEN",
            "to_state": "CLAIMED",
            "rationale_code": "bridge_test",
            "previous_transition_count": 0u32,
            "actor_id": "actor-bridge",
            "timestamp_ns": 42u64
        })
        .to_string()
        .into_bytes();
        let event_record = EventRecord::new(
            "work_transitioned",
            "W-BRIDGE-001",
            "actor-bridge",
            bridge_payload,
        );
        mock_ledger.events.lock().unwrap().insert(1, event_record);

        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));
        registry.register_connection("conn-bridge").unwrap();
        let sub = SubscriptionState::new(
            "sub-bridge",
            "client-sub-bridge",
            vec![test_pattern("work.W-BRIDGE-001.events")],
            0,
        );
        registry.add_subscription("conn-bridge", sub).unwrap();

        let mut publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            mock_ledger,
            Arc::clone(&registry),
        );
        let mock_sink = Arc::new(MockPulseFrameSink::new());
        publisher.register_connection("conn-bridge", mock_sink.clone());

        let notification = CommitNotification::new(1, [0x11; 32], "work_transitioned", "kernel");
        sender.send(notification).await.unwrap();

        let count = publisher.drain_batch(10).await;
        assert_eq!(count, 1);

        let frames = mock_sink.received_frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(
            decode_envelope_topic(&frames[0]),
            "work.W-BRIDGE-001.events"
        );
    }

    #[tokio::test]
    async fn test_bridge_payload_work_id_overrides_session_id_fallback() {
        let (sender, receiver) = create_commit_notification_channel();
        let mock_ledger = Arc::new(MockLedgerBackend::new());
        let bridge_payload = serde_json::json!({
            "event_type": "work_transitioned",
            "work_id": "W-BRIDGE-PAYLOAD",
            "from_state": "OPEN",
            "to_state": "CLAIMED"
        })
        .to_string()
        .into_bytes();
        // session_id intentionally differs from payload work_id.
        let event_record = EventRecord::new(
            "work_transitioned",
            "W-LEGACY-SESSION-ID",
            "actor-bridge",
            bridge_payload,
        );
        mock_ledger.events.lock().unwrap().insert(1, event_record);

        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));
        registry
            .register_connection("conn-bridge-priority")
            .unwrap();
        let sub = SubscriptionState::new(
            "sub-bridge-priority",
            "client-sub-bridge-priority",
            vec![
                test_pattern("work.W-BRIDGE-PAYLOAD.events"),
                test_pattern("work.W-LEGACY-SESSION-ID.events"),
            ],
            0,
        );
        registry
            .add_subscription("conn-bridge-priority", sub)
            .unwrap();

        let mut publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            mock_ledger,
            Arc::clone(&registry),
        );
        let mock_sink = Arc::new(MockPulseFrameSink::new());
        publisher.register_connection("conn-bridge-priority", mock_sink.clone());

        let notification = CommitNotification::new(1, [0x15; 32], "work_transitioned", "kernel");
        sender.send(notification).await.unwrap();

        let count = publisher.drain_batch(10).await;
        assert_eq!(count, 1);

        let frames = mock_sink.received_frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(
            decode_envelope_topic(&frames[0]),
            "work.W-BRIDGE-PAYLOAD.events"
        );
    }

    #[tokio::test]
    async fn test_bridge_raw_work_graph_payload_preserves_multi_topic_routing() {
        let (sender, receiver) = create_commit_notification_channel();
        let mock_ledger = Arc::new(MockLedgerBackend::new());
        let work_graph_event = WorkGraphEvent {
            event: Some(work_graph_event::Event::Added(WorkEdgeAdded {
                from_work_id: "W-FROM-BRIDGE".to_string(),
                to_work_id: "W-TO-BRIDGE".to_string(),
                edge_type: WorkEdgeType::Dependency as i32,
                rationale: "bridge".to_string(),
            })),
        };
        let event_record = EventRecord::new(
            "work_graph.edge.added",
            "kernel",
            "actor-bridge",
            work_graph_event.encode_to_vec(),
        );
        mock_ledger.events.lock().unwrap().insert(1, event_record);

        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));
        registry.register_connection("conn-graph").unwrap();
        let sub = SubscriptionState::new(
            "sub-graph",
            "client-sub-graph",
            vec![test_pattern("work_graph.*.edge")],
            0,
        );
        registry.add_subscription("conn-graph", sub).unwrap();

        let mut publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            mock_ledger,
            Arc::clone(&registry),
        );
        let mock_sink = Arc::new(MockPulseFrameSink::new());
        publisher.register_connection("conn-graph", mock_sink.clone());

        let notification =
            CommitNotification::new(1, [0x22; 32], "work_graph.edge.added", "kernel");
        sender.send(notification).await.unwrap();

        let count = publisher.drain_batch(10).await;
        assert_eq!(count, 1);

        let frames = mock_sink.received_frames();
        assert_eq!(frames.len(), 2);
        let topics: Vec<String> = frames.iter().map(decode_envelope_topic).collect();
        assert!(topics.contains(&"work_graph.W-FROM-BRIDGE.edge".to_string()));
        assert!(topics.contains(&"work_graph.W-TO-BRIDGE.edge".to_string()));
    }

    #[tokio::test]
    async fn test_malformed_bridge_payload_is_bounded_and_loop_continues() {
        let (sender, receiver) = create_commit_notification_channel();
        let mock_ledger = Arc::new(MockLedgerBackend::new());

        let oversized_payload = vec![0x41; MAX_BRIDGE_ROUTING_PAYLOAD_BYTES + 1];
        mock_ledger.events.lock().unwrap().insert(
            1,
            EventRecord::new(
                "work_transitioned",
                "W-MALFORMED-001",
                "actor-malformed",
                oversized_payload,
            ),
        );
        mock_ledger.events.lock().unwrap().insert(
            2,
            EventRecord::new(
                "LedgerEvent",
                "session-2",
                "actor-2",
                KernelEvent::default().encode_to_vec(),
            ),
        );

        let registry = Arc::new(SubscriptionRegistry::new(ResourceQuotaConfig::for_testing()));
        registry.register_connection("conn-bounded").unwrap();
        let sub = SubscriptionState::new(
            "sub-bounded",
            "client-sub-bounded",
            vec![test_pattern("ledger.head")],
            0,
        );
        registry.add_subscription("conn-bounded", sub).unwrap();

        let mut publisher = PulsePublisher::new(
            PulsePublisherConfig::for_testing(),
            receiver,
            mock_ledger,
            Arc::clone(&registry),
        );
        let mock_sink = Arc::new(MockPulseFrameSink::new());
        publisher.register_connection("conn-bounded", mock_sink.clone());

        sender
            .send(CommitNotification::new(
                1,
                [0x33; 32],
                "work_transitioned",
                "kernel",
            ))
            .await
            .unwrap();
        sender
            .send(CommitNotification::new(
                2,
                [0x44; 32],
                "LedgerEvent",
                "kernel",
            ))
            .await
            .unwrap();

        let count = publisher.drain_batch(10).await;
        assert_eq!(count, 2);

        let frames = mock_sink.received_frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(decode_envelope_topic(&frames[0]), "ledger.head");
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
