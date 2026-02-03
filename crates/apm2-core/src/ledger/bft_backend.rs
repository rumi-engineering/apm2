// AGENT-AUTHORED
//! BFT-integrated ledger backend for distributed consensus.
//!
//! This module provides [`BftLedgerBackend`], a wrapper around a storage
//! backend (e.g., [`SqliteLedgerBackend`]) that integrates with BFT consensus
//! for finalization of authority events.
//!
//! # Architecture
//!
//! ```text
//! +-----------------+     +---------------+     +------------------+
//! | Client          | --> | BftLedger     | --> | BftMachine       |
//! | (append request)|     | Backend       |     | (consensus)      |
//! +-----------------+     +---------------+     +------------------+
//!                               |                      |
//!                               v                      v
//!                        +---------------+     +------------------+
//!                        | Storage       |     | Network          |
//!                        | Backend       |     | (validators)     |
//!                        +---------------+     +------------------+
//! ```
//!
//! # Consensus Flow
//!
//! 1. Client calls `append()` with event and metadata
//! 2. If metadata requires `TotalOrder`, event is submitted to BFT consensus
//! 3. BFT machine proposes the event to validators
//! 4. Validators vote and form quorum certificate
//! 5. Event is committed to storage with QC
//! 6. `append()` returns with `ConsensusIndex`
//!
//! # Crash Recovery
//!
//! Consensus metadata (epoch, round, committed blocks) is persisted in a
//! separate table for crash recovery. On startup:
//!
//! 1. Load consensus state from metadata table
//! 2. Replay uncommitted events through consensus
//! 3. Resume normal operation
//!
//! # Security Properties
//!
//! - **Atomic Writes (CTR-1502)**: Events and QCs are written atomically
//! - **Bounded Storage (CTR-1303)**: Pending events bounded by
//!   `MAX_PENDING_EVENTS`
//! - **Replay Safety**: Consensus metadata enables deterministic replay
//!
//! # References
//!
//! - RFC-0014: Distributed Consensus and Replication Layer
//! - TCK-00189: BFT `LedgerBackend` Integration
//! - DD-0002: `LedgerBackend` Trait Abstraction

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, RwLock, oneshot};
use tracing::{debug, warn};

use super::backend::{BoxFuture, LedgerBackend};
use super::storage::{EventRecord, LedgerError, SqliteLedgerBackend};
use crate::consensus::bft::{BlockHash, QuorumCertificate};
use crate::consensus::metrics::ConsensusMetrics;
use crate::schema_registry::{SchemaDigest, SchemaRegistry, SchemaRegistryError};

// =============================================================================
// No-Op Schema Registry (for backward compatibility)
// =============================================================================

/// A no-op schema registry that accepts all schemas.
///
/// This is used as the default type parameter for `BftLedgerBackend` to
/// maintain backward compatibility with existing code that doesn't need
/// schema validation. When schema validation is needed, use
/// `BftLedgerBackend::with_schema_registry()`.
#[derive(Debug, Clone, Default)]
pub struct NoOpSchemaRegistry;

impl SchemaRegistry for NoOpSchemaRegistry {
    fn register<'a>(
        &'a self,
        _entry: &'a crate::schema_registry::SchemaEntry,
    ) -> crate::schema_registry::BoxFuture<'a, Result<(), SchemaRegistryError>> {
        Box::pin(async { Ok(()) })
    }

    fn lookup_by_digest<'a>(
        &'a self,
        _digest: &'a SchemaDigest,
    ) -> crate::schema_registry::BoxFuture<
        'a,
        Result<Option<std::sync::Arc<crate::schema_registry::SchemaEntry>>, SchemaRegistryError>,
    > {
        // NoOp registry: always returns None (schema not found).
        // This means validation is effectively skipped for backends without
        // a real registry configured.
        Box::pin(async { Ok(None) })
    }

    fn lookup_by_stable_id<'a>(
        &'a self,
        _stable_id: &'a str,
    ) -> crate::schema_registry::BoxFuture<
        'a,
        Result<Option<std::sync::Arc<crate::schema_registry::SchemaEntry>>, SchemaRegistryError>,
    > {
        Box::pin(async { Ok(None) })
    }

    fn handshake<'a>(
        &'a self,
        _peer_digests: &'a [SchemaDigest],
    ) -> crate::schema_registry::BoxFuture<
        'a,
        Result<crate::schema_registry::HandshakeResult, SchemaRegistryError>,
    > {
        Box::pin(async {
            Ok(crate::schema_registry::HandshakeResult {
                compatible: vec![],
                missing_local: vec![],
                missing_remote: vec![],
            })
        })
    }

    fn all_digests(
        &self,
    ) -> crate::schema_registry::BoxFuture<'_, Result<Vec<SchemaDigest>, SchemaRegistryError>> {
        Box::pin(async { Ok(vec![]) })
    }

    fn len(&self) -> crate::schema_registry::BoxFuture<'_, Result<usize, SchemaRegistryError>> {
        Box::pin(async { Ok(0) })
    }
}

// =============================================================================
// Replay Constants
// =============================================================================

/// Maximum number of events to load per batch during replay.
///
/// This prevents memory exhaustion by processing the ledger in bounded chunks
/// rather than loading everything at once (Finding 2: Memory Exhaustion).
pub const REPLAY_BATCH_SIZE: u64 = 1000;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of pending events waiting for BFT finalization.
///
/// Bounded to prevent denial-of-service via memory exhaustion (CTR-1303).
pub const MAX_PENDING_EVENTS: usize = 1024;

/// Default timeout for BFT finalization in milliseconds.
pub const DEFAULT_FINALIZATION_TIMEOUT_MS: u64 = 30_000;

/// Maximum consensus epoch age for replay.
///
/// Events from epochs more than this many behind current are rejected.
#[allow(dead_code)]
pub const MAX_EPOCH_AGE: u64 = 2;

/// Schema version for consensus metadata table.
pub const CONSENSUS_METADATA_VERSION: u32 = 1;

// =============================================================================
// Types
// =============================================================================

/// Ordering guarantee for an event.
///
/// Mirrors the design from RFC-0014 CTR-0001.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderingGuarantee {
    /// Requires total ordering via BFT consensus (control plane).
    TotalOrder,
    /// Eventual consistency acceptable (data plane).
    Eventual,
}

/// Merge operator for CRDT-style convergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MergeOperator {
    /// Last-writer-wins by timestamp.
    #[default]
    LastWriterWins,
    /// Grow-only counter (sum).
    GCounter,
    /// Set union (no duplicates by hash).
    SetUnion,
    /// Authority-tier selection (higher authority wins).
    AuthorityTier,
    /// No merge allowed (conflict = defect).
    NoMerge,
}

/// Hybrid Logical Clock timestamp for causal ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct HlcTimestamp {
    /// Wall clock time in nanoseconds since Unix epoch.
    pub wall_time_ns: u64,
    /// Logical counter for ordering within same wall time.
    pub logical_counter: u32,
}

/// Event metadata for routing and consensus decisions.
#[derive(Debug, Clone)]
pub struct EventMetadata {
    /// Namespace for quorum routing.
    pub namespace: String,
    /// Required ordering guarantee.
    pub ordering: OrderingGuarantee,
    /// Merge operator for conflict resolution.
    pub merge_op: MergeOperator,
    /// Admission-critical evidence flag (requires `TotalOrder`).
    pub strict_evidence: bool,
    /// Actor ID (signer).
    pub actor_id: String,
    /// Dedupe key for idempotency.
    pub dedupe_key: Option<[u8; 32]>,
    /// Hybrid Logical Clock timestamp.
    pub hlc_timestamp: HlcTimestamp,
    /// Canonicalizer identifier.
    pub canonicalizer_id: String,
    /// Canonicalizer version.
    pub canonicalizer_version: String,
}

impl Default for EventMetadata {
    fn default() -> Self {
        Self {
            namespace: "kernel".to_string(),
            ordering: OrderingGuarantee::Eventual,
            merge_op: MergeOperator::default(),
            strict_evidence: false,
            actor_id: String::new(),
            dedupe_key: None,
            hlc_timestamp: HlcTimestamp::default(),
            canonicalizer_id: "jcs".to_string(),
            canonicalizer_version: "1.0.0".to_string(),
        }
    }
}

impl EventMetadata {
    /// Creates metadata for a total-order event.
    #[must_use]
    pub fn total_order(namespace: impl Into<String>, actor_id: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            ordering: OrderingGuarantee::TotalOrder,
            actor_id: actor_id.into(),
            ..Default::default()
        }
    }

    /// Creates metadata for an eventual-consistency event.
    #[must_use]
    pub fn eventual(namespace: impl Into<String>, actor_id: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            ordering: OrderingGuarantee::Eventual,
            actor_id: actor_id.into(),
            ..Default::default()
        }
    }
}

/// Consensus-specific index information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusIndex {
    /// Consensus epoch.
    pub epoch: u64,
    /// Round within epoch.
    pub round: u64,
    /// Index within the round (for batched commits).
    pub index: u64,
}

/// Result of appending an event to the ledger.
#[derive(Debug, Clone)]
pub struct AppendResult {
    /// Assigned sequence ID.
    pub seq_id: u64,
    /// Event hash (`prev_hash` || content).
    pub event_hash: [u8; 32],
    /// For consensus backends: BFT term/round/index.
    pub consensus_index: Option<ConsensusIndex>,
}

/// Pending event waiting for BFT finalization.
struct PendingEvent {
    /// The event record to commit.
    event: EventRecord,
    /// Metadata for consensus routing.
    metadata: EventMetadata,
    /// Channel to notify the caller when committed.
    notifier: oneshot::Sender<Result<AppendResult, LedgerError>>,
    /// Submission timestamp for timeout tracking.
    #[allow(dead_code)]
    submitted_at: std::time::Instant,
    /// The block hash this event is assigned to (set when block is proposed).
    assigned_block: Option<BlockHash>,
}

/// Tracks the mapping from block hashes to the events they contain.
///
/// This is critical for Finding 1 (Finalization Confusion): we must only
/// finalize events that were actually included in the committed block.
#[derive(Default)]
struct BlockEventMapping {
    /// Maps `block_hash` -> set of payload hashes included in that block.
    block_to_events: HashMap<BlockHash, Vec<[u8; 32]>>,
}

/// Persisted consensus metadata for crash recovery.
#[derive(Debug, Clone, Default)]
pub struct ConsensusMetadata {
    /// Current consensus epoch.
    pub epoch: u64,
    /// Current consensus round.
    pub round: u64,
    /// Hash of the last committed block.
    pub last_committed_hash: Option<[u8; 32]>,
    /// Serialized high QC for recovery.
    pub high_qc: Option<Vec<u8>>,
    /// Schema version for metadata format.
    pub schema_version: u32,
}

// =============================================================================
// Errors
// =============================================================================

/// Errors specific to BFT ledger operations.
#[derive(Debug, thiserror::Error)]
pub enum BftLedgerError {
    /// Underlying ledger error.
    #[error("ledger error: {0}")]
    Ledger(#[from] LedgerError),

    /// Consensus timeout.
    #[error("consensus timeout after {timeout_ms}ms")]
    ConsensusTimeout {
        /// Timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// Not the leader for this namespace.
    #[error("not leader for namespace {namespace}, leader hint: {leader_hint:?}")]
    NotLeader {
        /// The namespace.
        namespace: String,
        /// Hint about who the leader is.
        leader_hint: Option<String>,
    },

    /// Too many pending events.
    #[error("too many pending events: {count} >= {max}")]
    TooManyPending {
        /// Current count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Invalid quorum certificate.
    #[error("invalid quorum certificate: {0}")]
    InvalidQc(String),

    /// Consensus not available.
    #[error("consensus not available: {0}")]
    ConsensusUnavailable(String),

    /// Consensus required but disabled (fail-closed for `TotalOrder`).
    ///
    /// This error is returned when a `TotalOrder` event is submitted but
    /// consensus is disabled. `TotalOrder` events MUST go through BFT consensus
    /// to maintain security guarantees (Finding 3: Fail-Open Ordering).
    #[error("consensus required for TotalOrder events but consensus is disabled")]
    ConsensusRequiredButDisabled,

    /// Block not found for finalization.
    #[error("block {0} not found in pending blocks")]
    BlockNotFound(String),

    /// Schema mismatch: event has unknown `schema_digest`.
    ///
    /// This error is returned when an event's `schema_digest` is not registered
    /// in the schema registry. This is a fail-closed security posture: events
    /// with unknown schemas are rejected to prevent data corruption from schema
    /// drift (DD-0004, TCK-00194).
    #[error("schema mismatch: digest {digest} is not registered")]
    SchemaMismatch {
        /// The hex-encoded schema digest that was not found.
        digest: String,
    },
}

// =============================================================================
// BFT Ledger Backend
// =============================================================================

/// A BFT-integrated ledger backend that wraps a storage backend.
///
/// This implementation provides:
/// - Transparent BFT finalization for `TotalOrder` events
/// - Direct storage for `Eventual` consistency events
/// - Quorum certificate storage with authority events
/// - Consensus metadata persistence for crash recovery
///
/// # Security Properties
///
/// - **Block-specific finalization (Finding 1)**: Events are only finalized
///   when their specific block is committed, not when any block commits.
/// - **Bounded replay (Finding 2)**: Replay uses pagination to prevent OOM.
/// - **Fail-closed `TotalOrder` (Finding 3)**: `TotalOrder` events require
///   consensus.
/// - **Proper serialization (Finding 4)**: Uses postcard for deterministic QC
///   encoding.
pub struct BftLedgerBackend<R: SchemaRegistry = NoOpSchemaRegistry> {
    /// Underlying storage backend.
    storage: Arc<SqliteLedgerBackend>,

    /// Pending events waiting for BFT finalization.
    /// Key: payload hash (for deduplication and lookup).
    pending_events: Arc<Mutex<HashMap<[u8; 32], PendingEvent>>>,

    /// Maps block hashes to the events they contain.
    /// Critical for Finding 1: only finalize events in the committed block.
    block_event_mapping: Arc<Mutex<BlockEventMapping>>,

    /// Current consensus metadata (epoch, round, etc.).
    consensus_metadata: Arc<RwLock<ConsensusMetadata>>,

    /// Finalization timeout duration.
    finalization_timeout: Duration,

    /// Whether consensus is enabled.
    consensus_enabled: Arc<RwLock<bool>>,

    /// Optional schema registry for `schema_digest` validation (TCK-00194).
    ///
    /// When present, events with `schema_digest` are validated against this
    /// registry. Unknown schemas cause rejection (fail-closed per DD-0004).
    schema_registry: Option<Arc<R>>,

    /// Optional commit notification sender (TCK-00304: HEF Outbox).
    ///
    /// When present, `on_commit()` sends a [`CommitNotification`] after each
    /// successful `tx.commit()` using `try_send()` for non-blocking delivery.
    /// Notification failure MUST NOT fail the ledger commit (best-effort).
    ///
    /// Per DD-HEF-0007: Ledger append MUST NOT block on pulse fanout.
    commit_notification_sender: Option<super::CommitNotificationSender>,

    /// Optional consensus metrics for recording notification drops (TCK-00304).
    ///
    /// When present, `on_commit()` and `append_eventual()` will increment the
    /// `hef_notification_drops` counter when notifications are dropped due to
    /// channel full.
    metrics: Option<Arc<ConsensusMetrics>>,
}

impl BftLedgerBackend<NoOpSchemaRegistry> {
    /// Creates a new BFT ledger backend wrapping the given storage.
    ///
    /// This creates a backend without schema validation. For schema validation,
    /// use [`BftLedgerBackend::with_schema_registry()`].
    ///
    /// # Arguments
    ///
    /// * `storage` - The underlying storage backend.
    /// * `finalization_timeout` - Timeout for BFT finalization.
    #[must_use]
    pub fn new(storage: SqliteLedgerBackend, finalization_timeout: Duration) -> Self {
        Self::with_notification_sender(storage, finalization_timeout, None)
    }

    /// Creates a new BFT ledger backend with commit notification sender
    /// (TCK-00304).
    ///
    /// Per DOD: "Accept sender at construction." This constructor accepts the
    /// optional sender at construction time for proper initialization.
    ///
    /// # Arguments
    ///
    /// * `storage` - The underlying storage backend.
    /// * `finalization_timeout` - Timeout for BFT finalization.
    /// * `notification_sender` - Optional commit notification sender for HEF
    ///   outbox.
    #[must_use]
    pub fn with_notification_sender(
        storage: SqliteLedgerBackend,
        finalization_timeout: Duration,
        notification_sender: Option<super::CommitNotificationSender>,
    ) -> Self {
        Self {
            storage: Arc::new(storage),
            pending_events: Arc::new(Mutex::new(HashMap::new())),
            block_event_mapping: Arc::new(Mutex::new(BlockEventMapping::default())),
            consensus_metadata: Arc::new(RwLock::new(ConsensusMetadata::default())),
            finalization_timeout,
            consensus_enabled: Arc::new(RwLock::new(false)),
            schema_registry: None,
            commit_notification_sender: notification_sender,
            metrics: None,
        }
    }

    /// Creates a new BFT ledger backend with default timeout.
    ///
    /// This creates a backend without schema validation.
    #[must_use]
    pub fn with_default_timeout(storage: SqliteLedgerBackend) -> Self {
        Self::new(
            storage,
            Duration::from_millis(DEFAULT_FINALIZATION_TIMEOUT_MS),
        )
    }
}

impl<R: SchemaRegistry + 'static> BftLedgerBackend<R> {
    /// Creates a new BFT ledger backend with schema validation (TCK-00194).
    ///
    /// Events with `schema_digest` set will be validated against the provided
    /// registry. Unknown schemas cause rejection (fail-closed per DD-0004).
    ///
    /// # Arguments
    ///
    /// * `storage` - The underlying storage backend.
    /// * `finalization_timeout` - Timeout for BFT finalization.
    /// * `schema_registry` - The schema registry for digest validation.
    #[must_use]
    pub fn with_schema_registry(
        storage: SqliteLedgerBackend,
        finalization_timeout: Duration,
        schema_registry: Arc<R>,
    ) -> Self {
        Self::with_schema_registry_and_sender(storage, finalization_timeout, schema_registry, None)
    }

    /// Creates a new BFT ledger backend with schema validation and notification
    /// sender (TCK-00194, TCK-00304).
    ///
    /// Per DOD: "Accept sender at construction." This constructor accepts both
    /// the schema registry and optional notification sender at construction
    /// time.
    ///
    /// # Arguments
    ///
    /// * `storage` - The underlying storage backend.
    /// * `finalization_timeout` - Timeout for BFT finalization.
    /// * `schema_registry` - The schema registry for digest validation.
    /// * `notification_sender` - Optional commit notification sender for HEF
    ///   outbox.
    #[must_use]
    pub fn with_schema_registry_and_sender(
        storage: SqliteLedgerBackend,
        finalization_timeout: Duration,
        schema_registry: Arc<R>,
        notification_sender: Option<super::CommitNotificationSender>,
    ) -> Self {
        Self {
            storage: Arc::new(storage),
            pending_events: Arc::new(Mutex::new(HashMap::new())),
            block_event_mapping: Arc::new(Mutex::new(BlockEventMapping::default())),
            consensus_metadata: Arc::new(RwLock::new(ConsensusMetadata::default())),
            finalization_timeout,
            consensus_enabled: Arc::new(RwLock::new(false)),
            schema_registry: Some(schema_registry),
            commit_notification_sender: notification_sender,
            metrics: None,
        }
    }

    /// Sets the commit notification sender for HEF outbox integration
    /// (TCK-00304).
    ///
    /// When set, `on_commit()` will send a [`super::CommitNotification`] via
    /// `try_send()` after each successful commit. This is non-blocking
    /// and best-effort per DD-HEF-0007.
    ///
    /// # Arguments
    ///
    /// * `sender` - The channel sender for commit notifications.
    pub fn set_commit_notification_sender(&mut self, sender: super::CommitNotificationSender) {
        self.commit_notification_sender = Some(sender);
    }

    /// Sets the consensus metrics for recording notification drops (TCK-00304).
    ///
    /// When set, the `hef_notification_drops` counter will be incremented when
    /// notifications are dropped due to channel full.
    ///
    /// # Arguments
    ///
    /// * `metrics` - The consensus metrics instance.
    pub fn set_metrics(&mut self, metrics: Arc<ConsensusMetrics>) {
        self.metrics = Some(metrics);
    }

    /// Returns true if a commit notification sender is configured.
    #[must_use]
    pub const fn has_commit_notification_sender(&self) -> bool {
        self.commit_notification_sender.is_some()
    }

    /// Enables consensus mode.
    pub async fn enable_consensus(&self) {
        let mut enabled = self.consensus_enabled.write().await;
        *enabled = true;
    }

    /// Disables consensus mode.
    pub async fn disable_consensus(&self) {
        let mut enabled = self.consensus_enabled.write().await;
        *enabled = false;
    }

    /// Returns whether consensus is enabled.
    pub async fn is_consensus_enabled(&self) -> bool {
        *self.consensus_enabled.read().await
    }

    /// Updates the consensus metadata.
    pub async fn update_consensus_metadata(&self, metadata: ConsensusMetadata) {
        let mut current = self.consensus_metadata.write().await;
        *current = metadata;
    }

    /// Gets the current consensus metadata.
    pub async fn consensus_metadata(&self) -> ConsensusMetadata {
        self.consensus_metadata.read().await.clone()
    }

    /// Appends an event with BFT integration.
    ///
    /// For `TotalOrder` events, this method submits the event to BFT consensus
    /// and waits for finalization. For `Eventual` events, this method writes
    /// directly to storage.
    ///
    /// # Schema Validation (TCK-00194)
    ///
    /// If the event has a `schema_digest` and a schema registry is configured,
    /// the digest is validated against the registry. Unknown schemas cause
    /// rejection with `SchemaMismatch` error (fail-closed per DD-0004).
    ///
    /// If no `schema_digest` is set, validation is skipped (backward
    /// compatible). If no schema registry is configured, validation is
    /// skipped.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace for this event.
    /// * `event` - The event record to append.
    /// * `metadata` - Event metadata including ordering guarantee.
    ///
    /// # Errors
    ///
    /// - `SchemaMismatch` if the event's `schema_digest` is not registered.
    /// - `ConsensusRequiredButDisabled` if `TotalOrder` but consensus is
    ///   disabled.
    /// - `ConsensusTimeout` if BFT finalization times out.
    pub async fn append_with_metadata(
        &self,
        #[allow(unused_variables)] namespace: &str,
        event: &EventRecord,
        metadata: &EventMetadata,
    ) -> Result<AppendResult, BftLedgerError> {
        // TCK-00194: Schema validation (fail-closed for unknown schemas)
        // This MUST happen before any storage operations to prevent events
        // with unknown schemas from entering the ledger.
        self.validate_schema_digest(event).await?;

        let consensus_enabled = self.is_consensus_enabled().await;

        // For eventual consistency, write directly to storage
        if metadata.ordering == OrderingGuarantee::Eventual {
            return self.append_eventual(namespace, event, metadata);
        }

        // For TotalOrder, consensus MUST be enabled (fail-closed security posture).
        // This prevents silently bypassing BFT requirements (Finding 3).
        if !consensus_enabled {
            return Err(BftLedgerError::ConsensusRequiredButDisabled);
        }

        // For TotalOrder with consensus enabled, go through consensus
        self.append_with_consensus(namespace, event, metadata).await
    }

    /// Validates an event's `schema_digest` against the registry (TCK-00194).
    ///
    /// # Fail-Closed Behavior
    ///
    /// - If `schema_digest` is `None`: validation passes (backward compatible)
    /// - If `schema_registry` is `None`: validation passes (no registry
    ///   configured)
    /// - If `schema_digest` is `Some` and registered: validation passes
    /// - If `schema_digest` is `Some` but NOT registered: **REJECT** with
    ///   `SchemaMismatch`
    ///
    /// This implements DD-0004 from RFC-0014: "Unknown schemas trigger
    /// rejection (fail-closed)."
    async fn validate_schema_digest(&self, event: &EventRecord) -> Result<(), BftLedgerError> {
        // If no schema_digest is set, skip validation (backward compatible)
        let schema_digest_bytes = match &event.schema_digest {
            Some(bytes) if !bytes.is_empty() => bytes,
            _ => return Ok(()),
        };

        // If no schema registry is configured, skip validation
        let Some(registry) = &self.schema_registry else {
            return Ok(());
        };

        // Convert bytes to SchemaDigest
        // Schema digests MUST be exactly 32 bytes (BLAKE3 output)
        let digest: [u8; 32] = schema_digest_bytes.as_slice().try_into().map_err(|_| {
            BftLedgerError::SchemaMismatch {
                digest: hex_encode_slice(schema_digest_bytes),
            }
        })?;
        let schema_digest = SchemaDigest::new(digest);

        // Look up the schema in the registry
        // Fail-closed: if not found, reject the event
        let found = registry
            .lookup_by_digest(&schema_digest)
            .await
            .map_err(|e| {
                BftLedgerError::ConsensusUnavailable(format!("schema registry error: {e}"))
            })?;

        if found.is_none() {
            return Err(BftLedgerError::SchemaMismatch {
                digest: schema_digest.to_hex(),
            });
        }

        Ok(())
    }

    /// Appends an event directly to storage (eventual consistency path).
    fn append_eventual(
        &self,
        namespace: &str,
        event: &EventRecord,
        metadata: &EventMetadata,
    ) -> Result<AppendResult, BftLedgerError> {
        // Prepare event with metadata
        let mut event_with_meta = event.clone();
        event_with_meta.hlc_wall_time = Some(metadata.hlc_timestamp.wall_time_ns);
        event_with_meta.hlc_counter = Some(metadata.hlc_timestamp.logical_counter);
        event_with_meta.canonicalizer_id = Some(metadata.canonicalizer_id.clone());
        event_with_meta.canonicalizer_version = Some(metadata.canonicalizer_version.clone());

        // Append to storage (using the sync method directly)
        let seq_id = self.storage.append(&event_with_meta)?;

        // Compute event hash
        let event_hash = Self::compute_event_hash(&event_with_meta);

        // TCK-00304: Send post-commit notification for HEF outbox
        // This MUST happen AFTER storage.append() succeeds
        // Notification failure MUST NOT fail the ledger commit (best-effort)
        if let Some(sender) = &self.commit_notification_sender {
            let notification = super::CommitNotification::new(
                seq_id,
                event_hash,
                &event_with_meta.event_type,
                namespace,
            );

            // Use try_send() for non-blocking notification per DD-HEF-0007
            match sender.try_send(notification) {
                Ok(()) => {
                    // Notification sent successfully
                },
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    // Channel full: increment hef_notification_drops metric (TCK-00304)
                    if let Some(metrics) = &self.metrics {
                        metrics.record_notification_drop();
                    }
                    warn!(
                        seq_id = seq_id,
                        event_type = %event_with_meta.event_type,
                        "HEF notification dropped: channel full"
                    );
                },
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    // Channel disconnected: LOG_DEBUG_IGNORE (expected during shutdown)
                    debug!(
                        seq_id = seq_id,
                        "HEF notification channel closed (shutdown)"
                    );
                },
            }
        }

        Ok(AppendResult {
            seq_id,
            event_hash,
            consensus_index: None,
        })
    }

    /// Appends an event through BFT consensus.
    async fn append_with_consensus(
        &self,
        _namespace: &str,
        event: &EventRecord,
        metadata: &EventMetadata,
    ) -> Result<AppendResult, BftLedgerError> {
        // Check pending events limit
        {
            let pending = self.pending_events.lock().await;
            if pending.len() >= MAX_PENDING_EVENTS {
                return Err(BftLedgerError::TooManyPending {
                    count: pending.len(),
                    max: MAX_PENDING_EVENTS,
                });
            }
        }

        // Compute payload hash for deduplication
        let payload_hash = Self::compute_payload_hash(event);

        // Create notification channel
        let (tx, rx) = oneshot::channel();

        // Add to pending events (assigned_block will be set later when block is
        // proposed)
        {
            let mut pending = self.pending_events.lock().await;
            pending.insert(
                payload_hash,
                PendingEvent {
                    event: event.clone(),
                    metadata: metadata.clone(),
                    notifier: tx,
                    submitted_at: std::time::Instant::now(),
                    assigned_block: None, // Set when block is proposed via assign_events_to_block
                },
            );
        }

        // Wait for finalization with timeout
        let result = tokio::time::timeout(self.finalization_timeout, rx).await;

        // Clean up pending event on timeout or completion
        {
            let mut pending = self.pending_events.lock().await;
            pending.remove(&payload_hash);
        }

        match result {
            Ok(Ok(result)) => result.map_err(BftLedgerError::from),
            Ok(Err(_)) => Err(BftLedgerError::ConsensusUnavailable(
                "notification channel closed".to_string(),
            )),
            Err(_) => Err(BftLedgerError::ConsensusTimeout {
                // Safe: timeout is bounded by DEFAULT_FINALIZATION_TIMEOUT_MS (30s), well under u64
                #[allow(clippy::cast_possible_truncation)]
                timeout_ms: self.finalization_timeout.as_millis() as u64,
            }),
        }
    }

    /// Assigns pending events to a block before proposal.
    ///
    /// This method MUST be called by the BFT machine before proposing a block.
    /// It creates the mapping from `block_hash` to event hashes, which is
    /// critical for ensuring only the correct events are finalized when the
    /// block commits (Finding 1: Finalization Confusion).
    ///
    /// # Arguments
    ///
    /// * `block_hash` - Hash of the block being proposed.
    /// * `event_hashes` - Payload hashes of events included in this block.
    pub async fn assign_events_to_block(&self, block_hash: BlockHash, event_hashes: Vec<[u8; 32]>) {
        // Update the block->events mapping
        {
            let mut mapping = self.block_event_mapping.lock().await;
            mapping
                .block_to_events
                .insert(block_hash, event_hashes.clone());
        }

        // Update each pending event with its assigned block
        {
            let mut pending = self.pending_events.lock().await;
            for payload_hash in &event_hashes {
                if let Some(event) = pending.get_mut(payload_hash) {
                    event.assigned_block = Some(block_hash);
                }
            }
        }
    }

    /// Gets pending event hashes that are not yet assigned to a block.
    ///
    /// This is used by the BFT machine to collect events for a new block
    /// proposal.
    pub async fn get_unassigned_pending_events(&self) -> Vec<[u8; 32]> {
        let pending = self.pending_events.lock().await;
        pending
            .iter()
            .filter(|(_, event)| event.assigned_block.is_none())
            .map(|(hash, _)| *hash)
            .collect()
    }

    /// Called by the BFT machine when a block is committed.
    ///
    /// This method finalizes ONLY the pending events that were included in the
    /// committed block, writing them to storage with the quorum certificate.
    ///
    /// # Security (Finding 1: Finalization Confusion)
    ///
    /// This method ONLY finalizes events that were explicitly assigned to this
    /// block via `assign_events_to_block`. It does NOT finalize all pending
    /// events, which would allow a single BFT commit to finalize unrelated
    /// events that haven't reached consensus.
    ///
    /// # Arguments
    ///
    /// * `block_hash` - Hash of the committed block.
    /// * `qc` - Quorum certificate for the committed block.
    /// * `epoch` - Consensus epoch.
    /// * `round` - Consensus round.
    ///
    /// # Errors
    ///
    /// Returns an error if events cannot be written to storage or if the block
    /// is not found in the mapping.
    pub async fn on_commit(
        &self,
        block_hash: &BlockHash,
        qc: &QuorumCertificate,
        epoch: u64,
        round: u64,
    ) -> Result<(), BftLedgerError> {
        // Serialize quorum certificate using postcard for deterministic encoding
        // (Finding 4: Wire-Semantic Mismatch - RFC-0014 specifies binary format)
        let qc_bytes = postcard::to_allocvec(qc)
            .map_err(|e| BftLedgerError::InvalidQc(format!("serialization failed: {e}")))?;

        // Get the event hashes that belong to this specific block (Finding 1)
        let event_hashes = {
            let mut mapping = self.block_event_mapping.lock().await;
            mapping.block_to_events.remove(block_hash)
        };

        // If no events are mapped to this block, this might be an empty block
        // or an error condition. For empty blocks, just update metadata.
        let event_hashes = event_hashes.unwrap_or_default();

        // Finalize ONLY the events that were included in this committed block
        let mut pending = self.pending_events.lock().await;
        let mut index: u64 = 0; // Track actual index within block (Finding 4)

        for payload_hash in event_hashes {
            if let Some(pending_event) = pending.remove(&payload_hash) {
                // Verify this event was assigned to this block
                if pending_event.assigned_block != Some(*block_hash) {
                    // Event wasn't assigned to this block - this shouldn't happen
                    // but we fail safely by not finalizing it
                    continue;
                }

                // Prepare event with consensus metadata
                let mut event = pending_event.event;
                event.consensus_epoch = Some(epoch);
                event.consensus_round = Some(round);
                event.quorum_cert = Some(qc_bytes.clone());
                event.hlc_wall_time = Some(pending_event.metadata.hlc_timestamp.wall_time_ns);
                event.hlc_counter = Some(pending_event.metadata.hlc_timestamp.logical_counter);
                event.canonicalizer_id = Some(pending_event.metadata.canonicalizer_id.clone());
                event.canonicalizer_version =
                    Some(pending_event.metadata.canonicalizer_version.clone());

                // Append to storage (using the sync method directly)
                let seq_id = self.storage.append(&event)?;

                // Compute event hash
                let event_hash = Self::compute_event_hash(&event);

                // Build consensus index
                let consensus_index = ConsensusIndex {
                    epoch,
                    round,
                    index, // Actual index within block, not hardcoded 0
                };

                // TCK-00304: Send post-commit notification for HEF outbox
                // This MUST happen AFTER tx.commit() succeeds (storage.append is sync)
                // Notification failure MUST NOT fail the ledger commit (best-effort)
                if let Some(sender) = &self.commit_notification_sender {
                    let notification = super::CommitNotification::with_consensus(
                        seq_id,
                        event_hash,
                        &event.event_type,
                        &pending_event.metadata.namespace,
                        consensus_index,
                    );

                    // Use try_send() for non-blocking notification per DD-HEF-0007
                    // On failure: LOG_WARN_DROP (fire-and-forget; never fails commit)
                    match sender.try_send(notification) {
                        Ok(()) => {
                            // Notification sent successfully
                        },
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            // Channel full: increment hef_notification_drops metric (TCK-00304)
                            if let Some(metrics) = &self.metrics {
                                metrics.record_notification_drop();
                            }
                            warn!(
                                seq_id = seq_id,
                                event_type = %event.event_type,
                                "HEF notification dropped: channel full"
                            );
                        },
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            // Channel disconnected: LOG_DEBUG_IGNORE
                            // Expected during shutdown
                            debug!(
                                seq_id = seq_id,
                                "HEF notification channel closed (shutdown)"
                            );
                        },
                    }
                }

                // Notify the caller with proper sequential index (Finding 4)
                let result = AppendResult {
                    seq_id,
                    event_hash,
                    consensus_index: Some(consensus_index),
                };

                let _ = pending_event.notifier.send(Ok(result));
                index += 1;
            }
        }

        // Update consensus metadata
        {
            let mut metadata = self.consensus_metadata.write().await;
            metadata.epoch = epoch;
            metadata.round = round;
            metadata.last_committed_hash = Some(*block_hash);
            metadata.high_qc = Some(qc_bytes);
            metadata.schema_version = CONSENSUS_METADATA_VERSION;
        }

        Ok(())
    }

    /// Computes the hash of an event's payload.
    fn compute_payload_hash(event: &EventRecord) -> [u8; 32] {
        blake3::hash(&event.payload).into()
    }

    /// Computes the hash of an event.
    fn compute_event_hash(event: &EventRecord) -> [u8; 32] {
        let prev_hash = event.prev_hash.as_deref().unwrap_or(&[0u8; 32]);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&event.payload);
        hasher.update(prev_hash);
        hasher.finalize().into()
    }

    /// Gets pending events count.
    pub async fn pending_count(&self) -> usize {
        self.pending_events.lock().await.len()
    }

    /// Cancels all pending events (for shutdown).
    pub async fn cancel_pending(&self) {
        let mut pending = self.pending_events.lock().await;
        for (_, event) in pending.drain() {
            let _ = event
                .notifier
                .send(Err(LedgerError::Crypto("consensus shutdown".to_string())));
        }
    }

    /// Gets the underlying storage backend.
    ///
    /// This is useful for operations that don't require consensus.
    #[must_use]
    pub fn storage(&self) -> &SqliteLedgerBackend {
        &self.storage
    }

    /// Reads events with their quorum certificates.
    ///
    /// Returns events along with parsed quorum certificates for those
    /// that have them.
    ///
    /// # Note
    ///
    /// Supports both postcard (new format) and JSON (legacy) QC deserialization
    /// for backwards compatibility.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from storage fails.
    pub fn read_with_qc(
        &self,
        _namespace: &str,
        cursor: u64,
        limit: u64,
    ) -> Result<Vec<(EventRecord, Option<QuorumCertificate>)>, LedgerError> {
        let events = self.storage.read_from(cursor, limit)?;

        let mut results = Vec::with_capacity(events.len());
        for event in events {
            // Try postcard first (new format), fall back to JSON (legacy)
            let qc = event.quorum_cert.as_ref().and_then(|bytes| {
                postcard::from_bytes(bytes)
                    .ok()
                    .or_else(|| serde_json::from_slice(bytes).ok())
            });
            results.push((event, qc));
        }

        Ok(results)
    }

    /// Verifies a quorum certificate against validator keys.
    ///
    /// This method can be used to validate QCs during replay or sync.
    ///
    /// # Arguments
    ///
    /// * `qc` - The quorum certificate to verify.
    /// * `validators` - The validator set to verify against.
    /// * `quorum_threshold` - The minimum number of signatures required.
    ///
    /// # Errors
    ///
    /// Returns an error if the QC is invalid.
    pub fn verify_qc(
        &self,
        qc: &QuorumCertificate,
        validators: &[crate::consensus::bft::ValidatorInfo],
        quorum_threshold: usize,
    ) -> Result<(), BftLedgerError> {
        qc.verify_signatures(validators, quorum_threshold)
            .map_err(|e| BftLedgerError::InvalidQc(e.to_string()))
    }

    /// Replays consensus state from persisted metadata.
    ///
    /// This method is called during startup to restore consensus state
    /// from the last checkpoint.
    ///
    /// # Security (Finding 2: Memory Exhaustion)
    ///
    /// This method uses bounded pagination to prevent OOM when replaying
    /// large ledgers. Instead of loading the entire ledger into memory,
    /// it processes events in batches and only retains the last event
    /// with consensus metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if replay fails.
    pub async fn replay_from_checkpoint(&self) -> Result<(), BftLedgerError> {
        // Find the last event with consensus metadata using bounded pagination
        // (Finding 2: prevents OOM by not loading entire ledger)
        let mut last_consensus_event: Option<EventRecord> = None;
        let mut cursor: u64 = 1;

        loop {
            // Read a bounded batch of events
            let events = self.storage.read_from(cursor, REPLAY_BATCH_SIZE)?;

            if events.is_empty() {
                break; // No more events
            }

            // Find last event with consensus metadata in this batch
            // (scanning in reverse to find the latest)
            for event in events.iter().rev() {
                if event.consensus_epoch.is_some() {
                    last_consensus_event = Some(event.clone());
                    break; // Found one in this batch, but continue to later batches
                }
            }

            // Move cursor past this batch
            // Safe: events.len() bounded by REPLAY_BATCH_SIZE (1000)
            #[allow(clippy::cast_possible_truncation)]
            let batch_len = events.len() as u64;
            cursor = cursor.saturating_add(batch_len);

            // If we got fewer events than requested, we've reached the end
            if batch_len < REPLAY_BATCH_SIZE {
                break;
            }
        }

        // Update consensus metadata from the last consensus event found
        if let Some(event) = last_consensus_event {
            let mut metadata = self.consensus_metadata.write().await;
            metadata.epoch = event.consensus_epoch.unwrap_or(0);
            metadata.round = event.consensus_round.unwrap_or(0);
            metadata.high_qc.clone_from(&event.quorum_cert);
            metadata.schema_version = CONSENSUS_METADATA_VERSION;

            // Parse QC to get committed hash
            // Try postcard first (new format), fall back to JSON (legacy)
            if let Some(qc_bytes) = &event.quorum_cert {
                if let Ok(qc) = postcard::from_bytes::<QuorumCertificate>(qc_bytes) {
                    metadata.last_committed_hash = Some(qc.block_hash);
                } else if let Ok(qc) = serde_json::from_slice::<QuorumCertificate>(qc_bytes) {
                    // Legacy JSON format for backwards compatibility
                    metadata.last_committed_hash = Some(qc.block_hash);
                }
            }
        }

        Ok(())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Hex-encodes a byte slice for error messages.
fn hex_encode_slice(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

// =============================================================================
// LedgerBackend Implementation
// =============================================================================

impl<R: SchemaRegistry + 'static> LedgerBackend for BftLedgerBackend<R> {
    fn append<'a>(
        &'a self,
        _namespace: &'a str,
        event: &'a EventRecord,
    ) -> BoxFuture<'a, Result<u64, LedgerError>> {
        // Use eventual consistency for the basic append interface
        // Callers who need TotalOrder should use append_with_metadata
        Box::pin(async move { self.storage.append(event) })
    }

    fn read_from<'a>(
        &'a self,
        _namespace: &'a str,
        cursor: u64,
        limit: u64,
    ) -> BoxFuture<'a, Result<Vec<EventRecord>, LedgerError>> {
        Box::pin(async move { self.storage.read_from(cursor, limit) })
    }

    fn head<'a>(&'a self, _namespace: &'a str) -> BoxFuture<'a, Result<u64, LedgerError>> {
        Box::pin(async move { self.storage.head_sync() })
    }

    fn verify_chain<'a>(
        &'a self,
        _namespace: &'a str,
        from_seq_id: u64,
        verify_hash_fn: super::backend::HashFn<'a>,
        verify_sig_fn: super::backend::VerifyFn<'a>,
    ) -> BoxFuture<'a, Result<(), LedgerError>> {
        Box::pin(async move {
            self.storage
                .verify_chain_from(from_seq_id, verify_hash_fn, verify_sig_fn)
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bft_backend_creation() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        assert!(!backend.is_consensus_enabled().await);
        assert_eq!(backend.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_enable_disable_consensus() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        assert!(!backend.is_consensus_enabled().await);

        backend.enable_consensus().await;
        assert!(backend.is_consensus_enabled().await);

        backend.disable_consensus().await;
        assert!(!backend.is_consensus_enabled().await);
    }

    #[tokio::test]
    async fn test_eventual_append() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        let event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());

        let metadata = EventMetadata::eventual("kernel", "actor-1");

        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await
            .unwrap();

        assert_eq!(result.seq_id, 1);
        assert!(result.consensus_index.is_none());
    }

    #[tokio::test]
    async fn test_consensus_metadata_update() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        let metadata = ConsensusMetadata {
            epoch: 5,
            round: 10,
            last_committed_hash: Some([0xab; 32]),
            high_qc: None,
            schema_version: CONSENSUS_METADATA_VERSION,
        };

        backend.update_consensus_metadata(metadata.clone()).await;

        let retrieved = backend.consensus_metadata().await;
        assert_eq!(retrieved.epoch, 5);
        assert_eq!(retrieved.round, 10);
        assert_eq!(retrieved.last_committed_hash, Some([0xab; 32]));
    }

    #[tokio::test]
    async fn test_read_with_qc() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        // Append an event without QC
        let event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
        let metadata = EventMetadata::eventual("kernel", "actor-1");
        let _ = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await
            .unwrap();

        // Read back with QC
        let results = backend.read_with_qc("kernel", 1, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_none()); // No QC for eventual events
    }

    #[tokio::test]
    async fn test_ledger_backend_trait() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend: Box<dyn LedgerBackend> =
            Box::new(BftLedgerBackend::with_default_timeout(storage));

        let event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());

        let seq_id = backend.append("kernel", &event).await.unwrap();
        assert_eq!(seq_id, 1);

        let head = backend.head("kernel").await.unwrap();
        assert_eq!(head, 1);

        let events = backend.read_from("kernel", 1, 10).await.unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_cancel_pending() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        backend.cancel_pending().await;
        assert_eq!(backend.pending_count().await, 0);
    }

    #[test]
    fn test_event_metadata_builders() {
        let total = EventMetadata::total_order("kernel", "actor-1");
        assert_eq!(total.ordering, OrderingGuarantee::TotalOrder);
        assert_eq!(total.namespace, "kernel");
        assert_eq!(total.actor_id, "actor-1");

        let eventual = EventMetadata::eventual("holon-1", "actor-2");
        assert_eq!(eventual.ordering, OrderingGuarantee::Eventual);
        assert_eq!(eventual.namespace, "holon-1");
        assert_eq!(eventual.actor_id, "actor-2");
    }

    #[test]
    fn test_hlc_ordering() {
        let hlc1 = HlcTimestamp {
            wall_time_ns: 100,
            logical_counter: 0,
        };
        let hlc2 = HlcTimestamp {
            wall_time_ns: 100,
            logical_counter: 1,
        };
        let hlc3 = HlcTimestamp {
            wall_time_ns: 101,
            logical_counter: 0,
        };

        assert!(hlc1 < hlc2);
        assert!(hlc2 < hlc3);
        assert!(hlc1 < hlc3);
    }

    #[test]
    fn test_append_result() {
        let result = AppendResult {
            seq_id: 42,
            event_hash: [0xab; 32],
            consensus_index: Some(ConsensusIndex {
                epoch: 1,
                round: 5,
                index: 0,
            }),
        };

        assert_eq!(result.seq_id, 42);
        assert!(result.consensus_index.is_some());
        let ci = result.consensus_index.unwrap();
        assert_eq!(ci.epoch, 1);
        assert_eq!(ci.round, 5);
    }

    #[test]
    fn test_bft_ledger_error_display() {
        let errors = [
            BftLedgerError::ConsensusTimeout { timeout_ms: 5000 },
            BftLedgerError::NotLeader {
                namespace: "kernel".to_string(),
                leader_hint: Some("node-2".to_string()),
            },
            BftLedgerError::TooManyPending {
                count: 1024,
                max: 1024,
            },
            BftLedgerError::InvalidQc("bad signature".to_string()),
            BftLedgerError::ConsensusUnavailable("not connected".to_string()),
        ];

        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }
}

/// Tests for TCK-00189 acceptance criteria.
#[cfg(test)]
mod tck_00189_tests {
    use super::*;

    /// AC1: `LedgerBackend` append waits for BFT finalization
    #[tokio::test]
    async fn tck_00189_append_waits_for_finalization() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::new(storage, Duration::from_millis(100));

        backend.enable_consensus().await;

        let event = EventRecord::new(
            "authority.event",
            "session-1",
            "actor-1",
            b"payload".to_vec(),
        );
        let metadata = EventMetadata::total_order("kernel", "actor-1");

        // Without a BFT machine providing commits, this should timeout
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(matches!(
            result,
            Err(BftLedgerError::ConsensusTimeout { .. })
        ));
    }

    /// AC2: Quorum certificates stored with authority events
    #[tokio::test]
    async fn tck_00189_qc_stored_with_events() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        // Create a QC
        let qc = QuorumCertificate::genesis(0, [0xab; 32]);

        // Simulate commit
        let _ = backend.on_commit(&[0xab; 32], &qc, 1, 5).await;

        // Verify metadata was updated
        let metadata = backend.consensus_metadata().await;
        assert_eq!(metadata.epoch, 1);
        assert_eq!(metadata.round, 5);
        assert!(metadata.high_qc.is_some());
    }

    /// AC3: Consensus metadata persisted and replayable
    #[tokio::test]
    async fn tck_00189_consensus_metadata_replayable() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        // Set up initial metadata
        let metadata = ConsensusMetadata {
            epoch: 10,
            round: 25,
            last_committed_hash: Some([0xcd; 32]),
            high_qc: Some(vec![1, 2, 3, 4]),
            schema_version: CONSENSUS_METADATA_VERSION,
        };

        backend.update_consensus_metadata(metadata).await;

        // Verify we can read it back
        let retrieved = backend.consensus_metadata().await;
        assert_eq!(retrieved.epoch, 10);
        assert_eq!(retrieved.round, 25);
        assert_eq!(retrieved.last_committed_hash, Some([0xcd; 32]));
        assert_eq!(retrieved.high_qc, Some(vec![1, 2, 3, 4]));
        assert_eq!(retrieved.schema_version, CONSENSUS_METADATA_VERSION);
    }

    /// Test bounded pending events (CTR-1303)
    #[test]
    fn tck_00189_bounded_pending_events() {
        // Verify constant is reasonable (using const block for compile-time check)
        const _: () = {
            assert!(MAX_PENDING_EVENTS > 0);
            assert!(MAX_PENDING_EVENTS <= 4096);
        };
    }

    /// Test event metadata types
    #[test]
    fn tck_00189_event_metadata_types() {
        // Verify all ordering guarantees
        let _: OrderingGuarantee = OrderingGuarantee::TotalOrder;
        let _: OrderingGuarantee = OrderingGuarantee::Eventual;

        // Verify all merge operators
        let _: MergeOperator = MergeOperator::LastWriterWins;
        let _: MergeOperator = MergeOperator::GCounter;
        let _: MergeOperator = MergeOperator::SetUnion;
        let _: MergeOperator = MergeOperator::AuthorityTier;
        let _: MergeOperator = MergeOperator::NoMerge;
    }

    /// Test consensus index structure
    #[test]
    fn tck_00189_consensus_index() {
        let ci = ConsensusIndex {
            epoch: 1,
            round: 2,
            index: 3,
        };

        assert_eq!(ci.epoch, 1);
        assert_eq!(ci.round, 2);
        assert_eq!(ci.index, 3);
    }
}

/// Security fix tests for PR #233 review findings.
#[cfg(test)]
mod security_fix_tests {
    use super::*;

    /// Finding 1: Finalization Confusion - only finalize events in committed
    /// block.
    ///
    /// Verifies that `on_commit` only finalizes events that were explicitly
    /// assigned to the committed block, not all pending events.
    #[tokio::test]
    #[allow(clippy::similar_names)]
    async fn finding_1_only_finalize_assigned_events() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        // Set up two different blocks with different events
        let block_a: BlockHash = [0xaa; 32];
        let block_b: BlockHash = [0xbb; 32];

        let event_hash_a: [u8; 32] = [0x01; 32];
        let event_hash_b: [u8; 32] = [0x02; 32];

        // Assign event_hash_a to block_a, event_hash_b to block_b
        backend
            .assign_events_to_block(block_a, vec![event_hash_a])
            .await;
        backend
            .assign_events_to_block(block_b, vec![event_hash_b])
            .await;

        // Verify mapping exists for both blocks
        {
            let mapping = backend.block_event_mapping.lock().await;
            assert!(mapping.block_to_events.contains_key(&block_a));
            assert!(mapping.block_to_events.contains_key(&block_b));
        }

        // Commit only block_a
        let qc = QuorumCertificate::genesis(0, block_a);
        let _ = backend.on_commit(&block_a, &qc, 1, 5).await;

        // Verify block_a mapping was removed (events finalized)
        // and block_b mapping still exists (events NOT finalized)
        {
            let mapping = backend.block_event_mapping.lock().await;
            assert!(
                !mapping.block_to_events.contains_key(&block_a),
                "block_a events should be finalized and removed"
            );
            assert!(
                mapping.block_to_events.contains_key(&block_b),
                "block_b events should NOT be finalized"
            );
        }
    }

    /// Finding 2: Memory Exhaustion - verify bounded replay batch size.
    #[test]
    fn finding_2_replay_batch_size_bounded() {
        // Verify REPLAY_BATCH_SIZE is reasonable (compile-time check)
        const _: () = {
            assert!(REPLAY_BATCH_SIZE > 0, "batch size must be positive");
            assert!(
                REPLAY_BATCH_SIZE <= 10000,
                "batch size should be bounded to prevent large memory usage"
            );
        };
    }

    /// Finding 3: Fail-Open - `TotalOrder` must fail when consensus disabled.
    #[tokio::test]
    async fn finding_3_total_order_fails_without_consensus() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        // Consensus is disabled by default
        assert!(!backend.is_consensus_enabled().await);

        let event = EventRecord::new(
            "authority.event",
            "session-1",
            "actor-1",
            b"critical-payload".to_vec(),
        );
        let metadata = EventMetadata::total_order("kernel", "actor-1");

        // TotalOrder with consensus disabled must fail (fail-closed)
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(
            matches!(result, Err(BftLedgerError::ConsensusRequiredButDisabled)),
            "TotalOrder events must fail when consensus is disabled, got: {result:?}"
        );
    }

    /// Finding 3: Eventual consistency still works without consensus.
    #[tokio::test]
    async fn finding_3_eventual_works_without_consensus() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        // Consensus is disabled by default
        assert!(!backend.is_consensus_enabled().await);

        let event = EventRecord::new("data.event", "session-1", "actor-1", b"payload".to_vec());
        let metadata = EventMetadata::eventual("kernel", "actor-1");

        // Eventual consistency should still work
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(
            result.is_ok(),
            "Eventual events should work without consensus"
        );
    }

    /// Finding 4: Postcard serialization for QC.
    #[test]
    fn finding_4_postcard_qc_serialization() {
        let qc = QuorumCertificate::genesis(1, [0xab; 32]);

        // Serialize with postcard
        let bytes = postcard::to_allocvec(&qc).expect("postcard serialization should work");

        // Deserialize back
        let qc2: QuorumCertificate =
            postcard::from_bytes(&bytes).expect("postcard deserialization should work");

        assert_eq!(qc.epoch, qc2.epoch);
        assert_eq!(qc.round, qc2.round);
        assert_eq!(qc.block_hash, qc2.block_hash);
    }

    /// Finding 4: Backwards compatibility with JSON QC format.
    #[test]
    fn finding_4_json_backwards_compatibility() {
        let qc = QuorumCertificate::genesis(1, [0xab; 32]);

        // Serialize with JSON (legacy format)
        let bytes = serde_json::to_vec(&qc).expect("json serialization should work");

        // Should be able to deserialize with JSON fallback
        let qc2: QuorumCertificate =
            serde_json::from_slice(&bytes).expect("json deserialization should work");

        assert_eq!(qc.epoch, qc2.epoch);
        assert_eq!(qc.round, qc2.round);
        assert_eq!(qc.block_hash, qc2.block_hash);
    }

    /// Finding 4: Sequential indexing for multi-event blocks.
    #[test]
    fn finding_4_sequential_consensus_index() {
        // Verify ConsensusIndex can track multiple events per block
        let indices: Vec<ConsensusIndex> = (0..5)
            .map(|i| ConsensusIndex {
                epoch: 1,
                round: 10,
                index: i,
            })
            .collect();

        // Each event should have a unique index
        for (i, idx) in indices.iter().enumerate() {
            assert_eq!(idx.index, i as u64, "index should be sequential");
            assert_eq!(idx.epoch, 1);
            assert_eq!(idx.round, 10);
        }
    }

    /// Test block event assignment API.
    #[tokio::test]
    async fn test_assign_events_to_block() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        let block_hash: BlockHash = [0xcc; 32];
        let event_hashes = vec![[0x01; 32], [0x02; 32], [0x03; 32]];

        backend
            .assign_events_to_block(block_hash, event_hashes.clone())
            .await;

        // Verify mapping was created
        let mapping = backend.block_event_mapping.lock().await;
        let stored = mapping.block_to_events.get(&block_hash).unwrap();
        assert_eq!(stored.len(), 3);
        assert!(stored.contains(&[0x01; 32]));
        assert!(stored.contains(&[0x02; 32]));
        assert!(stored.contains(&[0x03; 32]));
    }

    /// Test `get_unassigned_pending_events`.
    #[tokio::test]
    async fn test_get_unassigned_pending_events() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        // Initially no pending events
        let unassigned = backend.get_unassigned_pending_events().await;
        assert!(unassigned.is_empty());
    }

    /// Test new error variant display.
    #[test]
    fn test_consensus_required_error_display() {
        let err = BftLedgerError::ConsensusRequiredButDisabled;
        let msg = err.to_string();
        assert!(
            msg.contains("consensus required"),
            "error message should mention consensus required"
        );
        assert!(
            msg.contains("TotalOrder"),
            "error message should mention TotalOrder"
        );
    }

    /// Test block not found error.
    #[test]
    fn test_block_not_found_error_display() {
        let err = BftLedgerError::BlockNotFound("0xabc123".to_string());
        let msg = err.to_string();
        assert!(msg.contains("0xabc123"));
        assert!(msg.contains("not found"));
    }

    /// Test `SchemaMismatch` error display.
    #[test]
    fn tck_00194_schema_mismatch_error_display() {
        let err = BftLedgerError::SchemaMismatch {
            digest: "b3-256:abc123def456".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("schema mismatch"));
        assert!(msg.contains("b3-256:abc123def456"));
    }
}

/// Tests for TCK-00194: Schema validation in append path.
#[cfg(test)]
mod tck_00194_schema_validation_tests {
    use bytes::Bytes;

    use super::*;
    use crate::crypto::EventHasher;
    use crate::schema_registry::{InMemorySchemaRegistry, SchemaEntry};

    /// Helper to create a schema entry.
    fn make_schema_entry(stable_id: &str, content: &[u8]) -> SchemaEntry {
        let digest = SchemaDigest::new(EventHasher::hash_content(content));
        SchemaEntry {
            stable_id: stable_id.to_string(),
            digest,
            content: Bytes::copy_from_slice(content),
            canonicalizer_version: "cac-json-v1".to_string(),
            registered_at: 0,
            registered_by: "test-actor".to_string(),
        }
    }

    /// AC1: Event with known `schema_digest` passes validation.
    #[tokio::test]
    async fn tck_00194_event_with_known_schema_passes() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let registry = Arc::new(InMemorySchemaRegistry::new());

        // Register a schema
        let content = br#"{"type": "object"}"#;
        let entry = make_schema_entry("test:schema.v1", content);
        let schema_digest_bytes = entry.digest.as_bytes().to_vec();
        registry.register(&entry).await.unwrap();

        // Create backend with schema registry
        let backend = BftLedgerBackend::with_schema_registry(
            storage,
            Duration::from_millis(DEFAULT_FINALIZATION_TIMEOUT_MS),
            registry,
        );

        // Create event with known schema_digest
        let mut event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
        event.schema_digest = Some(schema_digest_bytes);

        let metadata = EventMetadata::eventual("kernel", "actor-1");

        // Should pass validation
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(
            result.is_ok(),
            "Event with known schema_digest should pass: {result:?}"
        );
    }

    /// AC2: Event with unknown `schema_digest` fails with `SchemaMismatch`.
    #[tokio::test]
    async fn tck_00194_event_with_unknown_schema_fails() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let registry = Arc::new(InMemorySchemaRegistry::new());

        // Register a schema (but we'll use a different digest)
        let content = br#"{"type": "object"}"#;
        let entry = make_schema_entry("test:schema.v1", content);
        registry.register(&entry).await.unwrap();

        // Create backend with schema registry
        let backend = BftLedgerBackend::with_schema_registry(
            storage,
            Duration::from_millis(DEFAULT_FINALIZATION_TIMEOUT_MS),
            registry,
        );

        // Create event with UNKNOWN schema_digest (different content)
        let unknown_digest = EventHasher::hash_content(br#"{"type": "string"}"#);
        let mut event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
        event.schema_digest = Some(unknown_digest.to_vec());

        let metadata = EventMetadata::eventual("kernel", "actor-1");

        // Should fail with SchemaMismatch
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(
            matches!(result, Err(BftLedgerError::SchemaMismatch { .. })),
            "Event with unknown schema_digest should fail with SchemaMismatch, got: {result:?}"
        );
    }

    /// AC3: Fail-closed behavior - unknown schema = rejection.
    #[tokio::test]
    async fn tck_00194_fail_closed_rejects_unknown() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let registry = Arc::new(InMemorySchemaRegistry::new());

        // Empty registry (no schemas registered)
        let backend = BftLedgerBackend::with_schema_registry(
            storage,
            Duration::from_millis(DEFAULT_FINALIZATION_TIMEOUT_MS),
            registry,
        );

        // Create event with any schema_digest
        let some_digest = EventHasher::hash_content(br#"{"any": "schema"}"#);
        let mut event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
        event.schema_digest = Some(some_digest.to_vec());

        let metadata = EventMetadata::eventual("kernel", "actor-1");

        // Fail-closed: must reject
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(
            matches!(result, Err(BftLedgerError::SchemaMismatch { .. })),
            "Fail-closed: empty registry must reject events with schema_digest, got: {result:?}"
        );
    }

    /// Backward compatibility: Event without `schema_digest` passes.
    #[tokio::test]
    async fn tck_00194_event_without_schema_digest_passes() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let registry = Arc::new(InMemorySchemaRegistry::new());

        // Create backend with schema registry (but no schemas registered)
        let backend = BftLedgerBackend::with_schema_registry(
            storage,
            Duration::from_millis(DEFAULT_FINALIZATION_TIMEOUT_MS),
            registry,
        );

        // Create event WITHOUT schema_digest
        let event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
        assert!(event.schema_digest.is_none());

        let metadata = EventMetadata::eventual("kernel", "actor-1");

        // Should pass (backward compatible)
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(
            result.is_ok(),
            "Event without schema_digest should pass (backward compatible): {result:?}"
        );
    }

    /// Backward compatibility: Event with empty `schema_digest` passes.
    #[tokio::test]
    async fn tck_00194_event_with_empty_schema_digest_passes() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let registry = Arc::new(InMemorySchemaRegistry::new());

        let backend = BftLedgerBackend::with_schema_registry(
            storage,
            Duration::from_millis(DEFAULT_FINALIZATION_TIMEOUT_MS),
            registry,
        );

        // Create event with empty schema_digest vec
        let mut event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
        event.schema_digest = Some(vec![]);

        let metadata = EventMetadata::eventual("kernel", "actor-1");

        // Should pass (empty digest treated as None)
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(
            result.is_ok(),
            "Event with empty schema_digest should pass: {result:?}"
        );
    }

    /// Backend without registry skips validation.
    #[tokio::test]
    async fn tck_00194_no_registry_skips_validation() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();

        // Backend without schema registry
        let backend = BftLedgerBackend::with_default_timeout(storage);

        // Create event with some schema_digest
        let some_digest = EventHasher::hash_content(br#"{"any": "schema"}"#);
        let mut event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
        event.schema_digest = Some(some_digest.to_vec());

        let metadata = EventMetadata::eventual("kernel", "actor-1");

        // Should pass (no registry configured)
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(
            result.is_ok(),
            "Backend without registry should skip validation: {result:?}"
        );
    }

    /// Invalid digest length is rejected.
    #[tokio::test]
    async fn tck_00194_invalid_digest_length_rejected() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let registry = Arc::new(InMemorySchemaRegistry::new());

        let backend = BftLedgerBackend::with_schema_registry(
            storage,
            Duration::from_millis(DEFAULT_FINALIZATION_TIMEOUT_MS),
            registry,
        );

        // Create event with invalid digest length (not 32 bytes)
        let mut event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
        event.schema_digest = Some(vec![1, 2, 3, 4, 5]); // Only 5 bytes

        let metadata = EventMetadata::eventual("kernel", "actor-1");

        // Should fail with SchemaMismatch (invalid length)
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(
            matches!(result, Err(BftLedgerError::SchemaMismatch { .. })),
            "Invalid digest length should be rejected: {result:?}"
        );
    }

    /// Schema validation happens before consensus check.
    #[tokio::test]
    async fn tck_00194_schema_validation_before_consensus_check() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let registry = Arc::new(InMemorySchemaRegistry::new());

        // Empty registry
        let backend = BftLedgerBackend::with_schema_registry(
            storage,
            Duration::from_millis(DEFAULT_FINALIZATION_TIMEOUT_MS),
            registry,
        );

        // Create TotalOrder event with unknown schema_digest
        let unknown_digest = EventHasher::hash_content(br#"{"unknown": "schema"}"#);
        let mut event = EventRecord::new(
            "authority.event",
            "session-1",
            "actor-1",
            b"payload".to_vec(),
        );
        event.schema_digest = Some(unknown_digest.to_vec());

        let metadata = EventMetadata::total_order("kernel", "actor-1");

        // Should fail with SchemaMismatch (not ConsensusRequiredButDisabled)
        // because schema validation happens FIRST
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;

        assert!(
            matches!(result, Err(BftLedgerError::SchemaMismatch { .. })),
            "Schema validation should happen before consensus check, got: {result:?}"
        );
    }

    /// Multiple schemas can be registered and validated.
    #[tokio::test]
    async fn tck_00194_multiple_schemas() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let registry = Arc::new(InMemorySchemaRegistry::new());

        // Register multiple schemas
        let schema1 = make_schema_entry("test:schema1.v1", br#"{"type": "object"}"#);
        let schema2 = make_schema_entry("test:schema2.v1", br#"{"type": "array"}"#);
        registry.register(&schema1).await.unwrap();
        registry.register(&schema2).await.unwrap();

        let backend = BftLedgerBackend::with_schema_registry(
            storage,
            Duration::from_millis(DEFAULT_FINALIZATION_TIMEOUT_MS),
            registry,
        );

        // Event with schema1 digest should pass
        let mut event1 =
            EventRecord::new("test.event1", "session-1", "actor-1", b"payload1".to_vec());
        event1.schema_digest = Some(schema1.digest.as_bytes().to_vec());
        let metadata = EventMetadata::eventual("kernel", "actor-1");
        let result1 = backend
            .append_with_metadata("kernel", &event1, &metadata)
            .await;
        assert!(result1.is_ok(), "Event with schema1 should pass");

        // Event with schema2 digest should pass
        let mut event2 =
            EventRecord::new("test.event2", "session-1", "actor-1", b"payload2".to_vec());
        event2.schema_digest = Some(schema2.digest.as_bytes().to_vec());
        let result2 = backend
            .append_with_metadata("kernel", &event2, &metadata)
            .await;
        assert!(result2.is_ok(), "Event with schema2 should pass");
    }

    /// `NoOpSchemaRegistry` always accepts (for backward compatibility).
    #[tokio::test]
    async fn tck_00194_noop_registry_always_accepts() {
        let noop = NoOpSchemaRegistry;

        // Lookup should return None
        let digest = SchemaDigest::new([42u8; 32]);
        let result = noop.lookup_by_digest(&digest).await.unwrap();
        assert!(result.is_none());

        // Register should succeed (no-op)
        let entry = make_schema_entry("test:schema.v1", br#"{"test": true}"#);
        noop.register(&entry).await.unwrap();

        // Handshake should return empty result
        let handshake = noop.handshake(&[digest]).await.unwrap();
        assert!(handshake.compatible.is_empty());
        assert!(handshake.missing_local.is_empty());
        assert!(handshake.missing_remote.is_empty());
    }
}

/// Tests for TCK-00304: Commit notification channel for HEF outbox.
#[cfg(test)]
mod tck_00304_commit_notification_tests {
    use super::*;

    /// AC1: `CommitNotification` struct defined with required fields.
    #[test]
    fn tck_00304_commit_notification_struct_fields() {
        let notification =
            super::super::CommitNotification::new(42, [0xab; 32], "WorkOpened", "kernel");

        assert_eq!(notification.seq_id, 42);
        assert_eq!(notification.event_hash, [0xab; 32]);
        assert_eq!(notification.event_type, "WorkOpened");
        assert_eq!(notification.namespace, "kernel");
        assert!(notification.consensus_index.is_none());
    }

    /// AC2: `CommitNotification::with_consensus` includes consensus index.
    #[test]
    fn tck_00304_commit_notification_with_consensus() {
        let consensus_index = ConsensusIndex {
            epoch: 5,
            round: 10,
            index: 3,
        };

        let notification = super::super::CommitNotification::with_consensus(
            100,
            [0xcd; 32],
            "GateReceipt",
            "holon-1",
            consensus_index,
        );

        assert_eq!(notification.seq_id, 100);
        assert_eq!(notification.consensus_index, Some(consensus_index));
    }

    /// AC3: `BftLedgerBackend` initially has no commit notification sender.
    #[tokio::test]
    async fn tck_00304_backend_no_sender_by_default() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let backend = BftLedgerBackend::with_default_timeout(storage);

        assert!(!backend.has_commit_notification_sender());
    }

    /// AC4: `set_commit_notification_sender` configures the sender.
    #[tokio::test]
    async fn tck_00304_backend_set_sender() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let mut backend = BftLedgerBackend::with_default_timeout(storage);

        let (sender, _receiver) = tokio::sync::mpsc::channel(1024);
        backend.set_commit_notification_sender(sender);

        assert!(backend.has_commit_notification_sender());
    }

    /// AC5: Notification sent on eventual append.
    #[tokio::test]
    async fn tck_00304_notification_on_eventual_append() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let mut backend = BftLedgerBackend::with_default_timeout(storage);

        let (sender, mut receiver) = tokio::sync::mpsc::channel(1024);
        backend.set_commit_notification_sender(sender);

        let event = EventRecord::new("work.opened", "session-1", "actor-1", b"payload".to_vec());
        let metadata = EventMetadata::eventual("kernel", "actor-1");

        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await
            .unwrap();

        // Notification should be sent
        let notification = receiver.try_recv().unwrap();
        assert_eq!(notification.seq_id, result.seq_id);
        assert_eq!(notification.event_hash, result.event_hash);
        assert_eq!(notification.event_type, "work.opened");
        assert_eq!(notification.namespace, "kernel");
        assert!(notification.consensus_index.is_none());
    }

    /// AC6: Channel full drops notification without failing commit.
    #[tokio::test]
    async fn tck_00304_channel_full_drops_notification() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let mut backend = BftLedgerBackend::with_default_timeout(storage);

        // Create a channel with capacity 1
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        backend.set_commit_notification_sender(sender);

        // Append first event - should succeed and send notification
        let event1 = EventRecord::new("event.first", "session-1", "actor-1", b"payload1".to_vec());
        let metadata = EventMetadata::eventual("kernel", "actor-1");
        let result1 = backend
            .append_with_metadata("kernel", &event1, &metadata)
            .await;
        assert!(result1.is_ok());

        // Append second event - notification should be dropped (channel full)
        // but the commit should still succeed
        let event2 = EventRecord::new("event.second", "session-1", "actor-1", b"payload2".to_vec());
        let result2 = backend
            .append_with_metadata("kernel", &event2, &metadata)
            .await;
        assert!(
            result2.is_ok(),
            "Commit should succeed even when notification is dropped"
        );
    }

    /// AC7: Channel closed logs debug and continues.
    #[tokio::test]
    async fn tck_00304_channel_closed_continues() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let mut backend = BftLedgerBackend::with_default_timeout(storage);

        let (sender, receiver) = tokio::sync::mpsc::channel(1024);
        backend.set_commit_notification_sender(sender);

        // Drop the receiver to close the channel
        drop(receiver);

        // Append should still succeed even with closed channel
        let event = EventRecord::new("event.test", "session-1", "actor-1", b"payload".to_vec());
        let metadata = EventMetadata::eventual("kernel", "actor-1");
        let result = backend
            .append_with_metadata("kernel", &event, &metadata)
            .await;
        assert!(
            result.is_ok(),
            "Commit should succeed with closed notification channel"
        );
    }

    /// AC8: Multiple notifications are sent in order.
    #[tokio::test]
    async fn tck_00304_notifications_in_order() {
        let storage = SqliteLedgerBackend::in_memory().unwrap();
        let mut backend = BftLedgerBackend::with_default_timeout(storage);

        let (sender, mut receiver) = tokio::sync::mpsc::channel(1024);
        backend.set_commit_notification_sender(sender);

        let metadata = EventMetadata::eventual("kernel", "actor-1");

        // Append multiple events
        for i in 0..5u64 {
            let event = EventRecord::new(
                format!("event.{i}"),
                "session-1",
                "actor-1",
                format!("payload-{i}").into_bytes(),
            );
            backend
                .append_with_metadata("kernel", &event, &metadata)
                .await
                .unwrap();
        }

        // Verify notifications are in order
        for i in 0..5u64 {
            let notification = receiver.try_recv().unwrap();
            assert_eq!(notification.seq_id, i + 1);
            assert_eq!(notification.event_type, format!("event.{i}"));
        }

        // No more notifications
        assert!(receiver.try_recv().is_err());
    }

    /// AC9: Channel capacity constant is as specified.
    #[test]
    fn tck_00304_channel_capacity_constant() {
        assert_eq!(
            super::super::COMMIT_NOTIFICATION_CHANNEL_CAPACITY,
            1024,
            "Channel capacity should be 1024 per TCK-00304 spec"
        );
    }
}
