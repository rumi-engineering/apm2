//! Flight recorder implementation for episode evidence.
//!
//! This module implements the `FlightRecorder` per AD-EVID-001, providing
//! per-episode ring buffers for PTY output, tool I/O, and telemetry frames.
//! Evidence is persisted to the content-addressed store on abnormal
//! termination.
//!
//! # Architecture
//!
//! ```text
//! FlightRecorder
//!     |
//!     +-- pty_buffer: RingBuffer<PtyOutput>
//!     +-- tool_buffer: RingBuffer<ToolEvent>
//!     +-- telemetry_buffer: RingBuffer<TelemetryFrame>
//!     +-- config: RecorderConfig
//!     |
//!     +-- push_pty(output) - Add PTY output
//!     +-- push_tool(event) - Add tool event
//!     +-- push_telemetry(frame) - Add telemetry frame
//!     +-- persist(cas, trigger) -> Vec<Hash> - Flush to CAS
//!     +-- clear() - Empty all buffers
//! ```
//!
//! # Lifecycle
//!
//! 1. Create recorder on episode creation with `new(risk_tier)`
//! 2. Push data during execution via `push_*` methods
//! 3. On normal termination, call `clear()` (evidence discarded)
//! 4. On abnormal termination, call `persist(cas, trigger)` (evidence retained)
//!
//! # Security Model
//!
//! - Buffers are bounded per risk tier to prevent memory exhaustion
//! - Evidence is content-addressed for integrity verification
//! - Persistence returns hashes for binding into receipts
//! - All operations are fail-closed (errors preserve evidence)
//!
//! # Invariants
//!
//! - [INV-FR001] Buffers respect configured capacity limits
//! - [INV-FR002] Oldest data is evicted when buffers are full
//! - [INV-FR003] Persist returns hashes for all non-empty buffers
//! - [INV-FR004] Clear empties all buffers completely
//!
//! # Contract References
//!
//! - AD-EVID-001: Flight recorder and ring buffers
//! - CTR-1303: Bounded collections

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use super::config::RecorderConfig;
use super::trigger::PersistTrigger;
use crate::episode::executor::ContentAddressedStore;
use crate::episode::output::{PtyOutput, PtyOutputRecord};
use crate::episode::ring_buffer::RingBuffer;
use crate::episode::{Hash, RiskTier};
use crate::telemetry::TelemetryFrame;

// =============================================================================
// ToolEvent
// =============================================================================

/// A tool event recorded for flight recorder evidence.
///
/// This captures tool requests and responses for debugging and audit.
/// The structure is designed to be serializable for CAS storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolEvent {
    /// Unique request ID.
    pub request_id: String,

    /// Tool class (read, write, execute, etc.).
    pub tool_class: String,

    /// Timestamp when the tool was invoked (nanoseconds).
    pub invoked_at_ns: u64,

    /// Timestamp when the tool completed (nanoseconds).
    pub completed_at_ns: Option<u64>,

    /// Whether the tool execution succeeded.
    pub success: bool,

    /// Error message if the tool failed.
    pub error_message: Option<String>,

    /// Hash of the arguments (stored separately in CAS).
    pub args_hash: Option<Hash>,

    /// Hash of the result (stored separately in CAS).
    pub result_hash: Option<Hash>,

    /// Budget delta consumed by this tool.
    pub budget_tokens: u64,

    /// I/O bytes consumed by this tool.
    pub budget_bytes_io: u64,
}

impl ToolEvent {
    /// Creates a new tool event for a started invocation.
    #[must_use]
    pub fn started(
        request_id: impl Into<String>,
        tool_class: impl Into<String>,
        invoked_at_ns: u64,
        args_hash: Option<Hash>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            tool_class: tool_class.into(),
            invoked_at_ns,
            completed_at_ns: None,
            success: false,
            error_message: None,
            args_hash,
            result_hash: None,
            budget_tokens: 0,
            budget_bytes_io: 0,
        }
    }

    /// Marks the event as completed successfully.
    #[must_use]
    pub const fn completed(
        mut self,
        completed_at_ns: u64,
        result_hash: Option<Hash>,
        budget_tokens: u64,
        budget_bytes_io: u64,
    ) -> Self {
        self.completed_at_ns = Some(completed_at_ns);
        self.success = true;
        self.result_hash = result_hash;
        self.budget_tokens = budget_tokens;
        self.budget_bytes_io = budget_bytes_io;
        self
    }

    /// Marks the event as failed.
    #[must_use]
    pub fn failed(
        mut self,
        completed_at_ns: u64,
        error_message: impl Into<String>,
        budget_tokens: u64,
        budget_bytes_io: u64,
    ) -> Self {
        self.completed_at_ns = Some(completed_at_ns);
        self.success = false;
        self.error_message = Some(error_message.into());
        self.budget_tokens = budget_tokens;
        self.budget_bytes_io = budget_bytes_io;
        self
    }

    /// Returns the duration in nanoseconds, if completed.
    #[must_use]
    pub fn duration_ns(&self) -> Option<u64> {
        self.completed_at_ns
            .map(|c| c.saturating_sub(self.invoked_at_ns))
    }
}

// =============================================================================
// EvidenceBundle
// =============================================================================

/// A bundle of serialized evidence ready for CAS storage.
///
/// This intermediate representation holds the serialized data before
/// it is stored in the CAS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    /// PTY output records.
    pub pty_records: Vec<PtyOutputRecord>,

    /// Tool events.
    pub tool_events: Vec<ToolEvent>,

    /// Telemetry frames.
    pub telemetry_frames: Vec<TelemetryFrame>,

    /// Trigger that caused persistence.
    pub trigger: PersistTrigger,

    /// Timestamp when persistence was triggered (nanoseconds).
    pub persisted_at_ns: u64,
}

impl EvidenceBundle {
    /// Returns `true` if the bundle contains any evidence.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pty_records.is_empty()
            && self.tool_events.is_empty()
            && self.telemetry_frames.is_empty()
    }

    /// Returns the total number of items in the bundle.
    #[must_use]
    pub fn total_items(&self) -> usize {
        self.pty_records.len() + self.tool_events.len() + self.telemetry_frames.len()
    }
}

// =============================================================================
// PersistResult
// =============================================================================

/// Result of persisting flight recorder evidence.
#[derive(Debug, Clone)]
pub struct PersistResult {
    /// Hash of the PTY evidence, if any was persisted.
    pub pty_hash: Option<Hash>,

    /// Hash of the tool evidence, if any was persisted.
    pub tool_hash: Option<Hash>,

    /// Hash of the telemetry evidence, if any was persisted.
    pub telemetry_hash: Option<Hash>,

    /// Hash of the complete evidence bundle.
    pub bundle_hash: Hash,

    /// Number of PTY records persisted.
    pub pty_count: usize,

    /// Number of tool events persisted.
    pub tool_count: usize,

    /// Number of telemetry frames persisted.
    pub telemetry_count: usize,
}

impl PersistResult {
    /// Returns all non-None hashes as a vector.
    #[must_use]
    pub fn all_hashes(&self) -> Vec<Hash> {
        let mut hashes = vec![self.bundle_hash];

        if let Some(h) = self.pty_hash {
            hashes.push(h);
        }
        if let Some(h) = self.tool_hash {
            hashes.push(h);
        }
        if let Some(h) = self.telemetry_hash {
            hashes.push(h);
        }

        hashes
    }

    /// Returns the total number of items persisted.
    #[must_use]
    pub const fn total_items(&self) -> usize {
        self.pty_count + self.tool_count + self.telemetry_count
    }
}

// =============================================================================
// FlightRecorder
// =============================================================================

/// Flight recorder for per-episode evidence collection.
///
/// The flight recorder maintains ring buffers for PTY output, tool I/O,
/// and telemetry frames. On abnormal termination, the buffers are
/// persisted to the content-addressed store for debugging and audit.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::recorder::FlightRecorder;
/// use apm2_daemon::episode::RiskTier;
///
/// // Create recorder for tier 2 episode
/// let mut recorder = FlightRecorder::new(RiskTier::Tier2);
///
/// // Push data during execution
/// recorder.push_pty(pty_output);
/// recorder.push_tool(tool_event);
/// recorder.push_telemetry(frame);
///
/// // On abnormal termination, persist evidence
/// let trigger = PersistTrigger::from_exit_code(1);
/// let result = recorder.persist(&cas, trigger, timestamp_ns)?;
///
/// // On normal termination, discard evidence
/// recorder.clear();
/// ```
pub struct FlightRecorder {
    /// PTY output buffer.
    pty_buffer: RingBuffer<PtyOutput>,

    /// Tool event buffer.
    tool_buffer: RingBuffer<ToolEvent>,

    /// Telemetry frame buffer.
    telemetry_buffer: RingBuffer<TelemetryFrame>,

    /// Configuration for this recorder.
    config: RecorderConfig,
}

impl FlightRecorder {
    /// Creates a new flight recorder for the given risk tier.
    ///
    /// Buffer sizes are determined by the risk tier per AD-EVID-001.
    #[must_use]
    pub fn new(risk_tier: RiskTier) -> Self {
        Self::with_config(RecorderConfig::from_risk_tier(risk_tier))
    }

    /// Creates a new flight recorder with custom configuration.
    #[must_use]
    pub fn with_config(config: RecorderConfig) -> Self {
        Self {
            pty_buffer: RingBuffer::new(config.pty_capacity()),
            tool_buffer: RingBuffer::new(config.tool_capacity()),
            telemetry_buffer: RingBuffer::new(config.telemetry_capacity()),
            config,
        }
    }

    /// Returns the configuration for this recorder.
    #[must_use]
    pub const fn config(&self) -> &RecorderConfig {
        &self.config
    }

    // =========================================================================
    // Push Methods
    // =========================================================================

    /// Pushes PTY output to the buffer.
    ///
    /// If the buffer is full, the oldest output is evicted.
    pub fn push_pty(&mut self, output: PtyOutput) {
        self.pty_buffer.push(output);
    }

    /// Pushes a tool event to the buffer.
    ///
    /// If the buffer is full, the oldest event is evicted.
    pub fn push_tool(&mut self, event: ToolEvent) {
        self.tool_buffer.push(event);
    }

    /// Pushes a telemetry frame to the buffer.
    ///
    /// If the buffer is full, the oldest frame is evicted.
    pub fn push_telemetry(&mut self, frame: TelemetryFrame) {
        self.telemetry_buffer.push(frame);
    }

    // =========================================================================
    // Query Methods
    // =========================================================================

    /// Returns the number of PTY outputs in the buffer.
    #[must_use]
    pub fn pty_len(&self) -> usize {
        self.pty_buffer.len()
    }

    /// Returns the number of tool events in the buffer.
    #[must_use]
    pub fn tool_len(&self) -> usize {
        self.tool_buffer.len()
    }

    /// Returns the number of telemetry frames in the buffer.
    #[must_use]
    pub fn telemetry_len(&self) -> usize {
        self.telemetry_buffer.len()
    }

    /// Returns the total number of items across all buffers.
    #[must_use]
    pub fn total_len(&self) -> usize {
        self.pty_len() + self.tool_len() + self.telemetry_len()
    }

    /// Returns `true` if all buffers are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pty_buffer.is_empty()
            && self.tool_buffer.is_empty()
            && self.telemetry_buffer.is_empty()
    }

    /// Returns the estimated memory usage in bytes.
    #[must_use]
    pub fn estimated_memory_bytes(&self) -> usize {
        // This is a rough estimate based on current buffer lengths
        // and estimated item sizes
        use super::config::{
            ESTIMATED_PTY_CHUNK_SIZE, ESTIMATED_TELEMETRY_FRAME_SIZE, ESTIMATED_TOOL_EVENT_SIZE,
        };

        self.pty_len() * ESTIMATED_PTY_CHUNK_SIZE
            + self.tool_len() * ESTIMATED_TOOL_EVENT_SIZE
            + self.telemetry_len() * ESTIMATED_TELEMETRY_FRAME_SIZE
    }

    // =========================================================================
    // Persistence
    // =========================================================================

    /// Persists all buffer contents to the content-addressed store.
    ///
    /// This method:
    /// 1. Drains all buffers
    /// 2. Serializes evidence to JSON
    /// 3. Stores each category separately in CAS
    /// 4. Stores a combined bundle with the trigger
    /// 5. Returns hashes for all stored evidence
    ///
    /// # Arguments
    ///
    /// * `cas` - Content-addressed store for evidence storage
    /// * `trigger` - The trigger that caused persistence
    /// * `timestamp_ns` - Current timestamp in nanoseconds
    ///
    /// # Returns
    ///
    /// A `PersistResult` containing hashes of all stored evidence.
    ///
    /// # Errors
    ///
    /// Returns an error string if serialization fails.
    #[instrument(skip(self, cas), fields(trigger_type = %trigger.trigger_type()))]
    pub fn persist(
        &mut self,
        cas: &Arc<dyn ContentAddressedStore>,
        trigger: PersistTrigger,
        timestamp_ns: u64,
    ) -> Result<PersistResult, String> {
        debug!(
            pty_count = self.pty_len(),
            tool_count = self.tool_len(),
            telemetry_count = self.telemetry_len(),
            "persisting flight recorder evidence"
        );

        // Drain all buffers and convert to serializable records
        let pty_records: Vec<PtyOutputRecord> =
            self.pty_buffer.drain().map(PtyOutputRecord::from).collect();
        let tool_events: Vec<ToolEvent> = self.tool_buffer.drain().collect();
        let telemetry_frames: Vec<TelemetryFrame> = self.telemetry_buffer.drain().collect();

        let pty_count = pty_records.len();
        let tool_count = tool_events.len();
        let telemetry_count = telemetry_frames.len();

        // Store each category separately (for selective retrieval)
        let pty_hash = if pty_records.is_empty() {
            None
        } else {
            let bytes = serde_json::to_vec(&pty_records)
                .map_err(|e| format!("failed to serialize PTY evidence: {e}"))?;
            Some(cas.store(&bytes))
        };

        let tool_hash = if tool_events.is_empty() {
            None
        } else {
            let bytes = serde_json::to_vec(&tool_events)
                .map_err(|e| format!("failed to serialize tool evidence: {e}"))?;
            Some(cas.store(&bytes))
        };

        let telemetry_hash = if telemetry_frames.is_empty() {
            None
        } else {
            let bytes = serde_json::to_vec(&telemetry_frames)
                .map_err(|e| format!("failed to serialize telemetry evidence: {e}"))?;
            Some(cas.store(&bytes))
        };

        // Create and store the complete bundle
        let bundle = EvidenceBundle {
            pty_records,
            tool_events,
            telemetry_frames,
            trigger,
            persisted_at_ns: timestamp_ns,
        };

        let bundle_bytes = serde_json::to_vec(&bundle)
            .map_err(|e| format!("failed to serialize evidence bundle: {e}"))?;
        let bundle_hash = cas.store(&bundle_bytes);

        debug!(
            bundle_hash = %hex::encode(&bundle_hash[..8]),
            pty_count,
            tool_count,
            telemetry_count,
            "evidence persisted successfully"
        );

        Ok(PersistResult {
            pty_hash,
            tool_hash,
            telemetry_hash,
            bundle_hash,
            pty_count,
            tool_count,
            telemetry_count,
        })
    }

    // =========================================================================
    // Clear
    // =========================================================================

    /// Clears all buffers, discarding all evidence.
    ///
    /// This should be called on normal episode termination when
    /// evidence retention is not needed.
    pub fn clear(&mut self) {
        self.pty_buffer.clear();
        self.tool_buffer.clear();
        self.telemetry_buffer.clear();
    }
}

impl std::fmt::Debug for FlightRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlightRecorder")
            .field("config", &self.config)
            .field("pty_len", &self.pty_len())
            .field("tool_len", &self.tool_len())
            .field("telemetry_len", &self.telemetry_len())
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::episode::EpisodeId;
    use crate::episode::broker::StubContentAddressedStore;
    use crate::episode::output::StreamKind;
    use crate::telemetry::O11yFlags;
    use crate::telemetry::stats::MetricSource;

    fn test_pty_output(seq: u64) -> PtyOutput {
        PtyOutput::new(
            Bytes::from(format!("output chunk {seq}")),
            seq,
            1_000_000 * seq,
            StreamKind::Combined,
        )
    }

    fn test_tool_event(request_id: &str) -> ToolEvent {
        ToolEvent::started(request_id, "read", 1_000_000_000, None)
    }

    fn test_telemetry_frame(seq: u64) -> TelemetryFrame {
        let episode_id = EpisodeId::new("test-episode").unwrap();
        TelemetryFrame::builder(episode_id, seq)
            .ts_mono(seq * 1_000_000)
            .cpu_ns(seq * 100_000)
            .source(MetricSource::Cgroup)
            .o11y_flags(O11yFlags::new())
            .build()
    }

    // =========================================================================
    // UT-00170-01: Ring buffer bounds
    // =========================================================================

    #[test]
    fn test_recorder_bounds_pty() {
        // Create a recorder with small capacity for testing
        let config = RecorderConfig::try_new(3, 3, 3).unwrap();
        let mut recorder = FlightRecorder::with_config(config);

        // Push more items than capacity
        for i in 0..10 {
            recorder.push_pty(test_pty_output(i));
        }

        // Should only contain last 3 items
        assert_eq!(recorder.pty_len(), 3);
    }

    #[test]
    fn test_recorder_bounds_tool() {
        let config = RecorderConfig::try_new(3, 3, 3).unwrap();
        let mut recorder = FlightRecorder::with_config(config);

        for i in 0..10 {
            recorder.push_tool(test_tool_event(&format!("req-{i}")));
        }

        assert_eq!(recorder.tool_len(), 3);
    }

    #[test]
    fn test_recorder_bounds_telemetry() {
        let config = RecorderConfig::try_new(3, 3, 3).unwrap();
        let mut recorder = FlightRecorder::with_config(config);

        for i in 0..10 {
            recorder.push_telemetry(test_telemetry_frame(i));
        }

        assert_eq!(recorder.telemetry_len(), 3);
    }

    // =========================================================================
    // UT-00170-02: Persistence to CAS
    // =========================================================================

    #[test]
    fn test_recorder_persist_stores_evidence() {
        let mut recorder = FlightRecorder::new(RiskTier::Tier1);
        let cas = Arc::new(StubContentAddressedStore::new());

        // Add some evidence
        recorder.push_pty(test_pty_output(0));
        recorder.push_pty(test_pty_output(1));
        recorder.push_tool(test_tool_event("req-1"));
        recorder.push_telemetry(test_telemetry_frame(0));

        // Persist
        let trigger = PersistTrigger::from_exit_code(1);
        let result = recorder
            .persist(
                &(cas as Arc<dyn ContentAddressedStore>),
                trigger,
                1_000_000_000,
            )
            .unwrap();

        // Verify results
        assert!(result.pty_hash.is_some());
        assert!(result.tool_hash.is_some());
        assert!(result.telemetry_hash.is_some());
        assert_eq!(result.pty_count, 2);
        assert_eq!(result.tool_count, 1);
        assert_eq!(result.telemetry_count, 1);
        assert_eq!(result.total_items(), 4);

        // Buffers should be empty after persist
        assert!(recorder.is_empty());
    }

    #[test]
    fn test_recorder_persist_empty_buffers() {
        let mut recorder = FlightRecorder::new(RiskTier::Tier1);
        let cas = Arc::new(StubContentAddressedStore::new());

        let trigger = PersistTrigger::from_exit_code(0);
        let result = recorder
            .persist(
                &(cas as Arc<dyn ContentAddressedStore>),
                trigger,
                1_000_000_000,
            )
            .unwrap();

        // Should still create bundle hash but no individual hashes
        assert!(result.pty_hash.is_none());
        assert!(result.tool_hash.is_none());
        assert!(result.telemetry_hash.is_none());
        assert_eq!(result.total_items(), 0);

        // Bundle hash should always exist
        assert_ne!(result.bundle_hash, [0u8; 32]);
    }

    #[test]
    fn test_recorder_persist_returns_all_hashes() {
        let mut recorder = FlightRecorder::new(RiskTier::Tier1);
        let cas = Arc::new(StubContentAddressedStore::new());

        recorder.push_pty(test_pty_output(0));
        recorder.push_tool(test_tool_event("req-1"));
        recorder.push_telemetry(test_telemetry_frame(0));

        let trigger = PersistTrigger::from_exit_code(1);
        let result = recorder
            .persist(
                &(cas as Arc<dyn ContentAddressedStore>),
                trigger,
                1_000_000_000,
            )
            .unwrap();

        let all_hashes = result.all_hashes();
        assert_eq!(all_hashes.len(), 4); // bundle + pty + tool + telemetry
    }

    // =========================================================================
    // UT-00170-03: Tier configuration
    // =========================================================================

    #[test]
    fn test_recorder_tier_1_capacities() {
        let recorder = FlightRecorder::new(RiskTier::Tier1);
        let config = recorder.config();

        assert_eq!(
            config.pty_capacity(),
            super::super::config::TIER_1_PTY_CAPACITY
        );
        assert_eq!(
            config.tool_capacity(),
            super::super::config::TIER_1_TOOL_CAPACITY
        );
        assert_eq!(
            config.telemetry_capacity(),
            super::super::config::TIER_1_TELEMETRY_CAPACITY
        );
    }

    #[test]
    fn test_recorder_tier_2_capacities() {
        let recorder = FlightRecorder::new(RiskTier::Tier2);
        let config = recorder.config();

        assert_eq!(
            config.pty_capacity(),
            super::super::config::TIER_2_PTY_CAPACITY
        );
        assert_eq!(
            config.tool_capacity(),
            super::super::config::TIER_2_TOOL_CAPACITY
        );
        assert_eq!(
            config.telemetry_capacity(),
            super::super::config::TIER_2_TELEMETRY_CAPACITY
        );
    }

    #[test]
    fn test_recorder_tier_3_capacities() {
        let recorder = FlightRecorder::new(RiskTier::Tier3);
        let config = recorder.config();

        assert_eq!(
            config.pty_capacity(),
            super::super::config::TIER_3_PLUS_PTY_CAPACITY
        );
        assert_eq!(
            config.tool_capacity(),
            super::super::config::TIER_3_PLUS_TOOL_CAPACITY
        );
        assert_eq!(
            config.telemetry_capacity(),
            super::super::config::TIER_3_PLUS_TELEMETRY_CAPACITY
        );
    }

    // =========================================================================
    // Additional tests
    // =========================================================================

    #[test]
    fn test_recorder_clear() {
        let mut recorder = FlightRecorder::new(RiskTier::Tier1);

        recorder.push_pty(test_pty_output(0));
        recorder.push_tool(test_tool_event("req-1"));
        recorder.push_telemetry(test_telemetry_frame(0));

        assert!(!recorder.is_empty());
        assert_eq!(recorder.total_len(), 3);

        recorder.clear();

        assert!(recorder.is_empty());
        assert_eq!(recorder.total_len(), 0);
    }

    #[test]
    fn test_recorder_estimated_memory() {
        let mut recorder = FlightRecorder::new(RiskTier::Tier1);

        assert_eq!(recorder.estimated_memory_bytes(), 0);

        recorder.push_pty(test_pty_output(0));
        recorder.push_tool(test_tool_event("req-1"));
        recorder.push_telemetry(test_telemetry_frame(0));

        let estimated = recorder.estimated_memory_bytes();
        assert!(estimated > 0);
    }

    #[test]
    fn test_tool_event_lifecycle() {
        let event = ToolEvent::started("req-1", "read", 1_000_000_000, None);
        assert!(!event.success);
        assert!(event.completed_at_ns.is_none());
        assert!(event.duration_ns().is_none());

        let completed = event.completed(2_000_000_000, None, 100, 1024);
        assert!(completed.success);
        assert_eq!(completed.completed_at_ns, Some(2_000_000_000));
        assert_eq!(completed.duration_ns(), Some(1_000_000_000));
        assert_eq!(completed.budget_tokens, 100);
        assert_eq!(completed.budget_bytes_io, 1024);
    }

    #[test]
    fn test_tool_event_failure() {
        let event = ToolEvent::started("req-2", "write", 1_000_000_000, None);
        let failed = event.failed(1_500_000_000, "permission denied", 50, 0);

        assert!(!failed.success);
        assert_eq!(failed.error_message, Some("permission denied".to_string()));
        assert_eq!(failed.duration_ns(), Some(500_000_000));
    }

    #[test]
    fn test_evidence_bundle() {
        let bundle = EvidenceBundle {
            pty_records: vec![],
            tool_events: vec![],
            telemetry_frames: vec![],
            trigger: PersistTrigger::from_exit_code(0),
            persisted_at_ns: 1_000_000_000,
        };

        assert!(bundle.is_empty());
        assert_eq!(bundle.total_items(), 0);
    }

    #[test]
    fn test_tool_event_serialization() {
        let event = ToolEvent::started("req-1", "read", 1_000_000_000, None);
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ToolEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event, deserialized);
    }

    /// SECURITY: Verify unknown fields are rejected.
    #[test]
    fn test_tool_event_rejects_unknown_fields() {
        let json = r#"{
            "request_id": "req-1",
            "tool_class": "read",
            "invoked_at_ns": 1000000000,
            "completed_at_ns": null,
            "success": false,
            "error_message": null,
            "args_hash": null,
            "result_hash": null,
            "budget_tokens": 0,
            "budget_bytes_io": 0,
            "malicious": "attack"
        }"#;

        let result: Result<ToolEvent, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn test_recorder_debug() {
        let recorder = FlightRecorder::new(RiskTier::Tier1);
        let debug_str = format!("{recorder:?}");

        assert!(debug_str.contains("FlightRecorder"));
        assert!(debug_str.contains("config"));
        assert!(debug_str.contains("pty_len"));
    }
}
