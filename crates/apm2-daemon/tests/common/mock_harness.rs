//! Mock harness for controlled E2E testing.
//!
//! This module provides `MockHarness` for testing tool mediation and telemetry
//! collection in controlled scenarios. Unlike real harness adapters that spawn
//! processes, `MockHarness` simulates harness behavior deterministically.

// Allow dead code and missing const fn in test utilities - not all test files use all utilities.
#![allow(dead_code)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::doc_markdown)]
//! # Architecture
//!
//! ```text
//! MockHarness
//!     +-- config: MockHarnessConfig
//!     +-- state: MockHarnessState
//!     +-- scheduled_events: Vec<ScheduledEvent>
//!
//! Test Flow:
//!     1. Configure expected behavior (tool calls, outputs, exit code)
//!     2. Start the mock harness
//!     3. Harness emits configured events in sequence
//!     4. Test verifies expected outcomes
//! ```
//!
//! # Contract References
//!
//! - TCK-00176: E2E tool and telemetry tests
//! - REQ-TOOL-001: Tool mediation requirements
//! - REQ-TEL-001: Telemetry requirements

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apm2_daemon::episode::{
    AdapterError, AdapterResult, BudgetDelta, DedupeKey, EpisodeId, HarnessEvent, OutputKind,
    RiskTier, TerminationClassification, ToolClass,
};

// =============================================================================
// MockToolCall
// =============================================================================

/// A tool call that the mock harness will emit.
#[derive(Debug, Clone)]
pub struct MockToolCall {
    /// Unique ID for this tool call.
    pub request_id: String,

    /// The tool class being invoked.
    pub tool_class: ToolClass,

    /// Dedupe key for idempotent replay.
    pub dedupe_key: DedupeKey,

    /// Optional path for filesystem operations.
    pub path: Option<PathBuf>,

    /// Expected output from the tool.
    pub expected_output: Vec<u8>,

    /// Whether the tool should succeed.
    pub success: bool,

    /// Optional exit code.
    pub exit_code: Option<i32>,

    /// Budget consumed by this tool call.
    pub budget_delta: BudgetDelta,

    /// Simulated execution duration.
    pub duration: Duration,
}

impl MockToolCall {
    /// Creates a new successful mock tool call.
    #[must_use]
    pub fn success(
        request_id: impl Into<String>,
        tool_class: ToolClass,
        dedupe_key: impl Into<String>,
        output: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            tool_class,
            dedupe_key: DedupeKey::new(dedupe_key.into()),
            path: None,
            expected_output: output.into(),
            success: true,
            exit_code: Some(0),
            budget_delta: BudgetDelta::single_call(),
            duration: Duration::from_millis(10),
        }
    }

    /// Creates a failed mock tool call.
    #[must_use]
    pub fn failure(
        request_id: impl Into<String>,
        tool_class: ToolClass,
        dedupe_key: impl Into<String>,
        error_message: impl Into<String>,
        exit_code: i32,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            tool_class,
            dedupe_key: DedupeKey::new(dedupe_key.into()),
            path: None,
            expected_output: error_message.into().into_bytes(),
            success: false,
            exit_code: Some(exit_code),
            budget_delta: BudgetDelta::single_call(),
            duration: Duration::from_millis(5),
        }
    }

    /// Sets the path for this tool call.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the budget delta.
    #[must_use]
    pub fn with_budget_delta(mut self, delta: BudgetDelta) -> Self {
        self.budget_delta = delta;
        self
    }

    /// Sets the duration.
    #[must_use]
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }
}

// =============================================================================
// ScheduledEvent
// =============================================================================

/// An event scheduled to occur at a specific time.
#[derive(Debug, Clone)]
pub enum ScheduledEvent {
    /// Emit output text.
    Output {
        /// Output text.
        text: String,
        /// Output kind (stdout/stderr).
        kind: OutputKind,
        /// Delay before emitting.
        delay: Duration,
    },

    /// Emit a tool call request.
    ToolCall {
        /// The tool call to emit.
        call: MockToolCall,
        /// Delay before emitting.
        delay: Duration,
    },

    /// Complete the harness with an exit code.
    Complete {
        /// Exit code.
        exit_code: i32,
        /// Delay before completing.
        delay: Duration,
    },
}

impl ScheduledEvent {
    /// Creates an output event.
    #[must_use]
    pub fn output(text: impl Into<String>, kind: OutputKind, delay: Duration) -> Self {
        Self::Output {
            text: text.into(),
            kind,
            delay,
        }
    }

    /// Creates a stdout output event.
    #[must_use]
    pub fn stdout(text: impl Into<String>, delay: Duration) -> Self {
        Self::output(text, OutputKind::Stdout, delay)
    }

    /// Creates a stderr output event.
    #[must_use]
    #[allow(dead_code)]
    pub fn stderr(text: impl Into<String>, delay: Duration) -> Self {
        Self::output(text, OutputKind::Stderr, delay)
    }

    /// Creates a tool call event.
    #[must_use]
    pub fn tool_call(call: MockToolCall, delay: Duration) -> Self {
        Self::ToolCall { call, delay }
    }

    /// Creates a completion event.
    #[must_use]
    pub fn complete(exit_code: i32, delay: Duration) -> Self {
        Self::Complete { exit_code, delay }
    }
}

// =============================================================================
// MockHarnessConfig
// =============================================================================

/// Configuration for the mock harness.
#[derive(Debug, Clone)]
pub struct MockHarnessConfig {
    /// Episode ID.
    pub episode_id: EpisodeId,

    /// Risk tier for capability validation.
    pub risk_tier: RiskTier,

    /// Scheduled events to emit.
    pub events: Vec<ScheduledEvent>,

    /// Default exit code if no completion event is scheduled.
    pub default_exit_code: i32,

    /// Whether to fail on start.
    pub fail_on_start: bool,

    /// Simulated CPU usage per millisecond.
    pub cpu_ns_per_ms: u64,

    /// Simulated I/O bytes per tool call.
    pub io_bytes_per_call: u64,

    /// Simulated memory RSS.
    pub mem_rss_bytes: u64,
}

impl Default for MockHarnessConfig {
    fn default() -> Self {
        Self {
            episode_id: EpisodeId::new("mock-episode-001").expect("valid episode ID"),
            risk_tier: RiskTier::Tier0,
            events: Vec::new(),
            default_exit_code: 0,
            fail_on_start: false,
            cpu_ns_per_ms: 1_000_000, // 1ms CPU per ms wall time (100% CPU)
            io_bytes_per_call: 1024,
            mem_rss_bytes: 10 * 1024 * 1024, // 10 MB
        }
    }
}

impl MockHarnessConfig {
    /// Creates a new mock harness config with the given episode ID.
    #[must_use]
    pub fn new(episode_id: EpisodeId) -> Self {
        Self {
            episode_id,
            ..Default::default()
        }
    }

    /// Sets the risk tier.
    #[must_use]
    pub const fn with_risk_tier(mut self, tier: RiskTier) -> Self {
        self.risk_tier = tier;
        self
    }

    /// Adds scheduled events.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_events(mut self, events: Vec<ScheduledEvent>) -> Self {
        self.events = events;
        self
    }

    /// Adds a single scheduled event.
    #[must_use]
    pub fn with_event(mut self, event: ScheduledEvent) -> Self {
        self.events.push(event);
        self
    }

    /// Sets the default exit code.
    #[must_use]
    pub const fn with_default_exit_code(mut self, code: i32) -> Self {
        self.default_exit_code = code;
        self
    }

    /// Configures the harness to fail on start.
    #[must_use]
    pub const fn with_fail_on_start(mut self) -> Self {
        self.fail_on_start = true;
        self
    }

    /// Sets the simulated CPU usage.
    #[must_use]
    pub const fn with_cpu_ns_per_ms(mut self, cpu_ns: u64) -> Self {
        self.cpu_ns_per_ms = cpu_ns;
        self
    }

    /// Sets the simulated I/O bytes per call.
    #[must_use]
    pub const fn with_io_bytes_per_call(mut self, bytes: u64) -> Self {
        self.io_bytes_per_call = bytes;
        self
    }

    /// Sets the simulated memory RSS.
    #[must_use]
    pub const fn with_mem_rss_bytes(mut self, bytes: u64) -> Self {
        self.mem_rss_bytes = bytes;
        self
    }
}

// =============================================================================
// MockHarnessState
// =============================================================================

/// Shared state for the mock harness.
#[derive(Debug)]
pub struct MockHarnessState {
    /// Whether the harness is running.
    running: AtomicBool,

    /// Whether the harness has completed.
    completed: AtomicBool,

    /// Exit code (set when completed).
    exit_code: Mutex<Option<i32>>,

    /// Events queue.
    events: Mutex<VecDeque<ScheduledEvent>>,

    /// Tool calls that have been processed.
    processed_tool_calls: Mutex<Vec<MockToolCall>>,

    /// Simulated elapsed time in milliseconds.
    elapsed_ms: AtomicU64,

    /// Total CPU time consumed in nanoseconds.
    cpu_ns: AtomicU64,

    /// Total I/O bytes consumed.
    io_bytes: AtomicU64,

    /// Configuration snapshot.
    config: MockHarnessConfig,
}

impl MockHarnessState {
    /// Creates a new mock harness state.
    #[must_use]
    pub fn new(config: MockHarnessConfig) -> Self {
        let events = VecDeque::from(config.events.clone());
        Self {
            running: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            exit_code: Mutex::new(None),
            events: Mutex::new(events),
            processed_tool_calls: Mutex::new(Vec::new()),
            elapsed_ms: AtomicU64::new(0),
            cpu_ns: AtomicU64::new(0),
            io_bytes: AtomicU64::new(0),
            config,
        }
    }

    /// Returns the episode ID.
    #[must_use]
    #[allow(dead_code)]
    pub fn episode_id(&self) -> &EpisodeId {
        &self.config.episode_id
    }

    /// Returns the risk tier.
    #[must_use]
    #[allow(dead_code)]
    pub const fn risk_tier(&self) -> RiskTier {
        self.config.risk_tier
    }

    /// Returns `true` if the harness is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Returns `true` if the harness has completed.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::Relaxed)
    }

    /// Returns the exit code if completed.
    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        *self.exit_code.lock().unwrap()
    }

    /// Returns the elapsed time in milliseconds.
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms.load(Ordering::Relaxed)
    }

    /// Returns the total CPU time in nanoseconds.
    #[must_use]
    pub fn cpu_ns(&self) -> u64 {
        self.cpu_ns.load(Ordering::Relaxed)
    }

    /// Returns the total I/O bytes.
    #[must_use]
    pub fn io_bytes(&self) -> u64 {
        self.io_bytes.load(Ordering::Relaxed)
    }

    /// Returns the configured memory RSS.
    #[must_use]
    pub fn mem_rss_bytes(&self) -> u64 {
        self.config.mem_rss_bytes
    }

    /// Returns the processed tool calls.
    #[must_use]
    pub fn processed_tool_calls(&self) -> Vec<MockToolCall> {
        self.processed_tool_calls.lock().unwrap().clone()
    }

    /// Starts the harness.
    pub fn start(&self) -> AdapterResult<()> {
        if self.config.fail_on_start {
            return Err(AdapterError::SpawnFailed {
                reason: "mock configured to fail on start".to_string(),
            });
        }
        self.running.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Advances time by the given duration.
    pub fn advance_time(&self, duration: Duration) {
        let ms = duration.as_millis() as u64;
        self.elapsed_ms.fetch_add(ms, Ordering::Relaxed);

        // Simulate CPU usage
        let cpu_delta = ms * self.config.cpu_ns_per_ms;
        self.cpu_ns.fetch_add(cpu_delta, Ordering::Relaxed);
    }

    /// Adds I/O bytes.
    pub fn add_io_bytes(&self, bytes: u64) {
        self.io_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Takes the next event from the queue.
    #[must_use]
    pub fn take_next_event(&self) -> Option<ScheduledEvent> {
        self.events.lock().unwrap().pop_front()
    }

    /// Records a processed tool call.
    pub fn record_tool_call(&self, call: MockToolCall) {
        self.add_io_bytes(self.config.io_bytes_per_call);
        self.processed_tool_calls.lock().unwrap().push(call);
    }

    /// Completes the harness with the given exit code.
    pub fn complete(&self, exit_code: i32) {
        self.running.store(false, Ordering::Relaxed);
        self.completed.store(true, Ordering::Relaxed);
        *self.exit_code.lock().unwrap() = Some(exit_code);
    }

    /// Resets the harness to its initial state.
    pub fn reset(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.completed.store(false, Ordering::Relaxed);
        *self.exit_code.lock().unwrap() = None;
        *self.events.lock().unwrap() = VecDeque::from(self.config.events.clone());
        self.processed_tool_calls.lock().unwrap().clear();
        self.elapsed_ms.store(0, Ordering::Relaxed);
        self.cpu_ns.store(0, Ordering::Relaxed);
        self.io_bytes.store(0, Ordering::Relaxed);
    }
}

/// Shared mock harness state.
pub type SharedMockHarnessState = Arc<MockHarnessState>;

/// Creates a new shared mock harness state.
#[must_use]
pub fn new_shared_mock_state(config: MockHarnessConfig) -> SharedMockHarnessState {
    Arc::new(MockHarnessState::new(config))
}

// =============================================================================
// MockHarness
// =============================================================================

/// Mock harness for controlled E2E testing.
///
/// This harness simulates agent behavior deterministically for testing
/// tool mediation, deduplication, and telemetry collection.
///
/// # Example
///
/// ```rust,ignore
/// use crate::common::mock_harness::{MockHarness, MockHarnessConfig, MockToolCall, ScheduledEvent};
///
/// let config = MockHarnessConfig::new(episode_id)
///     .with_event(ScheduledEvent::tool_call(
///         MockToolCall::success("req-1", ToolClass::Read, "key-1", b"file contents"),
///         Duration::from_millis(10),
///     ))
///     .with_event(ScheduledEvent::complete(0, Duration::from_millis(100)));
///
/// let harness = MockHarness::new(config);
/// harness.start().await?;
///
/// // Process events and verify behavior
/// while let Some(event) = harness.next_event().await {
///     // Handle event
/// }
/// ```
#[derive(Debug)]
pub struct MockHarness {
    /// Shared state.
    state: SharedMockHarnessState,
}

impl MockHarness {
    /// Creates a new mock harness.
    #[must_use]
    pub fn new(config: MockHarnessConfig) -> Self {
        Self {
            state: new_shared_mock_state(config),
        }
    }

    /// Creates a mock harness from shared state.
    #[must_use]
    #[allow(dead_code)]
    pub fn from_state(state: SharedMockHarnessState) -> Self {
        Self { state }
    }

    /// Returns the shared state.
    #[must_use]
    #[allow(dead_code)]
    pub fn state(&self) -> &SharedMockHarnessState {
        &self.state
    }

    /// Returns the episode ID.
    #[must_use]
    #[allow(dead_code)]
    pub fn episode_id(&self) -> &EpisodeId {
        self.state.episode_id()
    }

    /// Returns the risk tier.
    #[must_use]
    #[allow(dead_code)]
    pub fn risk_tier(&self) -> RiskTier {
        self.state.risk_tier()
    }

    /// Returns `true` if the harness is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.state.is_running()
    }

    /// Returns `true` if the harness has completed.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        self.state.is_completed()
    }

    /// Returns the exit code if completed.
    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        self.state.exit_code()
    }

    /// Starts the mock harness.
    ///
    /// # Errors
    ///
    /// Returns an error if configured to fail on start.
    pub fn start(&self) -> AdapterResult<()> {
        self.state.start()
    }

    /// Takes the next scheduled event.
    #[must_use]
    pub fn take_next_event(&self) -> Option<ScheduledEvent> {
        self.state.take_next_event()
    }

    /// Processes a tool call and records it.
    pub fn record_tool_call(&self, call: MockToolCall) {
        self.state.record_tool_call(call);
    }

    /// Advances simulated time.
    pub fn advance_time(&self, duration: Duration) {
        self.state.advance_time(duration);
    }

    /// Completes the harness with the given exit code.
    pub fn complete(&self, exit_code: i32) {
        self.state.complete(exit_code);
    }

    /// Returns the processed tool calls.
    #[must_use]
    pub fn processed_tool_calls(&self) -> Vec<MockToolCall> {
        self.state.processed_tool_calls()
    }

    /// Returns current resource stats (simulated).
    #[must_use]
    pub fn resource_stats(&self) -> MockResourceStats {
        MockResourceStats {
            elapsed_ms: self.state.elapsed_ms(),
            cpu_ns: self.state.cpu_ns(),
            io_bytes: self.state.io_bytes(),
            mem_rss_bytes: self.state.mem_rss_bytes(),
        }
    }

    /// Resets the harness for re-use.
    pub fn reset(&self) {
        self.state.reset();
    }

    /// Returns the termination classification based on exit code.
    #[must_use]
    pub fn termination_classification(&self) -> Option<TerminationClassification> {
        self.exit_code().map(|code| {
            if code == 0 {
                TerminationClassification::Success
            } else {
                TerminationClassification::Failure
            }
        })
    }
}

impl Clone for MockHarness {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

// =============================================================================
// MockResourceStats
// =============================================================================

/// Simulated resource statistics from the mock harness.
#[derive(Debug, Clone, Copy, Default)]
pub struct MockResourceStats {
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,

    /// Total CPU time in nanoseconds.
    pub cpu_ns: u64,

    /// Total I/O bytes.
    pub io_bytes: u64,

    /// Memory RSS in bytes.
    pub mem_rss_bytes: u64,
}

impl MockResourceStats {
    /// Returns CPU time in milliseconds.
    #[must_use]
    pub const fn cpu_ms(&self) -> u64 {
        self.cpu_ns / 1_000_000
    }
}

// =============================================================================
// MockHarnessEvent
// =============================================================================

/// Event emitted by the mock harness (for compatibility with HarnessEvent).
#[derive(Debug, Clone)]
pub enum MockHarnessEvent {
    /// Output produced by the harness.
    Output {
        /// Output text.
        text: String,
        /// Output kind.
        kind: OutputKind,
    },

    /// Tool call requested.
    ToolCall(MockToolCall),

    /// Harness completed.
    Completed {
        /// Exit code.
        exit_code: i32,
    },
}

impl MockHarnessEvent {
    /// Converts to a `HarnessEvent` (for compatibility).
    #[must_use]
    #[allow(dead_code)]
    pub fn to_harness_event(&self, seq: u64, ts: u64) -> HarnessEvent {
        match self {
            Self::Output { text, kind } => HarnessEvent::Output {
                chunk: text.clone().into_bytes(),
                kind: *kind,
                seq,
                ts,
            },
            Self::ToolCall(_) => HarnessEvent::Output {
                chunk: b"[tool call]".to_vec(),
                kind: OutputKind::Stdout,
                seq,
                ts,
            },
            Self::Completed { exit_code } => HarnessEvent::Terminated {
                exit_code: Some(*exit_code),
                classification: if *exit_code == 0 {
                    TerminationClassification::Success
                } else {
                    TerminationClassification::Failure
                },
            },
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_episode_id() -> EpisodeId {
        EpisodeId::new("mock-test-001").expect("valid episode ID")
    }

    #[test]
    fn test_mock_harness_config_default() {
        let config = MockHarnessConfig::default();
        assert_eq!(config.default_exit_code, 0);
        assert!(!config.fail_on_start);
        assert!(config.events.is_empty());
    }

    #[test]
    fn test_mock_harness_config_builder() {
        let config = MockHarnessConfig::new(test_episode_id())
            .with_risk_tier(RiskTier::Tier1)
            .with_default_exit_code(1)
            .with_cpu_ns_per_ms(500_000);

        assert_eq!(config.risk_tier, RiskTier::Tier1);
        assert_eq!(config.default_exit_code, 1);
        assert_eq!(config.cpu_ns_per_ms, 500_000);
    }

    #[test]
    fn test_mock_harness_start_and_complete() {
        let config = MockHarnessConfig::new(test_episode_id());
        let harness = MockHarness::new(config);

        assert!(!harness.is_running());
        assert!(!harness.is_completed());

        harness.start().expect("start should succeed");
        assert!(harness.is_running());
        assert!(!harness.is_completed());

        harness.complete(0);
        assert!(!harness.is_running());
        assert!(harness.is_completed());
        assert_eq!(harness.exit_code(), Some(0));
    }

    #[test]
    fn test_mock_harness_fail_on_start() {
        let config = MockHarnessConfig::new(test_episode_id()).with_fail_on_start();
        let harness = MockHarness::new(config);

        let result = harness.start();
        assert!(result.is_err());
        assert!(!harness.is_running());
    }

    #[test]
    fn test_mock_harness_events() {
        let config = MockHarnessConfig::new(test_episode_id())
            .with_event(ScheduledEvent::stdout("Hello", Duration::from_millis(10)))
            .with_event(ScheduledEvent::complete(0, Duration::from_millis(100)));

        let harness = MockHarness::new(config);
        harness.start().unwrap();

        let event1 = harness.take_next_event();
        assert!(matches!(event1, Some(ScheduledEvent::Output { .. })));

        let event2 = harness.take_next_event();
        assert!(matches!(event2, Some(ScheduledEvent::Complete { .. })));

        let event3 = harness.take_next_event();
        assert!(event3.is_none());
    }

    #[test]
    fn test_mock_harness_tool_call() {
        let call = MockToolCall::success("req-1", ToolClass::Read, "key-1", b"file contents");

        let config = MockHarnessConfig::new(test_episode_id())
            .with_event(ScheduledEvent::tool_call(call, Duration::from_millis(10)));

        let harness = MockHarness::new(config);
        harness.start().unwrap();

        if let Some(ScheduledEvent::ToolCall { call, .. }) = harness.take_next_event() {
            harness.record_tool_call(call);
        }

        let calls = harness.processed_tool_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].request_id, "req-1");
    }

    #[test]
    fn test_mock_harness_resource_stats() {
        let config = MockHarnessConfig::new(test_episode_id())
            .with_cpu_ns_per_ms(2_000_000) // 2ms CPU per ms wall time
            .with_io_bytes_per_call(4096)
            .with_mem_rss_bytes(50 * 1024 * 1024);

        let harness = MockHarness::new(config);
        harness.start().unwrap();

        // Advance time by 100ms
        harness.advance_time(Duration::from_millis(100));

        let stats = harness.resource_stats();
        assert_eq!(stats.elapsed_ms, 100);
        assert_eq!(stats.cpu_ns, 200_000_000); // 100ms * 2_000_000 ns/ms
        assert_eq!(stats.cpu_ms(), 200);
        assert_eq!(stats.mem_rss_bytes, 50 * 1024 * 1024);

        // Record a tool call to add I/O bytes
        let call = MockToolCall::success("req-1", ToolClass::Read, "key-1", b"data");
        harness.record_tool_call(call);

        let stats = harness.resource_stats();
        assert_eq!(stats.io_bytes, 4096);
    }

    #[test]
    fn test_mock_harness_reset() {
        let config = MockHarnessConfig::new(test_episode_id())
            .with_event(ScheduledEvent::stdout("Hello", Duration::from_millis(10)));

        let harness = MockHarness::new(config);
        harness.start().unwrap();
        let _ = harness.take_next_event();
        harness.advance_time(Duration::from_millis(50));
        harness.complete(1);

        // Reset
        harness.reset();

        assert!(!harness.is_running());
        assert!(!harness.is_completed());
        assert!(harness.exit_code().is_none());
        assert!(harness.take_next_event().is_some()); // Events restored
        assert_eq!(harness.resource_stats().elapsed_ms, 0);
    }

    #[test]
    fn test_mock_tool_call_builder() {
        let call = MockToolCall::success("req-1", ToolClass::Write, "key-1", b"output")
            .with_path("/workspace/file.txt")
            .with_budget_delta(BudgetDelta::single_call().with_tokens(100))
            .with_duration(Duration::from_millis(50));

        assert_eq!(call.request_id, "req-1");
        assert_eq!(call.tool_class, ToolClass::Write);
        assert_eq!(
            call.path.as_ref().unwrap().to_string_lossy(),
            "/workspace/file.txt"
        );
        assert_eq!(call.budget_delta.tokens, 100);
        assert_eq!(call.duration, Duration::from_millis(50));
        assert!(call.success);
    }

    #[test]
    fn test_mock_tool_call_failure() {
        let call = MockToolCall::failure(
            "req-2",
            ToolClass::Execute,
            "key-2",
            "command not found",
            127,
        );

        assert_eq!(call.request_id, "req-2");
        assert!(!call.success);
        assert_eq!(call.exit_code, Some(127));
    }

    #[test]
    fn test_mock_harness_clone() {
        let config = MockHarnessConfig::new(test_episode_id());
        let harness1 = MockHarness::new(config);
        let harness2 = harness1.clone();

        harness1.start().unwrap();

        // Both share the same state
        assert!(harness2.is_running());

        harness2.complete(42);
        assert_eq!(harness1.exit_code(), Some(42));
    }

    #[test]
    fn test_termination_classification() {
        let config = MockHarnessConfig::new(test_episode_id());
        let harness = MockHarness::new(config);

        assert!(harness.termination_classification().is_none());

        harness.start().unwrap();
        harness.complete(0);
        assert!(matches!(
            harness.termination_classification(),
            Some(TerminationClassification::Success)
        ));

        harness.reset();
        harness.start().unwrap();
        harness.complete(1);
        assert!(matches!(
            harness.termination_classification(),
            Some(TerminationClassification::Failure)
        ));
    }
}
