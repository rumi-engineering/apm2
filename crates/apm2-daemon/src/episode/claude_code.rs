//! Claude Code harness adapter implementation.
//!
//! This module implements the [`ClaudeCodeAdapter`] for parsing Claude Code CLI
//! output and emitting structured [`HarnessEvent`]s, per AD-ADAPT-001.
//!
//! # Design
//!
//! The adapter wraps the PTY output stream with a parser that:
//! - Strips ANSI escape sequences
//! - Detects tool call patterns in the output
//! - Emits `HarnessEvent::ToolRequest` for detected tool calls
//! - Passes through regular output as `HarnessEvent::Output`
//!
//! # Architecture
//!
//! ```text
//! PTY Output ──► ClaudeCodeParser ──► HarnessEvent Stream
//!                     │
//!                     ├── Output events (sanitized)
//!                     ├── ToolRequest events (parsed)
//!                     └── Defect events (on parse errors)
//! ```
//!
//! # Holon Implementation
//!
//! Per AD-LAYER-001 and AD-ADAPT-001, `ClaudeCodeAdapter` provides per-episode
//! [`Holon`] instances via the factory method
//! [`ClaudeCodeAdapter::create_holon`]. This follows the same pattern as
//! [`RawAdapter`](super::raw_adapter::RawAdapter).
//!
//! # Contract References
//!
//! - AD-ADAPT-001: `HarnessAdapter` implements Holon trait
//! - CTR-DAEMON-003: `HarnessAdapter` trait
//! - TB-ADAPTER-001: ANSI sanitization and rate limiting

use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use apm2_holon::{Artifact, EpisodeContext, EpisodeResult, Holon, HolonError, StopCondition};
use tokio::sync::{Mutex, Semaphore};

use super::adapter::{
    AdapterError, AdapterResult, AdapterType, HarnessAdapter, HarnessConfig, HarnessEvent,
    HarnessEventStream, HarnessHandle, HarnessHandleInner, OutputKind, TerminationClassification,
};
use super::claude_parser::{ClaudeCodeParser, DEFAULT_RATE_LIMIT_PER_SEC};
use super::pty::{PtyConfig, PtyRunner};
use super::raw_adapter::MAX_CONCURRENT_ADAPTERS;

/// Counter for generating unique handle IDs.
static HANDLE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Maximum number of events to collect in the holon's event buffer.
///
/// Per CTR-1303 (Bounded Stores), in-memory stores must have `max_entries`
/// limits to prevent denial-of-service via memory exhaustion.
pub const MAX_COLLECTED_EVENTS: usize = 16384;

// ============================================================================
// Output Types
// ============================================================================

/// Output produced by the `ClaudeCodeAdapter` when used as a Holon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeCodeOutput {
    /// Exit code from the process, if available.
    pub exit_code: Option<i32>,

    /// Number of output events emitted.
    pub output_event_count: u64,

    /// Number of tool requests parsed.
    pub tool_request_count: u64,

    /// Whether the process terminated successfully.
    pub success: bool,
}

/// State of the `ClaudeCodeAdapter` when used as a Holon.
///
/// This state is wrapped in `Arc<Mutex<_>>` for thread-safe updates from
/// the background PTY reader task.
#[derive(Debug, Clone, Default)]
pub struct ClaudeCodeState {
    /// Current episode ID being processed.
    pub episode_id: Option<String>,

    /// Number of output events received in current episode.
    pub output_event_count: u64,

    /// Number of tool requests parsed.
    pub tool_request_count: u64,

    /// Whether intake has been called.
    pub intake_called: bool,

    /// Last exit code, if process has terminated.
    pub last_exit_code: Option<i32>,

    /// Whether the process has been spawned.
    pub process_spawned: bool,

    /// Whether the process has terminated.
    pub process_terminated: bool,
}

/// Shared state wrapper for thread-safe access across tasks.
pub type SharedClaudeCodeState = Arc<Mutex<ClaudeCodeState>>;

// ============================================================================
// Claude Code Adapter
// ============================================================================

/// Claude Code harness adapter.
///
/// This adapter spawns Claude Code CLI processes and parses their PTY output
/// to emit structured events. Unlike
/// [`RawAdapter`](super::raw_adapter::RawAdapter), this adapter:
///
/// - Strips ANSI escape sequences from output
/// - Detects and parses tool invocations
/// - Emits `HarnessEvent::ToolRequest` for tool calls
/// - Enforces rate limiting on tool extraction
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::claude_code::ClaudeCodeAdapter;
/// use apm2_daemon::episode::adapter::{HarnessConfig, HarnessAdapter};
///
/// let adapter = ClaudeCodeAdapter::new();
/// let config = HarnessConfig::new("claude", "episode-1")
///     .with_args(vec!["--help".to_string()]);
///
/// let (handle, mut events) = adapter.spawn(config).await?;
///
/// while let Some(event) = events.recv().await {
///     match event {
///         HarnessEvent::ToolRequest { tool, args, .. } => {
///             println!("Tool call: {} with {:?}", tool, args);
///         }
///         HarnessEvent::Output { chunk, .. } => {
///             println!("Output: {}", String::from_utf8_lossy(&chunk));
///         }
///         _ => {}
///     }
/// }
/// ```
#[derive(Debug)]
pub struct ClaudeCodeAdapter {
    /// Semaphore for tracking and limiting concurrent spawned tasks.
    task_semaphore: Arc<Semaphore>,

    /// Rate limit for tool request extraction (requests per second).
    tool_rate_limit: u32,
}

impl Default for ClaudeCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeCodeAdapter {
    /// Create a new Claude Code adapter with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_rate_limit(DEFAULT_RATE_LIMIT_PER_SEC)
    }

    /// Create a new adapter with a custom tool rate limit.
    #[must_use]
    pub fn with_rate_limit(tool_rate_limit: u32) -> Self {
        Self {
            task_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_ADAPTERS)),
            tool_rate_limit,
        }
    }

    /// Creates a per-episode Holon instance for holonic coordination.
    ///
    /// Per AD-LAYER-001 and AD-ADAPT-001, this factory method creates a fresh
    /// [`ClaudeCodeHolon`] for each episode.
    #[must_use]
    pub fn create_holon(&self) -> Box<ClaudeCodeHolon> {
        Box::new(ClaudeCodeHolon::new(
            Arc::clone(&self.task_semaphore),
            self.tool_rate_limit,
        ))
    }

    /// Returns the number of currently active (spawned) processes.
    #[must_use]
    pub fn active_count(&self) -> usize {
        MAX_CONCURRENT_ADAPTERS - self.task_semaphore.available_permits()
    }

    /// Returns the number of available slots for new processes.
    #[must_use]
    pub fn available_slots(&self) -> usize {
        self.task_semaphore.available_permits()
    }

    /// Generate a new unique handle ID.
    fn next_handle_id() -> u64 {
        HANDLE_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    /// Get current timestamp in nanoseconds.
    #[allow(clippy::cast_possible_truncation)]
    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Classify the exit status into a termination classification.
    const fn classify_exit(exit_status: super::pty::ExitStatus) -> TerminationClassification {
        match exit_status {
            super::pty::ExitStatus::Exited(0) => TerminationClassification::Success,
            super::pty::ExitStatus::Exited(_) => TerminationClassification::Failure,
            super::pty::ExitStatus::Signaled(_) => TerminationClassification::Killed,
            super::pty::ExitStatus::Running => TerminationClassification::Unknown,
        }
    }

    /// Internal spawn implementation with parsing.
    async fn spawn_internal(
        config: HarnessConfig,
        semaphore: Arc<Semaphore>,
        tool_rate_limit: u32,
        shared_state: Option<SharedClaudeCodeState>,
    ) -> AdapterResult<(HarnessHandle, HarnessEventStream)> {
        // Validate configuration before spawning
        config.validate()?;

        // Try to acquire a permit without blocking
        let permit = semaphore.clone().try_acquire_owned().map_err(|_| {
            AdapterError::resource_limit_exceeded(format!(
                "maximum concurrent adapters ({MAX_CONCURRENT_ADAPTERS}) reached"
            ))
        })?;

        let handle_id = Self::next_handle_id();
        let episode_id = config.episode_id.clone();

        // Create PTY configuration from harness config
        let (cols, rows) = config.pty_size;
        let pty_config = PtyConfig::default().with_window_size(cols, rows);

        // Get timestamp for spawn
        let timestamp_ns = Self::now_ns();

        // Build args slice
        let args: Vec<&str> = config.args.iter().map(String::as_str).collect();

        // Spawn the process via PtyRunner
        let mut runner = PtyRunner::spawn(&config.command, &args, pty_config, timestamp_ns)
            .map_err(|e| AdapterError::spawn_failed(format!("PTY spawn failed: {e}")))?;

        // Create the event channel
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        // Mark process as spawned in shared state if provided
        if let Some(ref state) = shared_state {
            let mut guard = state.lock().await;
            guard.process_spawned = true;
        }

        // Spawn a task that reads from the PTY, parses output, and emits events
        tokio::spawn(async move {
            // Hold the permit for the duration of the task
            let _permit = permit;

            let mut seq = 0u64;
            let mut parser = ClaudeCodeParser::with_rate_limit(tool_rate_limit);

            // Read output from PTY and emit events
            while let Some(output) = runner.recv().await {
                // Parse the output chunk for tool calls
                let parse_result = parser.parse(&output.chunk);

                // Emit sanitized output event
                let output_event = HarnessEvent::output(
                    parse_result.sanitized_output.clone(),
                    OutputKind::Combined,
                    seq,
                    output.ts_mono,
                );
                seq += 1;

                // Update shared state with output count if provided
                if let Some(ref state) = shared_state {
                    let mut guard = state.lock().await;
                    guard.output_event_count = seq;
                }

                if tx.send(output_event).await.is_err() {
                    // Receiver dropped, stop reading
                    break;
                }

                // Emit tool request events
                for tool_call in parse_result.tool_calls {
                    let tool_event = ClaudeCodeParser::to_harness_event(&tool_call);

                    // Update tool request count
                    if let Some(ref state) = shared_state {
                        let mut guard = state.lock().await;
                        guard.tool_request_count += 1;
                    }

                    if tx.send(tool_event).await.is_err() {
                        break;
                    }
                }

                // Log defects (but don't emit as events to avoid noise)
                for defect in parse_result.defects {
                    tracing::warn!(
                        description = %defect.description,
                        offset = defect.offset,
                        "Parser defect detected"
                    );
                }
            }

            // Wait for process to exit and get status
            let exit_status = runner.wait().unwrap_or(super::pty::ExitStatus::Running);

            let exit_code = exit_status.code();
            let classification = Self::classify_exit(exit_status);

            // Update shared state with exit code and termination if provided
            if let Some(ref state) = shared_state {
                let mut guard = state.lock().await;
                guard.last_exit_code = exit_code;
                guard.process_terminated = true;
            }

            // Emit terminated event
            let _ = tx
                .send(HarnessEvent::terminated(exit_code, classification))
                .await;
        });

        let handle = HarnessHandle::new(handle_id, episode_id, HarnessHandleInner::Placeholder);

        Ok((handle, rx))
    }
}

impl HarnessAdapter for ClaudeCodeAdapter {
    fn adapter_type(&self) -> AdapterType {
        AdapterType::ClaudeCode
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn spawn(
        &self,
        config: HarnessConfig,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = AdapterResult<(HarnessHandle, HarnessEventStream)>>
                + Send
                + '_,
        >,
    > {
        let semaphore = Arc::clone(&self.task_semaphore);
        let rate_limit = self.tool_rate_limit;

        Box::pin(async move { Self::spawn_internal(config, semaphore, rate_limit, None).await })
    }

    fn send_input(
        &self,
        _handle: &HarnessHandle,
        _input: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<()>> + Send + '_>> {
        Box::pin(async move {
            Err(AdapterError::input_failed(
                "claude code adapter send_input requires handle-based PTY storage (not yet implemented)",
            ))
        })
    }

    fn terminate(
        &self,
        _handle: &HarnessHandle,
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<ExitStatus>> + Send + '_>> {
        Box::pin(async move {
            Err(AdapterError::terminate_failed(
                "claude code adapter terminate requires handle-based PTY storage (not yet implemented)",
            ))
        })
    }
}

// =============================================================================
// ClaudeCodeHolon - Per-Episode Holon Implementation
// =============================================================================

/// Per-episode Holon implementation for Claude Code adapter execution.
///
/// Created via [`ClaudeCodeAdapter::create_holon`], this type provides:
/// - Thread-safe state via `Arc<Mutex<ClaudeCodeState>>`
/// - Process lifecycle management with parsed tool extraction
/// - State updates from background PTY reader task
#[derive(Debug)]
pub struct ClaudeCodeHolon {
    /// Shared semaphore for concurrency limiting (from parent adapter).
    task_semaphore: Arc<Semaphore>,

    /// Rate limit for tool request extraction.
    tool_rate_limit: u32,

    /// Thread-safe state shared with background PTY reader task.
    shared_state: SharedClaudeCodeState,

    /// Stored configuration from intake (used for spawn).
    config: Option<HarnessConfig>,

    /// Event stream receiver (if process has been spawned).
    event_rx: Option<HarnessEventStream>,

    /// Collected events from the process output stream.
    collected_events: Vec<HarnessEvent>,

    /// Episode ID stored for `holon_id()` access.
    episode_id: Option<String>,
}

impl ClaudeCodeHolon {
    /// Create a new per-episode holon instance.
    fn new(task_semaphore: Arc<Semaphore>, tool_rate_limit: u32) -> Self {
        Self {
            task_semaphore,
            tool_rate_limit,
            shared_state: Arc::new(Mutex::new(ClaudeCodeState::default())),
            config: None,
            event_rx: None,
            collected_events: Vec::new(),
            episode_id: None,
        }
    }

    /// Returns a clone of the shared state for external access.
    #[must_use]
    pub fn shared_state(&self) -> SharedClaudeCodeState {
        Arc::clone(&self.shared_state)
    }

    /// Returns a reference to collected output events.
    #[must_use]
    pub fn collected_events(&self) -> &[HarnessEvent] {
        &self.collected_events
    }

    /// Takes ownership of collected events, clearing the internal buffer.
    pub fn take_collected_events(&mut self) -> Vec<HarnessEvent> {
        std::mem::take(&mut self.collected_events)
    }

    /// Returns collected tool request events.
    #[must_use]
    pub fn collected_tool_requests(&self) -> Vec<&HarnessEvent> {
        self.collected_events
            .iter()
            .filter(|e| matches!(e, HarnessEvent::ToolRequest { .. }))
            .collect()
    }

    /// Collects pending events from the event stream into the internal buffer.
    fn collect_pending_events(&mut self) {
        if let Some(ref mut rx) = self.event_rx {
            while let Ok(event) = rx.try_recv() {
                if self.collected_events.len() < MAX_COLLECTED_EVENTS {
                    self.collected_events.push(event);
                } else {
                    tracing::warn!(
                        episode_id = ?self.episode_id,
                        max_events = MAX_COLLECTED_EVENTS,
                        "dropping event: collected_events buffer full (per CTR-1303)"
                    );
                }
            }
        }
    }

    /// Returns a snapshot of the current state.
    #[must_use]
    pub fn state_snapshot(&self) -> Option<ClaudeCodeState> {
        self.shared_state.try_lock().ok().map(|g| g.clone())
    }
}

impl Holon for ClaudeCodeHolon {
    type Input = HarnessConfig;
    type Output = ClaudeCodeOutput;
    type State = ClaudeCodeState;

    fn intake(&mut self, input: Self::Input, _lease_id: &str) -> Result<(), HolonError> {
        input.validate().map_err(|e| {
            HolonError::invalid_input(format!("HarnessConfig validation failed: {e}"))
        })?;

        let episode_id = input.episode_id.clone();
        self.config = Some(input);
        self.episode_id = Some(episode_id.clone());
        self.collected_events.clear();

        let state = self.shared_state.try_lock();
        match state {
            Ok(mut guard) => {
                guard.episode_id = Some(episode_id);
                guard.intake_called = true;
                guard.output_event_count = 0;
                guard.tool_request_count = 0;
                guard.last_exit_code = None;
                guard.process_spawned = false;
                guard.process_terminated = false;
            },
            Err(_) => {
                return Err(HolonError::episode_failed(
                    "failed to acquire state lock during intake",
                    true,
                ));
            },
        }

        Ok(())
    }

    fn execute_episode(
        &mut self,
        _ctx: &EpisodeContext,
    ) -> Result<EpisodeResult<Self::Output>, HolonError> {
        let state_result: Option<(bool, bool, bool, u64, u64, Option<i32>)> =
            self.shared_state.try_lock().ok().map(|guard| {
                (
                    guard.intake_called,
                    guard.process_spawned,
                    guard.process_terminated,
                    guard.output_event_count,
                    guard.tool_request_count,
                    guard.last_exit_code,
                )
            });

        let Some((
            intake_called,
            process_spawned,
            process_terminated,
            output_count,
            tool_count,
            exit_code,
        )) = state_result
        else {
            self.collect_pending_events();
            return Ok(EpisodeResult::continuation());
        };

        if !intake_called {
            return Err(HolonError::episode_failed(
                "intake() must be called before execute_episode()",
                true,
            ));
        }

        if !process_spawned {
            let config = self.config.take().ok_or_else(|| {
                HolonError::episode_failed("configuration already consumed", true)
            })?;

            let semaphore = Arc::clone(&self.task_semaphore);
            let shared_state = Arc::clone(&self.shared_state);
            let rate_limit = self.tool_rate_limit;

            let spawn_result = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(async {
                    ClaudeCodeAdapter::spawn_internal(
                        config,
                        semaphore,
                        rate_limit,
                        Some(shared_state),
                    )
                    .await
                })
            });

            match spawn_result {
                Ok((_handle, rx)) => {
                    self.event_rx = Some(rx);
                    return Ok(EpisodeResult::continue_with_progress("process spawned"));
                },
                Err(e) => {
                    return Err(HolonError::episode_failed(
                        format!("failed to spawn process: {e}"),
                        false,
                    ));
                },
            }
        }

        if process_terminated {
            self.collect_pending_events();

            let output = ClaudeCodeOutput {
                exit_code,
                output_event_count: output_count,
                tool_request_count: tool_count,
                success: exit_code.is_some_and(|c| c == 0),
            };
            return Ok(EpisodeResult::completed(output));
        }

        self.collect_pending_events();

        Ok(EpisodeResult::continue_with_progress(format!(
            "running, {} outputs, {} tool requests, {} collected",
            output_count,
            tool_count,
            self.collected_events.len()
        )))
    }

    fn emit_artifact(&self, _artifact: Artifact) -> Result<(), HolonError> {
        Ok(())
    }

    fn escalate(&mut self, reason: &str) -> Result<(), HolonError> {
        tracing::warn!(reason = %reason, "ClaudeCodeHolon escalation requested (no supervisor)");
        Ok(())
    }

    fn should_stop(&self, ctx: &EpisodeContext) -> StopCondition {
        if ctx.episode_limit_reached() {
            return StopCondition::max_episodes_reached(ctx.episode_number());
        }

        if ctx.tokens_exhausted() {
            return StopCondition::budget_exhausted("tokens");
        }

        if let Ok(guard) = self.shared_state.try_lock() {
            if guard.process_terminated {
                return StopCondition::GoalSatisfied;
            }
        }

        StopCondition::Continue
    }

    fn state(&self) -> &Self::State {
        static DEFAULT_STATE: ClaudeCodeState = ClaudeCodeState {
            episode_id: None,
            output_event_count: 0,
            tool_request_count: 0,
            intake_called: false,
            last_exit_code: None,
            process_spawned: false,
            process_terminated: false,
        };
        &DEFAULT_STATE
    }

    fn holon_id(&self) -> Option<&str> {
        self.episode_id.as_deref()
    }

    fn type_name(&self) -> &'static str {
        "ClaudeCodeHolon"
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claude_code_adapter_new() {
        let adapter = ClaudeCodeAdapter::new();
        assert_eq!(adapter.adapter_type(), AdapterType::ClaudeCode);
    }

    #[test]
    fn test_claude_code_adapter_with_rate_limit() {
        let adapter = ClaudeCodeAdapter::with_rate_limit(5);
        assert_eq!(adapter.tool_rate_limit, 5);
    }

    #[test]
    fn test_create_holon() {
        let adapter = ClaudeCodeAdapter::new();
        let holon = adapter.create_holon();
        assert_eq!(holon.type_name(), "ClaudeCodeHolon");
    }

    #[test]
    fn test_holon_intake() {
        let adapter = ClaudeCodeAdapter::new();
        let mut holon = adapter.create_holon();
        let config = HarnessConfig::new("echo", "episode-test");

        let result = holon.intake(config, "lease-123");
        assert!(result.is_ok());

        let state = holon.state_snapshot().expect("state should be available");
        assert!(state.intake_called);
        assert_eq!(state.episode_id, Some("episode-test".to_string()));
    }

    #[test]
    fn test_holon_intake_validation_error() {
        let adapter = ClaudeCodeAdapter::new();
        let mut holon = adapter.create_holon();
        let config = HarnessConfig::new("", "episode-invalid");

        let result = holon.intake(config, "lease-123");
        assert!(result.is_err());
    }

    #[test]
    fn test_holon_execute_without_intake() {
        let adapter = ClaudeCodeAdapter::new();
        let mut holon = adapter.create_holon();
        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        let result = holon.execute_episode(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_adapter_active_count() {
        let adapter = ClaudeCodeAdapter::new();
        assert_eq!(adapter.active_count(), 0);
        assert_eq!(adapter.available_slots(), MAX_CONCURRENT_ADAPTERS);
    }

    #[test]
    fn test_claude_code_output() {
        let output = ClaudeCodeOutput {
            exit_code: Some(0),
            output_event_count: 10,
            tool_request_count: 3,
            success: true,
        };

        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.output_event_count, 10);
        assert_eq!(output.tool_request_count, 3);
        assert!(output.success);
    }

    #[test]
    fn test_holon_collected_events() {
        let adapter = ClaudeCodeAdapter::new();
        let holon = adapter.create_holon();

        assert!(holon.collected_events().is_empty());
        assert!(holon.collected_tool_requests().is_empty());
    }

    #[tokio::test]
    async fn test_spawn_echo() {
        let adapter = ClaudeCodeAdapter::new();
        let config =
            HarnessConfig::new("echo", "episode-test").with_args(vec!["hello".to_string()]);

        let result = adapter.spawn(config).await;
        assert!(result.is_ok());

        let (handle, mut events) = result.unwrap();
        assert_eq!(handle.episode_id(), "episode-test");

        // Collect events until terminated
        let mut terminated = false;
        while let Some(event) = events.recv().await {
            if event.is_terminal() {
                terminated = true;
                break;
            }
        }

        assert!(terminated);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_holon_full_lifecycle() {
        let adapter = ClaudeCodeAdapter::new();
        let mut holon = adapter.create_holon();
        let config =
            HarnessConfig::new("echo", "episode-lifecycle").with_args(vec!["test".to_string()]);

        holon.intake(config, "lease-123").unwrap();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        // First execute should spawn
        let result = holon.execute_episode(&ctx);
        assert!(result.is_ok());
        assert!(result.unwrap().needs_continuation());

        // Wait for process to complete
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Poll until complete
        loop {
            let result = holon.execute_episode(&ctx).unwrap();
            if result.is_completed() {
                let output = result.into_output().expect("should have output");
                assert!(output.success);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
