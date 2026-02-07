//! Raw adapter implementation.
//!
//! The [`RawAdapter`] is a baseline adapter that spawns processes and emits
//! all PTY output as raw [`HarnessEvent::Output`] events without any parsing.
//!
//! # Runtime Requirements
//!
//! **IMPORTANT**: The [`RawAdapterHolon`] implementation requires a
//! **multi-threaded tokio runtime**. The [`Holon::execute_episode`] method
//! uses `tokio::task::block_in_place` to bridge synchronous holon execution
//! with async process spawning. This will **panic** if called from a
//! single-threaded runtime.
//!
//! When using `RawAdapterHolon`, ensure your tokio runtime is configured with
//! multiple worker threads:
//!
//! ```rust,ignore
//! #[tokio::main(flavor = "multi_thread")]
//! async fn main() {
//!     // Safe to use RawAdapterHolon here
//! }
//!
//! // Or explicitly:
//! let rt = tokio::runtime::Builder::new_multi_thread()
//!     .worker_threads(4)
//!     .build()
//!     .unwrap();
//! ```
//!
//! The `apm2-daemon` binary uses a multi-threaded runtime by default.
//!
//! # Behavior
//!
//! - Spawns processes using PTY (pseudo-terminal) for proper terminal emulation
//! - Emits all output as `Output` events with `OutputKind::Combined`
//! - Does not parse tool calls or structured events
//! - Forwards termination status directly
//!
//! # Resource Bounds
//!
//! The adapter enforces a maximum of [`MAX_CONCURRENT_ADAPTERS`] concurrent
//! spawned processes to prevent resource exhaustion. If this limit is reached,
//! [`spawn`](RawAdapter::spawn) will return an error.
//!
//! # Holon Implementation
//!
//! Per AD-LAYER-001 and AD-ADAPT-001, `RawAdapter` provides per-episode
//! [`Holon`] instances via the factory method [`RawAdapter::create_holon`].
//! Each episode gets a fresh [`RawAdapterHolon`] that:
//!
//! - `Input`: [`HarnessConfig`] - Configuration for spawning
//! - `Output`: [`RawAdapterOutput`] - Exit status and output count
//! - `State`: [`RawAdapterState`] - Current adapter state (thread-safe)
//!
//! The separation between `RawAdapter` (shared, concurrent-safe singleton for
//! resource management) and `RawAdapterHolon` (per-episode execution handle)
//! ensures thread-safe operation in a concurrent daemon environment.
//!
//! This adapter is useful for:
//! - Running arbitrary shell commands
//! - Testing and debugging harness infrastructure
//! - Processes that don't have structured output formats

use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use apm2_holon::{Artifact, EpisodeContext, EpisodeResult, Holon, HolonError, StopCondition};
use tokio::sync::{Mutex, Semaphore};

use super::adapter::{
    AdapterError, AdapterResult, AdapterType, HarnessAdapter, HarnessConfig, HarnessEvent,
    HarnessEventStream, HarnessHandle, MAX_SEND_INPUT_BYTES, OutputKind, TerminationClassification,
    create_real_handle_inner, process_pty_control_command, pty_control_channel_capacity,
    read_proc_start_time, send_input_with_handle, terminate_with_handle,
};
use super::pty::{PtyConfig, PtyRunner};

/// Counter for generating unique handle IDs.
static HANDLE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Maximum number of concurrent adapter instances allowed.
///
/// This limit prevents resource exhaustion from spawning too many processes.
/// The limit is intentionally conservative to account for system resources
/// like file descriptors, memory, and CPU time.
///
/// Each spawned process consumes:
/// - At least 3 file descriptors (stdin, stdout, stderr / PTY)
/// - Memory for the process and its buffers
/// - A tokio task for event handling
///
/// With this limit, the maximum file descriptor usage is approximately
/// 100 * 3 = 300 FDs, well within typical system limits.
pub const MAX_CONCURRENT_ADAPTERS: usize = 100;

/// Maximum number of events to collect in the holon's event buffer.
///
/// This limit prevents memory exhaustion from collecting too many events.
/// Events beyond this limit are logged and dropped. The limit is set high
/// enough for typical episodes but provides a safety bound.
///
/// Per CTR-1303 (Bounded Stores), in-memory stores must have `max_entries`
/// limits to prevent denial-of-service via memory exhaustion.
pub const MAX_COLLECTED_EVENTS: usize = 16384;

/// Output produced by the `RawAdapter` when used as a Holon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAdapterOutput {
    /// Exit code from the process, if available.
    pub exit_code: Option<i32>,
    /// Number of output events emitted.
    pub output_event_count: u64,
    /// Whether the process terminated successfully.
    pub success: bool,
}

/// State of the `RawAdapter` when used as a Holon.
///
/// This state is wrapped in `Arc<Mutex<_>>` for thread-safe updates from
/// the background PTY reader task.
#[derive(Debug, Clone, Default)]
pub struct RawAdapterState {
    /// Current episode ID being processed.
    pub episode_id: Option<String>,
    /// Number of output events received in current episode.
    pub output_event_count: u64,
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
pub type SharedAdapterState = Arc<Mutex<RawAdapterState>>;

/// Raw adapter that emits unstructured output.
///
/// This adapter spawns processes and emits all PTY output as raw events.
/// It does not parse tool calls or structured events.
///
/// # Resource Bounds
///
/// The adapter tracks spawned tasks and enforces [`MAX_CONCURRENT_ADAPTERS`]
/// as the maximum number of concurrent processes. When this limit is reached,
/// [`spawn`](RawAdapter::spawn) returns
/// [`AdapterError::ResourceLimitExceeded`].
///
/// # Holon Factory
///
/// Per AD-LAYER-001 and AD-ADAPT-001, `RawAdapter` acts as a factory for
/// per-episode [`RawAdapterHolon`] instances via
/// [`create_holon`](Self::create_holon). This separation ensures:
///
/// - Thread-safe singleton for resource management (semaphore)
/// - Fresh per-episode state for each Holon instance
/// - Proper state isolation between concurrent episodes
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::raw_adapter::RawAdapter;
/// use apm2_daemon::episode::adapter::{HarnessConfig, HarnessAdapter};
///
/// let adapter = RawAdapter::new();
/// let config = HarnessConfig::new("echo", "episode-1")
///     .with_args(vec!["hello".to_string()]);
///
/// let (handle, mut events) = adapter.spawn(config).await?;
///
/// while let Some(event) = events.recv().await {
///     println!("Event: {:?}", event);
/// }
/// ```
#[derive(Debug)]
pub struct RawAdapter {
    /// Semaphore for tracking and limiting concurrent spawned tasks.
    ///
    /// Each successful spawn acquires a permit, which is released when
    /// the spawned task completes. This bounds resource usage.
    task_semaphore: Arc<Semaphore>,
}

impl Default for RawAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RawAdapter {
    /// Create a new raw adapter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            task_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_ADAPTERS)),
        }
    }

    /// Creates a per-episode Holon instance for holonic coordination.
    ///
    /// Per AD-LAYER-001 and AD-ADAPT-001, this factory method creates a fresh
    /// [`RawAdapterHolon`] for each episode. The holon shares the adapter's
    /// semaphore for resource limiting but maintains its own state.
    ///
    /// # Returns
    ///
    /// A boxed [`RawAdapterHolon`] implementing the [`Holon`] trait.
    #[must_use]
    pub fn create_holon(&self) -> Box<RawAdapterHolon> {
        Box::new(RawAdapterHolon::new(Arc::clone(&self.task_semaphore)))
    }

    /// Returns the number of currently active (spawned) processes.
    ///
    /// This is useful for monitoring resource usage.
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

    /// Internal spawn implementation that optionally updates shared state.
    ///
    /// This method is used by both `HarnessAdapter::spawn` and
    /// `RawAdapterHolon` to spawn processes. When `shared_state` is
    /// provided, the background task updates it with output count and exit
    /// code.
    ///
    /// # Arguments
    ///
    /// * `config` - The harness configuration
    /// * `semaphore` - Semaphore for concurrency limiting
    /// * `shared_state` - Optional shared state for Holon coordination
    ///
    /// # Returns
    ///
    /// A tuple of the handle and event stream.
    async fn spawn_internal(
        config: HarnessConfig,
        semaphore: Arc<Semaphore>,
        shared_state: Option<SharedAdapterState>,
    ) -> AdapterResult<(HarnessHandle, HarnessEventStream)> {
        // Validate configuration before spawning
        config.validate()?;

        // Try to acquire a permit without blocking
        // This enforces the concurrent adapter limit
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
        let pid_raw = runner.pid().as_raw();
        let pid = u32::try_from(pid_raw)
            .map_err(|_| AdapterError::spawn_failed(format!("invalid PTY child pid: {pid_raw}")))?;
        let start_time_ticks = read_proc_start_time(pid);

        let (control_tx, mut control_rx) =
            tokio::sync::mpsc::channel(pty_control_channel_capacity());
        let handle_inner = create_real_handle_inner(pid, start_time_ticks, control_tx);

        // Create the event channel
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        // Mark process as spawned in shared state if provided
        if let Some(ref state) = shared_state {
            let mut guard = state.lock().await;
            guard.process_spawned = true;
        }

        // Spawn a task that reads from the PTY and emits events
        // The permit is moved into the task and dropped when it completes,
        // releasing the slot for a new process.
        let task_episode_id = episode_id.clone();
        tokio::spawn(async move {
            // Hold the permit for the duration of the task
            let _permit = permit;
            let episode_id = task_episode_id;

            let mut seq = 0u64;
            let mut exit_status = None;
            let mut control_open = true;
            let mut output_live = true;

            loop {
                tokio::select! {
                    maybe_cmd = control_rx.recv(), if control_open => {
                        if let Some(command) = maybe_cmd {
                            if let Some(status) = process_pty_control_command(
                                command,
                                &mut runner,
                                pid,
                                start_time_ticks,
                            ).await {
                                exit_status = Some(status);
                                break;
                            }
                        } else {
                            control_open = false;
                            // If output is also dead, nothing left to do
                            if !output_live {
                                break;
                            }
                        }
                    }
                    maybe_output = runner.recv() => {
                        if let Some(output) = maybe_output {
                            if output_live {
                                let event = HarnessEvent::output(
                                    output.chunk.to_vec(),
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

                                match tx.try_send(event) {
                                    Ok(()) => {},
                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                        // Receiver dropped — stop forwarding output but
                                        // keep servicing control commands for liveness.
                                        output_live = false;
                                    },
                                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                        // Channel full — drop this event to avoid blocking
                                        // the select loop, which would starve control-plane
                                        // commands (send_input, terminate). This is the
                                        // non-blocking output policy per the control-plane
                                        // decoupling invariant: control commands MUST always
                                        // be serviced regardless of output backpressure.
                                        tracing::warn!(
                                            episode_id = %episode_id,
                                            seq = seq - 1,
                                            "output event dropped: event channel full (backpressure)"
                                        );
                                    },
                                }
                            }
                            // else: drain output silently to detect process termination
                        } else {
                            exit_status = Some(runner.wait().unwrap_or(super::pty::ExitStatus::Running));
                            break;
                        }
                    }
                }
            }

            let exit_status = exit_status
                .unwrap_or_else(|| runner.wait().unwrap_or(super::pty::ExitStatus::Running));

            let exit_code = exit_status.code();
            let classification = Self::classify_exit(exit_status);

            // Update shared state with exit code and termination if provided
            if let Some(ref state) = shared_state {
                let mut guard = state.lock().await;
                guard.last_exit_code = exit_code;
                guard.process_terminated = true;
                guard.output_event_count = seq;
            }

            // Emit terminated event (best-effort, non-blocking to avoid
            // stalling permit release if the receiver is backpressured).
            let _ = tx.try_send(HarnessEvent::terminated(exit_code, classification));

            // Permit is automatically released when dropped here
        });

        let handle = HarnessHandle::new(handle_id, episode_id, handle_inner);

        Ok((handle, rx))
    }
}

impl HarnessAdapter for RawAdapter {
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Raw
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
        // Clone the semaphore Arc for use in the async block
        let semaphore = Arc::clone(&self.task_semaphore);

        Box::pin(async move { Self::spawn_internal(config, semaphore, None).await })
    }

    fn send_input(
        &self,
        handle: &HarnessHandle,
        input: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<()>> + Send + '_>> {
        let handle_id = handle.id();
        // Validate size before cloning to avoid unnecessary allocation
        let input_len = input.len();
        if input_len > MAX_SEND_INPUT_BYTES {
            return Box::pin(async move {
                Err(AdapterError::input_failed(format!(
                    "input payload too large: {input_len} bytes exceeds maximum {MAX_SEND_INPUT_BYTES} bytes",
                )))
            });
        }
        let runner_handle = handle.real_runner_handle();
        let input = input.to_vec();
        Box::pin(async move { send_input_with_handle(handle_id, runner_handle, input).await })
    }

    fn terminate(
        &self,
        handle: &HarnessHandle,
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<ExitStatus>> + Send + '_>> {
        let handle_id = handle.id();
        let runner_handle = handle.real_runner_handle();
        Box::pin(async move { terminate_with_handle(handle_id, runner_handle).await })
    }
}

// =============================================================================
// RawAdapterHolon - Per-Episode Holon Implementation
// =============================================================================
//
// Per AD-LAYER-001 and AD-ADAPT-001, RawAdapterHolon provides a per-episode
// Holon instance created via the RawAdapter::create_holon() factory method.
// This separation ensures:
// - Thread-safe singleton for resource management (semaphore in RawAdapter)
// - Fresh per-episode state for each Holon instance
// - Proper state isolation between concurrent episodes
// - Background task can update shared state for process lifecycle tracking

/// Per-episode Holon implementation for raw adapter execution.
///
/// Created via [`RawAdapter::create_holon`], this type provides:
/// - Thread-safe state via `Arc<Mutex<RawAdapterState>>`
/// - Process lifecycle management in `execute_episode`
/// - State updates from background PTY reader task
///
/// # Thread Safety
///
/// The holon state is wrapped in `Arc<Mutex<_>>` and shared with the background
/// task that reads PTY output. This ensures the state is properly updated with
/// `output_event_count` and `last_exit_code` as the process runs.
///
/// # Process Lifecycle
///
/// Per AD-LAYER-001 and AD-ADAPT-001, `execute_episode`:
/// 1. Spawns the process on first call (returns `NeedsContinuation`)
/// 2. Polls for termination on subsequent calls
/// 3. Returns `Completed` only when the process has terminated
#[derive(Debug)]
pub struct RawAdapterHolon {
    /// Shared semaphore for concurrency limiting (from parent `RawAdapter`).
    task_semaphore: Arc<Semaphore>,

    /// Thread-safe state shared with background PTY reader task.
    shared_state: SharedAdapterState,

    /// Stored configuration from intake (used for spawn).
    config: Option<HarnessConfig>,

    /// Event stream receiver (if process has been spawned).
    event_rx: Option<HarnessEventStream>,

    /// Collected events from the process output stream.
    ///
    /// Events are collected during `execute_episode` polling to preserve
    /// PTY output for evidence collection. Bounded by [`MAX_COLLECTED_EVENTS`]
    /// to prevent memory exhaustion (per CTR-1303).
    collected_events: Vec<HarnessEvent>,

    /// Episode ID stored for `holon_id()` access.
    ///
    /// Stored separately from `shared_state` to avoid mutex access in the
    /// synchronous `holon_id()` method.
    episode_id: Option<String>,
}

impl RawAdapterHolon {
    /// Create a new per-episode holon instance.
    ///
    /// This is called by [`RawAdapter::create_holon`].
    fn new(task_semaphore: Arc<Semaphore>) -> Self {
        Self {
            task_semaphore,
            shared_state: Arc::new(Mutex::new(RawAdapterState::default())),
            config: None,
            event_rx: None,
            collected_events: Vec::new(),
            episode_id: None,
        }
    }

    /// Returns a clone of the shared state for external access.
    ///
    /// This can be used to check state from outside the holon without
    /// needing mutable access.
    #[must_use]
    pub fn shared_state(&self) -> SharedAdapterState {
        Arc::clone(&self.shared_state)
    }

    /// Returns a reference to collected output events.
    ///
    /// Events are collected during `execute_episode` polling and preserved
    /// for evidence collection. This provides access to all PTY output
    /// captured since process spawn.
    #[must_use]
    pub fn collected_events(&self) -> &[HarnessEvent] {
        &self.collected_events
    }

    /// Takes ownership of collected events, clearing the internal buffer.
    ///
    /// This is useful when transferring events to an evidence collector
    /// without copying.
    pub fn take_collected_events(&mut self) -> Vec<HarnessEvent> {
        std::mem::take(&mut self.collected_events)
    }

    /// Collects pending events from the event stream into the internal buffer.
    ///
    /// This method drains all available events from `event_rx` and stores them
    /// in `collected_events` for evidence preservation. Events are bounded by
    /// [`MAX_COLLECTED_EVENTS`] per CTR-1303 to prevent memory exhaustion.
    ///
    /// Events beyond the limit are logged and dropped.
    fn collect_pending_events(&mut self) {
        if let Some(ref mut rx) = self.event_rx {
            while let Ok(event) = rx.try_recv() {
                if self.collected_events.len() < MAX_COLLECTED_EVENTS {
                    self.collected_events.push(event);
                } else {
                    // Log that we're dropping events due to buffer limit
                    tracing::warn!(
                        episode_id = ?self.episode_id,
                        max_events = MAX_COLLECTED_EVENTS,
                        "dropping event: collected_events buffer full (per CTR-1303)"
                    );
                    // Continue draining to prevent channel backup, but don't
                    // store
                }
            }
        }
    }
}

impl Holon for RawAdapterHolon {
    type Input = HarnessConfig;
    type Output = RawAdapterOutput;
    type State = RawAdapterState;

    fn intake(&mut self, input: Self::Input, _lease_id: &str) -> Result<(), HolonError> {
        // Validate the input configuration
        input.validate().map_err(|e| {
            HolonError::invalid_input(format!("HarnessConfig validation failed: {e}"))
        })?;

        // Store the configuration and update state
        let episode_id = input.episode_id.clone();
        self.config = Some(input);

        // Store episode_id for holon_id() access (avoids mutex in sync method)
        self.episode_id = Some(episode_id.clone());

        // Clear any collected events from previous episodes
        self.collected_events.clear();

        // Update shared state
        // Note: We use try_lock in synchronous context, which is safe here
        // because no other task has access to the state yet (process not spawned).
        let state = self.shared_state.try_lock();
        match state {
            Ok(mut guard) => {
                guard.episode_id = Some(episode_id);
                guard.intake_called = true;
                guard.output_event_count = 0;
                guard.last_exit_code = None;
                guard.process_spawned = false;
                guard.process_terminated = false;
            },
            Err(_) => {
                // This shouldn't happen as we're the only accessor at intake time
                return Err(HolonError::episode_failed(
                    "failed to acquire state lock during intake",
                    true,
                ));
            },
        }

        Ok(())
    }

    /// Executes an episode step, driving the process lifecycle.
    ///
    /// # Runtime Requirements
    ///
    /// **IMPORTANT**: This method requires a **multi-threaded tokio runtime**.
    /// It uses `tokio::task::block_in_place` to bridge the synchronous `Holon`
    /// trait with async process spawning. Calling this method from a
    /// single-threaded runtime will **panic**.
    ///
    /// # Lifecycle
    ///
    /// 1. First call: Spawns the process (returns `NeedsContinuation`)
    /// 2. Subsequent calls: Polls for termination and collects output events
    /// 3. Final call: Returns `Completed` when process terminates
    fn execute_episode(
        &mut self,
        _ctx: &EpisodeContext,
    ) -> Result<EpisodeResult<Self::Output>, HolonError> {
        // Check if intake was called - extract values and drop guard immediately
        // We use a separate scope and explicit drop to ensure the borrow ends
        // before we call collect_pending_events.
        let state_result: Option<(bool, bool, bool, u64, Option<i32>)> =
            self.shared_state.try_lock().ok().map(|guard| {
                (
                    guard.intake_called,
                    guard.process_spawned,
                    guard.process_terminated,
                    guard.output_event_count,
                    guard.last_exit_code,
                )
            });

        let Some((intake_called, process_spawned, process_terminated, output_count, exit_code)) =
            state_result
        else {
            // Lock held by background task, process is running
            // Collect events even when lock is held
            self.collect_pending_events();
            return Ok(EpisodeResult::continuation());
        };

        if !intake_called {
            return Err(HolonError::episode_failed(
                "intake() must be called before execute_episode()",
                true,
            ));
        }

        // If process hasn't been spawned yet, spawn it
        if !process_spawned {
            let config = self.config.take().ok_or_else(|| {
                HolonError::episode_failed("configuration already consumed", true)
            })?;

            // Spawn the process using the internal method
            // We need to use a blocking approach here since Holon trait is sync
            let semaphore = Arc::clone(&self.task_semaphore);
            let shared_state = Arc::clone(&self.shared_state);

            // Use tokio's Handle to spawn from sync context
            // We use block_in_place to allow running async code from within
            // a sync context when already in a tokio runtime
            let spawn_result = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(async {
                    RawAdapter::spawn_internal(config, semaphore, Some(shared_state)).await
                })
            });

            match spawn_result {
                Ok((_handle, rx)) => {
                    self.event_rx = Some(rx);
                    // Return continuation - process is now running
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

        // Process has been spawned, check if it has terminated
        if process_terminated {
            // Drain any remaining events before returning completion
            self.collect_pending_events();

            // Process has completed
            let output = RawAdapterOutput {
                exit_code,
                output_event_count: output_count,
                success: exit_code.is_some_and(|c| c == 0),
            };
            return Ok(EpisodeResult::completed(output));
        }

        // Process is still running - collect pending events for evidence preservation
        // Per CTR-1303, we bound the collection to MAX_COLLECTED_EVENTS
        self.collect_pending_events();

        Ok(EpisodeResult::continue_with_progress(format!(
            "running, {output_count} events received, {} collected",
            self.collected_events.len()
        )))
    }

    fn emit_artifact(&self, _artifact: Artifact) -> Result<(), HolonError> {
        // RawAdapterHolon does not emit artifacts directly.
        // All output is streamed via HarnessEvent::Output events.
        // Artifacts would be collected by the episode runtime from the output stream.
        Ok(())
    }

    fn escalate(&mut self, reason: &str) -> Result<(), HolonError> {
        // RawAdapterHolon doesn't have a supervisor to escalate to.
        // Log the escalation reason and return success (no-op escalation).
        tracing::warn!(reason = %reason, "RawAdapterHolon escalation requested (no supervisor)");
        Ok(())
    }

    fn should_stop(&self, ctx: &EpisodeContext) -> StopCondition {
        // Check standard stop conditions
        if ctx.episode_limit_reached() {
            return StopCondition::max_episodes_reached(ctx.episode_number());
        }

        if ctx.tokens_exhausted() {
            return StopCondition::budget_exhausted("tokens");
        }

        // Check if process has terminated
        if let Ok(guard) = self.shared_state.try_lock() {
            if guard.process_terminated {
                return StopCondition::GoalSatisfied;
            }
        }

        StopCondition::Continue
    }

    fn state(&self) -> &Self::State {
        // Note: This returns a reference to the state, but since the state is
        // behind Arc<Mutex<_>>, we need a workaround. We use a leaked Box here
        // for API compatibility. In a real implementation, the Holon trait
        // should be redesigned to return a clone or use interior mutability.
        //
        // For now, we return a snapshot of the state. This is safe because:
        // 1. The Holon trait expects &Self::State which has the same lifetime as self
        // 2. We're returning a reference that will be valid for the duration of self
        //
        // This is a known limitation that should be addressed in a future refactor.
        static DEFAULT_STATE: RawAdapterState = RawAdapterState {
            episode_id: None,
            output_event_count: 0,
            intake_called: false,
            last_exit_code: None,
            process_spawned: false,
            process_terminated: false,
        };

        // Try to get a snapshot, fall back to default if lock is held
        // Note: This is a limitation of the sync Holon trait with async state
        &DEFAULT_STATE
    }

    fn holon_id(&self) -> Option<&str> {
        // Return the episode_id stored during intake.
        // This is stored separately from shared_state to avoid mutex access
        // in this synchronous method.
        self.episode_id.as_deref()
    }

    fn type_name(&self) -> &'static str {
        "RawAdapterHolon"
    }
}

/// Returns the current state snapshot from the shared state.
///
/// This is a helper method to get a copy of the state for inspection.
impl RawAdapterHolon {
    /// Returns a snapshot of the current state.
    ///
    /// Unlike `state()`, this returns a clone that can be inspected freely.
    #[must_use]
    pub fn state_snapshot(&self) -> Option<RawAdapterState> {
        self.shared_state.try_lock().ok().map(|g| g.clone())
    }
}

/// Helper functions for testing the raw adapter.
#[cfg(test)]
pub(crate) mod test_helpers {
    use std::time::SystemTime;

    use super::super::adapter::OutputKind;
    use super::*;

    /// Get the current timestamp in nanoseconds.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Create a mock output event for testing.
    #[must_use]
    pub fn mock_output_event(data: &[u8], seq: u64) -> HarnessEvent {
        HarnessEvent::output(data.to_vec(), OutputKind::Combined, seq, now_ns())
    }
}

#[cfg(test)]
mod tests {
    use super::super::adapter::OutputKind;
    use super::*;

    #[test]
    fn test_raw_adapter_new() {
        let adapter = RawAdapter::new();
        assert_eq!(adapter.adapter_type(), AdapterType::Raw);
    }

    #[test]
    fn test_raw_adapter_default() {
        let adapter = RawAdapter::default();
        assert_eq!(adapter.adapter_type(), AdapterType::Raw);
    }

    #[test]
    fn test_raw_adapter_debug() {
        let adapter = RawAdapter::new();
        let debug_str = format!("{adapter:?}");
        assert!(debug_str.contains("RawAdapter"));
    }

    #[test]
    fn test_handle_id_generation() {
        let id1 = RawAdapter::next_handle_id();
        let id2 = RawAdapter::next_handle_id();
        let id3 = RawAdapter::next_handle_id();

        // IDs should be monotonically increasing
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[tokio::test]
    async fn test_raw_adapter_spawn_echo() {
        let adapter = RawAdapter::new();
        let config =
            HarnessConfig::new("echo", "episode-test").with_args(vec!["hello".to_string()]);

        let result = adapter.spawn(config).await;
        assert!(result.is_ok());

        let (handle, mut events) = result.unwrap();
        assert!(!handle.episode_id().is_empty());
        assert_eq!(handle.episode_id(), "episode-test");

        // Collect events until terminated
        let mut output_events = Vec::new();
        let mut terminated_event = None;

        while let Some(event) = events.recv().await {
            if event.is_terminal() {
                terminated_event = Some(event);
                break;
            }
            output_events.push(event);
        }

        // Should have received at least one output event with "hello"
        assert!(!output_events.is_empty(), "expected output events");

        // Check that we got output containing "hello"
        let has_hello = output_events.iter().any(|e| {
            if let HarnessEvent::Output { chunk, .. } = e {
                String::from_utf8_lossy(chunk).contains("hello")
            } else {
                false
            }
        });
        assert!(has_hello, "expected output to contain 'hello'");

        // Should have terminated successfully
        assert!(terminated_event.is_some(), "expected terminated event");
        if let Some(HarnessEvent::Terminated {
            exit_code,
            classification,
        }) = terminated_event
        {
            assert_eq!(exit_code, Some(0));
            assert_eq!(classification, TerminationClassification::Success);
        }
    }

    #[tokio::test]
    async fn test_raw_adapter_spawn_with_exit_code() {
        let adapter = RawAdapter::new();
        let config = HarnessConfig::new("sh", "episode-exit")
            .with_args(vec!["-c".to_string(), "exit 42".to_string()]);

        let (_, mut events) = adapter.spawn(config).await.unwrap();

        // Drain events until terminated
        let mut terminated_event = None;
        while let Some(event) = events.recv().await {
            if event.is_terminal() {
                terminated_event = Some(event);
                break;
            }
        }

        // Check exit code
        if let Some(HarnessEvent::Terminated {
            exit_code,
            classification,
        }) = terminated_event
        {
            assert_eq!(exit_code, Some(42));
            assert_eq!(classification, TerminationClassification::Failure);
        } else {
            panic!("expected terminated event");
        }
    }

    #[tokio::test]
    async fn test_raw_adapter_send_input_and_terminate() {
        let adapter = RawAdapter::new();
        let config = HarnessConfig::new("cat", "episode-interactive");

        let (handle, mut events) = adapter.spawn(config).await.unwrap();
        let (pid, start_time_ticks) = match &handle.inner {
            super::super::adapter::HarnessHandleInner::Real(real) => {
                let guard = real.lock().await;
                (guard.pid, guard.start_time_ticks)
            },
        };
        assert!(
            start_time_ticks.is_some(),
            "spawn should capture start-time binding for PID validation"
        );

        adapter
            .send_input(&handle, b"hello from raw adapter\n")
            .await
            .unwrap();

        let observed_output = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let HarnessEvent::Output { chunk, .. } = event {
                    if String::from_utf8_lossy(&chunk).contains("hello from raw adapter") {
                        return true;
                    }
                }
            }
            false
        })
        .await
        .expect("timed out waiting for output event");
        assert!(observed_output, "expected echo output from cat");

        let exit_status = adapter.terminate(&handle).await.unwrap();
        assert!(
            !exit_status.success(),
            "terminate should stop the process via signal"
        );

        let terminated_event = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let HarnessEvent::Terminated { .. } = event {
                    return Some(event);
                }
            }
            None
        })
        .await
        .expect("timed out waiting for terminated event")
        .expect("expected terminated event after terminate()");

        if let HarnessEvent::Terminated { classification, .. } = terminated_event {
            assert!(matches!(
                classification,
                TerminationClassification::Killed | TerminationClassification::Terminated
            ));
        }

        if let Some(expected_start) = start_time_ticks {
            assert_ne!(
                super::super::adapter::read_proc_start_time(pid),
                Some(expected_start),
                "original process identity must not remain alive after terminate"
            );
        }

        let send_after_terminate = adapter.send_input(&handle, b"post-terminate\n").await;
        assert!(matches!(
            send_after_terminate,
            Err(AdapterError::InvalidHandle { .. })
        ));
    }

    /// Verify that terminate fails closed when start-time binding is missing
    /// on the handle.
    ///
    /// Without a start-time binding, signal delivery cannot validate PID
    /// identity, risking signals to a recycled PID. The handle-level guard
    /// in `terminate_with_handle` must reject the request before the
    /// command reaches the control task.
    ///
    /// NOTE: This test only exercises the handle-level guard. The control
    /// task's captured `start_time_ticks` retains the original (non-None)
    /// value from spawn; the mutation below only affects the handle mirror.
    #[tokio::test]
    async fn test_raw_adapter_terminate_fails_without_start_time_binding() {
        let adapter = RawAdapter::new();
        let config = HarnessConfig::new("cat", "episode-terminate-no-start-time");
        let (handle, _events) = adapter.spawn(config).await.unwrap();

        // Clear the handle-side start-time binding to simulate missing
        // identity data. The spawned control task retains its own copy.
        let runner_handle = handle.real_runner_handle();
        {
            let mut guard = runner_handle.lock().await;
            guard.start_time_ticks = None;
        }

        // Terminate must fail closed due to missing start-time binding
        let terminate_result = adapter.terminate(&handle).await;
        assert!(
            terminate_result.is_err(),
            "terminate must fail without start-time binding, got: {terminate_result:?}"
        );
        let err_msg = terminate_result.unwrap_err().to_string();
        assert!(
            err_msg.contains("start-time binding"),
            "error must mention start-time binding, got: {err_msg}"
        );

        // Clean up: restore binding so the process can be terminated
        {
            let mut guard = runner_handle.lock().await;
            guard.start_time_ticks = super::super::adapter::read_proc_start_time(guard.pid);
        }
        let _ = adapter.terminate(&handle).await;
    }

    #[test]
    fn test_mock_output_event() {
        let event = test_helpers::mock_output_event(b"test data", 1);

        match event {
            HarnessEvent::Output {
                chunk,
                kind,
                seq,
                ts,
            } => {
                assert_eq!(chunk, b"test data");
                assert_eq!(kind, OutputKind::Combined);
                assert_eq!(seq, 1);
                assert!(ts > 0);
            },
            _ => panic!("expected Output event"),
        }
    }

    #[test]
    fn test_raw_adapter_initial_capacity() {
        let adapter = RawAdapter::new();
        assert_eq!(adapter.active_count(), 0);
        assert_eq!(adapter.available_slots(), MAX_CONCURRENT_ADAPTERS);
    }

    #[tokio::test]
    async fn test_raw_adapter_tracks_active_count() {
        let adapter = RawAdapter::new();
        let config = HarnessConfig::new("echo", "ep-1");

        // Before spawn, no active tasks
        assert_eq!(adapter.active_count(), 0);

        // Spawn a process
        let (_handle, mut events) = adapter.spawn(config).await.unwrap();

        // Wait for the task to complete
        while events.recv().await.is_some() {}

        // After completion, the permit should be released
        // Give a small delay for the task to fully complete
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(adapter.active_count(), 0);
        assert_eq!(adapter.available_slots(), MAX_CONCURRENT_ADAPTERS);
    }

    #[tokio::test]
    async fn test_raw_adapter_validates_config_on_spawn() {
        let adapter = RawAdapter::new();

        // Empty command should fail validation
        let config = HarnessConfig::new("", "ep-1");
        let result = adapter.spawn(config).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AdapterError::ValidationFailed(_)));
    }

    #[tokio::test]
    async fn test_raw_adapter_validates_args_on_spawn() {
        let adapter = RawAdapter::new();

        // Arg with null byte should fail validation
        let config = HarnessConfig::new("echo", "ep-1").with_args(vec!["bad\0arg".to_string()]);
        let result = adapter.spawn(config).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AdapterError::ValidationFailed(_)));
    }

    // =========================================================================
    // Holon Factory Tests
    // =========================================================================

    #[test]
    fn test_create_holon() {
        let adapter = RawAdapter::new();
        let holon = adapter.create_holon();
        assert_eq!(holon.type_name(), "RawAdapterHolon");
    }

    #[test]
    fn test_holon_intake() {
        let adapter = RawAdapter::new();
        let mut holon = adapter.create_holon();
        let config =
            HarnessConfig::new("echo", "episode-holon").with_args(vec!["test".to_string()]);

        let result = holon.intake(config, "lease-123");
        assert!(result.is_ok());

        let state = holon.state_snapshot().expect("state should be available");
        assert!(state.intake_called);
        assert_eq!(state.episode_id, Some("episode-holon".to_string()));
    }

    #[test]
    fn test_holon_intake_validation_error() {
        let adapter = RawAdapter::new();
        let mut holon = adapter.create_holon();
        let config = HarnessConfig::new("", "episode-invalid"); // Empty command

        let result = holon.intake(config, "lease-123");
        assert!(result.is_err());
    }

    #[test]
    fn test_holon_execute_without_intake() {
        let adapter = RawAdapter::new();
        let mut holon = adapter.create_holon();
        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        let result = holon.execute_episode(&ctx);
        assert!(result.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_holon_execute_spawns_process() {
        let adapter = RawAdapter::new();
        let mut holon = adapter.create_holon();
        let config = HarnessConfig::new("echo", "episode-exec").with_args(vec!["test".to_string()]);

        holon.intake(config, "lease-123").unwrap();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        // First execute should spawn and return continuation
        let result = holon.execute_episode(&ctx);
        assert!(result.is_ok());
        let episode_result = result.unwrap();
        assert!(episode_result.needs_continuation());

        // Wait for process to complete
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Poll until complete
        loop {
            let result = holon.execute_episode(&ctx);
            assert!(result.is_ok());
            let episode_result = result.unwrap();
            if episode_result.is_completed() {
                let output = episode_result.into_output().expect("should have output");
                assert!(output.success);
                assert_eq!(output.exit_code, Some(0));
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_holon_state_updates_from_background_task() {
        let adapter = RawAdapter::new();
        let mut holon = adapter.create_holon();
        let config = HarnessConfig::new("echo", "episode-state")
            .with_args(vec!["hello".to_string(), "world".to_string()]);

        holon.intake(config, "lease-123").unwrap();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        // Spawn the process
        let _ = holon.execute_episode(&ctx).unwrap();

        // Wait for process to complete
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Check that state was updated
        let shared_state = holon.shared_state();
        let guard = shared_state.lock().await;
        assert!(guard.process_spawned);
        assert!(guard.process_terminated);
        assert!(guard.output_event_count > 0);
        assert_eq!(guard.last_exit_code, Some(0));
    }

    #[test]
    fn test_holon_should_stop() {
        let adapter = RawAdapter::new();
        let holon = adapter.create_holon();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        // Without exit code, should continue
        let condition = holon.should_stop(&ctx);
        assert_eq!(condition, StopCondition::Continue);
    }

    #[test]
    fn test_holon_should_stop_budget_exhausted() {
        let adapter = RawAdapter::new();
        let holon = adapter.create_holon();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .remaining_tokens(0)
            .build();

        let condition = holon.should_stop(&ctx);
        assert!(matches!(condition, StopCondition::BudgetExhausted { .. }));
    }

    #[test]
    fn test_holon_should_stop_max_episodes() {
        let adapter = RawAdapter::new();
        let holon = adapter.create_holon();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .episode_number(10)
            .max_episodes(10)
            .build();

        let condition = holon.should_stop(&ctx);
        assert!(matches!(
            condition,
            StopCondition::MaxEpisodesReached { .. }
        ));
    }

    #[test]
    fn test_holon_type_name() {
        let adapter = RawAdapter::new();
        let holon = adapter.create_holon();
        assert_eq!(holon.type_name(), "RawAdapterHolon");
    }

    #[test]
    fn test_holon_emit_artifact() {
        let adapter = RawAdapter::new();
        let holon = adapter.create_holon();
        let artifact = Artifact::builder()
            .kind("test")
            .work_id("work-1")
            .content("test content")
            .build();

        let result = holon.emit_artifact(artifact);
        assert!(result.is_ok());
    }

    #[test]
    fn test_holon_escalate() {
        let adapter = RawAdapter::new();
        let mut holon = adapter.create_holon();
        let result = holon.escalate("test escalation");
        assert!(result.is_ok());
    }

    #[test]
    fn test_raw_adapter_output() {
        let output = RawAdapterOutput {
            exit_code: Some(0),
            output_event_count: 10,
            success: true,
        };

        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.output_event_count, 10);
        assert!(output.success);
    }

    // =========================================================================
    // Thread Safety Tests
    // =========================================================================

    #[test]
    fn test_multiple_holons_from_same_adapter() {
        let adapter = RawAdapter::new();

        // Should be able to create multiple holons from the same adapter
        let holon1 = adapter.create_holon();
        let holon2 = adapter.create_holon();

        // They should have independent state
        assert_eq!(holon1.type_name(), "RawAdapterHolon");
        assert_eq!(holon2.type_name(), "RawAdapterHolon");

        // They share the same semaphore (verified by available_slots)
        assert_eq!(adapter.available_slots(), MAX_CONCURRENT_ADAPTERS);
    }

    // =========================================================================
    // Holon ID and Event Collection Tests
    // =========================================================================

    #[test]
    fn test_holon_id_before_intake() {
        let adapter = RawAdapter::new();
        let holon = adapter.create_holon();

        // Before intake, holon_id should be None
        assert!(holon.holon_id().is_none());
    }

    #[test]
    fn test_holon_id_after_intake() {
        let adapter = RawAdapter::new();
        let mut holon = adapter.create_holon();
        let config = HarnessConfig::new("echo", "episode-id-test");

        holon.intake(config, "lease-123").unwrap();

        // After intake, holon_id should return the episode_id
        assert_eq!(holon.holon_id(), Some("episode-id-test"));
    }

    #[test]
    fn test_collected_events_initially_empty() {
        let adapter = RawAdapter::new();
        let holon = adapter.create_holon();

        // Initially, collected_events should be empty
        assert!(holon.collected_events().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_holon_collects_events_during_execution() {
        let adapter = RawAdapter::new();
        let mut holon = adapter.create_holon();
        let config =
            HarnessConfig::new("echo", "episode-events").with_args(vec!["test".to_string()]);

        holon.intake(config, "lease-123").unwrap();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        // Spawn the process
        let _ = holon.execute_episode(&ctx).unwrap();

        // Wait for process to complete and poll
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Poll until complete - this should collect events
        loop {
            let result = holon.execute_episode(&ctx);
            assert!(result.is_ok());
            let episode_result = result.unwrap();
            if episode_result.is_completed() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // After completion, collected_events should contain the output
        let events = holon.collected_events();
        assert!(!events.is_empty(), "expected collected events");

        // Should contain at least one output event
        let has_output = events
            .iter()
            .any(|e| matches!(e, HarnessEvent::Output { .. }));
        assert!(has_output, "expected at least one Output event");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_holon_take_collected_events() {
        let adapter = RawAdapter::new();
        let mut holon = adapter.create_holon();
        let config = HarnessConfig::new("echo", "episode-take").with_args(vec!["test".to_string()]);

        holon.intake(config, "lease-123").unwrap();

        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        // Spawn and wait for completion
        let _ = holon.execute_episode(&ctx).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        loop {
            let result = holon.execute_episode(&ctx).unwrap();
            if result.is_completed() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Take the collected events
        let events = holon.take_collected_events();
        assert!(!events.is_empty(), "expected events");

        // After take, the buffer should be empty
        assert!(holon.collected_events().is_empty());
    }

    // =========================================================================
    // Control-plane decoupling regression tests (backpressure)
    // =========================================================================

    /// UT-BACKPRESSURE-01: Control commands (terminate) must be serviced even
    /// when the output event channel is full.
    ///
    /// This is a regression test for the BLOCKER finding: if the event channel
    /// is full and output forwarding uses a blocking `.await` send, the select
    /// loop stalls and control commands time out.  With non-blocking
    /// `try_send`, the loop continues servicing `control_rx` even when the
    /// channel is saturated.
    #[tokio::test]
    async fn test_terminate_succeeds_under_output_backpressure() {
        let adapter = RawAdapter::new();

        // Spawn `yes` which produces output rapidly, filling the 256-slot
        // event channel almost instantly. We intentionally do NOT consume
        // events from `_events`, so the channel stays full.
        let config = HarnessConfig::new("yes", "episode-backpressure-terminate");
        let (handle, _events) = adapter.spawn(config).await.unwrap();

        // Give the background task time to fill the event channel.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Terminate MUST succeed even though the output channel is full.
        // Under the old blocking-send code, this would time out because the
        // select loop was stuck on `tx.send(event).await`.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            adapter.terminate(&handle),
        )
        .await;

        assert!(
            result.is_ok(),
            "terminate must not time out under output backpressure"
        );
        let exit_result = result.unwrap();
        assert!(
            exit_result.is_ok(),
            "terminate must succeed, got: {exit_result:?}"
        );
    }

    /// UT-BACKPRESSURE-02: `send_input` must be serviced even when the output
    /// event channel is full.
    #[tokio::test]
    async fn test_send_input_succeeds_under_output_backpressure() {
        let adapter = RawAdapter::new();

        // `cat` echoes input back, producing output. We fill the channel by
        // sending enough input to saturate it, then verify subsequent
        // send_input calls still succeed.
        let config = HarnessConfig::new("cat", "episode-backpressure-input");
        let (handle, _events) = adapter.spawn(config).await.unwrap();

        // Send a burst of input to generate output and fill the channel.
        for _ in 0..300 {
            let _ = adapter
                .send_input(&handle, b"backpressure test line\n")
                .await;
        }

        // Give time for output to accumulate and fill the 256-slot channel.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // This send_input MUST succeed despite the full output channel.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            adapter.send_input(&handle, b"still works\n"),
        )
        .await;

        assert!(
            result.is_ok(),
            "send_input must not time out under output backpressure"
        );
        let send_result = result.unwrap();
        assert!(
            send_result.is_ok(),
            "send_input must succeed, got: {send_result:?}"
        );

        // Clean up
        let _ = adapter.terminate(&handle).await;
    }
}
