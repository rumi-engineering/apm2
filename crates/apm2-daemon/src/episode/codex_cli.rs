//! Codex CLI harness adapter with TI1 tool bridge protocol.
//!
//! This module implements the [`CodexCliAdapter`] using the blanket-preserving
//! TI1 delimiter grammar (RFC-0019 section 11, Option C). Agent output is
//! scanned for `⟦TI1 <nonce>⟧` delimited tool requests; all other output is
//! treated as opaque internal state (Markov blanket preserved).
//!
//! # Architecture
//!
//! ```text
//! PTY Output ──► TI1 Scanner ──► HarnessEvent Stream
//!                     │
//!                     ├── Output events (opaque agent text)
//!                     ├── ToolRequest events (parsed TI1 frames)
//!                     └── Error events (parse failures)
//! ```
//!
//! # Security Invariants
//!
//! - Agent output NOT matching TI1 delimiter is NEVER interpreted as tool
//!   requests (Markov blanket preserved per RFC-0020 section 2.2.1)
//! - Nonce is per-episode: `BLAKE3(nonce_prefix || episode_id ||
//!   spawn_time_ns)`
//! - TI1 args are bounded by `max_args_size` from `ToolBridgeConfig`
//! - Model parameter is validated against `[a-zA-Z0-9.\-]+` to prevent command
//!   injection
//! - `--dangerously-bypass-approvals-and-sandbox` is disabled by default, only
//!   enabled behind WVR-0002 waiver guard
//! - `CODEX_HEADLESS=1` prevents interactive prompts
//!
//! # Contract References
//!
//! - AD-ADAPT-001: `HarnessAdapter` implements Holon trait
//! - CTR-DAEMON-003: `HarnessAdapter` trait
//! - RFC-0019 section 11: TI1 `ToolIntent` protocol

use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use apm2_core::fac::ToolBridgeConfig;
use apm2_holon::{Artifact, EpisodeContext, EpisodeResult, Holon, HolonError, StopCondition};
use tokio::sync::{Mutex, Semaphore};

use super::adapter::{
    AdapterError, AdapterResult, AdapterType, HarnessAdapter, HarnessConfig, HarnessEvent,
    HarnessEventStream, HarnessHandle, MAX_SEND_INPUT_BYTES, OutputKind, TerminationClassification,
    create_real_handle_inner, process_pty_control_command, pty_control_channel_capacity,
    read_proc_start_time, send_input_with_handle, terminate_with_handle,
};
use super::pty::{PtyConfig, PtyRunner};
use super::raw_adapter::MAX_CONCURRENT_ADAPTERS;
use super::ti1_scanner::{Ti1ScannerConfig, compute_nonce, scan_output};

/// Counter for generating unique handle IDs.
static HANDLE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Maximum number of events to collect in the holon's event buffer.
///
/// Per CTR-1303 (Bounded Stores), in-memory stores must have `max_entries`
/// limits to prevent denial-of-service via memory exhaustion.
pub const MAX_COLLECTED_EVENTS: usize = 16384;

/// Regex pattern for valid model parameter strings.
///
/// Only alphanumeric characters, dots, and hyphens are allowed to prevent
/// command injection.
fn validate_model_param(model: &str) -> Result<(), AdapterError> {
    if model.is_empty() {
        return Err(AdapterError::spawn_failed(
            "model parameter cannot be empty",
        ));
    }
    if !model
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(AdapterError::spawn_failed(format!(
            "model parameter contains invalid characters: '{model}' \
             (only alphanumeric, dots, and hyphens allowed)",
        )));
    }
    Ok(())
}

// ============================================================================
// Output Types
// ============================================================================

/// Output produced by the `CodexCliAdapter` when used as a Holon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexCliOutput {
    /// Exit code from the process, if available.
    pub exit_code: Option<i32>,
    /// Number of output events emitted.
    pub output_event_count: u64,
    /// Number of TI1 tool requests parsed.
    pub tool_request_count: u64,
    /// Whether the process terminated successfully.
    pub success: bool,
}

/// State of the `CodexCliAdapter` when used as a Holon.
#[derive(Debug, Clone, Default)]
pub struct CodexCliState {
    /// Current episode ID being processed.
    pub episode_id: Option<String>,
    /// Number of output events received in current episode.
    pub output_event_count: u64,
    /// Number of TI1 tool requests parsed.
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
pub type SharedCodexCliState = Arc<Mutex<CodexCliState>>;

// ============================================================================
// Codex CLI Adapter
// ============================================================================

/// Configuration for the Codex CLI adapter.
#[derive(Debug, Clone)]
pub struct CodexCliAdapterConfig {
    /// Model to use (e.g., "gpt-5.3-codex"). Validated against safe pattern.
    pub model: String,
    /// Tool bridge configuration from the selected adapter profile.
    pub tool_bridge_config: ToolBridgeConfig,
    /// Capability map: agent tool names -> kernel tool classes.
    pub capability_map: HashMap<String, String>,
    /// Whether `--dangerously-bypass-approvals-and-sandbox` is enabled.
    /// Default: false. Only enabled behind WVR-0002 waiver guard.
    pub bypass_enabled: bool,
}

impl Default for CodexCliAdapterConfig {
    fn default() -> Self {
        Self {
            model: "gpt-5.3-codex".to_string(),
            tool_bridge_config: ToolBridgeConfig {
                nonce_prefix: "codex".to_string(),
                ..ToolBridgeConfig::default()
            },
            capability_map: HashMap::new(),
            bypass_enabled: false,
        }
    }
}

/// Codex CLI harness adapter with TI1 tool bridge protocol.
///
/// This adapter spawns `codex exec` processes and scans their PTY output for
/// TI1-framed tool requests. Non-matching output is treated as opaque agent
/// internal state (Markov blanket preserved).
///
/// # Resource Bounds
///
/// The adapter enforces [`MAX_CONCURRENT_ADAPTERS`] concurrent processes to
/// prevent resource exhaustion.
///
/// # Holon Factory
///
/// Per AD-LAYER-001 and AD-ADAPT-001, `CodexCliAdapter` provides per-episode
/// [`Holon`] instances via [`create_holon`](Self::create_holon).
#[derive(Debug)]
pub struct CodexCliAdapter {
    /// Semaphore for tracking and limiting concurrent spawned tasks.
    task_semaphore: Arc<Semaphore>,
    /// Adapter configuration.
    config: CodexCliAdapterConfig,
    /// Per-handle nonce and framing state for TR1 stdin injection.
    handle_bridge_state: Arc<Mutex<HashMap<u64, HandleBridgeState>>>,
}

#[derive(Debug, Clone)]
struct HandleBridgeState {
    nonce: String,
    tr1_framing_enabled: bool,
}

impl Default for CodexCliAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CodexCliAdapter {
    /// Create a new Codex CLI adapter with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(CodexCliAdapterConfig::default())
    }

    /// Create a new adapter with custom configuration.
    #[must_use]
    pub fn with_config(config: CodexCliAdapterConfig) -> Self {
        Self {
            task_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_ADAPTERS)),
            config,
            handle_bridge_state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Creates a per-episode Holon instance for holonic coordination.
    ///
    /// Per AD-LAYER-001 and AD-ADAPT-001, this factory method creates a fresh
    /// [`CodexCliHolon`] for each episode.
    #[must_use]
    pub fn create_holon(&self) -> Box<CodexCliHolon> {
        Box::new(CodexCliHolon::new(
            Arc::clone(&self.task_semaphore),
            self.config.clone(),
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

    /// Returns true when the command targets Codex CLI.
    fn is_codex_command(command: &str) -> bool {
        std::path::Path::new(command)
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name == "codex")
    }

    /// Best-effort prompt extraction from CLI args.
    fn extract_prompt_arg(args: &[String]) -> String {
        // Expected codex shape: exec -m <model> <prompt> OR exec <prompt>
        if let Some(model_idx) = args.iter().position(|arg| arg == "-m") {
            if model_idx + 2 < args.len() {
                return args[model_idx + 2].clone();
            }
        }
        args.last().cloned().unwrap_or_default()
    }

    /// Maps TI1 tool names to kernel tool classes via capability map.
    fn map_tool_intent(
        capability_map: &HashMap<String, String>,
        tool_name: &str,
    ) -> Option<String> {
        capability_map.get(tool_name).cloned()
    }

    fn frame_tr1_stdin_payload(nonce: &str, raw_payload: &[u8]) -> AdapterResult<Vec<u8>> {
        let payload = std::str::from_utf8(raw_payload).map_err(|e| {
            AdapterError::input_failed(format!("TR1 payload must be valid UTF-8: {e}"))
        })?;
        let payload = payload.trim();
        if payload.is_empty() {
            return Err(AdapterError::input_failed(
                "TR1 payload cannot be empty for codex adapter",
            ));
        }

        if payload.starts_with('\u{27E6}') && payload.starts_with("⟦TR1 ") {
            let mut framed = payload.to_string();
            if !framed.ends_with('\n') {
                framed.push('\n');
            }
            return Ok(framed.into_bytes());
        }

        Ok(format!("\u{27E6}TR1 {nonce}\u{27E7} {payload}\n").into_bytes())
    }

    /// Converts `HarnessConfig` env map to the `(CString, CString)` pairs
    /// expected by `PtyConfig`.
    fn harness_env_to_pty_env(
        env: &std::collections::HashMap<String, secrecy::SecretString>,
    ) -> Vec<(std::ffi::CString, std::ffi::CString)> {
        use secrecy::ExposeSecret;
        env.iter()
            .filter_map(|(k, v)| {
                let key = std::ffi::CString::new(k.as_bytes()).ok()?;
                let val = std::ffi::CString::new(v.expose_secret().as_bytes()).ok()?;
                Some((key, val))
            })
            .collect()
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

    /// Internal spawn implementation with TI1 scanning.
    async fn spawn_internal(
        config: HarnessConfig,
        semaphore: Arc<Semaphore>,
        adapter_config: CodexCliAdapterConfig,
        shared_state: Option<SharedCodexCliState>,
        handle_bridge_state: Arc<Mutex<HashMap<u64, HandleBridgeState>>>,
    ) -> AdapterResult<(HarnessHandle, HarnessEventStream)> {
        // Validate configuration before spawning
        config.validate()?;

        if !adapter_config.tool_bridge_config.enabled {
            return Err(AdapterError::spawn_failed(
                "codex tool_bridge must be enabled",
            ));
        }
        if adapter_config.tool_bridge_config.protocol_version != "TI1" {
            return Err(AdapterError::spawn_failed(format!(
                "unsupported tool bridge protocol '{}': expected TI1",
                adapter_config.tool_bridge_config.protocol_version
            )));
        }

        // Validate model parameter to prevent command injection
        validate_model_param(&adapter_config.model)?;

        // Try to acquire a permit without blocking
        let permit = semaphore.clone().try_acquire_owned().map_err(|_| {
            AdapterError::resource_limit_exceeded(format!(
                "maximum concurrent adapters ({MAX_CONCURRENT_ADAPTERS}) reached"
            ))
        })?;

        let handle_id = Self::next_handle_id();
        let episode_id = config.episode_id.clone();
        let terminate_grace_period = config.terminate_grace_period;
        let (cols, rows) = config.pty_size;

        // Get timestamp for spawn (also used for nonce derivation)
        let timestamp_ns = Self::now_ns();

        // Compute per-episode nonce
        let nonce = compute_nonce(
            &adapter_config.tool_bridge_config.nonce_prefix,
            &episode_id,
            timestamp_ns,
        );

        // For codex command paths, inject TI1 preamble + model arg at spawn.
        let mut spawn_config = config;
        if Self::is_codex_command(&spawn_config.command) {
            let prompt = Self::extract_prompt_arg(&spawn_config.args);
            let mut rebuilt_config = build_codex_harness_config(
                &episode_id,
                &prompt,
                &adapter_config.model,
                &nonce,
                &adapter_config.capability_map,
                adapter_config.bypass_enabled,
            )
            .with_terminate_grace_period(terminate_grace_period)
            .with_pty_size(cols, rows);

            if let Some(cwd) = spawn_config.cwd.clone() {
                rebuilt_config = rebuilt_config.with_cwd(cwd);
            }
            for (key, value) in &spawn_config.env {
                rebuilt_config = rebuilt_config.with_secret_env(key.clone(), value.clone());
            }

            rebuilt_config.validate()?;
            spawn_config = rebuilt_config;
        }

        // Create PTY configuration from harness config.
        let mut pty_config = PtyConfig::default().with_window_size(cols, rows);
        if let Some(ref cwd) = spawn_config.cwd {
            pty_config = pty_config.with_cwd(cwd);
        }
        pty_config = pty_config.with_env(Self::harness_env_to_pty_env(&spawn_config.env));

        // Build args slice
        let args: Vec<&str> = spawn_config.args.iter().map(String::as_str).collect();

        // Spawn the process via PtyRunner
        let mut runner =
            PtyRunner::spawn(&spawn_config.command, &args, pty_config, timestamp_ns)
                .map_err(|e| AdapterError::spawn_failed(format!("PTY spawn failed: {e}")))?;
        let pid_raw = runner.pid().as_raw();
        let pid = u32::try_from(pid_raw)
            .map_err(|_| AdapterError::spawn_failed(format!("invalid PTY child pid: {pid_raw}")))?;
        let start_time_ticks = read_proc_start_time(pid);

        let (control_tx, mut control_rx) =
            tokio::sync::mpsc::channel(pty_control_channel_capacity());
        let handle_inner = create_real_handle_inner(pid, start_time_ticks, control_tx);

        // Register per-handle nonce for TR1 response framing in send_input().
        {
            let mut guard = handle_bridge_state.lock().await;
            guard.insert(
                handle_id,
                HandleBridgeState {
                    nonce: nonce.clone(),
                    tr1_framing_enabled: Self::is_codex_command(&spawn_config.command),
                },
            );
        }

        // Create the event channel
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        // Mark process as spawned in shared state if provided
        if let Some(ref state) = shared_state {
            let mut guard = state.lock().await;
            guard.process_spawned = true;
        }

        // Create TI1 scanner config
        let scanner_config = Ti1ScannerConfig {
            nonce: nonce.clone(),
            max_args_size: adapter_config.tool_bridge_config.max_args_size,
        };
        let capability_map = adapter_config.capability_map.clone();
        let handle_bridge_state_for_task = Arc::clone(&handle_bridge_state);

        // Spawn a task that reads from the PTY, scans for TI1 frames,
        // and emits events
        let task_episode_id = episode_id.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let episode_id = task_episode_id;

            let mut seq = 0u64;
            let mut exit_status = None;
            let mut control_open = true;
            let mut output_live = true;
            let mut line_buffer = String::new();

            let mut dropped_output_events: u64 = 0;
            let mut dropped_tool_events: u64 = 0;

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
                            if !output_live {
                                break;
                            }
                        }
                    }
                    maybe_output = runner.recv() => {
                        if let Some(output) = maybe_output {
                            if output_live {
                                // Emit raw output event (opaque agent text)
                                let output_event = HarnessEvent::output(
                                    output.chunk.to_vec(),
                                    OutputKind::Combined,
                                    seq,
                                    output.ts_mono,
                                );
                                seq += 1;

                                // Update shared state with output count
                                if let Some(ref state) = shared_state {
                                    let mut guard = state.lock().await;
                                    guard.output_event_count = seq;
                                }

                                match tx.try_send(output_event) {
                                    Ok(()) => {},
                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                        output_live = false;
                                        continue;
                                    },
                                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                        if dropped_output_events == 0 {
                                            tracing::warn!(
                                                episode_id = %episode_id,
                                                seq = seq - 1,
                                                "output event dropped: event channel full (backpressure)"
                                            );
                                        }
                                        dropped_output_events += 1;
                                    },
                                }

                                // Scan for TI1 frames in this output chunk
                                let scan_results = scan_output(
                                    &output.chunk,
                                    &scanner_config,
                                    &mut line_buffer,
                                );

                                for result in scan_results {
                                    match result {
                                        Ok(frame) => {
                                            if let Some(mapped_tool_class) =
                                                Self::map_tool_intent(&capability_map, &frame.tool_name)
                                            {
                                                let tool_event = HarnessEvent::tool_request(
                                                    frame.request_id,
                                                    mapped_tool_class,
                                                    frame.args,
                                                );

                                                // Update shared state
                                                if let Some(ref state) = shared_state {
                                                    let mut guard = state.lock().await;
                                                    guard.tool_request_count += 1;
                                                }

                                                match tx.try_send(tool_event) {
                                                    Ok(()) => {},
                                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                                        output_live = false;
                                                        break;
                                                    },
                                                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                                        if dropped_tool_events == 0 {
                                                            tracing::warn!(
                                                                episode_id = %episode_id,
                                                                "TI1 tool event dropped: event channel full"
                                                            );
                                                        }
                                                        dropped_tool_events += 1;
                                                    },
                                                }
                                            } else {
                                                tracing::warn!(
                                                    episode_id = %episode_id,
                                                    request_id = %frame.request_id,
                                                    tool_name = %frame.tool_name,
                                                    "rejecting TI1 tool request: unmapped capability"
                                                );
                                                let _ = tx.try_send(HarnessEvent::error(
                                                    "TI1_UNKNOWN_TOOL",
                                                    format!(
                                                        "tool '{}' is not declared in capability_map",
                                                        frame.tool_name
                                                    ),
                                                ));
                                            }
                                        },
                                        Err(e) => {
                                            tracing::warn!(
                                                episode_id = %episode_id,
                                                error = %e,
                                                "TI1 frame parse error"
                                            );
                                        },
                                    }
                                }
                            }
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

            // Update shared state with exit code and termination
            if let Some(ref state) = shared_state {
                let mut guard = state.lock().await;
                guard.last_exit_code = exit_code;
                guard.process_terminated = true;
                guard.output_event_count = seq;
            }

            // Log backpressure drop summary
            if dropped_output_events > 0 {
                tracing::warn!(
                    episode_id = %episode_id,
                    dropped_output_events,
                    "task exiting with dropped output events due to backpressure"
                );
            }
            if dropped_tool_events > 0 {
                tracing::warn!(
                    episode_id = %episode_id,
                    dropped_tool_events,
                    "task exiting with dropped TI1 tool events due to backpressure"
                );
            }

            // Emit terminated event with bounded timeout
            let terminated_event = HarnessEvent::terminated(exit_code, classification);
            match tokio::time::timeout(Duration::from_secs(5), tx.send(terminated_event)).await {
                Ok(Ok(())) => {},
                Ok(Err(_)) => {
                    tracing::error!(
                        episode_id = %episode_id,
                        "terminated event could not be delivered: receiver dropped"
                    );
                },
                Err(_) => {
                    tracing::warn!(
                        episode_id = %episode_id,
                        "terminated event delivery timed out (channel full)"
                    );
                },
            }

            let mut guard = handle_bridge_state_for_task.lock().await;
            guard.remove(&handle_id);
        });

        let handle =
            HarnessHandle::new(handle_id, episode_id, terminate_grace_period, handle_inner);

        Ok((handle, rx))
    }
}

impl HarnessAdapter for CodexCliAdapter {
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Codex
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
        let adapter_config = self.config.clone();
        let handle_bridge_state = Arc::clone(&self.handle_bridge_state);

        Box::pin(async move {
            Self::spawn_internal(config, semaphore, adapter_config, None, handle_bridge_state).await
        })
    }

    fn send_input(
        &self,
        handle: &HarnessHandle,
        input: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<()>> + Send + '_>> {
        let handle_id = handle.id();
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
        let handle_bridge_state = Arc::clone(&self.handle_bridge_state);
        Box::pin(async move {
            let maybe_state = {
                let guard = handle_bridge_state.lock().await;
                guard.get(&handle_id).cloned()
            };

            let payload = match maybe_state {
                Some(state) if state.tr1_framing_enabled => {
                    Self::frame_tr1_stdin_payload(&state.nonce, &input)?
                },
                _ => input,
            };
            send_input_with_handle(handle_id, runner_handle, payload).await
        })
    }

    fn terminate(
        &self,
        handle: &HarnessHandle,
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<ExitStatus>> + Send + '_>> {
        let handle_id = handle.id();
        let runner_handle = handle.real_runner_handle();
        let grace_period = handle.terminate_grace_period();
        let handle_bridge_state = Arc::clone(&self.handle_bridge_state);
        Box::pin(async move {
            let status = terminate_with_handle(handle_id, runner_handle, grace_period).await?;
            let mut guard = handle_bridge_state.lock().await;
            guard.remove(&handle_id);
            Ok(status)
        })
    }
}

// =============================================================================
// CodexCliHolon - Per-Episode Holon Implementation
// =============================================================================

/// Per-episode Holon implementation for Codex CLI adapter execution.
///
/// Created via [`CodexCliAdapter::create_holon`].
#[derive(Debug)]
pub struct CodexCliHolon {
    /// Shared semaphore for concurrency limiting.
    task_semaphore: Arc<Semaphore>,
    /// Adapter configuration.
    adapter_config: CodexCliAdapterConfig,
    /// Thread-safe state shared with background PTY reader task.
    shared_state: SharedCodexCliState,
    /// Stored configuration from intake (used for spawn).
    config: Option<HarnessConfig>,
    /// Event stream receiver (if process has been spawned).
    event_rx: Option<HarnessEventStream>,
    /// Collected events from the process output stream.
    collected_events: Vec<HarnessEvent>,
    /// Episode ID stored for `holon_id()` access.
    episode_id: Option<String>,
}

impl CodexCliHolon {
    /// Create a new per-episode holon instance.
    fn new(task_semaphore: Arc<Semaphore>, adapter_config: CodexCliAdapterConfig) -> Self {
        Self {
            task_semaphore,
            adapter_config,
            shared_state: Arc::new(Mutex::new(CodexCliState::default())),
            config: None,
            event_rx: None,
            collected_events: Vec::new(),
            episode_id: None,
        }
    }

    /// Returns a clone of the shared state for external access.
    #[must_use]
    pub fn shared_state(&self) -> SharedCodexCliState {
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
}

impl Holon for CodexCliHolon {
    type Input = HarnessConfig;
    type Output = CodexCliOutput;
    type State = CodexCliState;

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
            let adapter_config = self.adapter_config.clone();

            let spawn_result = tokio::task::block_in_place(|| {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(async {
                    CodexCliAdapter::spawn_internal(
                        config,
                        semaphore,
                        adapter_config,
                        Some(shared_state),
                        Arc::new(Mutex::new(HashMap::new())),
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
            let output = CodexCliOutput {
                exit_code,
                output_event_count: output_count,
                tool_request_count: tool_count,
                success: exit_code.is_some_and(|c| c == 0),
            };
            return Ok(EpisodeResult::completed(output));
        }

        self.collect_pending_events();

        Ok(EpisodeResult::continue_with_progress(format!(
            "running, {output_count} output events, {tool_count} tool requests, {} collected",
            self.collected_events.len()
        )))
    }

    fn emit_artifact(&self, _artifact: Artifact) -> Result<(), HolonError> {
        Ok(())
    }

    fn escalate(&mut self, reason: &str) -> Result<(), HolonError> {
        tracing::warn!(reason = %reason, "CodexCliHolon escalation requested (no supervisor)");
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
        static DEFAULT_STATE: CodexCliState = CodexCliState {
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
        "CodexCliHolon"
    }
}

/// Returns a snapshot of the current state.
impl CodexCliHolon {
    /// Returns a snapshot of the current state.
    #[must_use]
    pub fn state_snapshot(&self) -> Option<CodexCliState> {
        self.shared_state.try_lock().ok().map(|g| g.clone())
    }
}

// =============================================================================
// Helper: Build HarnessConfig for Codex CLI
// =============================================================================

/// Build a `HarnessConfig` for a Codex CLI episode.
///
/// This constructs the config with TI1 preamble prepended to the prompt,
/// correct env vars (`CODEX_HEADLESS=1`, `NO_COLOR=1`), and model param.
#[must_use]
pub fn build_codex_harness_config<S: std::hash::BuildHasher>(
    episode_id: &str,
    prompt: &str,
    model: &str,
    nonce: &str,
    capability_map: &HashMap<String, String, S>,
    bypass_enabled: bool,
) -> HarnessConfig {
    use super::ti1_scanner::generate_ti1_preamble;

    // Generate TI1 preamble and prepend to prompt
    let ordered_capability_map: BTreeMap<String, String> = capability_map
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let preamble = generate_ti1_preamble(nonce, &ordered_capability_map);
    let normalized_prompt = prompt.replace('\n', " ");
    let full_prompt = format!("{preamble}{normalized_prompt}");

    // Build args
    let mut args = vec![
        "exec".to_string(),
        "-m".to_string(),
        model.to_string(),
        full_prompt,
    ];

    // WVR-0002: bypass flag is disabled by default
    if bypass_enabled {
        args.push("--dangerously-bypass-approvals-and-sandbox".to_string());
    }

    HarnessConfig::new("codex", episode_id)
        .with_args(args)
        .with_env("CODEX_HEADLESS", "1")
        .with_env("NO_COLOR", "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Model parameter validation
    // =========================================================================

    #[test]
    fn test_validate_model_valid() {
        assert!(validate_model_param("gpt-5.3-codex").is_ok());
        assert!(validate_model_param("o4-mini").is_ok());
        assert!(validate_model_param("claude-3.5-sonnet").is_ok());
        assert!(validate_model_param("model123").is_ok());
    }

    #[test]
    fn test_validate_model_empty() {
        assert!(validate_model_param("").is_err());
    }

    #[test]
    fn test_validate_model_injection_attempt() {
        // Semicolons, backticks, spaces, etc. should be rejected
        assert!(validate_model_param("model; rm -rf /").is_err());
        assert!(validate_model_param("model`whoami`").is_err());
        assert!(validate_model_param("model$(cmd)").is_err());
        assert!(validate_model_param("model with spaces").is_err());
        assert!(validate_model_param("model\ninjection").is_err());
    }

    #[test]
    fn test_map_tool_intent_capability_map() {
        let mut capability_map = HashMap::new();
        capability_map.insert("read_file".to_string(), "kernel.fs.read".to_string());

        assert_eq!(
            CodexCliAdapter::map_tool_intent(&capability_map, "read_file"),
            Some("kernel.fs.read".to_string())
        );
        assert_eq!(
            CodexCliAdapter::map_tool_intent(&capability_map, "unknown_tool"),
            None
        );
    }

    #[test]
    fn test_frame_tr1_stdin_payload_wraps_unframed_payload() {
        let framed =
            CodexCliAdapter::frame_tr1_stdin_payload("abcd", b"req-001 ok deadbeef").unwrap();
        assert_eq!(
            String::from_utf8(framed).unwrap(),
            "\u{27E6}TR1 abcd\u{27E7} req-001 ok deadbeef\n"
        );
    }

    #[test]
    fn test_frame_tr1_stdin_payload_preserves_already_framed_line() {
        let framed = CodexCliAdapter::frame_tr1_stdin_payload(
            "ignored",
            "\u{27E6}TR1 abcd\u{27E7} req-001 ok deadbeef".as_bytes(),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(framed).unwrap(),
            "\u{27E6}TR1 abcd\u{27E7} req-001 ok deadbeef\n"
        );
    }

    // =========================================================================
    // Adapter basic tests
    // =========================================================================

    #[test]
    fn test_codex_adapter_new() {
        let adapter = CodexCliAdapter::new();
        assert_eq!(adapter.adapter_type(), AdapterType::Codex);
    }

    #[test]
    fn test_codex_adapter_default() {
        let adapter = CodexCliAdapter::default();
        assert_eq!(adapter.adapter_type(), AdapterType::Codex);
    }

    #[test]
    fn test_codex_adapter_initial_capacity() {
        let adapter = CodexCliAdapter::new();
        assert_eq!(adapter.active_count(), 0);
        assert_eq!(adapter.available_slots(), MAX_CONCURRENT_ADAPTERS);
    }

    #[test]
    fn test_codex_adapter_debug() {
        let adapter = CodexCliAdapter::new();
        let debug_str = format!("{adapter:?}");
        assert!(debug_str.contains("CodexCliAdapter"));
    }

    // =========================================================================
    // Holon factory tests
    // =========================================================================

    #[test]
    fn test_create_holon() {
        let adapter = CodexCliAdapter::new();
        let holon = adapter.create_holon();
        assert_eq!(holon.type_name(), "CodexCliHolon");
    }

    #[test]
    fn test_holon_intake() {
        let adapter = CodexCliAdapter::new();
        let mut holon = adapter.create_holon();
        let config = HarnessConfig::new("echo", "episode-codex");

        let result = holon.intake(config, "lease-123");
        assert!(result.is_ok());

        let state = holon.state_snapshot().expect("state should be available");
        assert!(state.intake_called);
        assert_eq!(state.episode_id, Some("episode-codex".to_string()));
    }

    #[test]
    fn test_holon_intake_validation_error() {
        let adapter = CodexCliAdapter::new();
        let mut holon = adapter.create_holon();
        let config = HarnessConfig::new("", "episode-invalid");

        let result = holon.intake(config, "lease-123");
        assert!(result.is_err());
    }

    #[test]
    fn test_holon_id_before_intake() {
        let adapter = CodexCliAdapter::new();
        let holon = adapter.create_holon();
        assert!(holon.holon_id().is_none());
    }

    #[test]
    fn test_holon_id_after_intake() {
        let adapter = CodexCliAdapter::new();
        let mut holon = adapter.create_holon();
        let config = HarnessConfig::new("echo", "ep-codex-test");
        holon.intake(config, "lease-123").unwrap();
        assert_eq!(holon.holon_id(), Some("ep-codex-test"));
    }

    #[test]
    fn test_holon_execute_without_intake() {
        let adapter = CodexCliAdapter::new();
        let mut holon = adapter.create_holon();
        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();

        let result = holon.execute_episode(&ctx);
        assert!(result.is_err());
    }

    // =========================================================================
    // Build config helper tests
    // =========================================================================

    #[test]
    fn test_build_codex_harness_config_basic() {
        let mut cap_map = HashMap::new();
        cap_map.insert("read_file".to_string(), "kernel.fs.read".to_string());

        let config = build_codex_harness_config(
            "ep-001",
            "Write hello world",
            "o4-mini",
            "test_nonce",
            &cap_map,
            false,
        );

        assert_eq!(config.command, "codex");
        assert_eq!(config.episode_id, "ep-001");
        assert!(config.args.contains(&"exec".to_string()));
        assert!(config.args.contains(&"-m".to_string()));
        assert!(config.args.contains(&"o4-mini".to_string()));
        // Prompt should include TI1 preamble
        let prompt_arg = config.args.last().unwrap();
        assert!(
            prompt_arg.contains("TI1"),
            "prompt should contain TI1 preamble"
        );
        assert!(prompt_arg.contains("Write hello world"));
        // No bypass flag
        assert!(
            !config
                .args
                .contains(&"--dangerously-bypass-approvals-and-sandbox".to_string())
        );
    }

    #[test]
    fn test_build_codex_harness_config_with_bypass() {
        let cap_map = HashMap::new();
        let config =
            build_codex_harness_config("ep-002", "test prompt", "o4-mini", "nonce", &cap_map, true);

        assert!(
            config
                .args
                .contains(&"--dangerously-bypass-approvals-and-sandbox".to_string())
        );
    }

    #[test]
    fn test_build_codex_harness_config_env() {
        use secrecy::ExposeSecret;

        let cap_map = HashMap::new();
        let config =
            build_codex_harness_config("ep-003", "prompt", "model", "nonce", &cap_map, false);

        assert_eq!(
            config
                .env
                .get("CODEX_HEADLESS")
                .map(|s| s.expose_secret().to_string()),
            Some("1".to_string())
        );
        assert_eq!(
            config
                .env
                .get("NO_COLOR")
                .map(|s| s.expose_secret().to_string()),
            Some("1".to_string())
        );
    }

    // =========================================================================
    // Spawn with echo (integration test)
    // =========================================================================

    #[tokio::test]
    async fn test_codex_adapter_spawn_echo() {
        let adapter = CodexCliAdapter::new();
        let config =
            HarnessConfig::new("echo", "episode-codex-echo").with_args(vec!["hello".to_string()]);

        let result = adapter.spawn(config).await;
        assert!(result.is_ok());

        let (handle, mut events) = result.unwrap();
        assert_eq!(handle.episode_id(), "episode-codex-echo");

        // Collect events until terminated
        let mut terminated = false;
        while let Some(event) = events.recv().await {
            if event.is_terminal() {
                terminated = true;
                break;
            }
        }
        assert!(terminated, "expected terminated event");
    }

    #[tokio::test]
    async fn test_codex_adapter_send_input_and_terminate() {
        let adapter = CodexCliAdapter::new();
        let config = HarnessConfig::new("cat", "episode-codex-interactive");

        let (handle, mut events) = adapter.spawn(config).await.unwrap();

        adapter
            .send_input(&handle, b"hello from codex adapter\n")
            .await
            .unwrap();

        let observed_output = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                if let HarnessEvent::Output { chunk, .. } = event {
                    if String::from_utf8_lossy(&chunk).contains("hello from codex adapter") {
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
        assert!(!exit_status.success(), "terminate should stop via signal");
    }

    #[tokio::test]
    async fn test_codex_adapter_validates_config() {
        let adapter = CodexCliAdapter::new();
        let config = HarnessConfig::new("", "ep-1");
        let result = adapter.spawn(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_codex_adapter_validates_model_on_spawn() {
        let adapter = CodexCliAdapter::with_config(CodexCliAdapterConfig {
            model: "bad model; rm -rf /".to_string(),
            ..CodexCliAdapterConfig::default()
        });
        let config = HarnessConfig::new("echo", "ep-1");
        let result = adapter.spawn(config).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("invalid characters"));
    }

    // =========================================================================
    // Holon should_stop tests
    // =========================================================================

    #[test]
    fn test_holon_should_stop_continue() {
        let adapter = CodexCliAdapter::new();
        let holon = adapter.create_holon();
        let ctx = EpisodeContext::builder()
            .work_id("work-1")
            .lease_id("lease-1")
            .build();
        let condition = holon.should_stop(&ctx);
        assert_eq!(condition, StopCondition::Continue);
    }

    #[test]
    fn test_holon_should_stop_budget() {
        let adapter = CodexCliAdapter::new();
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
        let adapter = CodexCliAdapter::new();
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
}
