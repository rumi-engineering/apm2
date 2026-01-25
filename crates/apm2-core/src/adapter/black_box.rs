//! Black-box adapter for observation-based agent monitoring.
//!
//! This adapter wraps an agent process and derives events from side effects
//! without requiring any instrumentation or cooperation from the agent. It:
//!
//! - Spawns the agent process with configured environment
//! - Monitors the filesystem for changes
//! - Detects tool requests from side effects (file writes, etc.)
//! - Emits progress signals derived from activity patterns
//! - Classifies process exit and emits termination events
//!
//! # Security Model
//!
//! The black-box adapter follows a **default-deny, least-privilege,
//! fail-closed** security model:
//!
//! - Environment variables are filtered to exclude sensitive keys
//! - Process is spawned with minimal capabilities
//! - All observations are treated as untrusted and validated
//! - Failures result in session termination (fail-closed)
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::adapter::{BlackBoxAdapter, BlackBoxConfig, AdapterEventPayload};
//!
//! let config = BlackBoxConfig::new("session-123", "claude")
//!     .with_working_dir("/workspace")
//!     .with_watch_path("/workspace");
//!
//! let mut adapter = BlackBoxAdapter::new(config);
//!
//! // Take the event receiver for async event consumption
//! let mut rx = adapter.take_event_receiver().unwrap();
//!
//! adapter.start().await?;
//!
//! // Poll in a loop to drive the adapter, or use run() for convenience
//! while let Some(event) = rx.recv().await {
//!     println!("Event: {:?}", event);
//!     if matches!(event.payload, AdapterEventPayload::ProcessExited(_)) {
//!         break;
//!     }
//! }
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time;

use super::config::BlackBoxConfig;
use super::error::AdapterError;
use super::event::{
    AdapterEvent, AdapterEventPayload, DetectionMethod, ExitClassification, FilesystemChange,
    ProcessExited, ProcessStarted, ProgressSignal, ProgressType, StallDetected,
    ToolRequestDetected,
};
use super::watcher::FilesystemWatcher;

/// Black-box adapter for observation-based agent monitoring.
#[derive(Debug)]
pub struct BlackBoxAdapter {
    /// Configuration for this adapter.
    config: BlackBoxConfig,

    /// Current state of the adapter.
    state: AdapterState,

    /// Sequence number generator for events.
    sequence: AtomicU64,

    /// Event sender.
    event_tx: Option<mpsc::Sender<AdapterEvent>>,

    /// Event receiver (taken when `start()` is called).
    event_rx: Option<mpsc::Receiver<AdapterEvent>>,
}

/// Internal state of the adapter.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // Running state is the common case; boxing adds indirection
enum AdapterState {
    /// Adapter is not started.
    Idle,

    /// Adapter is running with a child process.
    Running {
        /// The child process handle.
        child: Child,
        /// OS process ID.
        pid: u32,
        /// Time when the process started.
        started_at: Instant,
        /// Filesystem watcher.
        watcher: FilesystemWatcher,
        /// Last activity timestamp.
        last_activity: Instant,
        /// Stall count.
        stall_count: u32,
        /// Shutdown signal.
        shutdown: Arc<AtomicBool>,
    },

    /// Adapter has stopped.
    Stopped {
        /// Exit code if available.
        exit_code: Option<i32>,
        /// Signal if available.
        signal: Option<i32>,
    },
}

impl BlackBoxAdapter {
    /// Creates a new black-box adapter with the given configuration.
    #[must_use]
    pub fn new(config: BlackBoxConfig) -> Self {
        let (tx, rx) = mpsc::channel(config.filesystem.buffer_size);

        Self {
            config,
            state: AdapterState::Idle,
            sequence: AtomicU64::new(0),
            event_tx: Some(tx),
            event_rx: Some(rx),
        }
    }

    /// Starts the adapter, spawning the agent process and beginning monitoring.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The adapter is already running
    /// - The process fails to spawn
    /// - The filesystem watcher fails to initialize
    pub async fn start(&mut self) -> Result<(), AdapterError> {
        if matches!(self.state, AdapterState::Running { .. }) {
            return Err(AdapterError::AlreadyRunning);
        }

        // Build the command
        let mut cmd = Command::new(&self.config.process.command);

        cmd.args(&self.config.process.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        // Set working directory
        if let Some(ref cwd) = self.config.process.working_dir {
            cmd.current_dir(cwd);
        }

        // Set environment variables (filtered for security)
        self.apply_environment(&mut cmd);

        // Spawn the process
        let child = cmd
            .spawn()
            .map_err(|e| AdapterError::SpawnFailed(e.to_string()))?;

        let pid = child
            .id()
            .ok_or_else(|| AdapterError::SpawnFailed("failed to get PID".to_string()))?;

        // Initialize filesystem watcher
        let mut watcher = FilesystemWatcher::new(self.config.filesystem.clone());
        watcher.initialize()?;

        let now = Instant::now();
        let shutdown = Arc::new(AtomicBool::new(false));

        self.state = AdapterState::Running {
            child,
            pid,
            started_at: now,
            watcher,
            last_activity: now,
            stall_count: 0,
            shutdown,
        };

        // Emit process started event
        self.emit_process_started(pid).await?;

        Ok(())
    }

    /// Applies environment configuration to the command.
    fn apply_environment(&self, cmd: &mut Command) {
        let env_config = &self.config.environment;

        if !env_config.inherit {
            cmd.env_clear();
        }

        // Apply configured variables
        for (key, value) in &env_config.variables {
            if !env_config.exclude.contains(key) {
                cmd.env(key, value);
            }
        }

        // Remove excluded variables from inherited environment
        if env_config.inherit {
            for key in &env_config.exclude {
                cmd.env_remove(key);
            }
        }
    }

    /// Polls for events and returns the next event if available.
    ///
    /// This is a non-blocking poll that checks:
    /// - Process exit status
    /// - Filesystem changes
    /// - Stall detection
    ///
    /// # Errors
    ///
    /// Returns an error if the adapter is not running.
    pub async fn poll(&mut self) -> Result<Option<AdapterEvent>, AdapterError> {
        let (child, pid, started_at, watcher, last_activity, stall_count, shutdown) =
            match &mut self.state {
                AdapterState::Running {
                    child,
                    pid,
                    started_at,
                    watcher,
                    last_activity,
                    stall_count,
                    shutdown,
                } => (
                    child,
                    *pid,
                    *started_at,
                    watcher,
                    last_activity,
                    stall_count,
                    shutdown.clone(),
                ),
                AdapterState::Idle => return Err(AdapterError::NotRunning),
                AdapterState::Stopped { .. } => return Ok(None),
            };

        // Check for process exit first (even if shutdown was requested)
        // This ensures we properly detect process termination and emit ProcessExited
        if let Some(status) = child.try_wait().map_err(AdapterError::Io)? {
            let uptime = started_at.elapsed();
            let exit_code = status.code();
            let signal = Self::extract_signal(status);

            let classification = Self::classify_exit(exit_code, signal);

            // Emit exit event
            let event = self.create_event(AdapterEventPayload::ProcessExited(ProcessExited {
                pid,
                exit_code,
                signal,
                uptime,
                classification,
            }));

            self.state = AdapterState::Stopped { exit_code, signal };

            if let Some(tx) = &self.event_tx {
                let _ = tx.send(event.clone()).await;
            }

            return Ok(Some(event));
        }

        // Check if shutdown was requested (after checking for process exit)
        // This ensures we can properly detect and report process termination
        if shutdown.load(Ordering::SeqCst) {
            return Ok(None);
        }

        // Poll filesystem for changes
        // Use block_in_place to prevent blocking the async executor with filesystem I/O
        let changes = tokio::task::block_in_place(|| watcher.poll())?;
        if !changes.is_empty() {
            *last_activity = Instant::now();

            // Process each change
            for change in changes {
                // Emit filesystem change event
                let event =
                    self.create_event(AdapterEventPayload::FilesystemChange(change.clone()));
                if let Some(tx) = &self.event_tx {
                    let _ = tx.send(event).await;
                }

                // Try to infer tool requests from filesystem changes
                if let Some(tool_event) = self.infer_tool_request(&change) {
                    let event = self.create_event(tool_event);
                    if let Some(tx) = &self.event_tx {
                        let _ = tx.send(event).await;
                    }
                }
            }

            // Emit progress signal
            let progress_event = self.create_event(AdapterEventPayload::Progress(ProgressSignal {
                signal_type: ProgressType::Activity,
                description: "Filesystem activity detected".to_string(),
                entropy_cost: 0,
            }));

            if let Some(tx) = &self.event_tx {
                let _ = tx.send(progress_event.clone()).await;
            }

            return Ok(Some(progress_event));
        }

        // Check for stall
        if self.config.stall_detection.enabled {
            let idle_duration = last_activity.elapsed();
            if idle_duration >= self.config.stall_detection.timeout {
                *stall_count += 1;
                let current_stall_count = *stall_count;
                *last_activity = Instant::now(); // Reset to avoid repeated stall events

                let threshold = self.config.stall_detection.timeout;
                let stall_event =
                    self.create_event(AdapterEventPayload::StallDetected(StallDetected {
                        idle_duration,
                        threshold,
                        stall_count: current_stall_count,
                    }));

                if let Some(tx) = &self.event_tx {
                    let _ = tx.send(stall_event.clone()).await;
                }

                return Ok(Some(stall_event));
            }
        }

        Ok(None)
    }

    /// Runs the adapter event loop until the process exits or shutdown is
    /// requested.
    ///
    /// # Errors
    ///
    /// Returns an error if the adapter is not running.
    pub async fn run(&mut self) -> Result<(), AdapterError> {
        let poll_interval = match &self.state {
            AdapterState::Running { watcher, .. } => watcher.poll_interval(),
            _ => return Err(AdapterError::NotRunning),
        };

        loop {
            match self.poll().await? {
                Some(event) => {
                    if matches!(event.payload, AdapterEventPayload::ProcessExited(_)) {
                        break;
                    }
                },
                None => {
                    // Check if we're still running
                    if !matches!(self.state, AdapterState::Running { .. }) {
                        break;
                    }
                },
            }

            // Sleep between polls
            time::sleep(poll_interval).await;
        }

        Ok(())
    }

    /// Stops the adapter, terminating the agent process if running.
    ///
    /// # Errors
    ///
    /// Returns an error if process termination fails.
    pub async fn stop(&mut self) -> Result<(), AdapterError> {
        if let AdapterState::Running {
            child, shutdown, ..
        } = &mut self.state
        {
            shutdown.store(true, Ordering::SeqCst);
            child.kill().await.map_err(AdapterError::Io)?;
        }

        Ok(())
    }

    /// Returns the event receiver.
    ///
    /// This can only be called once; subsequent calls return `None`.
    pub const fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<AdapterEvent>> {
        self.event_rx.take()
    }

    /// Returns the session ID for this adapter.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.config.session_id
    }

    /// Returns whether the adapter is running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self.state, AdapterState::Running { .. })
    }

    /// Returns the process ID if running.
    #[must_use]
    pub const fn pid(&self) -> Option<u32> {
        match &self.state {
            AdapterState::Running { pid, .. } => Some(*pid),
            _ => None,
        }
    }

    /// Creates an event with the next sequence number.
    fn create_event(&self, payload: AdapterEventPayload) -> AdapterEvent {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
        // Truncation is intentional: nanos since epoch fits in u64 until year 2554
        #[allow(clippy::cast_possible_truncation)]
        let timestamp_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        AdapterEvent {
            sequence,
            timestamp_nanos,
            session_id: self.config.session_id.clone(),
            payload,
        }
    }

    /// Emits a process started event.
    async fn emit_process_started(&self, pid: u32) -> Result<(), AdapterError> {
        let working_dir = self
            .config
            .process
            .working_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));

        // Filter environment to safe keys
        let env: BTreeMap<String, String> = self
            .config
            .environment
            .variables
            .iter()
            .filter(|(k, _)| !self.config.environment.exclude.contains(k))
            .cloned()
            .collect();

        let event = self.create_event(AdapterEventPayload::ProcessStarted(ProcessStarted {
            pid,
            command: self.config.process.command.clone(),
            args: self.config.process.args.clone(),
            working_dir,
            env,
            adapter_type: "black-box".to_string(),
        }));

        if let Some(tx) = &self.event_tx {
            tx.send(event)
                .await
                .map_err(|e| AdapterError::ChannelSend(e.to_string()))?;
        }

        Ok(())
    }

    /// Infers a tool request from a filesystem change.
    ///
    /// Returns `Some` if a tool request can be inferred from the change,
    /// `None` otherwise (reserved for future patterns that may not map to
    /// tools).
    #[allow(clippy::unused_self)] // Will use self for future inference patterns
    #[allow(clippy::unnecessary_wraps)] // Future patterns may return None
    fn infer_tool_request(&self, change: &FilesystemChange) -> Option<AdapterEventPayload> {
        let path_str = change.path.to_string_lossy();
        let mut context = BTreeMap::new();
        context.insert("path".to_string(), path_str.to_string());

        match change.change_type {
            super::event::FileChangeType::Created | super::event::FileChangeType::Modified => {
                // Infer file_write tool
                context.insert(
                    "size_bytes".to_string(),
                    change.size_bytes.unwrap_or(0).to_string(),
                );

                Some(AdapterEventPayload::ToolRequestDetected(
                    ToolRequestDetected {
                        tool_name: "file_write".to_string(),
                        detection_method: DetectionMethod::FilesystemObservation,
                        confidence_percent: 80,
                        context,
                    },
                ))
            },
            super::event::FileChangeType::Deleted => {
                // Infer file_delete tool
                Some(AdapterEventPayload::ToolRequestDetected(
                    ToolRequestDetected {
                        tool_name: "file_delete".to_string(),
                        detection_method: DetectionMethod::FilesystemObservation,
                        confidence_percent: 90,
                        context,
                    },
                ))
            },
            super::event::FileChangeType::Renamed => {
                // Infer file_rename tool
                Some(AdapterEventPayload::ToolRequestDetected(
                    ToolRequestDetected {
                        tool_name: "file_rename".to_string(),
                        detection_method: DetectionMethod::FilesystemObservation,
                        confidence_percent: 85,
                        context,
                    },
                ))
            },
        }
    }

    /// Extracts the signal number from an exit status (Unix only).
    #[cfg(unix)]
    fn extract_signal(status: std::process::ExitStatus) -> Option<i32> {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }

    /// Windows doesn't have Unix signals.
    #[cfg(not(unix))]
    fn extract_signal(_status: std::process::ExitStatus) -> Option<i32> {
        None
    }

    /// Classifies the exit based on exit code and signal.
    const fn classify_exit(exit_code: Option<i32>, signal: Option<i32>) -> ExitClassification {
        match (exit_code, signal) {
            (Some(0), None) => ExitClassification::CleanSuccess,
            (Some(_), None) => ExitClassification::CleanError,
            (None, Some(_)) => ExitClassification::Signal,
            _ => ExitClassification::Unknown,
        }
    }

    /// Returns the exit code if the adapter has stopped.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        match &self.state {
            AdapterState::Stopped { exit_code, .. } => *exit_code,
            _ => None,
        }
    }

    /// Returns the signal that terminated the process, if any.
    #[must_use]
    pub const fn exit_signal(&self) -> Option<i32> {
        match &self.state {
            AdapterState::Stopped { signal, .. } => *signal,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_adapter_creation() {
        let config = BlackBoxConfig::new("session-123", "echo");
        let adapter = BlackBoxAdapter::new(config);

        assert_eq!(adapter.session_id(), "session-123");
        assert!(!adapter.is_running());
        assert!(adapter.pid().is_none());
    }

    #[test]
    fn test_exit_classification() {
        assert_eq!(
            BlackBoxAdapter::classify_exit(Some(0), None),
            ExitClassification::CleanSuccess
        );
        assert_eq!(
            BlackBoxAdapter::classify_exit(Some(1), None),
            ExitClassification::CleanError
        );
        assert_eq!(
            BlackBoxAdapter::classify_exit(None, Some(9)),
            ExitClassification::Signal
        );
        assert_eq!(
            BlackBoxAdapter::classify_exit(None, None),
            ExitClassification::Unknown
        );
    }

    #[cfg_attr(miri, ignore)] // Miri can't spawn processes
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_adapter_start_and_poll() {
        let config = BlackBoxConfig::new("session-test", "echo").with_args(["hello", "world"]);

        let mut adapter = BlackBoxAdapter::new(config);
        adapter.start().await.unwrap();

        assert!(adapter.is_running());
        assert!(adapter.pid().is_some());

        // Poll until process exits
        loop {
            match adapter.poll().await {
                Ok(Some(event)) => {
                    if matches!(event.payload, AdapterEventPayload::ProcessExited(_)) {
                        break;
                    }
                },
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                },
                Err(e) => panic!("poll error: {e}"),
            }
        }

        assert!(!adapter.is_running());
    }

    #[cfg_attr(miri, ignore)] // Miri can't spawn processes
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_adapter_double_start() {
        let config = BlackBoxConfig::new("session-test", "sleep").with_args(["1"]);

        let mut adapter = BlackBoxAdapter::new(config);
        adapter.start().await.unwrap();

        // Second start should fail
        let result = adapter.start().await;
        assert!(matches!(result, Err(AdapterError::AlreadyRunning)));

        adapter.stop().await.unwrap();
    }

    #[cfg_attr(miri, ignore)] // Miri can't spawn processes
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_adapter_with_filesystem_watch() {
        let dir = tempfile::tempdir().unwrap();

        let mut config = BlackBoxConfig::new("session-test", "sleep")
            .with_args(["3"])
            .with_working_dir(dir.path())
            .with_watch_path(dir.path());

        // Use shorter debounce for faster test
        config.filesystem.debounce = Duration::from_millis(10);

        let mut adapter = BlackBoxAdapter::new(config);

        // Take the event receiver for filesystem change events
        let mut rx = adapter.take_event_receiver().unwrap();

        adapter.start().await.unwrap();

        // Wait for adapter to initialize
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Create a file in the watched directory
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, "test content").unwrap();

        // Poll to trigger filesystem change detection
        let mut found_fs_change = false;
        for _ in 0..50 {
            let _ = adapter.poll().await;

            // Check the event receiver for filesystem change events
            while let Ok(event) = tokio::time::timeout(Duration::from_millis(5), rx.recv()).await {
                if let Some(event) = event {
                    if matches!(event.payload, AdapterEventPayload::FilesystemChange(_)) {
                        found_fs_change = true;
                        break;
                    }
                }
            }

            if found_fs_change {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert!(found_fs_change, "Expected to detect filesystem change");

        adapter.stop().await.unwrap();
    }

    #[test]
    fn test_infer_tool_request() {
        let config = BlackBoxConfig::new("session-test", "echo");
        let adapter = BlackBoxAdapter::new(config);

        // Test file creation inference
        let change = FilesystemChange {
            path: PathBuf::from("/tmp/test.txt"),
            change_type: super::super::event::FileChangeType::Created,
            size_bytes: Some(100),
        };

        let tool_event = adapter.infer_tool_request(&change);
        assert!(tool_event.is_some());

        if let Some(AdapterEventPayload::ToolRequestDetected(req)) = tool_event {
            assert_eq!(req.tool_name, "file_write");
            assert_eq!(req.detection_method, DetectionMethod::FilesystemObservation);
        }

        // Test file deletion inference
        let change = FilesystemChange {
            path: PathBuf::from("/tmp/deleted.txt"),
            change_type: super::super::event::FileChangeType::Deleted,
            size_bytes: None,
        };

        let tool_event = adapter.infer_tool_request(&change);
        assert!(tool_event.is_some());

        if let Some(AdapterEventPayload::ToolRequestDetected(req)) = tool_event {
            assert_eq!(req.tool_name, "file_delete");
        }
    }
}
