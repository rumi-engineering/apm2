//! Agent adapter module for wrapping heterogeneous agent runtimes.
//!
//! This module provides adapters that normalize different agent types into a
//! common event contract. It supports both **black-box adapters** (observation-
//! based) and **instrumented adapters** (native event reporting).
//!
//! # Architecture
//!
//! The adapter layer sits between the supervisor and agent processes:
//!
//! ```text
//! ┌─────────────┐
//! │  Supervisor │
//! └──────┬──────┘
//!        │ AdapterEvent
//!        ▼
//! ┌─────────────┐
//! │   Adapter   │ ◄── Common interface (Adapter trait)
//! └──────┬──────┘
//!        │ spawn/observe
//!        ▼
//! ┌─────────────┐
//! │Agent Process│ ◄── Could be Claude, Gemini, custom agent, etc.
//! └─────────────┘
//! ```
//!
//! # Adapter Types
//!
//! ## Black-Box Adapter
//!
//! The black-box adapter derives events from side effects without any
//! cooperation from the agent. It:
//!
//! - Spawns the agent process with configured environment
//! - Monitors filesystem for changes
//! - Infers tool requests from observations
//! - Emits progress signals based on activity patterns
//!
//! This is the most portable adapter type and works with any agent.
//!
//! ## Claude Code Instrumented Adapter
//!
//! The Claude Code adapter integrates with Claude Code's native hook system
//! to receive rich telemetry. It provides:
//!
//! - **Native tool requests**: Exact tool invocations via `PreToolUse` hooks
//! - **Tool responses**: Results via `PostToolUse` hooks
//! - **Rich progress signals**: Precise event timing and context
//! - **Session lifecycle**: Claude Code session start/stop events
//!
//! Use the instrumented adapter when running Claude Code for maximum
//! observability and control.
//!
//! # Event Contract
//!
//! All adapters emit [`AdapterEvent`] instances that include:
//!
//! - **Lifecycle events**: Process started, exited
//! - **Progress signals**: Activity, heartbeats, tool completion
//! - **Filesystem changes**: File created, modified, deleted
//! - **Tool detections**: Inferred tool requests (black-box) or reported
//!   (instrumented)
//! - **Stall detection**: Lack of activity exceeding threshold
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::adapter::{BlackBoxAdapter, BlackBoxConfig};
//!
//! // Configure the black-box adapter
//! let config = BlackBoxConfig::new("session-123", "claude")
//!     .with_working_dir("/workspace")
//!     .with_watch_path("/workspace")
//!     .with_stall_timeout(Duration::from_secs(120));
//!
//! // Create and start the adapter
//! let mut adapter = BlackBoxAdapter::new(config);
//! adapter.start().await?;
//!
//! // Receive events
//! let mut rx = adapter.take_event_receiver().unwrap();
//! while let Some(event) = rx.recv().await {
//!     match event.payload {
//!         AdapterEventPayload::ProcessStarted(e) => println!("Started: PID {}", e.pid),
//!         AdapterEventPayload::Progress(e) => println!("Progress: {:?}", e.signal_type),
//!         AdapterEventPayload::ProcessExited(e) => println!("Exited: {:?}", e.classification),
//!         _ => {}
//!     }
//! }
//! ```
//!
//! # Security Model
//!
//! Adapters follow a **default-deny, least-privilege, fail-closed** model:
//!
//! - Environment variables are filtered to exclude sensitive keys
//! - Processes are spawned with minimal capabilities
//! - All observations are treated as untrusted
//! - Failures result in session termination
//! - On Linux, seccomp-bpf filtering restricts syscalls (defense in depth)

mod black_box;
mod claude_code;
mod config;
mod error;
mod event;
pub mod seccomp;
mod traits;
mod watcher;

#[cfg(test)]
mod tests;

// Re-export main types
pub use black_box::BlackBoxAdapter;
pub use claude_code::{
    ClaudeCodeAdapter, ClaudeCodeConfig, HookConfig, HookEvent, HookResponse, ProgressEvent,
    SessionEndEvent, SessionStartEvent, ToolResultEvent, ToolUseEvent,
};
pub use config::{
    BlackBoxConfig, EnvironmentConfig, FilesystemConfig, ProcessConfig, ProgressConfig,
    StallDetectionConfig,
};
pub use error::AdapterError;
pub use event::{
    AdapterEvent, AdapterEventPayload, DetectionMethod, ExitClassification, FileChangeType,
    FilesystemChange, ProcessExited, ProcessStarted, ProgressSignal, ProgressType, StallDetected,
    ToolRequestDetected,
};
pub use seccomp::{
    CompiledSeccompFilter, SeccompError, SeccompProfile, SeccompProfileLevel, SeccompResult,
    apply_seccomp_filter, compile_seccomp_filter,
};
pub use traits::{Adapter, AdapterExt, BoxFuture};
pub use watcher::{FilesystemWatcher, WatcherHandle};
