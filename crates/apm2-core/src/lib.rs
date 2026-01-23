//! # apm2-core
//!
//! Core library for apm2 - an AI CLI process manager with credential
//! management.
//!
//! This crate provides the fundamental building blocks for managing AI CLI
//! processes like Claude Code, Gemini CLI, and Codex CLI, with a focus on
//! credential/login management and hot-swapping capabilities.
//!
//! ## Features
//!
//! - **Process Management**: Spawn, monitor, and control child processes
//! - **Credential Management**: Secure storage and hot-swapping of credentials
//! - **Supervision**: Automatic restart with configurable policies
//! - **Health Checks**: Monitor process health via HTTP, TCP, or scripts
//! - **IPC**: Unix socket-based communication between CLI and daemon
//!
//! ## Example
//!
//! ```rust,no_run
//! use apm2_core::process::ProcessSpec;
//! use apm2_core::restart::RestartConfig;
//!
//! let spec = ProcessSpec::builder()
//!     .name("claude-code")
//!     .command("claude")
//!     .args(["--session", "project"])
//!     .restart(RestartConfig::default())
//!     .build();
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

pub mod config;
pub mod credentials;
pub mod health;
pub mod ipc;
pub mod ledger;
pub mod log;
pub mod process;
pub mod restart;
pub mod shutdown;
pub mod state;
pub mod supervisor;

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::config::EcosystemConfig;
    pub use crate::credentials::{AuthMethod, CredentialProfile, Provider};
    pub use crate::process::{ProcessHandle, ProcessSpec, ProcessState};
    pub use crate::restart::RestartConfig;
    pub use crate::supervisor::Supervisor;
}

/// Re-export commonly used types at the crate root.
pub use config::EcosystemConfig;
pub use credentials::CredentialProfile;
pub use process::{ProcessHandle, ProcessSpec, ProcessState};
pub use restart::RestartConfig;
pub use supervisor::Supervisor;
