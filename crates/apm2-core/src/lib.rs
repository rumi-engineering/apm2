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
//! - **Protocol**: Control-plane IPC via `ProtocolServer` (DD-009)
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
// Allow large stack arrays in tests for schema registry handshake limit testing.
// The actual code uses heap allocation (Vec), but const evaluation may trigger
// this lint during test compilation with MAX_HANDSHAKE_DIGESTS (10000).
#![cfg_attr(test, allow(clippy::large_stack_arrays))]

pub mod adapter;
pub mod agent;
pub mod bootstrap;
pub mod budget;
pub mod cac;
pub mod capsule;
pub mod ccp;
pub mod config;
pub mod consensus;
pub mod context;
pub mod coordination;
pub mod credentials;
pub mod crypto;
pub mod determinism;
pub mod events;
pub mod evidence;
pub mod fac;
pub mod github;
pub mod health;
pub mod htf;
pub mod impact_map;
pub mod lease;
pub mod ledger;
pub mod liveness;
pub mod log;
pub mod model_router;
pub mod pcac;
pub mod policy;
pub mod process;
pub mod reducer;
pub mod refactor_radar;
pub mod restart;
pub mod rfc_framer;
pub mod run_manifest;
pub mod schema_registry;
pub mod session;
pub mod shutdown;
pub mod state;
pub mod supervisor;
pub mod syscall;
pub mod ticket_emitter;
pub mod tool;
pub mod webhook;
pub mod work;

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
