//! apm2-daemon - AI CLI Process Manager Daemon Library
//!
//! This library provides the core daemon functionality for managing AI CLI
//! processes. The daemon supervises agent processes, handles IPC requests, and
//! maintains runtime state through event sourcing.
//!
//! # Modules
//!
//! - [`episode`]: Episode runtime for bounded execution management
//! - [`protocol`]: UDS protocol and message framing
//! - [`telemetry`]: Cgroup-based resource telemetry collection
//! - [`evidence`]: Flight recording and evidence retention

pub mod episode;
pub mod evidence;
pub mod protocol;
pub mod telemetry;
