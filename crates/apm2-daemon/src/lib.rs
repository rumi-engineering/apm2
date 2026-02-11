// Allow large stack arrays in tests: HashMap monomorphization triggers spanless
// false positives that cannot be scoped to specific modules (TCK-00388).
#![cfg_attr(test, allow(clippy::large_stack_arrays))]

//! apm2-daemon - AI CLI Process Manager Daemon Library
//!
//! This library provides the core daemon functionality for managing AI CLI
//! processes. The daemon supervises agent processes, handles IPC requests, and
//! maintains runtime state through event sourcing.
//!
//! # Runtime Requirements
//!
//! This crate requires a **multi-threaded tokio runtime** for full
//! functionality. Specifically, the [`episode::RawAdapterHolon`] uses
//! `tokio::task::block_in_place` to bridge synchronous `Holon` trait methods
//! with async process spawning. Using a single-threaded runtime will cause
//! a panic when using the holon interface.
//!
//! The `apm2-daemon` binary configures tokio with `flavor = "multi_thread"` by
//! default. If you are using this library directly, ensure your runtime is
//! configured appropriately:
//!
//! ```rust,ignore
//! #[tokio::main(flavor = "multi_thread")]
//! async fn main() {
//!     // Use apm2-daemon components here
//! }
//! ```
//!
//! # Modules
//!
//! - [`episode`]: Episode runtime for bounded execution management
//! - [`evidence`]: Flight recording and evidence retention
//! - [`gate`]: Gate execution orchestrator for autonomous gate lifecycle
//!   (TCK-00388)
//! - [`htf`]: Holonic Time Framework clock service and envelope stamping
//! - [`metrics`]: Prometheus metrics for daemon health observability
//!   (REQ-DCP-0012)
//! - [`projection`]: FAC projection adapters for external system sync
//! - [`protocol`]: UDS protocol and message framing
//! - [`session`]: Session handling with context firewall integration
//! - [`hmp`]: Holonic Message Protocol (HMP) — digest-first channels and
//!   admission receipt semantics for RFC-0020 (TCK-00380)
//! - [`hsi_contract`]: HSI Contract Manifest V1 for RFC-0020 (TCK-00347)
//! - [`identity`]: Canonical identity identifiers (`PublicKeyIdV1`,
//!   `KeySetIdV1`, `CellIdV1`, `HolonIdV1`) for RFC-0020
//! - [`telemetry`]: Cgroup-based resource telemetry collection

pub mod cas;
pub mod episode;
pub mod evidence;
pub mod gate;
pub mod governance;
pub mod governance_channel;
pub mod hmp;
pub mod hsi_contract;
pub mod htf;
pub mod identity;
pub mod ledger;
pub mod metrics;
pub mod pcac;
pub mod projection;
pub mod protocol;
pub mod session;
pub mod state;
pub mod telemetry;
pub mod work;
