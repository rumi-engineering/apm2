// Allow large stack arrays in tests: HashMap monomorphization triggers spanless
// false positives that cannot be scoped to specific modules
// (RFC-0032::REQ-0142).
#![cfg_attr(test, allow(clippy::large_stack_arrays))]
// Suppress pedantic doc-formatting lints crate-wide.  RFC-prefixed identifiers
// (e.g. RFC-0032::REQ-0134) are used pervasively in doc comments and cannot
// be individually backtick-wrapped without reducing readability.  This mirrors
// the same suppression applied to apm2-core and apm2-holon.
#![allow(clippy::doc_markdown)]
#![allow(clippy::too_long_first_doc_paragraph)]
#![allow(clippy::doc_lazy_continuation)]

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
//! - [`admission_kernel`]: `AdmissionKernel` plan/execute API with
//!   capability-gated effect surfaces (RFC-0019 REQ-0023, RFC-0032::REQ-0170)
//! - [`episode`]: Episode runtime for bounded execution management
//! - [`evidence`]: Flight recording and evidence retention
//! - [`gate`]: Gate execution orchestrator for autonomous gate lifecycle
//!   (RFC-0032::REQ-0142)
//! - [`htf`]: Holonic Time Framework clock service and envelope stamping
//! - [`metrics`]: Prometheus metrics for daemon health observability
//!   (REQ-DCP-0012)
//! - [`projection`]: FAC projection adapters for external system sync
//! - [`protocol`]: UDS protocol and message framing
//! - [`session`]: Session handling with context firewall integration
//! - [`hmp`]: Holonic Message Protocol (HMP) — digest-first channels and
//!   admission receipt semantics for RFC-0020 (RFC-0020::REQ-0034)
//! - [`hsi_contract`]: HSI Contract Manifest V1 for RFC-0020
//!   (RFC-0020::REQ-0001)
//! - [`identity`]: Canonical identity identifiers (`PublicKeyIdV1`,
//!   `KeySetIdV1`, `CellIdV1`, `HolonIdV1`) for RFC-0020
//! - [`fs_safe`]: Safe atomic file I/O primitives (atomic write, symlink
//!   refusal, bounded JSON read) for queue/lease/receipt state files
//! - [`telemetry`]: Cgroup-based resource telemetry collection

pub mod admission_kernel;
pub mod cas;
pub mod episode;
pub mod evidence;
pub mod fs_safe;
pub mod gate;
pub mod governance;
pub mod governance_channel;
pub mod hmp;
pub mod hsi_contract;
pub mod htf;
pub mod identity;
pub mod ledger;
/// Shared freeze-aware ledger polling module (TCK-00675).
///
/// Consolidates the duplicated SQL query logic for polling events from both
/// the legacy `ledger_events` table and the canonical `events` table
/// introduced by RFC-0032 freeze mode.
pub mod ledger_poll;
pub mod metrics;
pub mod pcac;
pub mod projection;
pub mod protocol;
pub mod quarantine_store;
pub mod session;
pub mod state;
pub mod telemetry;
pub mod work;
