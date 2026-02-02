//! Kernel event types generated from Protocol Buffers.
//!
//! This module provides the core event types for the APM2 kernel, including:
//!
//! - **Session events**: Start, progress, termination, quarantine
//! - **Work events**: Opening, transitions, completion, abort
//! - **Tool events**: Requests, decisions, execution results
//! - **Lease events**: Issue, renewal, release, expiration, conflicts
//! - **Policy events**: Loading, violations, budget exceeded
//! - **Adjudication events**: Requests, votes, resolution, timeout
//! - **Evidence events**: Published artifacts, gate receipts
//!
//! All events are wrapped in a [`KernelEvent`] envelope that includes
//! sequence numbers, timestamps, signatures, and hash chain links.
//!
//! # CI Workflow Events
//!
//! The [`ci`] submodule provides ledger event types for CI workflow
//! completions, separate from the Protocol Buffer-based kernel events. These
//! are JSON-serializable events for audit logging and downstream processing.
//!
//! # Canonical Encoding
//!
//! Events use Protocol Buffers for encoding with the following constraints
//! to ensure deterministic serialization (required for signatures):
//!
//! - No maps are used in message types (maps have non-deterministic ordering)
//! - All repeated fields use sorted order when signed
//! - `BTreeMap` is used for any map-like structures in Rust
//!
//! # Example
//!
//! ```rust
//! use apm2_core::events::kernel_event::Payload;
//! use apm2_core::events::session_event::Event;
//! use apm2_core::events::{KernelEvent, SessionEvent, SessionStarted};
//! use prost::Message;
//!
//! // Create a session started event
//! let started = SessionStarted {
//!     session_id: "session-123".to_string(),
//!     actor_id: "actor-456".to_string(),
//!     adapter_type: "claude-code".to_string(),
//!     work_id: "work-789".to_string(),
//!     lease_id: "lease-012".to_string(),
//!     entropy_budget: 1000,
//!     resume_cursor: 0,
//!     restart_attempt: 0,
//!     // HTF time envelope reference (RFC-0016): not yet populated.
//!     time_envelope_ref: None,
//! };
//!
//! let session_event = SessionEvent {
//!     event: Some(Event::Started(started)),
//! };
//!
//! let kernel_event = KernelEvent {
//!     sequence: 1,
//!     session_id: "session-123".to_string(),
//!     payload: Some(Payload::Session(session_event)),
//!     ..Default::default()
//! };
//!
//! // Encode to bytes
//! let bytes = kernel_event.encode_to_vec();
//!
//! // Decode from bytes
//! let decoded = KernelEvent::decode(bytes.as_slice()).unwrap();
//! assert_eq!(decoded.sequence, 1);
//! ```

#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::doc_markdown,
    clippy::match_single_binding,
    clippy::missing_const_for_fn,
    clippy::must_use_candidate,
    clippy::redundant_closure,
    clippy::struct_field_names,
    missing_docs
)]
mod generated {
    include!("apm2.kernel.v1.rs");
}

mod canonical;
pub mod ci;

pub use canonical::{
    Canonicalize, DomainSeparatedCanonical, EPISODE_SPAWNED_DOMAIN_PREFIX,
    SESSION_TERMINATED_DOMAIN_PREFIX, TOOL_DECIDED_DOMAIN_PREFIX, TOOL_EXECUTED_DOMAIN_PREFIX,
    WORK_CLAIMED_DOMAIN_PREFIX,
};
pub use generated::*;

#[cfg(test)]
mod tests;
