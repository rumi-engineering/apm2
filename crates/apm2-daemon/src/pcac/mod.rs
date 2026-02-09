// AGENT-AUTHORED
//! PCAC lifecycle gate for `RequestTool` authority control (TCK-00423).
//!
//! This module wires the `AuthorityJoinKernel` lifecycle into the daemon's
//! session dispatch path. Every authoritative side effect (tool execution)
//! must pass through `join -> revalidate -> consume` before the effect is
//! permitted.
//!
//! # Integration Point
//!
//! The [`LifecycleGate`] is injected into [`SessionDispatcher`] and called
//! between V1 scope enforcement and broker dispatch in `handle_request_tool`.

pub mod durable_consume;
mod lifecycle_gate;

#[cfg(test)]
mod tests;

pub use durable_consume::{
    ConsumeError, DurableConsumeIndex, DurableConsumeMetrics, DurableKernel, FileBackedConsumeIndex,
};
pub use lifecycle_gate::{InProcessKernel, LifecycleGate, LifecycleReceipts};
