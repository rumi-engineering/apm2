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
//! The [`LifecycleGate`] is injected into `SessionDispatcher` and called
//! in split stages from `handle_request_tool`:
//! `join -> revalidate-before-decision -> broker decision ->
//!  revalidate-before-execution -> consume-before-effect`.
//!
//! Anti-entropy economics is exposed through
//! [`LifecycleGate::enforce_anti_entropy_economics`] as a runtime hook for
//! daemon catch-up sync paths.

pub mod durable_consume;
mod lifecycle_gate;
pub mod sovereignty;

#[cfg(test)]
mod tests;

pub use durable_consume::{
    ConsumeError, DurableConsumeIndex, DurableConsumeMetrics, DurableKernel, DurableKernelShared,
    FileBackedConsumeIndex,
};
pub use lifecycle_gate::{
    InProcessKernel, LifecycleGate, LifecycleReceipts, TemporalArbitrationError,
};
pub use sovereignty::{SovereigntyChecker, SovereigntyState};
