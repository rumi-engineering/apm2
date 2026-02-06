// AGENT-AUTHORED (TCK-00388)
//! Gate execution orchestrator for autonomous gate lifecycle.
//!
//! This module implements the [`GateOrchestrator`] which watches for
//! `session_terminated` ledger events and autonomously orchestrates the
//! gate lifecycle: policy resolution, lease issuance, gate executor
//! spawning, and receipt collection.
//!
//! # FAC State Machine
//!
//! ```text
//! session_terminated -> RUN_GATES -> gate_receipt -> AWAIT_REVIEW
//! ```
//!
//! The `GateOrchestrator` bridges the gap between session termination and
//! gate execution by:
//!
//! 1. Watching for `session_terminated` events on the ledger
//! 2. Resolving policy via `PolicyResolvedForChangeSet`
//! 3. Issuing `GateLease` for each required gate (aat, quality, security)
//! 4. Spawning gate executor episodes via `EpisodeRuntime`
//! 5. Collecting `GateReceipt` results (or timeout -> FAIL verdict)
//!
//! # Security Invariants
//!
//! - **Ordering invariant**: `PolicyResolvedForChangeSet` MUST be emitted
//!   before any `GateLeaseIssued` event for the same `work_id/changeset`.
//! - **Domain-separated signatures**: All gate leases use the
//!   `GATE_LEASE_ISSUED:` Ed25519 domain prefix.
//! - **Fail-closed timeouts**: Expired leases produce FAIL verdict, not silent
//!   expiry.
//! - **Changeset binding**: The `changeset_digest` in each lease MUST match the
//!   actual changeset from the terminated session.
//!
//! # Resource Limits
//!
//! - Maximum concurrent gate orchestrations: [`MAX_CONCURRENT_ORCHESTRATIONS`]
//! - Maximum gate types per orchestration: [`MAX_GATE_TYPES`]
//! - Gate lease timeout: [`DEFAULT_GATE_TIMEOUT_MS`]

mod orchestrator;

pub use orchestrator::{
    Clock, DEFAULT_GATE_TIMEOUT_MS, GateOrchestrator, GateOrchestratorConfig,
    GateOrchestratorError, GateOrchestratorEvent, GateOutcome, GateStatus, GateType,
    MAX_CONCURRENT_ORCHESTRATIONS, MAX_GATE_TYPES, MAX_TERMINATED_AT_AGE_MS, MAX_WORK_ID_LENGTH,
    SessionTerminatedInfo, SystemClock, create_timeout_receipt,
};
