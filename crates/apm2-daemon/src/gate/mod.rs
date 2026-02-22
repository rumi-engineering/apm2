// AGENT-AUTHORED (TCK-00388, TCK-00390)
//! Gate execution orchestrator and merge executor for autonomous gate
//! lifecycle.
//!
//! This module implements the [`GateOrchestrator`] which watches for
//! `session_terminated` ledger events and autonomously orchestrates the
//! gate lifecycle: policy resolution, lease issuance, gate executor
//! spawning, and receipt collection.
//!
//! It also implements the [`MergeExecutor`] (TCK-00390) which watches for
//! all required gate receipts reaching PASS verdict and autonomously
//! executes the merge via GitHub API, creates a signed `MergeReceipt`,
//! and transitions work state to Completed.
//!
//! # FAC State Machine
//!
//! ```text
//! session_terminated -> RUN_GATES -> gate_receipt -> AWAIT_REVIEW
//!                                                 -> ALL_PASS -> MERGE -> Completed
//!                                                 -> CONFLICT -> ReviewBlocked
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
//! 6. When all gates pass, the [`MergeExecutor`] autonomously merges
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

pub mod merge_executor;
mod orchestrator;
mod timeout_kernel;

pub use merge_executor::{
    ExecuteOrBlockResult, GitHubMergeAdapter, MAX_PENDING_MERGES, MergeExecutor,
    MergeExecutorError, MergeExecutorEvent, MergeInput, MergeResult,
};
pub use orchestrator::{
    Clock, DEFAULT_GATE_TIMEOUT_MS, GateOrchestrator, GateOrchestratorConfig,
    GateOrchestratorError, GateOrchestratorEvent, GateOutcome, GateStatus, GateType,
    MAX_CONCURRENT_ORCHESTRATIONS, MAX_GATE_TYPES, MAX_IDEMPOTENCY_KEYS, MAX_TERMINATED_AT_AGE_MS,
    MAX_WORK_ID_LENGTH, SessionTerminatedInfo, SystemClock, TIMEOUT_AUTHORITY_ACTOR_ID,
    create_timeout_receipt,
};
pub use timeout_kernel::{GateTimeoutKernel, GateTimeoutKernelConfig, GateTimeoutKernelError};
