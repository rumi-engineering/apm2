// AGENT-AUTHORED (TCK-00212, TCK-00322)
//! Projection adapters for the FAC (Forge Admission Cycle).
//!
//! This module implements write-only projection adapters that synchronize
//! ledger state to external systems. The key design principle is that the
//! ledger is always the source of truth - projections are one-way writes.
//!
//! # RFC-0019: Projection Worker (TCK-00322)
//!
//! Per RFC-0019 Workstream F, this module now includes a long-running
//! projection worker that:
//!
//! 1. Tails the ledger for `ReviewReceiptRecorded` events
//! 2. Maintains a work index: `changeset_digest` -> `work_id` -> PR metadata
//! 3. Projects review results to GitHub (status + comment)
//! 4. Stores projection receipts in CAS for idempotency
//!
//! # RFC-0015: FAC Projections
//!
//! Per RFC-0015, projection adapters:
//!
//! 1. Receive status updates from the FAC ledger
//! 2. Project those statuses to external systems (e.g., GitHub)
//! 3. Generate signed [`ProjectionReceipt`] proving the projection
//! 4. Maintain idempotency with `(work_id, changeset_digest, ledger_head)` key
//!
//! # Security Model
//!
//! - **Write-only**: Adapters NEVER read external state as truth
//! - **Ledger is truth**: All decisions are made based on ledger state
//! - **Signed receipts**: Every projection generates a signed receipt
//! - **Domain separation**: Receipts use `PROJECTION_RECEIPT:` prefix
//! - **Idempotent**: Safe for retries
//! - **Persistent cache**: Idempotency cache survives restarts (THESIS-02)
//!
//! # Components
//!
//! - [`ProjectionWorker`]: Long-running worker that tails ledger and projects
//! - [`WorkIndex`]: Work index for changeset -> `work_id` -> PR mappings
//! - [`LedgerTailer`]: Ledger event tailer for driving projection decisions
//! - [`ProjectionAdapter`]: Async trait for write-only projection adapters
//! - [`GitHubProjectionAdapter`]: GitHub commit status projection
//! - [`ProjectionReceipt`]: Signed proof of projection
//! - [`ProjectedStatus`]: Status values that can be projected
//! - [`IdempotencyKey`]: Key for idempotent projection operations
//! - [`DivergenceWatchdog`]: Monitors for ledger/trunk divergence (TCK-00213)
//! - [`FreezeRegistry`]: Tracks active intervention freezes
//! - [`TamperEvent`]: Event emitted when tamper is detected (TCK-00214)
//! - [`TamperResult`]: Result of handling a tamper event
//! - [`IntentBuffer`]: Durable SQLite-backed buffer for projection intents and
//!   deferred replay backlog (TCK-00504)
//! - [`ConfigBackedResolver`]: Config-backed continuity profile resolver for
//!   economics gate input assembly (TCK-00507)
//! - [`ContinuityProfileResolver`]: Trait for resolving continuity profiles,
//!   sink snapshots, and continuity windows
//! - [`DeferredReplayWorker`]: Worker that drains the deferred replay backlog
//!   after sink recovery, re-evaluating economics gate AND PCAC lifecycle
//!   enforcement for each replayed intent (TCK-00508)
//!
//! # Divergence Watchdog (TCK-00213)
//!
//! The divergence watchdog monitors for discrepancies between the ledger's
//! `MergeReceipt` and the external trunk HEAD. When divergence is detected:
//!
//! 1. Emits `DefectRecord(PROJECTION_DIVERGENCE)`
//! 2. Creates `InterventionFreeze` to halt admissions
//! 3. Requires adjudication-based `InterventionUnfreeze` to resume
//!
//! # Tamper Detection (TCK-00214)
//!
//! Tamper detection identifies when GitHub status has been modified by a
//! non-adapter identity. Unlike divergence (trunk HEAD mismatch), tamper
//! detection focuses on status spoofing. When tamper is detected:
//!
//! 1. Emits `DefectRecord(PROJECTION_TAMPER)`
//! 2. Overwrites GitHub status to match ledger truth
//!
//! # Example: Projection Worker
//!
//! ```rust,ignore
//! use std::sync::{Arc, Mutex};
//! use apm2_daemon::projection::{ProjectionWorker, ProjectionWorkerConfig};
//! use rusqlite::Connection;
//!
//! // Create worker with ledger connection
//! let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
//! let config = ProjectionWorkerConfig::new()
//!     .with_poll_interval(std::time::Duration::from_secs(1));
//!
//! let mut worker = ProjectionWorker::new(conn, config).unwrap();
//!
//! // Register PR association
//! worker.work_index().register_pr("work-001", 123, "owner", "repo", "abc123").unwrap();
//!
//! // Run worker (blocks until shutdown)
//! // worker.run().await.unwrap();
//! ```
//!
//! # Example: Direct Projection
//!
//! ```rust,ignore
//! use apm2_core::crypto::Signer;
//! use apm2_daemon::projection::{
//!     GitHubProjectionAdapter, GitHubAdapterConfig, ProjectionAdapter, ProjectedStatus,
//! };
//!
//! // Create adapter
//! let signer = Signer::generate();
//! let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo")?;
//! let adapter = GitHubProjectionAdapter::new_mock(signer, config)?;
//!
//! // Project a status (async)
//! let receipt = adapter.project_status(
//!     "work-001",
//!     [0x42; 32],  // changeset_digest
//!     [0xAB; 32],  // ledger_head
//!     ProjectedStatus::Success,
//! ).await?;
//!
//! // Verify the receipt
//! assert!(receipt.validate_signature(&adapter.verifying_key()).is_ok());
//! ```

pub mod continuity_resolver;
pub mod deferred_replay_worker;
pub mod divergence_watchdog;
pub mod github_sync;
pub mod intent_buffer;
pub mod projection_receipt;
pub mod worker;

// Re-export main types
pub use continuity_resolver::{
    ConfigBackedResolver, ConfigResolverError, ContinuityProfileResolver, MAX_RESOLVED_PROFILES,
    ResolvedContinuityProfile, ResolvedContinuityWindow,
};
pub use deferred_replay_worker::{
    DEFAULT_REPLAY_BATCH_SIZE, DENY_REPLAY_ALREADY_PROJECTED, DENY_REPLAY_ECONOMICS_GATE,
    DENY_REPLAY_HORIZON_OUT_OF_WINDOW, DENY_REPLAY_LIFECYCLE_GATE, DENY_REPLAY_MISSING_DEPENDENCY,
    DeferredReplayError, DeferredReplayWorker, DeferredReplayWorkerConfig, ReplayCycleResult,
};
pub use divergence_watchdog::{
    DivergenceError, DivergenceResult, DivergenceWatchdog, DivergenceWatchdogConfig, FreezeCheck,
    FreezeCheckError, FreezeRegistry, FreezeScope, InterventionFreeze, InterventionFreezeBuilder,
    InterventionUnfreeze, InterventionUnfreezeBuilder, ResolutionType, SystemTimeSource,
    TimeSource,
};
pub use github_sync::{
    GitHubAdapterConfig, GitHubProjectionAdapter, ProjectionAdapter, ProjectionError, TamperEvent,
    TamperResult,
};
pub use intent_buffer::{
    DeferredReplayEntry, IntentBuffer, IntentBufferError, IntentVerdict, MAX_BACKLOG_ITEMS,
    ProjectionIntent,
};
pub use projection_receipt::{
    DeferredReplayReceiptInput, IdempotencyKey, MAX_BOUNDARY_ID_LENGTH, MAX_STRING_LENGTH,
    ProjectedStatus, ProjectionAdmissionReceipt, ProjectionAdmissionReceiptBuilder,
    ProjectionReceipt, ProjectionReceiptBuilder, ProjectionReceiptError,
};
pub use worker::{
    AdmissionTelemetry, LedgerTailer, PrMetadata, ProjectionWorker, ProjectionWorkerConfig,
    ProjectionWorkerError, WorkIndex, lifecycle_deny,
};
