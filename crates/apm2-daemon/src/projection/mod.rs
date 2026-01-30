// AGENT-AUTHORED (TCK-00212)
//! Projection adapters for the FAC (Forge Admission Cycle).
//!
//! This module implements write-only projection adapters that synchronize
//! ledger state to external systems. The key design principle is that the
//! ledger is always the source of truth - projections are one-way writes.
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
//! - [`ProjectionAdapter`]: Async trait for write-only projection adapters
//! - [`GitHubProjectionAdapter`]: GitHub commit status projection
//! - [`ProjectionReceipt`]: Signed proof of projection
//! - [`ProjectedStatus`]: Status values that can be projected
//! - [`IdempotencyKey`]: Key for idempotent projection operations
//!
//! # Future Work
//!
//! - Divergence watchdog (TCK-00213)
//! - Tamper detection (TCK-00214)
//!
//! # Example
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

pub mod github_sync;
pub mod projection_receipt;

// Re-export main types
pub use github_sync::{
    GitHubAdapterConfig, GitHubProjectionAdapter, ProjectionAdapter, ProjectionError,
};
pub use projection_receipt::{
    IdempotencyKey, MAX_STRING_LENGTH, ProjectedStatus, ProjectionReceipt,
    ProjectionReceiptBuilder, ProjectionReceiptError,
};
