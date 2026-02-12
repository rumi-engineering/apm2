// AGENT-AUTHORED (TCK-00496)
//! Durable quarantine store with priority-aware eviction, per-session quota
//! isolation, saturation-safe insertion, and restart-safe persistence.
//!
//! # Overview
//!
//! This module implements the [`DurableQuarantineGuard`] which satisfies the
//! [`QuarantineGuard`](crate::admission_kernel::QuarantineGuard) trait for
//! fail-closed admission. It provides:
//!
//! - **Priority-aware eviction**: Expired entries evicted first, then lowest
//!   priority; unexpired entries with priority >= incoming are never evicted.
//! - **Saturation-safe insertion**: When mandatory quarantine capacity is
//!   exhausted and no evictable entry exists, the request is denied
//!   (fail-closed).
//! - **Per-session quota isolation**: Bounded per-session entries prevent one
//!   adversarial session from exhausting global capacity.
//! - **Restart-safe persistence**: `SQLite`-backed storage survives daemon
//!   restart; storage unavailable = deny.
//! - **Audit-bindable operations**: Insert/evict carry `RequestId` +
//!   `AdmissionBundleDigest` for audit traceability.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │         DurableQuarantineGuard           │
//! │  (implements QuarantineGuard trait)       │
//! │                                          │
//! │  ┌──────────────────────────────────┐    │
//! │  │     QuarantineStore (in-mem)     │    │
//! │  │  - BTreeMap<EntryId, Entry>      │    │
//! │  │  - HashMap<SessionId, count>     │    │
//! │  │  - Priority-aware eviction       │    │
//! │  └──────────────┬───────────────────┘    │
//! │                 │                        │
//! │  ┌──────────────▼───────────────────┐    │
//! │  │   SqliteQuarantineBackend        │    │
//! │  │  - Persistent quarantine entries │    │
//! │  │  - WAL mode for durability       │    │
//! │  └──────────────────────────────────┘    │
//! └──────────────────────────────────────────┘
//! ```
//!
//! # Security
//!
//! - All collections bounded by `MAX_*` constants
//! - Fail-closed on storage errors
//! - No panics on untrusted input
//! - Constant-time hash comparison for reservation verification
//! - HTF tick-based expiry (not wall clock)

mod store;
#[cfg(test)]
mod tests;

pub use store::{
    DurableQuarantineGuard, QuarantineEntry, QuarantineEntryId, QuarantinePriority,
    QuarantineStore, QuarantineStoreConfig, QuarantineStoreError, SqliteQuarantineBackend,
};
