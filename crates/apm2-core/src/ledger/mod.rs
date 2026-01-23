//! Ledger storage layer for the APM2 kernel.
//!
//! This module provides an append-only event ledger backed by `SQLite` with WAL
//! mode for efficient concurrent reads. The ledger stores all kernel events in
//! sequence and maintains references to artifacts stored in the
//! content-addressable storage.
//!
//! # Features
//!
//! - **Append-only semantics**: Events can only be added, never modified or
//!   deleted
//! - **Cursor-based reads**: Efficient iteration through events by sequence
//!   number
//! - **WAL mode**: Concurrent read access while writes are in progress
//! - **Artifact references**: Links to content-addressable storage for large
//!   payloads
//!
//! # Example
//!
//! ```rust,no_run
//! use apm2_core::ledger::{EventRecord, Ledger};
//!
//! # fn example() -> Result<(), apm2_core::ledger::LedgerError> {
//! let ledger = Ledger::open("/path/to/ledger.db")?;
//!
//! // Append an event
//! let event = EventRecord::new(
//!     "session.start",
//!     "session-123",
//!     b"{\"user\": \"alice\"}".to_vec(),
//! );
//! let seq_id = ledger.append(&event)?;
//!
//! // Read events from a cursor
//! let events = ledger.read_from(0, 100)?;
//! # Ok(())
//! # }
//! ```

mod storage;

#[cfg(test)]
mod tests;

pub use storage::{ArtifactRef, EventRecord, Ledger, LedgerError, LedgerStats};
