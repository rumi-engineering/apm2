//! Work contract data model and lifecycle management.
//!
//! This module provides the work item tracking infrastructure for the APM2
//! kernel. Work items represent units of work that agents can claim, process,
//! and complete.
//!
//! # Architecture
//!
//! ```text
//! WorkOpened --> Work (OPEN)
//!               |
//!               v
//! WorkTransitioned --> Work (CLAIMED/IN_PROGRESS/REVIEW/NEEDS_INPUT)
//!               |
//!               v
//! WorkCompleted/WorkAborted --> Work (COMPLETED/ABORTED)
//! ```
//!
//! # Key Concepts
//!
//! - **Work**: A tracked unit of work with state transitions
//! - **`WorkState`**: The current lifecycle state of work (OPEN, CLAIMED, etc.)
//! - **Spec Snapshot**: Hash of the specification at work creation time
//! - **Requirement Binding**: Links work to PRD requirements
//!
//! # Example
//!
//! ```rust
//! use apm2_core::reducer::{Reducer, ReducerContext};
//! use apm2_core::work::{WorkReducer, WorkState, WorkType};
//!
//! let mut reducer = WorkReducer::new();
//! // Apply work events from the ledger...
//! ```

mod error;
mod reducer;
mod state;

#[cfg(test)]
mod tests;

pub use error::WorkError;
pub use reducer::{WorkReducer, WorkReducerState, helpers};
pub use state::{Work, WorkState, WorkType};
