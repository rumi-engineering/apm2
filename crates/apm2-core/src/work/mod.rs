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
//! # CI-Gated Workflow
//!
//! The CI-gated workflow adds additional states for PR-based work:
//!
//! ```text
//! InProgress --PR created--> CiPending
//!                            |
//!            CI Success------+------CI Failure
//!            v                      v
//!       ReadyForReview          Blocked
//!            |                      |
//!            v                      v
//!         Review           CiPending (retry)
//! ```
//!
//! See [`ci_queue`] for CI event processing logic.
//!
//! # Key Concepts
//!
//! - **Work**: A tracked unit of work with state transitions
//! - **`WorkState`**: The current lifecycle state of work (OPEN, CLAIMED, etc.)
//! - **Spec Snapshot**: Hash of the specification at work creation time
//! - **Requirement Binding**: Links work to PRD requirements
//! - **CI Gating**: Work items can be gated on CI completion before review
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

pub mod ci_queue;
mod error;
pub mod parity;
mod reducer;
mod state;

#[cfg(test)]
mod tests;

pub use ci_queue::{
    CiQueueProcessResult, CiTransitionBuilder, can_transition_from_ci, process_ci_event,
    target_phase_for_conclusion,
};
pub use error::WorkError;
pub use parity::{
    EventFamily, EventFamilyMapping, EventFamilyPromotionGate, MAPPING_MATRIX, ParityCheckResult,
    ParityDefect, ParityField, ParityValidator, PromotionGateResult, ReplayEquivalenceChecker,
    ReplayResult, TransitionClass,
};
pub use reducer::{
    MAX_IDENTITY_CHAIN_DEFECTS, ReceiptOutcome, WorkReducer, WorkReducerState,
    extract_work_id_and_digest_from_payload, hash_defect_preimage, helpers,
};
pub use state::{Work, WorkState, WorkType};
