//! Orchestrator kernel runtime harness.
//!
//! The kernel provides a minimal extraction-first control loop:
//! Observe -> Plan -> Execute -> Receipt.
//! It is intentionally narrow and reusable across daemon orchestrators.
//!
//! # Cursor model
//!
//! The kernel is cursor-generic via the [`KernelCursor`] trait.  Each
//! [`LedgerReader`] declares an associated cursor type that defines the
//! total order used by the Observe phase.  The cursor must implement `Ord`
//! consistently with the ledger's returned event order.
//!
//! [`CompositeCursor`] (`timestamp_ns` + `event_id`) remains the default
//! implementation for timestamp-based ledgers and is available as the
//! [`DefaultCursor`] type alias.  Sequence-based or BFT commit-index
//! cursors are equally valid; the kernel only requires `Ord`.
//!
//! # Phase contracts
//!
//! - Observe: read ledger events strictly after a durable cursor.
//! - Plan: derive intents deterministically from folded state.
//! - Execute: dispatch bounded intent batches behind effect-journal fencing.
//! - Receipt: durably persist receipt events before acknowledging completion.
//!
//! # Safety invariants
//!
//! - Cursor progression is monotonic by cursor `Ord`.
//! - Cursor advancement never happens before receipt durability for the same
//!   observed span.
//! - `Unknown`/in-doubt effect states require explicit resolution; ambiguity is
//!   fail-closed.
//! - Per-tick observe and execute work is explicitly bounded by `TickConfig`.

pub mod controller_loop;
pub mod effect_journal;
pub mod intent_store;
pub mod ledger_tailer;
pub mod types;

pub use controller_loop::{ControllerLoopError, OrchestratorDomain, ReceiptWriter, run_tick};
pub use effect_journal::{
    EffectExecutionState, EffectJournal, InDoubtResolution, OutputReleaseDenied,
    OutputReleasePolicy, check_output_release_permitted,
};
pub use intent_store::IntentStore;
pub use ledger_tailer::{
    CursorEvent, CursorStore, LedgerReader, advance_cursor_with_event, is_after_cursor,
    sort_and_truncate_events,
};
pub use types::{
    CompositeCursor, DefaultCursor, EventEnvelope, ExecutionOutcome, KernelCursor, TickConfig,
    TickReport,
};
