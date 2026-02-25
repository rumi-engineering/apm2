//! Shared `SQLite` adapter kit for orchestrator kernel storage concerns.
//!
//! This module provides reusable, multi-tenant `SQLite` implementations of the
//! `apm2_core::orchestrator_kernel` storage traits:
//!
//! - [`SqliteCursorStore`]: durable cursor checkpoint via
//!   `orchestrator_kernel_cursors`
//! - [`SqliteIntentStore`]: durable intent queue via
//!   `orchestrator_kernel_intents`
//! - [`SqliteEffectJournal`]: effect idempotency fence via
//!   `orchestrator_kernel_effect_journal`
//!
//! All tables are keyed by `orchestrator_id` so multiple orchestrators can
//! share a single database file. All async adapter methods use `spawn_blocking`
//! for rusqlite calls to avoid blocking the tokio executor.
//!
//! # Schema initialization
//!
//! Call [`init_orchestrator_runtime_schema`] once at daemon startup for each
//! `SQLite` connection that will host orchestrator kernel state.
//!
//! # Memory adapters
//!
//! The [`memory`] sub-module provides in-memory implementations for unit tests.

pub mod memory;
pub mod sqlite;

pub use memory::{MemoryCursorStore, MemoryEffectJournal, MemoryIntentStore};
pub use sqlite::{
    SqliteCursorStore, SqliteEffectJournal, SqliteIntentStore, init_orchestrator_runtime_schema,
};
