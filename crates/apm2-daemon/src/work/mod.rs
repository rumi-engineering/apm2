//! Work lifecycle authority module (RFC-0032::REQ-0159, RFC-0032::REQ-0164).
//!
//! Runtime authority decisions must come from ledger-backed projections only.
//! Filesystem ticket YAML is explicitly non-authoritative.
//!
//! # Alias Reconciliation (RFC-0032::REQ-0164)
//!
//! The [`authority::AliasReconciliationGate`] trait and
//! [`authority::ProjectionAliasReconciliationGate`] implementation wire the
//! alias reconciliation module (`apm2_core::events::alias_reconcile`) into
//! the daemon work authority layer, providing production callsites for
//! reconciliation, promotion gating, and snapshot-emitter sunset evaluation.

/// Projection-backed lifecycle authority interfaces.
pub mod authority;
/// Ledger-event projection rebuild implementation.
pub mod projection;
