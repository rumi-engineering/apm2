//! Work lifecycle authority module (TCK-00415).
//!
//! Runtime authority decisions must come from ledger-backed projections only.
//! Filesystem ticket YAML is explicitly non-authoritative.

/// Projection-backed lifecycle authority interfaces.
pub mod authority;
/// Ledger-event projection rebuild implementation.
pub mod projection;
