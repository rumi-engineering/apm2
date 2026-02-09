// AGENT-AUTHORED
//! Proof-Carrying Authority Continuity (PCAC) — RFC-0027.
//!
//! This module implements the core PCAC primitives: the authority lifecycle
//! contract (`join -> revalidate -> consume -> effect`) that gates all
//! authority-bearing side effects with a single, canonical, one-time-consumable
//! authority witness.
//!
//! # Core Abstractions
//!
//! - [`AuthorityJoinInputV1`]: Canonical input set for computing admissible
//!   authority.
//! - [`AuthorityJoinCertificateV1`] (AJC): Single-use authority witness with
//!   copy-tolerant semantics.
//! - [`AuthorityJoinKernel`]: Minimal kernel API (`join`, `revalidate`,
//!   `consume`).
//! - Lifecycle receipts: [`AuthorityJoinReceiptV1`],
//!   [`AuthorityRevalidateReceiptV1`], [`AuthorityConsumeReceiptV1`],
//!   [`AuthorityDenyReceiptV1`].
//! - [`AuthorityDenyV1`]: Machine-checkable deny taxonomy.
//!
//! # Semantic Laws (RFC-0027 §4)
//!
//! 1. **Linear Consumption**: each AJC authorizes at most one side effect.
//! 2. **Intent Equality**: consume requires exact intent digest equality.
//! 3. **Freshness Dominance**: Tier2+ consume denies on stale/missing/ambiguous
//!    freshness.
//! 4. **Revocation Dominance**: revocation frontier advancement denies consume.
//! 5. **Delegation Narrowing**: delegated joins must be strict-subset of
//!    parent.
//! 6. **Boundary Monotonicity**: `join < revalidate <= consume <= effect`.
//! 7. **Evidence Sufficiency**: authoritative outcomes require
//!    replay-resolvable receipts.
//!
//! # Security Model
//!
//! All types enforce fail-closed semantics: missing required fields, unknown
//! enum variants, and ambiguous authority states produce deterministic denials.

mod deny;
mod kernel;
mod receipts;
mod types;

#[cfg(test)]
mod tests;

pub use deny::{AuthorityDenyClass, AuthorityDenyV1};
pub use kernel::AuthorityJoinKernel;
pub use receipts::{
    AuthorityConsumeReceiptV1, AuthorityDenyReceiptV1, AuthorityJoinReceiptV1,
    AuthorityRevalidateReceiptV1,
};
pub use types::{
    AuthorityConsumeRecordV1, AuthorityConsumedV1, AuthorityJoinCertificateV1,
    AuthorityJoinInputV1, IdentityEvidenceLevel,
};
