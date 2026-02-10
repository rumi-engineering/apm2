//! Canonical economics profiles and deterministic budget admission.
//!
//! This module implements RFC-0029 REQ-0001 baseline primitives:
//! - canonical, content-addressed economics profiles keyed by `(RiskTier,
//!   BoundaryIntentClass)`
//! - deterministic admission decisions with fail-closed deny behavior
//! - replay-verifiable admission traces with stable deny reasons

pub mod admission;
pub mod profile;

pub use admission::{
    BudgetAdmissionDecision, BudgetAdmissionEvaluator, BudgetAdmissionTrace,
    BudgetAdmissionVerdict, ObservedUsage,
};
pub use profile::{
    BudgetEntry, ECONOMICS_PROFILE_HASH_DOMAIN, EconomicsProfile, EconomicsProfileError,
    EconomicsProfileInputState, LifecycleCostVector,
};
