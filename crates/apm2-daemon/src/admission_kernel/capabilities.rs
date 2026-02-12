// AGENT-AUTHORED
//! Capability tokens for `AdmissionKernel` effect gating (RFC-0019 §5.2).
//!
//! These tokens enforce mechanical no-bypass for authoritative effect
//! surfaces. Each token is only constructible within the `admission_kernel`
//! module, preventing external code from invoking effect execution,
//! ledger writes, or quarantine insertion without going through the
//! kernel's plan/execute lifecycle.
//!
//! # Security Model
//!
//! - Tokens use module privacy: the inner field is `pub(super)`, making
//!   construction impossible from outside the `admission_kernel` module.
//! - Tokens are `#[must_use]` to prevent accidental discard.
//! - Tokens are non-`Clone`, non-`Copy` to enforce single-use semantics.
//! - Tokens carry provenance hashes for audit traceability.
//!
//! # Capability Forgery Defense
//!
//! Per RFC-0019 §5.2, capability token construction MUST be impossible
//! via safe public APIs. The `pub(super)` constructor pattern ensures
//! this: only code within `admission_kernel` can create these tokens.

use apm2_core::crypto::Hash;

// =============================================================================
// EffectCapability
// =============================================================================

/// Capability token required to invoke effect execution (RFC-0019 §5.2).
///
/// Only constructible by [`super::AdmissionKernelV1`] after successful
/// plan/consume lifecycle. The effect executor/broker MUST require this
/// token to proceed.
///
/// # Invariants
///
/// - [INV-AK01] Only constructible within `admission_kernel` module.
/// - [INV-AK02] Non-cloneable, non-copyable (single-use).
/// - [INV-AK03] Carries AJC ID and intent digest for audit binding.
#[must_use]
pub struct EffectCapability {
    /// AJC ID that authorized this effect.
    ajc_id: Hash,
    /// Intent digest bound at consume time.
    intent_digest: Hash,
    /// Request ID for audit traceability.
    request_id: Hash,
}

impl EffectCapability {
    /// Create a new effect capability token.
    ///
    /// This constructor is `pub(super)` to enforce that only the
    /// admission kernel module can create these tokens.
    pub(super) const fn new(ajc_id: Hash, intent_digest: Hash, request_id: Hash) -> Self {
        Self {
            ajc_id,
            intent_digest,
            request_id,
        }
    }

    /// The AJC ID that authorized this effect.
    #[must_use]
    pub const fn ajc_id(&self) -> &Hash {
        &self.ajc_id
    }

    /// The intent digest bound at consume time.
    #[must_use]
    pub const fn intent_digest(&self) -> &Hash {
        &self.intent_digest
    }

    /// The request ID for audit traceability.
    #[must_use]
    pub const fn request_id(&self) -> &Hash {
        &self.request_id
    }
}

impl std::fmt::Debug for EffectCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectCapability")
            .field("ajc_id", &hex::encode(self.ajc_id))
            .field("intent_digest", &hex::encode(self.intent_digest))
            .field("request_id", &hex::encode(self.request_id))
            .finish()
    }
}

// =============================================================================
// LedgerWriteCapability
// =============================================================================

/// Capability token required for authoritative ledger writes (RFC-0019 §5.2).
///
/// Only constructible by [`super::AdmissionKernelV1`] after successful
/// consume barrier. Authoritative receipt/event emission MUST require
/// this token.
///
/// # Invariants
///
/// - [INV-AK04] Only constructible within `admission_kernel` module.
/// - [INV-AK05] Non-cloneable, non-copyable (single-use).
/// - [INV-AK06] Carries AJC ID for ledger provenance binding.
#[must_use]
pub struct LedgerWriteCapability {
    /// AJC ID that authorized this write.
    ajc_id: Hash,
    /// Request ID for provenance binding.
    request_id: Hash,
}

impl LedgerWriteCapability {
    /// Create a new ledger write capability token.
    pub(super) const fn new(ajc_id: Hash, request_id: Hash) -> Self {
        Self { ajc_id, request_id }
    }

    /// The AJC ID that authorized this write.
    #[must_use]
    pub const fn ajc_id(&self) -> &Hash {
        &self.ajc_id
    }

    /// The request ID for provenance binding.
    #[must_use]
    pub const fn request_id(&self) -> &Hash {
        &self.request_id
    }
}

impl std::fmt::Debug for LedgerWriteCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerWriteCapability")
            .field("ajc_id", &hex::encode(self.ajc_id))
            .field("request_id", &hex::encode(self.request_id))
            .finish()
    }
}

// =============================================================================
// QuarantineCapability
// =============================================================================

/// Capability token required for quarantine insertion (RFC-0019 §5.2, §7).
///
/// Only constructible by [`super::AdmissionKernelV1`]. Quarantine
/// insertion for boundary violations MUST require this token.
///
/// # Quarantine Reservation
///
/// For fail-closed tiers, the kernel MUST ensure quarantine capacity
/// is available before executing the externalized effect (RFC-0019 §7).
/// This token carries a reservation hash that proves capacity was
/// reserved before effect execution.
///
/// # Invariants
///
/// - [INV-AK07] Only constructible within `admission_kernel` module.
/// - [INV-AK08] Non-cloneable, non-copyable (single-use).
/// - [INV-AK09] Carries reservation hash for durable capacity guard.
#[must_use]
pub struct QuarantineCapability {
    /// AJC ID that authorized this quarantine action.
    ajc_id: Hash,
    /// Request ID for audit traceability.
    request_id: Hash,
    /// Reservation hash proving quarantine capacity was reserved.
    /// Zero hash means reservation was not required (non-fail-closed tier).
    reservation_hash: Hash,
}

impl QuarantineCapability {
    /// Create a new quarantine capability token.
    pub(super) const fn new(ajc_id: Hash, request_id: Hash, reservation_hash: Hash) -> Self {
        Self {
            ajc_id,
            request_id,
            reservation_hash,
        }
    }

    /// The AJC ID that authorized this quarantine action.
    #[must_use]
    pub const fn ajc_id(&self) -> &Hash {
        &self.ajc_id
    }

    /// The request ID for audit traceability.
    #[must_use]
    pub const fn request_id(&self) -> &Hash {
        &self.request_id
    }

    /// The reservation hash proving quarantine capacity was reserved.
    #[must_use]
    pub const fn reservation_hash(&self) -> &Hash {
        &self.reservation_hash
    }
}

impl std::fmt::Debug for QuarantineCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuarantineCapability")
            .field("ajc_id", &hex::encode(self.ajc_id))
            .field("request_id", &hex::encode(self.request_id))
            .field("reservation_hash", &hex::encode(self.reservation_hash))
            .finish()
    }
}
