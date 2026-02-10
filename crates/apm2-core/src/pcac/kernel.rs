// AGENT-AUTHORED
//! `AuthorityJoinKernel` — the minimal PCAC kernel API (RFC-0027 §3.3).
//!
//! This trait defines the three operations of the authority lifecycle:
//!
//! 1. `join` — construct an AJC from validated inputs.
//! 2. `revalidate` — verify an AJC remains valid against current state.
//! 3. `consume` — single-use consumption before side effect execution.
//!
//! # Replay Order Contract (RFC-0027 §6.4)
//!
//! For any side-effectful operation:
//!
//! `AuthorityJoin < AuthorityRevalidate < AuthorityConsume <= EffectReceipt`
//!
//! When pre-actuation checks apply:
//!
//! `AuthorityJoin < PreActuationCheck < AuthorityRevalidate < AuthorityConsume
//! <= EffectReceipt`

use super::deny::AuthorityDenyV1;
use super::intent_class::BoundaryIntentClass;
use super::types::{
    AuthorityConsumeRecordV1, AuthorityConsumedV1, AuthorityJoinCertificateV1,
    AuthorityJoinInputV1, PcacPolicyKnobs,
};
use crate::crypto::Hash;

/// Minimal kernel API for PCAC authority lifecycle operations.
///
/// # Implementations
///
/// - In-process implementation (Phase 1): validates locally against daemon
///   state.
/// - Distributed implementation (Phase 4, future): validates against replicated
///   authority state.
///
/// # Error Handling
///
/// All operations return `AuthorityDenyV1` on failure, which carries
/// machine-checkable deny class, time witness, and audit context.
pub trait AuthorityJoinKernel: Send + Sync {
    /// Construct an AJC from validated join inputs.
    ///
    /// # Process
    ///
    /// 1. Validate all required fields are present and non-zero.
    /// 2. Compute `authority_join_hash` over normalized inputs.
    /// 3. Mint AJC with expiry, revocation head, and time witness.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityDenyV1` with appropriate `AuthorityDenyClass`:
    /// - `MissingRequiredField` for absent inputs.
    /// - `ZeroHash` for uninitialized hash fields.
    /// - `InvalidSessionId`, `InvalidLeaseId` for malformed identifiers.
    /// - `StaleFreshnessAtJoin` for stale freshness witness.
    /// - `PointerOnlyDeniedAtTier2Plus` for Tier2+ without verified identity.
    fn join(
        &self,
        input: &AuthorityJoinInputV1,
        policy: &PcacPolicyKnobs,
    ) -> Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>>;

    /// Verify an AJC remains valid against current authority state.
    ///
    /// # Arguments
    ///
    /// * `cert` — The AJC to revalidate.
    /// * `current_time_envelope_ref` — Current HTF time witness.
    /// * `current_ledger_anchor` — Current ledger anchor.
    /// * `current_revocation_head_hash` — Current revocation frontier.
    /// * `policy` — Resolved PCAC policy knobs for this authority operation.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityDenyV1` with:
    /// - `CertificateExpired` if tick > `expires_at_tick`.
    /// - `RevocationFrontierAdvanced` if revocation head moved.
    /// - `StaleFreshnessAtRevalidate` for stale freshness.
    /// - `LedgerAnchorDrift` if ledger anchor advanced unexpectedly.
    fn revalidate(
        &self,
        cert: &AuthorityJoinCertificateV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
        policy: &PcacPolicyKnobs,
    ) -> Result<(), Box<AuthorityDenyV1>>;

    /// Consume an AJC for a specific intent, returning proof of consumption.
    ///
    /// # Process
    ///
    /// 1. Verify revocation frontier has not advanced (Law 4).
    /// 2. Verify intent digest equality (Law 2).
    /// 3. Check AJC has not been consumed (Law 1 — durable check).
    /// 4. Write durable consume record (before effect acceptance).
    /// 5. Return consumed witness and consume record.
    ///
    /// # Arguments
    ///
    /// * `cert` — The AJC to consume.
    /// * `intent_digest` — Must match the AJC's intent digest exactly.
    /// * `boundary_intent_class` — Consume-stage intent class presented by the
    ///   caller. MUST match the class bound in `cert`.
    /// * `requires_authoritative_acceptance` — Whether this consume path is
    ///   enforcing authoritative acceptance predicates.
    /// * `current_time_envelope_ref` — Current HTF time witness.
    /// * `current_revocation_head_hash` — Current revocation frontier; if this
    ///   has advanced beyond the AJC's `revocation_head_hash`, consume MUST be
    ///   denied with `RevocationFrontierAdvanced`.
    /// * `policy` — Resolved PCAC policy knobs for this authority operation.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityDenyV1` with:
    /// - `RevocationFrontierAdvanced` if the revocation frontier moved since
    ///   the AJC was issued.
    /// - `IntentDigestMismatch` if digests don't match.
    /// - `IntentClassDriftBetweenStages` if join/consume class bindings
    ///   diverge.
    /// - `ObservationalPayloadInAuthoritativePath` when an `observe` intent is
    ///   supplied for an authoritative consume path.
    /// - `AlreadyConsumed` if this AJC was already consumed.
    /// - `CertificateExpired` if the AJC has expired.
    #[allow(clippy::too_many_arguments)]
    fn consume(
        &self,
        cert: &AuthorityJoinCertificateV1,
        intent_digest: Hash,
        boundary_intent_class: BoundaryIntentClass,
        requires_authoritative_acceptance: bool,
        current_time_envelope_ref: Hash,
        current_revocation_head_hash: Hash,
        policy: &PcacPolicyKnobs,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>>;
}
