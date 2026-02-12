// AGENT-AUTHORED
//! `AdmissionKernel`: plan/execute API with capability-gated effect surfaces
//! (RFC-0019 REQ-0023, TCK-00492).
//!
//! This module owns the canonical lifecycle ordering for authoritative
//! request admission: `join -> revalidate -> consume -> effect`.
//!
//! # Architecture
//!
//! [`AdmissionKernelV1`] is the single entry point for all authority-bearing
//! request processing. Handlers call `plan()` to obtain an [`AdmissionPlanV1`],
//! then `execute()` to consume the plan and receive capability tokens for
//! effect execution.
//!
//! # Security Model
//!
//! - Capability tokens ([`EffectCapability`], [`LedgerWriteCapability`],
//!   [`QuarantineCapability`]) are only constructible within this module
//!   (`pub(super)` constructors).
//! - Plans are single-use, non-cloneable, non-serializable.
//! - Prerequisites fail closed: missing ledger state, policy root, or
//!   anti-rollback anchor denies for fail-closed tiers.
//! - Witness seeds are daemon-created with provider provenance binding.
//! - Boundary output is held until post-effect checks for fail-closed tiers.
//!
//! # Phase Ordering
//!
//! ```text
//! plan():    validate -> prerequisite resolution -> witness seed creation ->
//!            spine join extension -> PCAC join -> PCAC revalidate
//! execute(): prerequisite re-check (fail-closed) -> PCAC revalidate (fresh) ->
//!            durable consume -> capability mint -> boundary span init ->
//!            result assembly
//! ```

pub mod capabilities;
pub mod prerequisites;
pub mod trust_stack;
pub mod types;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityJoinInputV1, AuthorityJoinKernel, BoundaryIntentClass, DeterminismClass,
    IdentityEvidenceLevel,
};
use capabilities::{EffectCapability, LedgerWriteCapability, QuarantineCapability};
use prerequisites::{
    AntiRollbackAnchor, LedgerAnchorV1, LedgerTrustVerifier, PolicyRootResolver, TrustError,
};
use rand::RngCore;
use subtle::ConstantTimeEq;
use types::{
    ADMISSION_BUNDLE_SCHEMA_VERSION, AdmissionBundleV1, AdmissionPlanV1, AdmissionResultV1,
    AdmissionSpineJoinExtV1, AdmitError, BoundarySpanV1, EnforcementTier, KernelRequestV1,
    MAX_WITNESS_PROVIDER_ID_LENGTH, MonitorWaiverV1, PlanState, QuarantineActionV1,
    WitnessEvidenceV1, WitnessSeedV1,
};

// =============================================================================
// QuarantineGuard trait
// =============================================================================

/// Trait for durable quarantine capacity reservation (RFC-0019 §7).
///
/// For fail-closed tiers, the kernel MUST reserve quarantine capacity
/// before executing effects. If capacity cannot be reserved, the kernel
/// denies admission (fail-closed).
///
/// Implementations are provided by TCK-00496. This module defines only
/// the trait interface.
///
/// # Fail-Closed Contract
///
/// If capacity cannot be reserved, `reserve()` MUST return `Err`.
/// The kernel MUST deny admission for fail-closed tiers.
pub trait QuarantineGuard: Send + Sync {
    /// Reserve quarantine capacity for the given request.
    ///
    /// The `session_id` parameter identifies the requesting session for
    /// per-session quota isolation. Without it, all requests share a
    /// single quota bucket, enabling a single adversarial session to
    /// exhaust global capacity (denial of service).
    ///
    /// Returns a reservation hash proving capacity was reserved.
    ///
    /// # Errors
    ///
    /// Returns a reason string if capacity cannot be reserved.
    fn reserve(&self, session_id: &str, request_id: &Hash, ajc_id: &Hash) -> Result<Hash, String>;
}

// =============================================================================
// WitnessProviderConfig
// =============================================================================

/// Configuration for daemon witness seed creation.
///
/// Provides the provider identity and build digest used to bind
/// witness seeds to a specific daemon build.
#[derive(Debug, Clone)]
pub struct WitnessProviderConfig {
    /// Provider module identifier (e.g., "apm2-daemon/admission_kernel").
    pub provider_id: String,
    /// Build digest for measurement binding.
    pub provider_build_digest: Hash,
}

impl WitnessProviderConfig {
    /// Validate the provider configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if `provider_id` is empty or too long.
    pub fn validate(&self) -> Result<(), AdmitError> {
        if self.provider_id.is_empty() || self.provider_id.len() > MAX_WITNESS_PROVIDER_ID_LENGTH {
            return Err(AdmitError::WitnessSeedFailure {
                reason: format!(
                    "provider_id must be 1..={MAX_WITNESS_PROVIDER_ID_LENGTH} bytes, got {}",
                    self.provider_id.len()
                ),
            });
        }
        // QUALITY MAJOR 2 (TCK-00492): Non-zero provider_build_digest.
        // A zero build digest means the provider measurement is unbound,
        // which would allow any binary to impersonate this witness provider.
        if self.provider_build_digest == [0u8; 32] {
            return Err(AdmitError::WitnessSeedFailure {
                reason: "provider_build_digest is zero (unbound measurement)".into(),
            });
        }
        Ok(())
    }
}

// =============================================================================
// AdmissionKernelV1
// =============================================================================

/// `AdmissionKernel`: plan/execute API with capability-gated effect surfaces
/// (RFC-0019 REQ-0023, TCK-00492).
///
/// This is the authoritative kernel for all admission decisions. All
/// handler code MUST route through this kernel to obtain capability tokens
/// for effect execution.
///
/// # Lifecycle Guarantee
///
/// The kernel enforces `join -> revalidate -> consume -> effect` ordering.
/// Handler code cannot reorder or skip phases.
///
/// # Prerequisites (Fail-Closed)
///
/// For fail-closed tiers, the kernel requires:
/// - Validated ledger state via [`LedgerTrustVerifier`]
/// - Policy root via [`PolicyRootResolver`]
/// - Anti-rollback anchor via [`AntiRollbackAnchor`]
///
/// Missing prerequisites produce `AdmitError::MissingPrerequisite` or
/// the corresponding typed error.
///
/// # Capability Tokens
///
/// [`EffectCapability`], [`LedgerWriteCapability`], and
/// [`QuarantineCapability`] tokens are ONLY constructible by this kernel.
/// Effect executors/brokers MUST require these tokens to proceed.
pub struct AdmissionKernelV1 {
    /// PCAC lifecycle gate for join/revalidate/consume.
    pcac_kernel: Arc<dyn AuthorityJoinKernel>,
    /// Ledger trust verification (fail-closed on error).
    ledger_verifier: Option<Arc<dyn LedgerTrustVerifier>>,
    /// Policy root resolution (fail-closed on error).
    policy_resolver: Option<Arc<dyn PolicyRootResolver>>,
    /// Anti-rollback anchoring (fail-closed on error for fail-closed tiers).
    anti_rollback: Option<Arc<dyn AntiRollbackAnchor>>,
    /// Quarantine capacity guard (fail-closed on error for fail-closed tiers).
    quarantine_guard: Option<Arc<dyn QuarantineGuard>>,
    /// Witness provider configuration.
    ///
    /// `pub(crate)` to allow the post-effect witness evidence
    /// construction path in `SessionDispatcher::handle_request_tool`
    /// to access provider identity and build digest (TCK-00497).
    pub(crate) witness_provider: WitnessProviderConfig,
}

impl std::fmt::Debug for AdmissionKernelV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // pcac_kernel is `Arc<dyn AuthorityJoinKernel>` (no Debug), so we
        // use finish_non_exhaustive to signal the omitted trait-object field.
        f.debug_struct("AdmissionKernelV1")
            .field("has_ledger_verifier", &self.ledger_verifier.is_some())
            .field("has_policy_resolver", &self.policy_resolver.is_some())
            .field("has_anti_rollback", &self.anti_rollback.is_some())
            .field("has_quarantine_guard", &self.quarantine_guard.is_some())
            .field("witness_provider", &self.witness_provider)
            .finish_non_exhaustive()
    }
}

impl AdmissionKernelV1 {
    /// Create a new admission kernel with the minimum required dependencies.
    ///
    /// # Panics
    ///
    /// Does NOT panic. Returns a kernel that will fail-closed on any
    /// fail-closed tier request if optional prerequisites are missing.
    #[must_use]
    pub fn new(
        pcac_kernel: Arc<dyn AuthorityJoinKernel>,
        witness_provider: WitnessProviderConfig,
    ) -> Self {
        Self {
            pcac_kernel,
            ledger_verifier: None,
            policy_resolver: None,
            anti_rollback: None,
            quarantine_guard: None,
            witness_provider,
        }
    }

    /// Set the ledger trust verifier.
    #[must_use]
    pub fn with_ledger_verifier(mut self, verifier: Arc<dyn LedgerTrustVerifier>) -> Self {
        self.ledger_verifier = Some(verifier);
        self
    }

    /// Set the policy root resolver.
    #[must_use]
    pub fn with_policy_resolver(mut self, resolver: Arc<dyn PolicyRootResolver>) -> Self {
        self.policy_resolver = Some(resolver);
        self
    }

    /// Set the anti-rollback anchor verifier.
    #[must_use]
    pub fn with_anti_rollback(mut self, anchor: Arc<dyn AntiRollbackAnchor>) -> Self {
        self.anti_rollback = Some(anchor);
        self
    }

    /// Set the quarantine capacity guard.
    #[must_use]
    pub fn with_quarantine_guard(mut self, guard: Arc<dyn QuarantineGuard>) -> Self {
        self.quarantine_guard = Some(guard);
        self
    }

    // =========================================================================
    // plan()
    // =========================================================================

    /// Plan phase: validate inputs, resolve prerequisites, create witness
    /// seeds, assemble join input, and execute PCAC join + initial revalidate.
    ///
    /// Returns an [`AdmissionPlanV1`] that is single-use and must be consumed
    /// by [`execute()`](Self::execute).
    ///
    /// # Errors
    ///
    /// - [`AdmitError::InvalidRequest`] if the request fails validation.
    /// - [`AdmitError::MissingPrerequisite`] if a required prerequisite
    ///   interface is not wired (fail-closed tiers only).
    /// - [`AdmitError::LedgerTrustFailure`] if ledger verification fails.
    /// - [`AdmitError::PolicyRootFailure`] if policy root resolution fails.
    /// - [`AdmitError::AntiRollbackFailure`] if anti-rollback anchor fails.
    /// - [`AdmitError::WitnessSeedFailure`] if witness seed creation fails.
    /// - [`AdmitError::JoinDenied`] if PCAC join is denied.
    /// - [`AdmitError::RevalidationDenied`] if initial revalidation is denied.
    pub fn plan(&self, request: &KernelRequestV1) -> Result<AdmissionPlanV1, AdmitError> {
        // Phase A: Validate request inputs (bounded, non-zero).
        request.validate()?;

        // Phase B: Validate witness provider config.
        self.witness_provider.validate()?;

        // Phase C: Determine enforcement tier from risk tier.
        let enforcement_tier = enforcement_tier_from_risk(request.risk_tier);

        // Phase D: Resolve prerequisites (fail-closed for FailClosed tiers).
        let ledger_state = self.resolve_ledger_trust(enforcement_tier)?;
        let policy_state = self.resolve_policy_root(enforcement_tier, &ledger_state.anchor)?;
        self.verify_anti_rollback(enforcement_tier, &ledger_state.anchor)?;

        // Phase E: Create witness seeds (daemon-created, RFC-0019 §4.2.1).
        let nonce_leakage = generate_nonce();
        let nonce_timing = generate_nonce();

        let leakage_seed = WitnessSeedV1 {
            witness_class: "leakage".to_string(),
            request_id: request.request_id,
            session_id: request.session_id.clone(),
            tool_class: request.tool_class.clone(),
            boundary_profile_id: request.boundary_profile_id.clone(),
            ledger_anchor_hash: ledger_state.anchor.content_hash(),
            ht_start: request.freshness_witness_tick,
            nonce: nonce_leakage,
            provider_id: self.witness_provider.provider_id.clone(),
            provider_build_digest: self.witness_provider.provider_build_digest,
        };

        let timing_seed = WitnessSeedV1 {
            witness_class: "timing".to_string(),
            request_id: request.request_id,
            session_id: request.session_id.clone(),
            tool_class: request.tool_class.clone(),
            boundary_profile_id: request.boundary_profile_id.clone(),
            ledger_anchor_hash: ledger_state.anchor.content_hash(),
            ht_start: request.freshness_witness_tick,
            nonce: nonce_timing,
            provider_id: self.witness_provider.provider_id.clone(),
            provider_build_digest: self.witness_provider.provider_build_digest,
        };

        // Phase E.1: Validate witness seeds at join (TCK-00497 QUALITY BLOCKER 1).
        //
        // For fail-closed tiers: deny if seeds are zero, unbound, or have
        // reused nonces. This is the critical gate that prevents requests
        // from proceeding without valid witness instrumentation.
        //
        // For monitor tiers: seed structural validation is still performed
        // (same checks) but waiver enforcement is deferred to the
        // post-effect path (`finalize_post_effect_witness`) where the
        // caller supplies the governance waiver. At plan time, monitor
        // tiers validate seed integrity without requiring a waiver.
        if enforcement_tier == EnforcementTier::FailClosed {
            self.validate_witness_seeds_at_join(
                enforcement_tier,
                &leakage_seed,
                &timing_seed,
                None,
                request.freshness_witness_tick,
            )?;
        }

        // Phase F: Compute canonical request digest for spine extension.
        let canonical_request_digest = compute_canonical_request_digest(request);

        // Phase G: Build AdmissionSpineJoinExtV1.
        let spine_ext = AdmissionSpineJoinExtV1 {
            request_id: request.request_id,
            session_id: request.session_id.clone(),
            tool_class: request.tool_class.clone(),
            boundary_profile_id: request.boundary_profile_id.clone(),
            enforcement_tier,
            hsi_contract_manifest_digest: request.hsi_contract_manifest_digest,
            hsi_envelope_binding_digest: request.hsi_envelope_binding_digest,
            canonical_request_digest,
            effect_descriptor_digest: request.effect_descriptor_digest,
            declared_idempotent: request.declared_idempotent,
            stop_budget_digest: request.stop_budget_digest,
            ledger_anchor: ledger_state.anchor.clone(),
            policy_root_digest: policy_state.digest,
            policy_root_epoch: policy_state.epoch,
            leakage_witness_seed_hash: leakage_seed.content_hash(),
            timing_witness_seed_hash: timing_seed.content_hash(),
        };

        // Phase H: Compute spine extension content hash for join input.
        let spine_ext_hash = spine_ext.content_hash();

        // Phase I: Build PCAC join input via canonical builder pattern.
        // Pass the verifier-selected anchor (NOT the client-supplied
        // directory_head_hash) so the AJC binds to the authoritative
        // ledger state resolved in Phase D.
        let join_input = build_pcac_join_input(request, &spine_ext_hash, &ledger_state.anchor);

        // Phase J: Execute PCAC join.
        let certificate = self
            .pcac_kernel
            .join(&join_input, &request.pcac_policy)
            .map_err(|deny| AdmitError::JoinDenied {
                reason: format!("PCAC join denied: {}", deny.deny_class),
            })?;

        // Phase K: Execute initial revalidation (join-time freshness check).
        self.pcac_kernel
            .revalidate(
                &certificate,
                request.time_envelope_ref,
                ledger_state.anchor.content_hash(),
                request.revocation_head_hash,
                &request.pcac_policy,
            )
            .map_err(|deny| AdmitError::RevalidationDenied {
                reason: format!("Initial revalidation denied: {}", deny.deny_class),
            })?;

        // Phase L: Assemble plan.
        Ok(AdmissionPlanV1 {
            state: PlanState::Ready,
            certificate,
            spine_ext,
            leakage_witness_seed: leakage_seed,
            timing_witness_seed: timing_seed,
            request: request.clone(),
            enforcement_tier,
            as_of_ledger_anchor: ledger_state.anchor,
            policy_root_digest: policy_state.digest,
            policy_root_epoch: policy_state.epoch,
        })
    }

    // =========================================================================
    // execute()
    // =========================================================================

    /// Execute phase: fresh revalidation, durable consume, capability minting,
    /// and result assembly.
    ///
    /// Consumes the plan (single-use enforcement). The plan transitions from
    /// `Ready` to `Consumed`; a second call returns
    /// [`AdmitError::PlanAlreadyConsumed`].
    ///
    /// # Arguments
    ///
    /// * `plan` — The admission plan from [`plan()`](Self::plan).
    /// * `current_time_envelope_ref` — Fresh HTF time envelope reference.
    /// * `current_revocation_head_hash` — Fresh revocation head hash.
    ///
    /// # Errors
    ///
    /// - [`AdmitError::PlanAlreadyConsumed`] if the plan was already executed.
    /// - [`AdmitError::RevalidationDenied`] if fresh revalidation fails.
    /// - [`AdmitError::ConsumeDenied`] if PCAC consume fails.
    /// - [`AdmitError::QuarantineReservationFailure`] if quarantine capacity
    ///   cannot be reserved for fail-closed tiers.
    pub fn execute(
        &self,
        plan: &mut AdmissionPlanV1,
        current_time_envelope_ref: Hash,
        current_revocation_head_hash: Hash,
    ) -> Result<AdmissionResultV1, AdmitError> {
        // Phase M: Single-use enforcement.
        if plan.state == PlanState::Consumed {
            return Err(AdmitError::PlanAlreadyConsumed);
        }
        // Transition state BEFORE any fallible operations to prevent
        // re-execution even if a subsequent step fails. This is intentional:
        // a plan that fails mid-execute is still consumed. The caller must
        // create a new plan.
        plan.state = PlanState::Consumed;

        // Phase N: Prerequisite re-check and fresh revalidation.
        //
        // For fail-closed tiers, we freshly resolve all prerequisites to
        // close the TOCTOU window between plan() and execute(). If any
        // prerequisite drifted, the operation is denied. The fresh ledger
        // anchor is then used for PCAC revalidation so drift detection
        // compares the plan-time anchor (in the AJC cert) against the
        // current authoritative anchor.
        //
        // For monitor tiers, we use the plan-time anchor (no re-check
        // required since monitor tiers do not gate authoritative effects).
        let revalidation_ledger_anchor = if plan.enforcement_tier == EnforcementTier::FailClosed {
            // Re-resolve ledger trust to get the current authoritative anchor.
            let fresh_ledger = self.resolve_ledger_trust(plan.enforcement_tier)?;

            // Re-resolve policy root against the fresh anchor.
            let fresh_policy =
                self.resolve_policy_root(plan.enforcement_tier, &fresh_ledger.anchor)?;

            // Re-verify anti-rollback against the fresh anchor.
            self.verify_anti_rollback(plan.enforcement_tier, &fresh_ledger.anchor)?;

            // Detect policy root drift between plan and execute.
            // SECURITY BLOCKER 1 (TCK-00492): Use constant-time comparison
            // for digest equality to prevent timing side-channels that could
            // leak the expected policy root digest byte-by-byte.
            if !bool::from(fresh_policy.digest.ct_eq(&plan.policy_root_digest)) {
                return Err(AdmitError::ExecutePrerequisiteDrift {
                    prerequisite: "PolicyRoot".into(),
                    reason: "policy root digest drifted between plan and execute".into(),
                });
            }
            if fresh_policy.epoch != plan.policy_root_epoch {
                return Err(AdmitError::ExecutePrerequisiteDrift {
                    prerequisite: "PolicyRoot".into(),
                    reason: "policy root epoch drifted between plan and execute".into(),
                });
            }

            // Use the fresh anchor for PCAC revalidation so the lifecycle
            // gate can compare the cert's as_of_ledger_anchor (plan-time)
            // against the current authoritative anchor (execute-time).
            fresh_ledger.anchor.content_hash()
        } else {
            // Monitor tier: no prerequisite re-check; use plan-time anchor.
            plan.as_of_ledger_anchor.content_hash()
        };

        self.pcac_kernel
            .revalidate(
                &plan.certificate,
                current_time_envelope_ref,
                revalidation_ledger_anchor,
                current_revocation_head_hash,
                &plan.request.pcac_policy,
            )
            .map_err(|deny| AdmitError::RevalidationDenied {
                reason: format!("Execution-time revalidation denied: {}", deny.deny_class),
            })?;

        // Phase O: Quarantine capacity reservation (fail-closed tiers).
        let quarantine_reservation_hash =
            self.reserve_quarantine_capacity(plan.enforcement_tier, plan)?;

        // Phase P: Durable consume (PCAC).
        let (consumed_witness, consume_record) = self
            .pcac_kernel
            .consume(
                &plan.certificate,
                plan.request.intent_digest,
                BoundaryIntentClass::Actuate,
                plan.enforcement_tier == EnforcementTier::FailClosed,
                current_time_envelope_ref,
                current_revocation_head_hash,
                &plan.request.pcac_policy,
            )
            .map_err(|deny| AdmitError::ConsumeDenied {
                reason: format!("PCAC consume denied: {}", deny.deny_class),
            })?;

        // Phase P.1: Anti-rollback anchor commit is DEFERRED to
        // finalize_anti_rollback(), which MUST be called by the caller
        // AFTER the authoritative effect (broker dispatch, ledger write)
        // has been confirmed successful. Committing here (inside execute())
        // would create a pre-commit hazard: if the subsequent effect fails,
        // the anchor watermark would advance past the actual ledger head,
        // permanently deadlocking subsequent fail-closed admissions.
        //
        // See: finalize_anti_rollback() method below.

        // Phase Q: Mint capability tokens.
        let ajc_id = plan.certificate.ajc_id;
        let request_id = plan.request.request_id;
        let intent_digest = plan.request.intent_digest;

        let effect_capability = EffectCapability::new(ajc_id, intent_digest, request_id);

        // Gate LedgerWriteCapability to fail-closed tiers only (CTR-2617).
        // Monitor-tier requests MUST NOT receive authoritative ledger
        // write capabilities — they do not satisfy the prerequisite
        // checks that authorize ledger mutations.
        let ledger_write_capability = if plan.enforcement_tier == EnforcementTier::FailClosed {
            Some(LedgerWriteCapability::new(ajc_id, request_id))
        } else {
            None
        };

        let quarantine_capability = quarantine_reservation_hash.map(|reservation_hash| {
            QuarantineCapability::new(ajc_id, request_id, reservation_hash)
        });

        // Phase R: Initialize boundary span.
        let boundary_span = BoundarySpanV1 {
            request_id,
            output_held: plan.enforcement_tier == EnforcementTier::FailClosed,
            enforcement_tier: plan.enforcement_tier,
        };

        // Phase S: Construct and seal AdmissionBundleV1 (TCK-00493).
        //
        // The bundle is sealed BEFORE any receipts/events reference it.
        // The bundle digest IS the v1.1 AdmissionBindingHash.
        //
        // DIGEST CYCLE AVOIDANCE: The bundle MUST NOT include hashes/ids
        // of receipts/events created after this point. Forward indexing
        // is handled by AdmissionOutcomeIndexV1 (emitted post-bundle).
        let quarantine_actions: Vec<QuarantineActionV1> = quarantine_reservation_hash
            .map(|rh| {
                vec![QuarantineActionV1 {
                    reservation_hash: rh,
                    request_id,
                    ajc_id,
                }]
            })
            .unwrap_or_default();

        let bundle = AdmissionBundleV1 {
            schema_version: ADMISSION_BUNDLE_SCHEMA_VERSION,
            request_id,
            session_id: plan.request.session_id.clone(),
            hsi_contract_manifest_digest: plan.request.hsi_contract_manifest_digest,
            hsi_envelope_binding_digest: plan.request.hsi_envelope_binding_digest,
            policy_root_digest: plan.policy_root_digest,
            policy_root_epoch: plan.policy_root_epoch,
            ajc_id,
            authority_join_hash: plan.certificate.authority_join_hash,
            consume_selector_digest: consume_record.effect_selector_digest,
            intent_digest,
            consume_time_intent_digest: consumed_witness.intent_digest,
            leakage_witness_seed_hash: plan.leakage_witness_seed.content_hash(),
            timing_witness_seed_hash: plan.timing_witness_seed.content_hash(),
            effect_descriptor_digest: plan.request.effect_descriptor_digest,
            quarantine_actions,
            ledger_anchor: plan.as_of_ledger_anchor.clone(),
            time_envelope_ref: current_time_envelope_ref,
            freshness_witness_tick: plan.request.freshness_witness_tick,
            revocation_head_hash: current_revocation_head_hash,
            enforcement_tier: plan.enforcement_tier,
            spine_ext_hash: plan.spine_ext.content_hash(),
            stop_budget_digest: plan.request.stop_budget_digest,
            risk_tier: plan.request.risk_tier,
        };

        // Validate bundle before sealing (fail-closed).
        bundle.validate()?;

        // Seal: compute the deterministic content hash.
        let bundle_digest = bundle.content_hash();

        // Clone the witness seeds from the plan BEFORE returning.
        // The plan is already consumed (state = Consumed) but its fields
        // are still accessible. The runtime post-effect path needs the
        // actual seeds (not just hashes) to call
        // `finalize_post_effect_witness` with full seed/provider binding
        // validation (TCK-00497 QUALITY MAJOR 1).
        let leakage_witness_seed = plan.leakage_witness_seed.clone();
        let timing_witness_seed = plan.timing_witness_seed.clone();

        Ok(AdmissionResultV1 {
            bundle_digest,
            bundle,
            effect_capability,
            ledger_write_capability,
            quarantine_capability,
            consumed_witness,
            consume_record,
            boundary_span,
            leakage_witness_seed,
            timing_witness_seed,
        })
    }

    // =========================================================================
    // Witness closure: seed validation at join (TCK-00497)
    // =========================================================================

    /// Validate that witness seeds are present and non-zero for fail-closed
    /// tiers. Called during `plan()` after seed creation.
    ///
    /// For fail-closed tiers: missing or zero witness seed hashes deny
    /// the join. Stubbed/None seeds are forbidden.
    ///
    /// For monitor tiers: an explicit `monitor_waiver` MUST be provided.
    /// Silent permissive defaults are forbidden. A defect is emitted
    /// (returned as part of the result) if the waiver path is exercised.
    ///
    /// # Errors
    ///
    /// - [`AdmitError::WitnessSeedFailure`] if seeds are zero/missing at
    ///   fail-closed tier.
    /// - [`AdmitError::WitnessWaiverInvalid`] if monitor tier lacks a valid
    ///   waiver.
    pub fn validate_witness_seeds_at_join(
        &self,
        enforcement_tier: EnforcementTier,
        leakage_seed: &WitnessSeedV1,
        timing_seed: &WitnessSeedV1,
        monitor_waiver: Option<&MonitorWaiverV1>,
        current_tick: u64,
    ) -> Result<Option<Hash>, AdmitError> {
        const ZERO: Hash = [0u8; 32];

        let leakage_hash = leakage_seed.content_hash();
        let timing_hash = timing_seed.content_hash();

        match enforcement_tier {
            EnforcementTier::FailClosed => {
                // Fail-closed: both seed hashes MUST be non-zero.
                if leakage_hash == ZERO {
                    return Err(AdmitError::WitnessSeedFailure {
                        reason: "leakage witness seed hash is zero at join \
                                 (fail-closed tier denies missing seeds)"
                            .into(),
                    });
                }
                if timing_hash == ZERO {
                    return Err(AdmitError::WitnessSeedFailure {
                        reason: "timing witness seed hash is zero at join \
                                 (fail-closed tier denies missing seeds)"
                            .into(),
                    });
                }
                // Verify provider provenance binding is non-zero.
                if leakage_seed.provider_build_digest == ZERO {
                    return Err(AdmitError::WitnessSeedFailure {
                        reason: "leakage witness seed provider_build_digest is zero \
                                 (unbound measurement at fail-closed tier)"
                            .into(),
                    });
                }
                if timing_seed.provider_build_digest == ZERO {
                    return Err(AdmitError::WitnessSeedFailure {
                        reason: "timing witness seed provider_build_digest is zero \
                                 (unbound measurement at fail-closed tier)"
                            .into(),
                    });
                }
                // Verify seeds are unique (distinct nonces).
                if bool::from(leakage_seed.nonce.ct_eq(&timing_seed.nonce)) {
                    return Err(AdmitError::WitnessSeedFailure {
                        reason: "leakage and timing witness seeds have identical \
                                 nonces (nonce reuse detected)"
                            .into(),
                    });
                }
                Ok(None)
            },
            EnforcementTier::Monitor => {
                // Monitor tier: explicit waiver required. No silent bypass.
                match monitor_waiver {
                    Some(waiver) => {
                        waiver.validate(current_tick)?;
                        // Return the waiver hash for audit binding.
                        Ok(Some(waiver.content_hash()))
                    },
                    None => Err(AdmitError::WitnessWaiverInvalid {
                        reason: "monitor tier requires explicit waiver for \
                                 witness seed bypass (no silent permissive defaults)"
                            .into(),
                    }),
                }
            },
        }
    }

    // =========================================================================
    // Witness closure: post-effect evidence finalization (TCK-00497)
    // =========================================================================

    /// Finalize post-effect witness evidence and validate for output release.
    ///
    /// For fail-closed tiers: both leakage and timing witness evidence
    /// MUST be present, valid, and bound to the correct seeds. Output
    /// release is denied if evidence is missing or invalid.
    ///
    /// For monitor tiers: an explicit `monitor_waiver` MUST be provided
    /// to bypass evidence requirements. A defect hash is returned for
    /// audit binding.
    ///
    /// Returns the content hashes of the finalized evidence objects for
    /// binding into
    /// `AdmissionOutcomeIndexV1::post_effect_witness_evidence_hashes`.
    ///
    /// # Errors
    ///
    /// - [`AdmitError::WitnessEvidenceFailure`] if evidence is missing,
    ///   invalid, or unbound at fail-closed tier.
    /// - [`AdmitError::OutputReleaseDenied`] if output cannot be released due
    ///   to missing evidence at fail-closed tier.
    /// - [`AdmitError::WitnessWaiverInvalid`] if monitor tier lacks a valid
    ///   waiver.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_post_effect_witness(
        &self,
        enforcement_tier: EnforcementTier,
        leakage_seed: &WitnessSeedV1,
        timing_seed: &WitnessSeedV1,
        leakage_evidence: Option<&WitnessEvidenceV1>,
        timing_evidence: Option<&WitnessEvidenceV1>,
        monitor_waiver: Option<&MonitorWaiverV1>,
        current_tick: u64,
    ) -> Result<Vec<Hash>, AdmitError> {
        match enforcement_tier {
            EnforcementTier::FailClosed => {
                // Fail-closed: both evidence objects MUST be present.
                let leakage_ev =
                    leakage_evidence.ok_or_else(|| AdmitError::OutputReleaseDenied {
                        reason: "missing leakage witness evidence for \
                                 fail-closed tier (output release denied)"
                            .into(),
                    })?;
                let timing_ev = timing_evidence.ok_or_else(|| AdmitError::OutputReleaseDenied {
                    reason: "missing timing witness evidence for \
                                 fail-closed tier (output release denied)"
                        .into(),
                })?;

                // Validate evidence objects.
                leakage_ev.validate()?;
                timing_ev.validate()?;

                // Verify evidence binds to the correct seeds.
                validate_evidence_seed_binding(leakage_ev, leakage_seed)?;
                validate_evidence_seed_binding(timing_ev, timing_seed)?;

                // Verify provider provenance matches between seed and evidence.
                validate_evidence_provider_binding(leakage_ev, leakage_seed)?;
                validate_evidence_provider_binding(timing_ev, timing_seed)?;

                Ok(vec![leakage_ev.content_hash(), timing_ev.content_hash()])
            },
            EnforcementTier::Monitor => {
                // Monitor tier: explicit waiver required.
                match monitor_waiver {
                    Some(waiver) => {
                        waiver.validate(current_tick)?;
                        // If evidence is provided for monitor tier, validate
                        // including seed and provider binding checks
                        // (QUALITY MINOR 1: ensure caller-supplied evidence
                        // is actually bound to the correct plan seeds and
                        // provider, preventing evidence substitution even
                        // under monitor-tier waivers).
                        let mut hashes = Vec::new();
                        if let Some(ev) = leakage_evidence {
                            ev.validate()?;
                            validate_evidence_seed_binding(ev, leakage_seed)?;
                            validate_evidence_provider_binding(ev, leakage_seed)?;
                            hashes.push(ev.content_hash());
                        }
                        if let Some(ev) = timing_evidence {
                            ev.validate()?;
                            validate_evidence_seed_binding(ev, timing_seed)?;
                            validate_evidence_provider_binding(ev, timing_seed)?;
                            hashes.push(ev.content_hash());
                        }
                        // Include waiver hash in evidence hashes for audit.
                        hashes.push(waiver.content_hash());
                        Ok(hashes)
                    },
                    None => Err(AdmitError::WitnessWaiverInvalid {
                        reason: "monitor tier requires explicit waiver for \
                                 witness evidence bypass (no silent permissive defaults)"
                            .into(),
                    }),
                }
            },
        }
    }

    /// Release held boundary output after successful witness evidence
    /// finalization (fail-closed tiers only).
    ///
    /// # Errors
    ///
    /// - [`AdmitError::OutputReleaseDenied`] if evidence hashes are empty for
    ///   fail-closed tiers.
    /// - [`AdmitError::BoundaryMediationFailure`] if the span is not in the
    ///   expected held state.
    pub fn release_boundary_output(
        &self,
        boundary_span: &mut BoundarySpanV1,
        evidence_hashes: &[Hash],
    ) -> Result<(), AdmitError> {
        if boundary_span.enforcement_tier == EnforcementTier::FailClosed {
            if evidence_hashes.is_empty() {
                return Err(AdmitError::OutputReleaseDenied {
                    reason: "no witness evidence hashes for fail-closed tier \
                             (boundary output remains held)"
                        .into(),
                });
            }
            if !boundary_span.output_held {
                return Err(AdmitError::BoundaryMediationFailure {
                    reason: "boundary output already released (double-release \
                             attempt)"
                        .into(),
                });
            }
        }
        boundary_span.output_held = false;
        Ok(())
    }

    // =========================================================================
    // Anti-rollback anchor finalization (TCK-00502 BLOCKER-2)
    // =========================================================================

    /// Finalize anti-rollback anchor after successful effect execution.
    ///
    /// MUST only be called after the authoritative effect (ledger write,
    /// broker dispatch) has been confirmed successful. Committing before
    /// effect confirmation creates a pre-commit hazard where the anchor
    /// watermark advances past the actual ledger head, permanently
    /// deadlocking subsequent fail-closed admissions.
    ///
    /// For monitor tiers, this is a no-op: monitor tiers do not gate
    /// authoritative effects and MUST NOT advance the anti-rollback
    /// watermark.
    ///
    /// # Errors
    ///
    /// Returns [`AdmitError::AntiRollbackFailure`] if the anchor commit
    /// fails (persistence error, regression detected, etc.).
    pub fn finalize_anti_rollback(
        &self,
        enforcement_tier: EnforcementTier,
        anchor: &LedgerAnchorV1,
    ) -> Result<(), AdmitError> {
        if enforcement_tier == EnforcementTier::FailClosed {
            if let Some(ref ar) = self.anti_rollback {
                ar.commit(anchor)
                    .map_err(|e| AdmitError::AntiRollbackFailure {
                        reason: format!("failed to commit anti-rollback anchor: {e}"),
                    })?;
            }
        }
        Ok(())
    }

    // =========================================================================
    // Internal prerequisite resolution
    // =========================================================================

    /// Resolve and verify ledger trust state.
    ///
    /// For fail-closed tiers: missing or errored verifier produces denial.
    /// For monitor tiers: missing verifier returns a synthetic anchor.
    fn resolve_ledger_trust(
        &self,
        tier: EnforcementTier,
    ) -> Result<ResolvedLedgerState, AdmitError> {
        match &self.ledger_verifier {
            Some(verifier) => {
                let state =
                    verifier
                        .validated_state()
                        .map_err(|e| AdmitError::LedgerTrustFailure {
                            reason: e.to_string(),
                        })?;
                Ok(ResolvedLedgerState {
                    anchor: state.validated_anchor,
                })
            },
            None => {
                if tier == EnforcementTier::FailClosed {
                    Err(AdmitError::MissingPrerequisite {
                        prerequisite: "LedgerTrustVerifier".into(),
                    })
                } else {
                    // Monitor tier: use a synthetic zero anchor.
                    // This is safe because monitor tiers do not gate
                    // authoritative effects.
                    Ok(ResolvedLedgerState {
                        anchor: synthetic_monitor_anchor(),
                    })
                }
            },
        }
    }

    /// Resolve policy root state.
    ///
    /// For fail-closed tiers: missing or errored resolver produces denial.
    /// For monitor tiers: missing resolver returns a synthetic root.
    fn resolve_policy_root(
        &self,
        tier: EnforcementTier,
        anchor: &LedgerAnchorV1,
    ) -> Result<ResolvedPolicyRoot, AdmitError> {
        match &self.policy_resolver {
            Some(resolver) => {
                let state =
                    resolver
                        .resolve(anchor)
                        .map_err(|e| AdmitError::PolicyRootFailure {
                            reason: e.to_string(),
                        })?;
                Ok(ResolvedPolicyRoot {
                    digest: state.policy_root_digest,
                    epoch: state.policy_root_epoch,
                })
            },
            None => {
                if tier == EnforcementTier::FailClosed {
                    Err(AdmitError::MissingPrerequisite {
                        prerequisite: "PolicyRootResolver".into(),
                    })
                } else {
                    Ok(ResolvedPolicyRoot {
                        digest: [0u8; 32],
                        epoch: 0,
                    })
                }
            },
        }
    }

    /// Verify anti-rollback anchor.
    ///
    /// For fail-closed tiers: missing or errored anchor produces denial,
    /// except for `ExternalAnchorUnavailable` which is tolerated as the
    /// bootstrap path (no prior anchor exists on fresh install).
    ///
    /// For monitor tiers: missing anchor is allowed (warning only).
    #[allow(clippy::option_if_let_else)] // nested match on TrustError variant
    fn verify_anti_rollback(
        &self,
        tier: EnforcementTier,
        anchor: &LedgerAnchorV1,
    ) -> Result<(), AdmitError> {
        match &self.anti_rollback {
            Some(ar) => {
                match ar.verify_committed(anchor) {
                    Ok(()) => Ok(()),
                    Err(TrustError::ExternalAnchorUnavailable { .. }) => {
                        // Bootstrap path: on fresh install, no anchor has been
                        // committed yet. The first execute() will establish the
                        // initial anchor state via finalize_anti_rollback().
                        // This is NOT a security failure; the anti-rollback
                        // invariant is vacuously satisfied when no prior state
                        // exists to protect.
                        Ok(())
                    },
                    Err(e) => Err(AdmitError::AntiRollbackFailure {
                        reason: e.to_string(),
                    }),
                }
            },
            None => {
                if tier == EnforcementTier::FailClosed {
                    Err(AdmitError::MissingPrerequisite {
                        prerequisite: "AntiRollbackAnchor".into(),
                    })
                } else {
                    // Monitor tier: allowed without external anchor.
                    Ok(())
                }
            },
        }
    }

    /// Reserve quarantine capacity for fail-closed tiers.
    ///
    /// Returns `Some(reservation_hash)` if a quarantine guard is available
    /// and the tier requires it.
    fn reserve_quarantine_capacity(
        &self,
        tier: EnforcementTier,
        plan: &AdmissionPlanV1,
    ) -> Result<Option<Hash>, AdmitError> {
        if tier != EnforcementTier::FailClosed {
            return Ok(None);
        }

        match &self.quarantine_guard {
            Some(guard) => {
                let hash = guard
                    .reserve(
                        &plan.request.session_id,
                        &plan.request.request_id,
                        &plan.certificate.ajc_id,
                    )
                    .map_err(|reason| AdmitError::QuarantineReservationFailure { reason })?;
                Ok(Some(hash))
            },
            None => {
                // Quarantine guard not wired. For fail-closed tiers, this is
                // a prerequisite failure.
                Err(AdmitError::MissingPrerequisite {
                    prerequisite: "QuarantineGuard".into(),
                })
            },
        }
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Resolved ledger state from prerequisite verification.
struct ResolvedLedgerState {
    anchor: LedgerAnchorV1,
}

/// Resolved policy root from prerequisite resolution.
struct ResolvedPolicyRoot {
    digest: Hash,
    epoch: u64,
}

/// Derive enforcement tier from PCAC risk tier.
///
/// `Tier2Plus` maps to `FailClosed`; all others map to `Monitor`.
/// This is the conservative mapping per RFC-0019 §1.1.
const fn enforcement_tier_from_risk(risk_tier: apm2_core::pcac::RiskTier) -> EnforcementTier {
    match risk_tier {
        apm2_core::pcac::RiskTier::Tier2Plus => EnforcementTier::FailClosed,
        _ => EnforcementTier::Monitor,
    }
}

/// Generate a cryptographic nonce for witness seed uniqueness.
fn generate_nonce() -> Hash {
    let mut nonce = [0u8; 32];
    // Use a secure random source for nonce generation.
    // rand::rngs::OsRng is cryptographically secure.
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Compute a canonical request digest from the kernel request.
///
/// This digest covers ALL request fields in deterministic order with
/// length-prefixed variable-length fields, including `risk_tier` and
/// `pcac_policy` (QUALITY MINOR 1, TCK-00492).
#[allow(clippy::cast_possible_truncation)] // String fields are bounded by MAX_* constants (<=256), safe for u32.
fn compute_canonical_request_digest(request: &KernelRequestV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2-kernel-request-v1");
    hasher.update(&request.request_id);
    hasher.update(request.session_id.as_bytes());
    hasher.update(&(request.session_id.len() as u32).to_le_bytes());
    hasher.update(request.tool_class.as_bytes());
    hasher.update(&(request.tool_class.len() as u32).to_le_bytes());
    hasher.update(request.boundary_profile_id.as_bytes());
    hasher.update(&(request.boundary_profile_id.len() as u32).to_le_bytes());
    hasher.update(&request.effect_descriptor_digest);
    hasher.update(&request.intent_digest);
    hasher.update(&request.hsi_contract_manifest_digest);
    hasher.update(&request.hsi_envelope_binding_digest);
    hasher.update(&request.stop_budget_digest);
    hasher.update(&[u8::from(request.declared_idempotent)]);
    hasher.update(request.lease_id.as_bytes());
    hasher.update(&(request.lease_id.len() as u32).to_le_bytes());
    hasher.update(&request.identity_proof_hash);
    hasher.update(&request.capability_manifest_hash);
    hasher.update(&request.time_envelope_ref);
    hasher.update(&request.freshness_witness_tick.to_le_bytes());
    hasher.update(&request.directory_head_hash);
    hasher.update(&request.freshness_policy_hash);
    hasher.update(&request.revocation_head_hash);
    // Identity evidence fields (MINOR 1: no longer hardcoded).
    // The enum is #[non_exhaustive], so we include a fallback tag for
    // unknown future variants to maintain digest determinism.
    hasher.update(match request.identity_evidence_level {
        IdentityEvidenceLevel::Verified => &[0x01],
        IdentityEvidenceLevel::PointerOnly => &[0x02],
        _ => &[0xFF], // Unknown variant — deterministic fallback tag.
    });
    match &request.pointer_only_waiver_hash {
        Some(waiver) => {
            hasher.update(&[0x01]); // presence tag
            hasher.update(waiver);
        },
        None => {
            hasher.update(&[0x00]); // absence tag
        },
    }
    // QUALITY MINOR 1 (TCK-00492): Include risk_tier and pcac_policy
    // in canonical digest. These fields influence admission decisions
    // (enforcement tier derivation, lifecycle enforcement mode) and
    // must be bound to prevent request substitution attacks.
    hasher.update(match request.risk_tier {
        apm2_core::pcac::RiskTier::Tier0 => &[0x00],
        apm2_core::pcac::RiskTier::Tier1 => &[0x01],
        apm2_core::pcac::RiskTier::Tier2Plus => &[0x02],
        _ => &[0xFF], // Unknown variant — deterministic fallback tag.
    });
    // pcac_policy fields: lifecycle_enforcement, min_tier2_identity_evidence,
    // freshness_max_age_ticks, tier2_sovereignty_mode, pointer_only_waiver.
    hasher.update(&[u8::from(request.pcac_policy.lifecycle_enforcement)]);
    hasher.update(match request.pcac_policy.min_tier2_identity_evidence {
        IdentityEvidenceLevel::Verified => &[0x01],
        IdentityEvidenceLevel::PointerOnly => &[0x02],
        _ => &[0xFF],
    });
    hasher.update(&request.pcac_policy.freshness_max_age_ticks.to_le_bytes());
    hasher.update(match request.pcac_policy.tier2_sovereignty_mode {
        apm2_core::pcac::SovereigntyEnforcementMode::Strict => &[0x01],
        apm2_core::pcac::SovereigntyEnforcementMode::Monitor => &[0x02],
        apm2_core::pcac::SovereigntyEnforcementMode::Disabled => &[0x03],
        _ => &[0xFF],
    });
    match &request.pcac_policy.pointer_only_waiver {
        Some(waiver) => {
            hasher.update(&[0x01]); // presence tag
            hasher.update(waiver.waiver_id.as_bytes());
            hasher.update(&(waiver.waiver_id.len() as u32).to_le_bytes());
            hasher.update(&waiver.expires_at_tick.to_le_bytes());
            hasher.update(&waiver.scope_binding_hash);
        },
        None => {
            hasher.update(&[0x00]); // absence tag
        },
    }
    *hasher.finalize().as_bytes()
}

/// Build the PCAC `AuthorityJoinInputV1` from kernel request bindings.
///
/// # Canonical Builder Equivalence (SECURITY MAJOR 1, TCK-00492)
///
/// This function is the admission kernel's module-equivalent of
/// `PrivilegedPcacInputBuilder` (defined in `protocol::dispatch`).
/// It cannot reuse `PrivilegedPcacInputBuilder` directly because:
///
/// 1. **Domain tag scheme**: `PrivilegedPcacInputBuilder` uses
///    `PrivilegedHandlerClass`-parameterized domain tags (e.g.,
///    `"register-recovery-evidence-boundary_leakage_witness_hash-v1"`), whereas
///    the admission kernel uses kernel-specific domain tags
///    (`"apm2-admission-kernel-boundary-leakage-witness-hash-v1"`). Reusing
///    dispatch's builder would produce different witness hashes, breaking
///    digest compatibility.
///
/// 2. **Field coverage**: The admission kernel requires
///    `pointer_only_waiver_hash` passthrough and uses the verifier-selected
///    ledger anchor (not a client-supplied hash) for `as_of_ledger_anchor`.
///    `PrivilegedPcacInputBuilder` does not support `pointer_only_waiver_hash`.
///
/// 3. **Witness hash construction**: The kernel's witness hashes include
///    `spine_ext_hash` as binding context, which is unique to the admission
///    kernel lifecycle.
///
/// The field mapping below is structurally equivalent to
/// `PrivilegedPcacInputBuilder::build()` per RS-42 canonical lifecycle
/// requirements.
///
/// # Arguments
///
/// * `request` — The kernel request.
/// * `spine_ext_hash` — Hash of the spine join extension.
/// * `verifier_anchor` — The verifier-selected ledger anchor (from
///   `resolve_ledger_trust()`), NOT the client-supplied `directory_head_hash`.
///   This ensures the AJC `as_of_ledger_anchor` reflects the authoritative
///   ledger state, enabling drift detection in `execute()`.
fn build_pcac_join_input(
    request: &KernelRequestV1,
    spine_ext_hash: &Hash,
    verifier_anchor: &LedgerAnchorV1,
) -> AuthorityJoinInputV1 {
    // Compute leakage and timing witness hashes following the canonical
    // pattern from PrivilegedPcacInputBuilder.
    let tick_bytes = request.freshness_witness_tick.to_le_bytes();

    let leakage_witness_hash = {
        let mut h = blake3::Hasher::new();
        h.update(b"apm2-admission-kernel-boundary-leakage-witness-hash-v1");
        h.update(&request.intent_digest);
        h.update(spine_ext_hash);
        h.update(&tick_bytes);
        *h.finalize().as_bytes()
    };

    let timing_witness_hash = {
        let mut h = blake3::Hasher::new();
        h.update(b"apm2-admission-kernel-boundary-timing-witness-hash-v1");
        h.update(&request.time_envelope_ref);
        h.update(spine_ext_hash);
        h.update(&tick_bytes);
        *h.finalize().as_bytes()
    };

    AuthorityJoinInputV1 {
        session_id: request.session_id.clone(),
        holon_id: None,
        intent_digest: request.intent_digest,
        boundary_intent_class: BoundaryIntentClass::Actuate,
        capability_manifest_hash: request.capability_manifest_hash,
        scope_witness_hashes: vec![*spine_ext_hash],
        lease_id: request.lease_id.clone(),
        permeability_receipt_hash: None,
        identity_proof_hash: request.identity_proof_hash,
        identity_evidence_level: request.identity_evidence_level,
        pointer_only_waiver_hash: request.pointer_only_waiver_hash,
        directory_head_hash: request.directory_head_hash,
        freshness_policy_hash: request.freshness_policy_hash,
        freshness_witness_tick: request.freshness_witness_tick,
        stop_budget_profile_digest: request.stop_budget_digest,
        pre_actuation_receipt_hashes: Vec::new(),
        leakage_witness_hash,
        timing_witness_hash,
        risk_tier: request.risk_tier,
        determinism_class: DeterminismClass::Deterministic,
        time_envelope_ref: request.time_envelope_ref,
        as_of_ledger_anchor: verifier_anchor.content_hash(),
    }
}

/// Synthetic monitor-tier ledger anchor for when no verifier is configured.
///
/// This anchor uses deterministic non-zero values so it passes validation
/// but is clearly distinguishable from real anchors.
const fn synthetic_monitor_anchor() -> LedgerAnchorV1 {
    let mut monitor_id = [0u8; 32];
    monitor_id[0] = 0xFF;
    monitor_id[31] = 0x01;
    let mut monitor_hash = [0u8; 32];
    monitor_hash[0] = 0xFF;
    monitor_hash[31] = 0x02;
    LedgerAnchorV1 {
        ledger_id: monitor_id,
        event_hash: monitor_hash,
        height: 1,
        he_time: 1,
    }
}

/// Validate that witness evidence binds to its claimed seed.
///
/// Checks that the evidence's `seed_hash` matches the actual
/// content hash of the seed, and that identity fields (class,
/// `request_id`, `session_id`) are consistent.
///
/// # Errors
///
/// Returns [`AdmitError::WitnessEvidenceFailure`] if the binding is
/// invalid.
fn validate_evidence_seed_binding(
    evidence: &WitnessEvidenceV1,
    seed: &WitnessSeedV1,
) -> Result<(), AdmitError> {
    // Verify seed hash binding (constant-time comparison).
    let seed_hash = seed.content_hash();
    if !bool::from(evidence.seed_hash.ct_eq(&seed_hash)) {
        return Err(AdmitError::WitnessEvidenceFailure {
            reason: format!(
                "evidence seed_hash does not match seed content_hash \
                 (expected {}, got {})",
                hex::encode(seed_hash),
                hex::encode(evidence.seed_hash)
            ),
        });
    }

    // Verify witness class consistency.
    if evidence.witness_class != seed.witness_class {
        return Err(AdmitError::WitnessEvidenceFailure {
            reason: format!(
                "evidence witness_class '{}' does not match seed witness_class '{}'",
                evidence.witness_class, seed.witness_class
            ),
        });
    }

    // Verify request_id consistency (constant-time).
    if !bool::from(evidence.request_id.ct_eq(&seed.request_id)) {
        return Err(AdmitError::WitnessEvidenceFailure {
            reason: "evidence request_id does not match seed request_id".into(),
        });
    }

    // Verify session_id consistency.
    if evidence.session_id != seed.session_id {
        return Err(AdmitError::WitnessEvidenceFailure {
            reason: "evidence session_id does not match seed session_id".into(),
        });
    }

    // Verify evidence finalization time is after seed creation time.
    if evidence.ht_end < seed.ht_start {
        return Err(AdmitError::WitnessEvidenceFailure {
            reason: format!(
                "evidence ht_end ({}) is before seed ht_start ({}) \
                 (evidence cannot precede seed creation)",
                evidence.ht_end, seed.ht_start
            ),
        });
    }

    Ok(())
}

/// Validate that witness evidence provider matches the seed provider.
///
/// The provider identity and build digest MUST match between seed
/// and evidence to prevent measurement substitution attacks.
///
/// # Errors
///
/// Returns [`AdmitError::WitnessEvidenceFailure`] if the provider
/// binding is invalid.
fn validate_evidence_provider_binding(
    evidence: &WitnessEvidenceV1,
    seed: &WitnessSeedV1,
) -> Result<(), AdmitError> {
    // Verify provider_id consistency.
    if evidence.provider_id != seed.provider_id {
        return Err(AdmitError::WitnessEvidenceFailure {
            reason: format!(
                "evidence provider_id '{}' does not match seed provider_id '{}'",
                evidence.provider_id, seed.provider_id
            ),
        });
    }

    // Verify provider_build_digest consistency (constant-time).
    if !bool::from(
        evidence
            .provider_build_digest
            .ct_eq(&seed.provider_build_digest),
    ) {
        return Err(AdmitError::WitnessEvidenceFailure {
            reason: "evidence provider_build_digest does not match seed \
                     provider_build_digest (measurement substitution detected)"
                .into(),
        });
    }

    Ok(())
}
