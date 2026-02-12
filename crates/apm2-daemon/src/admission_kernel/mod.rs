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
use prerequisites::{AntiRollbackAnchor, LedgerAnchorV1, LedgerTrustVerifier, PolicyRootResolver};
use rand::RngCore;
use subtle::ConstantTimeEq;
use types::{
    ADMISSION_BUNDLE_SCHEMA_VERSION, AdmissionBundleV1, AdmissionPlanV1, AdmissionResultV1,
    AdmissionSpineJoinExtV1, AdmitError, BoundarySpanV1, EnforcementTier, KernelRequestV1,
    MAX_WITNESS_PROVIDER_ID_LENGTH, PlanState, QuarantineActionV1, WitnessSeedV1,
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
    /// Returns a reservation hash proving capacity was reserved.
    ///
    /// # Errors
    ///
    /// Returns a reason string if capacity cannot be reserved.
    fn reserve(&self, request_id: &Hash, ajc_id: &Hash) -> Result<Hash, String>;
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
    witness_provider: WitnessProviderConfig,
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

        Ok(AdmissionResultV1 {
            bundle_digest,
            bundle,
            effect_capability,
            ledger_write_capability,
            quarantine_capability,
            consumed_witness,
            consume_record,
            boundary_span,
        })
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
    /// For fail-closed tiers: missing or errored anchor produces denial.
    /// For monitor tiers: missing anchor is allowed (warning only).
    fn verify_anti_rollback(
        &self,
        tier: EnforcementTier,
        anchor: &LedgerAnchorV1,
    ) -> Result<(), AdmitError> {
        match &self.anti_rollback {
            Some(ar) => {
                ar.verify_committed(anchor)
                    .map_err(|e| AdmitError::AntiRollbackFailure {
                        reason: e.to_string(),
                    })?;
                Ok(())
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
                    .reserve(&plan.request.request_id, &plan.certificate.ajc_id)
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
