//! Governance integration for policy resolution.
//!
//! This module provides the `GovernancePolicyResolver` which delegates policy
//! decisions to the Governance Holon (or local policy configuration in Phase
//! 1).
//!
//! # TCK-00289
//!
//! Implements real policy resolution wiring. Currently uses local deterministic
//! resolution until the Governance Holon is fully integrated.
//!
//! # TCK-00352
//!
//! The policy resolver is the ONLY authorized source for minting
//! `CapabilityManifestV1` instances. It holds the [`PolicyMintToken`]
//! that proves minting authority. Requester surfaces cannot obtain this
//! token.
//!
//! # Phase 1 Transitional Tier Mapping (TCK-00340, v7 Finding 3)
//!
//! SECURITY NOTE: Risk tiers are assigned based on work role as a
//! transitional measure until full Governance Holon integration (RFC-0019).
//! Non-executor roles all resolve to Tier1 (`SelfSigned` attestation).
//! Higher-risk work in non-executor roles is NOT receiving stricter
//! attestation until RFC-0019 governance resolution is implemented.
//!
//! | Role            | Risk Tier | Attestation Required |
//! |-----------------|-----------|----------------------|
//! | `GateExecutor`  | Tier2     | `CounterSigned`      |
//! | `Reviewer`      | Tier1     | `SelfSigned`         |
//! | `Implementer`   | Tier1     | `SelfSigned`         |
//! | `Coordinator`   | Tier1     | `SelfSigned`         |
//! | `Unspecified`   | Tier1     | `SelfSigned`         |
//!
//! **Justification**: `GateExecutor` handles gate execution (highest risk
//! in Phase 1), so it receives Tier2 which requires `CounterSigned`
//! attestation. All other roles use Tier1 (`SelfSigned`), which the
//! daemon's IPC endpoints can produce without breaking throughput.
//!
//! **Scope**: Single-daemon, single-node operation only. All agents operate
//! within the daemon's trust boundary in Phase 1. The deployment guardrail
//! is architectural: no cross-node federation or multi-tenant IPC transport
//! exists in Phase 1 -- the daemon only listens on local Unix sockets,
//! which confines the trust boundary to the local machine.
//!
//! **Expiry**: This mapping expires when RFC-0019 governance resolution is
//! implemented, which will derive risk tiers from changeset metadata (file
//! paths, module criticality, dependency fanout).
//!
//! **Waiver**: TCK-00340 v9 MAJOR — Role-based tier mapping is a tracked
//! transitional measure. The waiver scope is bounded to Phase 1 single-node
//! operation and MUST NOT be carried forward into multi-tenant or cross-node
//! federation without full RFC-0019 governance resolution.

use tracing::warn;

use crate::episode::capability::PolicyMintToken;
use crate::protocol::dispatch::{
    PolicyResolution, PolicyResolutionError, PolicyResolver, build_policy_context_pack,
};
use crate::protocol::messages::WorkRole;

/// Resolves policy via governance integration.
///
/// # TCK-00352: Policy-Only Minting Authority
///
/// This resolver is the sole holder of [`PolicyMintToken`], which is required
/// to construct
/// [`CapabilityManifestV1`](crate::episode::CapabilityManifestV1) instances.
/// The token cannot be obtained from requester surfaces.
///
/// # Security
///
/// Both `new()` and `mint_token()` are `pub(crate)` to prevent external
/// crates from constructing a resolver and obtaining mint tokens. Only
/// daemon-internal production wiring (in `state.rs`) should create instances.
#[derive(Debug, Clone, Default)]
pub struct GovernancePolicyResolver;

impl GovernancePolicyResolver {
    /// Creates a new policy resolver.
    ///
    /// # Security
    ///
    /// This is `pub(crate)` to restrict construction to daemon-internal code.
    /// External crates cannot instantiate the resolver and thus cannot reach
    /// `mint_token()`.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    /// Returns a [`PolicyMintToken`] for minting `CapabilityManifestV1`.
    ///
    /// # TCK-00352: Minting Authority
    ///
    /// Only the policy resolver can create mint tokens. This method is the
    /// single point of authority for V1 manifest minting. The token proves
    /// that the caller has policy-resolver authority.
    ///
    /// # Security
    ///
    /// Both `PolicyMintToken::new()` and this method are `pub(crate)`, so
    /// external crates and requester surfaces cannot obtain a mint token.
    /// Minting is restricted to the sealed governance path inside the daemon.
    #[must_use]
    #[allow(clippy::unused_self)] // Takes &self to enforce resolver-only access pattern
    pub(crate) const fn mint_token(&self) -> PolicyMintToken {
        PolicyMintToken::new()
    }
}

impl PolicyResolver for GovernancePolicyResolver {
    fn resolve_for_claim(
        &self,
        work_id: &str,
        role: WorkRole,
        actor_id: &str,
    ) -> Result<PolicyResolution, PolicyResolutionError> {
        // TCK-00289: In Phase 1, we use deterministic local resolution.
        // In Phase 2, this will make an IPC call to the Governance Holon.

        // Generate deterministic hashes for policy and capability manifest
        let policy_hash = blake3::hash(format!("policy:{work_id}:{actor_id}").as_bytes());
        let manifest_hash = blake3::hash(format!("manifest:{work_id}:{actor_id}").as_bytes());

        // Create and seal a context pack manifest.
        // Uses the shared `build_policy_context_pack` helper so that
        // `seed_policy_artifacts_in_cas` reproduces the same preimage.
        let context_pack = build_policy_context_pack(work_id, actor_id);

        let context_pack_hash =
            context_pack
                .seal()
                .map_err(|e| PolicyResolutionError::GovernanceFailed {
                    message: format!("context pack sealing failed: {e}"),
                })?;

        // TODO(RFC-0019): Resolve from real governance policy evaluation.
        //
        // SECURITY NOTE (v8 Finding 1 — Role-Differentiated Risk Tiers):
        //
        // The previous hardcoded Tier4 value was fail-closed by design, but
        // it broke low-tier throughput because ALL governance-resolved claims
        // required ThresholdSigned attestation (which the IngestReviewReceipt
        // endpoint cannot provide — it only offers SelfSigned).
        //
        // This transitional mapping differentiates risk by work role:
        //
        // - GateExecutor: Tier2 (CounterSigned required — highest risk role)
        // - All other roles: Tier1 (SelfSigned required — safe default)
        //
        // SECURITY: Fail-closed semantics are preserved at higher tiers
        // via the attestation ratchet table in AttestationRequirements:
        //   - Tier0: None required
        //   - Tier1: SelfSigned required
        //   - Tier2: CounterSigned required (for Review receipts)
        //   - Tier3+: CounterSigned/ThresholdSigned
        //
        // See `transitional_risk_tier()` doc comment for full security analysis.
        //
        // When real governance resolution is wired (RFC-0019), the actual
        // risk tier from the changeset metadata will be used instead of
        // this role-based heuristic.
        let resolved_risk_tier = transitional_risk_tier(role);

        // MAJOR 1 v3 fix: The scope baseline MUST come from the policy
        // resolver (authoritative source), NOT from the candidate manifest.
        //
        // Phase 1 (transitional): For Reviewer, derive from the canonical
        // reviewer manifest. For other roles, provide an empty baseline
        // (which matches the empty fallback manifest). An empty baseline
        // is NOT fail-open: it means no tools/paths/patterns are permitted,
        // so any manifest with non-empty allowlists would be rejected.
        //
        // Phase 2 (future): Real governance policy will provide baselines.
        let resolved_scope_baseline = {
            use crate::episode::capability::ScopeBaseline;

            match role {
                WorkRole::Reviewer => {
                    let reviewer = crate::episode::reviewer_manifest::reviewer_v0_manifest();
                    Some(ScopeBaseline {
                        tools: reviewer.tool_allowlist.clone(),
                        write_paths: reviewer.write_allowlist.clone(),
                        shell_patterns: reviewer.shell_allowlist.clone(),
                    })
                },
                _ => Some(ScopeBaseline::default()),
            }
        };
        Ok(PolicyResolution {
            policy_resolved_ref: format!("PolicyResolvedForChangeSet:{work_id}"),
            resolved_policy_hash: *policy_hash.as_bytes(),
            capability_manifest_hash: *manifest_hash.as_bytes(),
            context_pack_hash,
            resolved_risk_tier,
            resolved_scope_baseline,
            expected_adapter_profile_hash: None,
            // TCK-00428: Populate PCAC policy knobs for Phase 1 transitional enforcement.
            // - Lifecycle: enforced (opt-in via gate presence).
            // - Identity: Tier2+ requires Verified evidence.
            // - Freshness: 100 ticks max age.
            // - Sovereignty: Strict for Tier2+.
            pcac_policy: Some(apm2_core::pcac::PcacPolicyKnobs {
                lifecycle_enforcement: true,
                min_tier2_identity_evidence: apm2_core::pcac::IdentityEvidenceLevel::Verified,
                freshness_max_age_ticks: 100,
                tier2_sovereignty_mode: apm2_core::pcac::SovereigntyEnforcementMode::Strict,
            }),
            // TCK-00428: PointerOnly waiver logic (stub for now).
            // For Phase 1, we assume no global waiver unless configured.
            pointer_only_waiver: None,
        })
    }
}

/// Transitional risk tier mapping based on work role (Phase 1).
///
/// # SECURITY NOTE (v8 Finding 1 — Role-Differentiated Risk Tiers)
///
/// This function implements a deterministic transitional tier mapping that
/// differentiates risk levels by work role:
///
/// - **`GateExecutor`** (highest risk — handles gate execution): **Tier2**
///   (requires `CounterSigned` attestation per the ratchet table). Gate
///   executors perform security-critical operations (running gates, producing
///   receipts) and MUST have stronger attestation than self-attestation.
///
/// - **`Reviewer`**: **Tier1** (requires `SelfSigned` attestation). Reviewers
///   attest their own review work. `SelfSigned` is appropriate because the
///   reviewer IS the authority on whether their review is complete.
///
/// - **`Implementer`**, **`Coordinator`**, **`Unspecified`**: **Tier1**
///   (requires `SelfSigned` attestation). Phase 1 default for roles where the
///   daemon's IPC endpoints produce `SelfSigned` attestation.
///
/// # Attestation Ratchet Table (default, Review receipts)
///
/// | Tier | Attestation Required    |
/// |------|-------------------------|
/// | 0    | None                    |
/// | 1    | `SelfSigned`            |
/// | 2    | `CounterSigned`         |
/// | 3    | `CounterSigned`         |
/// | 4    | `ThresholdSigned`       |
///
/// # Risk Analysis
///
/// **Impact**: Roles other than `GateExecutor` still only require
/// `SelfSigned` attestation. A compromised agent performing high-risk work
/// in a non-executor role would bypass the stronger `CounterSigned`
/// requirement. This is acceptable for Phase 1 where all agents operate
/// within the daemon's trust boundary, but MUST be addressed before
/// multi-tenant or cross-node federation.
///
/// # Deployment Guardrail (v9 MAJOR Mitigation)
///
/// The architectural guardrail is the transport layer: the daemon listens
/// only on local Unix sockets (`UnixListener`) with no TCP/network
/// federation transport. This confines all IPC to the local trust
/// boundary. The introduction of any cross-node transport MUST trigger
/// replacement of this function with RFC-0019 governance resolution.
///
/// # TODO(RFC-0019) — v7 Finding 3
///
/// Replace with Governance Holon policy resolution (RFC-0019) that derives
/// the actual risk tier from changeset metadata (file paths, module
/// criticality, dependency fanout, etc.) rather than work role alone.
fn transitional_risk_tier(role: WorkRole) -> u8 {
    // Phase 1 transitional mapping: differentiate by role to apply
    // stronger attestation to higher-risk operations.
    //
    // TODO(RFC-0019): Replace with Governance Holon policy resolution
    // that evaluates changeset metadata for risk classification (v7 Finding 3).
    let tier = match role {
        // GateExecutor handles gate execution — highest risk in Phase 1.
        // Tier2 requires CounterSigned attestation per the ratchet table.
        WorkRole::GateExecutor => 2,
        // All other roles: Tier1 requires SelfSigned attestation, which
        // the daemon's IPC endpoints can produce.
        WorkRole::Reviewer
        | WorkRole::Implementer
        | WorkRole::Coordinator
        | WorkRole::Unspecified => 1,
    };
    warn!(
        role = ?role,
        resolved_tier = tier,
        "Governance stub: transitional role-based tier mapping. \
         TODO(RFC-0019): implement real governance policy resolution."
    );
    tier
}

// =============================================================================
// Governance Freshness Monitor (TCK-00351 MAJOR 1)
// =============================================================================

/// Configuration for the governance freshness monitor.
///
/// The monitor checks whether the governance service is reachable and
/// responsive. When the service is unreachable or its response is stale
/// beyond `freshness_threshold`, the monitor sets the `governance_uncertain`
/// flag on the shared [`StopAuthority`], causing the pre-actuation gate to
/// enter deadline-based fail-closed logic.
///
/// [`StopAuthority`]: crate::episode::preactuation::StopAuthority
///
/// # TCK-00351 MAJOR 1
///
/// This struct wires the `set_governance_uncertain(...)` control surface
/// into the production path.  Prior to this fix, the flag was only ever
/// set in tests.
#[derive(Debug, Clone)]
pub struct GovernanceFreshnessConfig {
    /// Probe cadence hint (milliseconds) for monitor polling loops.
    pub poll_interval_ms: u64,
    /// Maximum age of the last successful governance response before the
    /// service is considered stale (milliseconds).
    pub freshness_threshold_ms: u64,
}

impl Default for GovernanceFreshnessConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 5_000,
            freshness_threshold_ms: 30_000,
        }
    }
}

/// Governance freshness monitor that probes governance service health and
/// updates the [`StopAuthority`] uncertainty flag.
///
/// # Production Wiring (TCK-00351 MAJOR 1)
///
/// Instantiate a monitor, invoke [`record_success`](Self::record_success) /
/// [`record_failure`](Self::record_failure) from governance probe paths,
/// and optionally run [`check_freshness`](Self::check_freshness) from an
/// explicit scheduler. Share the same `StopAuthority` with the
/// `PreActuationGate`.
///
/// ```rust,ignore
/// let authority = Arc::new(StopAuthority::new());
/// let monitor = GovernanceFreshnessMonitor::new(
///     Arc::clone(&authority),
///     GovernanceFreshnessConfig::default(),
///     false, // authenticated governance transport present
/// );
/// // In a background loop:
/// monitor.check_freshness();
/// ```
///
/// # Production Wiring
///
/// `state.rs` production constructors instantiate this monitor and share the
/// same `StopAuthority` with `PreActuationGate`, wire governance probe
/// success/failure call sites, and run periodic `check_freshness()` in a
/// background task.
///
/// [`StopAuthority`]: crate::episode::preactuation::StopAuthority
pub struct GovernanceFreshnessMonitor {
    /// Shared stop authority whose `governance_uncertain` flag is mutated.
    stop_authority: std::sync::Arc<crate::episode::preactuation::StopAuthority>,
    /// Monitor configuration.
    config: GovernanceFreshnessConfig,
    /// Most recent successful governance probe timestamp.
    ///
    /// `Instant` is monotonic and not affected by wall-clock rollback.
    last_success: std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    /// Whether the active resolver path is transitional-local.
    transitional_resolver: bool,
}

impl GovernanceFreshnessMonitor {
    /// Creates a new monitor with the given configuration.
    #[must_use]
    pub fn new(
        stop_authority: std::sync::Arc<crate::episode::preactuation::StopAuthority>,
        config: GovernanceFreshnessConfig,
        transitional_resolver: bool,
    ) -> Self {
        stop_authority.set_governance_transitional_resolver(transitional_resolver);
        if transitional_resolver {
            stop_authority.set_governance_uncertain(true);
        }
        Self {
            stop_authority,
            config,
            last_success: std::sync::Arc::new(std::sync::Mutex::new(if transitional_resolver {
                None
            } else {
                Some(std::time::Instant::now())
            })),
            transitional_resolver,
        }
    }

    /// Records a successful governance probe.
    ///
    /// Call this from any path that confirms the governance service is
    /// healthy (e.g., after a successful policy resolution response).
    pub fn record_success(&self) {
        if self.transitional_resolver {
            warn!(
                "Governance freshness success observed under transitional local resolver; \
                 not treated as freshness evidence"
            );
            self.stop_authority.set_governance_uncertain(true);
            return;
        }

        *self
            .last_success
            .lock()
            .expect("governance monitor lock poisoned") = Some(std::time::Instant::now());
        self.stop_authority.set_governance_uncertain(false);
    }

    /// Records a governance probe failure.
    ///
    /// Call this when the governance service is unreachable or returns an
    /// error.  The uncertainty flag is set immediately; the deadline-based
    /// denial in the pre-actuation gate will activate once the configured
    /// threshold elapses.
    pub fn record_failure(&self) {
        // Failure invalidates the freshness watermark until a new explicit
        // success is recorded.
        *self
            .last_success
            .lock()
            .expect("governance monitor lock poisoned") = None;
        self.stop_authority.set_governance_uncertain(true);
    }

    /// Checks freshness based on the last success timestamp and updates
    /// the `governance_uncertain` flag accordingly.
    ///
    /// Returns `true` if governance is considered fresh, `false` if stale.
    pub fn check_freshness(&self) -> bool {
        if self.transitional_resolver {
            self.stop_authority.set_governance_uncertain(true);
            return false;
        }

        let last_success = *self
            .last_success
            .lock()
            .expect("governance monitor lock poisoned");
        let Some(last_success) = last_success else {
            self.stop_authority.set_governance_uncertain(true);
            return false;
        };

        if last_success.elapsed().as_millis() > u128::from(self.config.freshness_threshold_ms) {
            self.stop_authority.set_governance_uncertain(true);
            return false;
        }

        self.stop_authority.set_governance_uncertain(false);
        true
    }

    /// Returns the configured freshness threshold in milliseconds.
    #[must_use]
    pub const fn freshness_threshold_ms(&self) -> u64 {
        self.config.freshness_threshold_ms
    }

    /// Returns whether monitor freshness evidence is currently transitional.
    #[must_use]
    pub const fn transitional_resolver(&self) -> bool {
        self.transitional_resolver
    }

    /// Clears the last-success sample (test helper).
    #[cfg(test)]
    pub fn clear_last_success_for_test(&self) {
        *self
            .last_success
            .lock()
            .expect("governance monitor lock poisoned") = None;
    }

    /// Returns whether a last-success sample is present (test helper).
    #[cfg(test)]
    #[must_use]
    pub fn has_last_success_for_test(&self) -> bool {
        self.last_success
            .lock()
            .expect("governance monitor lock poisoned")
            .is_some()
    }
}

impl std::fmt::Debug for GovernanceFreshnessMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GovernanceFreshnessMonitor")
            .field("config", &self.config)
            .field("stop_authority", &"<StopAuthority>")
            .field(
                "last_success_is_some",
                &self
                    .last_success
                    .lock()
                    .expect("governance monitor lock poisoned")
                    .is_some(),
            )
            .field("transitional_resolver", &self.transitional_resolver)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::episode::capability::{CapabilityManifestV1, ManifestV1Error};
    use crate::episode::{CapabilityManifestBuilder, RiskTier, ToolClass};

    #[test]
    fn policy_resolver_provides_mint_token() {
        let resolver = GovernancePolicyResolver::new();
        let token = resolver.mint_token();

        // Token can be used to mint a V1 manifest
        let manifest = CapabilityManifestBuilder::new("gov-test")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(2000)
            .tool_allowlist(vec![ToolClass::Read])
            .build()
            .unwrap();

        let result = CapabilityManifestV1::mint(token, manifest, RiskTier::Tier2, Vec::new());
        assert!(result.is_ok(), "mint with policy token should succeed");
    }

    #[test]
    fn policy_resolver_rejects_laundered_manifest() {
        let resolver = GovernancePolicyResolver::new();
        let token = resolver.mint_token();

        // Attempt to mint with no expiry (laundering attempt)
        let manifest = CapabilityManifestBuilder::new("launder-test")
            .delegator("policy-resolver")
            .created_at(1000)
            .expires_at(0) // No expiry!
            .tool_allowlist(vec![ToolClass::Read])
            .build()
            .unwrap();

        let result = CapabilityManifestV1::mint(token, manifest, RiskTier::Tier2, Vec::new());
        assert!(
            matches!(result, Err(ManifestV1Error::MissingExpiry)),
            "laundered manifest without expiry must be rejected"
        );
    }

    #[test]
    fn resolve_for_claim_returns_valid_resolution() {
        let resolver = GovernancePolicyResolver::new();
        let result = resolver.resolve_for_claim("W-001", WorkRole::Implementer, "agent-001");
        assert!(result.is_ok());
        let resolution = result.unwrap();
        assert!(!resolution.policy_resolved_ref.is_empty());
        assert_ne!(resolution.resolved_policy_hash, [0u8; 32]);
        assert_ne!(resolution.capability_manifest_hash, [0u8; 32]);
        assert_ne!(resolution.context_pack_hash, [0u8; 32]);
    }

    /// Verifies the governance resolver returns Tier1 for Phase 1 transitional
    /// operation. This ensures production claims can flow through
    /// `IngestReviewReceipt` which only provides `SelfSigned` attestation.
    /// Tier1 requires `SelfSigned` attestation, which the endpoint can provide.
    #[test]
    fn test_governance_resolver_returns_tier1_for_reviewer() {
        let resolver = GovernancePolicyResolver::new();
        let result = resolver
            .resolve_for_claim("work-001", WorkRole::Reviewer, "actor-001")
            .expect("resolve_for_claim should succeed");

        assert_eq!(
            result.resolved_risk_tier, 1,
            "Governance resolver must return Tier1 for Reviewer role \
             — Tier4 blocks all production SelfSigned attestation"
        );
    }

    /// Verifies that different roles get their expected risk tiers in the
    /// transitional mapping: `GateExecutor` gets Tier2, all others get Tier1.
    #[test]
    fn test_governance_resolver_role_differentiated_tiers() {
        let resolver = GovernancePolicyResolver::new();

        // Tier1 roles: Reviewer, Implementer, Coordinator
        for (role, name, expected_tier) in [
            (WorkRole::Reviewer, "Reviewer", 1),
            (WorkRole::Implementer, "Implementer", 1),
            (WorkRole::Coordinator, "Coordinator", 1),
        ] {
            let result = resolver
                .resolve_for_claim("work-001", role, "actor-001")
                .expect("resolve_for_claim should succeed");
            assert_eq!(
                result.resolved_risk_tier, expected_tier,
                "Role {name} must get Tier{expected_tier} in transitional mapping, got {}",
                result.resolved_risk_tier
            );
        }

        // GateExecutor: Tier2 (CounterSigned required — highest risk role)
        let executor_result = resolver
            .resolve_for_claim("work-001", WorkRole::GateExecutor, "actor-001")
            .expect("resolve_for_claim should succeed for GateExecutor");
        assert_eq!(
            executor_result.resolved_risk_tier, 2,
            "GateExecutor must get Tier2 in transitional mapping, got {}",
            executor_result.resolved_risk_tier
        );
    }

    /// Verifies that policy resolution is deterministic: same inputs produce
    /// the same outputs (policy hash, manifest hash, context pack hash).
    #[test]
    fn test_governance_resolver_deterministic() {
        let resolver = GovernancePolicyResolver::new();
        let r1 = resolver
            .resolve_for_claim("work-001", WorkRole::Reviewer, "actor-001")
            .unwrap();
        let r2 = resolver
            .resolve_for_claim("work-001", WorkRole::Reviewer, "actor-001")
            .unwrap();

        assert_eq!(r1.resolved_policy_hash, r2.resolved_policy_hash);
        assert_eq!(r1.capability_manifest_hash, r2.capability_manifest_hash);
        assert_eq!(r1.context_pack_hash, r2.context_pack_hash);
        assert_eq!(r1.resolved_risk_tier, r2.resolved_risk_tier);
    }

    /// Verifies that different work IDs produce different policy hashes,
    /// ensuring proper domain separation.
    #[test]
    fn test_governance_resolver_different_work_ids_differ() {
        let resolver = GovernancePolicyResolver::new();
        let r1 = resolver
            .resolve_for_claim("work-001", WorkRole::Reviewer, "actor-001")
            .unwrap();
        let r2 = resolver
            .resolve_for_claim("work-002", WorkRole::Reviewer, "actor-001")
            .unwrap();

        assert_ne!(
            r1.resolved_policy_hash, r2.resolved_policy_hash,
            "Different work_ids must produce different policy hashes"
        );
    }

    /// Integration test: verifies that a Reviewer claim (Tier1) allows
    /// `SelfSigned` attestation through the attestation ratchet. This
    /// exercises the production `ClaimWork -> IngestReviewReceipt` path.
    #[test]
    fn test_governance_resolver_reviewer_tier_allows_self_signed() {
        use apm2_core::fac::{AttestationLevel, AttestationRequirements, ReceiptKind, RiskTier};

        let resolver = GovernancePolicyResolver::new();
        let resolution = resolver
            .resolve_for_claim("work-001", WorkRole::Reviewer, "actor-001")
            .unwrap();

        let tier = RiskTier::try_from(resolution.resolved_risk_tier)
            .expect("resolved_risk_tier must be a valid RiskTier value (0-4)");

        assert_eq!(
            tier,
            RiskTier::Tier1,
            "Reviewer must return Tier1 for transitional operation"
        );

        // Verify SelfSigned satisfies the attestation requirement for Tier1.
        let requirements = AttestationRequirements::new();
        let required_level = requirements.required_level(ReceiptKind::Review, tier);
        assert!(
            AttestationLevel::SelfSigned.satisfies(required_level),
            "SelfSigned must satisfy {required_level} for Review at {tier:?}"
        );
    }

    /// Integration test: verifies that a `GateExecutor` claim (Tier2) requires
    /// `CounterSigned` attestation. `SelfSigned` MUST NOT satisfy Tier2
    /// for Review receipts -- this enforces the risk differentiation.
    #[test]
    fn test_governance_resolver_gate_executor_tier_requires_counter_signed() {
        use apm2_core::fac::{AttestationLevel, AttestationRequirements, ReceiptKind, RiskTier};

        let resolver = GovernancePolicyResolver::new();
        let resolution = resolver
            .resolve_for_claim("work-001", WorkRole::GateExecutor, "actor-001")
            .unwrap();

        let tier = RiskTier::try_from(resolution.resolved_risk_tier)
            .expect("resolved_risk_tier must be a valid RiskTier value (0-4)");

        assert_eq!(
            tier,
            RiskTier::Tier2,
            "GateExecutor must return Tier2 for transitional operation"
        );

        // Verify CounterSigned satisfies the attestation requirement for Tier2.
        let requirements = AttestationRequirements::new();
        let required_level = requirements.required_level(ReceiptKind::Review, tier);
        assert!(
            AttestationLevel::CounterSigned.satisfies(required_level),
            "CounterSigned must satisfy {required_level} for Review at {tier:?}"
        );

        // Verify SelfSigned does NOT satisfy Tier2 -- this is the fail-closed check.
        assert!(
            !AttestationLevel::SelfSigned.satisfies(required_level),
            "SelfSigned must NOT satisfy {required_level} for Review at {tier:?} \
             -- GateExecutor requires CounterSigned"
        );
    }
}
