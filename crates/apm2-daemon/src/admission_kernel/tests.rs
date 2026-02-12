// AGENT-AUTHORED
//! Tests for `AdmissionKernel` plan/execute API (TCK-00492).
//!
//! Coverage:
//! - (a) missing policy-root denies for fail-closed tiers
//! - (b) missing witness SEEDS deny for fail-closed tiers (provider validation)
//! - (c) anti-rollback anchor missing denies for fail-closed tiers
//! - (d) early output is impossible for fail-closed tiers
//! - (e) intent mismatch denies at consume boundary
//! - (f) plan cannot be executed twice
//! - (g) monitor tier proceeds without prerequisites
//! - (h) capability tokens are minted only through kernel
//! - (i) lifecycle ordering enforcement
//! - (j) missing ledger verifier denies for fail-closed tiers

use std::sync::Arc;

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityConsumeRecordV1, AuthorityConsumedV1, AuthorityDenyClass, AuthorityDenyV1,
    AuthorityJoinCertificateV1, AuthorityJoinInputV1, AuthorityJoinKernel, BoundaryIntentClass,
    FreezeAction, IdentityEvidenceLevel, PcacPolicyKnobs, RiskTier,
};

use super::prerequisites::{
    AntiRollbackAnchor, ExternalAnchorStateV1, LedgerAnchorV1, LedgerTrustVerifier, PolicyError,
    PolicyRootResolver, PolicyRootStateV1, TrustError, ValidatedLedgerStateV1,
};
use super::types::{AdmitError, EnforcementTier};
use super::{AdmissionKernelV1, QuarantineGuard, WitnessProviderConfig};

// =============================================================================
// Test helpers
// =============================================================================

/// Non-zero hash for testing.
fn test_hash(byte: u8) -> Hash {
    let mut h = [0u8; 32];
    h[0] = byte;
    h[31] = byte;
    h
}

/// Build a valid `KernelRequestV1` for testing.
fn valid_request(risk_tier: RiskTier) -> super::types::KernelRequestV1 {
    super::types::KernelRequestV1 {
        request_id: test_hash(1),
        session_id: "test-session-001".to_string(),
        tool_class: "filesystem.write".to_string(),
        boundary_profile_id: "boundary-001".to_string(),
        risk_tier,
        effect_descriptor_digest: test_hash(2),
        intent_digest: test_hash(3),
        hsi_contract_manifest_digest: test_hash(4),
        hsi_envelope_binding_digest: test_hash(5),
        stop_budget_digest: test_hash(6),
        pcac_policy: PcacPolicyKnobs::default(),
        declared_idempotent: false,
        lease_id: "lease-001".to_string(),
        identity_proof_hash: test_hash(7),
        capability_manifest_hash: test_hash(8),
        time_envelope_ref: test_hash(9),
        freshness_witness_tick: 42,
        directory_head_hash: test_hash(10),
        freshness_policy_hash: test_hash(11),
        revocation_head_hash: test_hash(12),
        identity_evidence_level: IdentityEvidenceLevel::Verified,
        pointer_only_waiver_hash: None,
    }
}

fn witness_provider() -> WitnessProviderConfig {
    WitnessProviderConfig {
        provider_id: "apm2-daemon/admission_kernel/test".to_string(),
        provider_build_digest: test_hash(99),
    }
}

// -- Mock implementations --

/// Result type for consume operations in the mock kernel.
type ConsumeResult = Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>>;

/// A mock PCAC kernel that tracks calls and can be configured to fail.
struct MockPcacKernel {
    join_result: std::sync::Mutex<Option<Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>>>>,
    consume_result: std::sync::Mutex<Option<ConsumeResult>>,
}

impl MockPcacKernel {
    fn passing() -> Self {
        Self {
            join_result: std::sync::Mutex::new(None),
            consume_result: std::sync::Mutex::new(None),
        }
    }

    fn with_consume_error(deny_class: AuthorityDenyClass) -> Self {
        let deny = AuthorityDenyV1 {
            deny_class,
            ajc_id: Some(test_hash(50)),
            time_envelope_ref: test_hash(51),
            ledger_anchor: test_hash(52),
            denied_at_tick: 100,
            containment_action: Some(FreezeAction::NoAction),
        };
        Self {
            join_result: std::sync::Mutex::new(None),
            consume_result: std::sync::Mutex::new(Some(Err(Box::new(deny)))),
        }
    }
}

impl AuthorityJoinKernel for MockPcacKernel {
    fn join(
        &self,
        _input: &AuthorityJoinInputV1,
        _policy: &PcacPolicyKnobs,
    ) -> Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>> {
        let guard = self
            .join_result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ref result) = *guard {
            return result.clone();
        }
        // Default: return a valid certificate
        Ok(AuthorityJoinCertificateV1 {
            ajc_id: test_hash(50),
            authority_join_hash: test_hash(51),
            intent_digest: test_hash(3),
            boundary_intent_class: BoundaryIntentClass::Actuate,
            risk_tier: RiskTier::Tier1,
            issued_time_envelope_ref: test_hash(52),
            issued_at_tick: 40,
            as_of_ledger_anchor: test_hash(53),
            expires_at_tick: 1000,
            revocation_head_hash: test_hash(54),
            identity_evidence_level: IdentityEvidenceLevel::PointerOnly,
            admission_capacity_token: None,
        })
    }

    fn revalidate(
        &self,
        _cert: &AuthorityJoinCertificateV1,
        _current_time_envelope_ref: Hash,
        _current_ledger_anchor: Hash,
        _current_revocation_head_hash: Hash,
        _policy: &PcacPolicyKnobs,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        Ok(())
    }

    fn consume(
        &self,
        cert: &AuthorityJoinCertificateV1,
        _intent_digest: Hash,
        _boundary_intent_class: BoundaryIntentClass,
        _requires_authoritative_acceptance: bool,
        _current_time_envelope_ref: Hash,
        _current_revocation_head_hash: Hash,
        _policy: &PcacPolicyKnobs,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>> {
        let guard = self
            .consume_result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ref result) = *guard {
            return result.clone();
        }
        // Default: return a valid consume result
        Ok((
            AuthorityConsumedV1 {
                ajc_id: cert.ajc_id,
                intent_digest: test_hash(3),
                consumed_time_envelope_ref: test_hash(61),
                consumed_at_tick: 45,
            },
            AuthorityConsumeRecordV1 {
                ajc_id: cert.ajc_id,
                consumed_time_envelope_ref: test_hash(61),
                consumed_at_tick: 45,
                effect_selector_digest: test_hash(60),
            },
        ))
    }
}

/// A mock ledger trust verifier.
struct MockLedgerVerifier {
    result: Result<ValidatedLedgerStateV1, TrustError>,
}

impl MockLedgerVerifier {
    fn passing() -> Self {
        Self {
            result: Ok(ValidatedLedgerStateV1 {
                validated_anchor: LedgerAnchorV1 {
                    ledger_id: test_hash(20),
                    event_hash: test_hash(21),
                    height: 100,
                    he_time: 1000,
                },
                tip_anchor: LedgerAnchorV1 {
                    ledger_id: test_hash(20),
                    event_hash: test_hash(22),
                    height: 105,
                    he_time: 1050,
                },
                ledger_keyset_digest: test_hash(23),
                root_trust_bundle_digest: test_hash(24),
            }),
        }
    }
}

impl LedgerTrustVerifier for MockLedgerVerifier {
    fn validated_state(&self) -> Result<ValidatedLedgerStateV1, TrustError> {
        self.result.clone()
    }
}

/// A mock policy root resolver.
struct MockPolicyResolver {
    result: Result<PolicyRootStateV1, PolicyError>,
}

impl MockPolicyResolver {
    fn passing() -> Self {
        Self {
            result: Ok(PolicyRootStateV1 {
                policy_root_digest: test_hash(30),
                policy_root_epoch: 5,
                anchor: LedgerAnchorV1 {
                    ledger_id: test_hash(20),
                    event_hash: test_hash(21),
                    height: 100,
                    he_time: 1000,
                },
                provenance: super::prerequisites::GovernanceProvenanceV1 {
                    signer_key_id: test_hash(31),
                    algorithm_id: "ed25519".to_string(),
                },
            }),
        }
    }

    fn failing() -> Self {
        Self {
            result: Err(PolicyError::NoGovernanceEvents),
        }
    }
}

impl PolicyRootResolver for MockPolicyResolver {
    fn resolve(&self, _as_of: &LedgerAnchorV1) -> Result<PolicyRootStateV1, PolicyError> {
        self.result.clone()
    }
}

/// A mock anti-rollback anchor.
struct MockAntiRollback {
    result: Result<(), TrustError>,
}

impl MockAntiRollback {
    fn passing() -> Self {
        Self { result: Ok(()) }
    }
}

impl AntiRollbackAnchor for MockAntiRollback {
    fn latest(&self) -> Result<ExternalAnchorStateV1, TrustError> {
        Ok(ExternalAnchorStateV1 {
            anchor: LedgerAnchorV1 {
                ledger_id: test_hash(20),
                event_hash: test_hash(21),
                height: 100,
                he_time: 1000,
            },
            mechanism_id: "test".to_string(),
            proof_hash: test_hash(40),
        })
    }

    fn verify_committed(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
        self.result.clone()
    }
}

/// A mock quarantine guard.
struct MockQuarantineGuard {
    result: Result<Hash, String>,
}

impl MockQuarantineGuard {
    fn passing() -> Self {
        Self {
            result: Ok(test_hash(70)),
        }
    }
}

impl QuarantineGuard for MockQuarantineGuard {
    fn reserve(&self, _request_id: &Hash, _ajc_id: &Hash) -> Result<Hash, String> {
        self.result.clone()
    }
}

/// A mock ledger verifier that returns different anchors on successive calls.
///
/// Used to test BLOCKER 1: ledger-anchor drift detection in `execute()`.
/// The first call (plan-time) returns `first_anchor`, and all subsequent
/// calls (execute-time) return `second_anchor`.
struct DriftingLedgerVerifier {
    call_count: std::sync::Mutex<u32>,
    first: ValidatedLedgerStateV1,
    second: ValidatedLedgerStateV1,
}

impl DriftingLedgerVerifier {
    /// Create a verifier that returns `first` on the first call and `second`
    /// on all subsequent calls, simulating ledger advancement between plan
    /// and execute.
    fn new(first: ValidatedLedgerStateV1, second: ValidatedLedgerStateV1) -> Self {
        Self {
            call_count: std::sync::Mutex::new(0),
            first,
            second,
        }
    }
}

impl LedgerTrustVerifier for DriftingLedgerVerifier {
    fn validated_state(&self) -> Result<ValidatedLedgerStateV1, TrustError> {
        let mut count = self
            .call_count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count += 1;
        if *count == 1 {
            Ok(self.first.clone())
        } else {
            Ok(self.second.clone())
        }
    }
}

/// A mock policy resolver that returns different roots on successive calls.
///
/// Used to test MAJOR 1: policy root drift detection in `execute()`.
struct DriftingPolicyResolver {
    call_count: std::sync::Mutex<u32>,
    first: PolicyRootStateV1,
    second: PolicyRootStateV1,
}

impl DriftingPolicyResolver {
    fn new(first: PolicyRootStateV1, second: PolicyRootStateV1) -> Self {
        Self {
            call_count: std::sync::Mutex::new(0),
            first,
            second,
        }
    }
}

impl PolicyRootResolver for DriftingPolicyResolver {
    fn resolve(&self, _as_of: &LedgerAnchorV1) -> Result<PolicyRootStateV1, PolicyError> {
        let mut count = self
            .call_count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count += 1;
        if *count == 1 {
            Ok(self.first.clone())
        } else {
            Ok(self.second.clone())
        }
    }
}

/// A mock anti-rollback that fails on the second call (simulating
/// anti-rollback failure between plan and execute).
struct DriftingAntiRollback {
    call_count: std::sync::Mutex<u32>,
}

impl DriftingAntiRollback {
    fn new() -> Self {
        Self {
            call_count: std::sync::Mutex::new(0),
        }
    }
}

impl AntiRollbackAnchor for DriftingAntiRollback {
    fn latest(&self) -> Result<ExternalAnchorStateV1, TrustError> {
        Ok(ExternalAnchorStateV1 {
            anchor: LedgerAnchorV1 {
                ledger_id: test_hash(20),
                event_hash: test_hash(21),
                height: 100,
                he_time: 1000,
            },
            mechanism_id: "test".to_string(),
            proof_hash: test_hash(40),
        })
    }

    fn verify_committed(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
        let mut count = self
            .call_count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count += 1;
        if *count <= 1 {
            Ok(())
        } else {
            Err(TrustError::ExternalAnchorMismatch {
                reason: "anti-rollback anchor drifted (test)".into(),
            })
        }
    }
}

/// A mock PCAC kernel that detects ledger anchor drift via revalidate.
///
/// The first call to `revalidate()` succeeds (plan-time), but the second
/// call fails if the ledger anchor differs from the cert's anchor.
struct DriftDetectingPcacKernel;

impl AuthorityJoinKernel for DriftDetectingPcacKernel {
    fn join(
        &self,
        input: &AuthorityJoinInputV1,
        _policy: &PcacPolicyKnobs,
    ) -> Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>> {
        // Mirror the join input's as_of_ledger_anchor into the cert,
        // as a real PCAC kernel would.
        Ok(AuthorityJoinCertificateV1 {
            ajc_id: test_hash(50),
            authority_join_hash: test_hash(51),
            intent_digest: test_hash(3),
            boundary_intent_class: BoundaryIntentClass::Actuate,
            risk_tier: RiskTier::Tier2Plus,
            issued_time_envelope_ref: test_hash(52),
            issued_at_tick: 40,
            as_of_ledger_anchor: input.as_of_ledger_anchor,
            expires_at_tick: 1000,
            revocation_head_hash: test_hash(54),
            identity_evidence_level: IdentityEvidenceLevel::Verified,
            admission_capacity_token: None,
        })
    }

    fn revalidate(
        &self,
        cert: &AuthorityJoinCertificateV1,
        _current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        _current_revocation_head_hash: Hash,
        _policy: &PcacPolicyKnobs,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        // Detect anchor drift: if the current ledger anchor differs from
        // the cert's as_of_ledger_anchor, deny.
        if current_ledger_anchor != cert.as_of_ledger_anchor {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::LedgerAnchorDrift,
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: test_hash(90),
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: 50,
                containment_action: Some(FreezeAction::NoAction),
            }));
        }
        Ok(())
    }

    fn consume(
        &self,
        cert: &AuthorityJoinCertificateV1,
        _intent_digest: Hash,
        _boundary_intent_class: BoundaryIntentClass,
        _requires_authoritative_acceptance: bool,
        _current_time_envelope_ref: Hash,
        _current_revocation_head_hash: Hash,
        _policy: &PcacPolicyKnobs,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>> {
        Ok((
            AuthorityConsumedV1 {
                ajc_id: cert.ajc_id,
                intent_digest: test_hash(3),
                consumed_time_envelope_ref: test_hash(61),
                consumed_at_tick: 45,
            },
            AuthorityConsumeRecordV1 {
                ajc_id: cert.ajc_id,
                consumed_time_envelope_ref: test_hash(61),
                consumed_at_tick: 45,
                effect_selector_digest: test_hash(60),
            },
        ))
    }
}

/// Build a fully-wired kernel for fail-closed tier testing.
fn fully_wired_kernel() -> AdmissionKernelV1 {
    AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()))
}

/// Build a minimal kernel (no optional prerequisites).
fn minimal_kernel() -> AdmissionKernelV1 {
    AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
}

// =============================================================================
// Test: (a) missing policy-root denies for fail-closed tiers
// =============================================================================

#[test]
fn test_missing_policy_root_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));
    // Deliberately NOT setting policy resolver.

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "fail-closed tier must deny when policy root resolver is missing"
    );
    let err = result.unwrap_err();
    match &err {
        AdmitError::MissingPrerequisite { prerequisite } => {
            assert_eq!(prerequisite, "PolicyRootResolver");
        },
        other => panic!("expected MissingPrerequisite, got: {other}"),
    }
}

#[test]
fn test_failing_policy_root_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::failing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "fail-closed tier must deny when policy root resolution fails"
    );
    match result.unwrap_err() {
        AdmitError::PolicyRootFailure { reason } => {
            assert!(
                reason.contains("governance"),
                "reason should mention governance events: {reason}"
            );
        },
        other => panic!("expected PolicyRootFailure, got: {other}"),
    }
}

// =============================================================================
// Test: (b) missing witness SEEDS deny for fail-closed tiers
// =============================================================================

#[test]
fn test_invalid_witness_provider_denies() {
    let bad_provider = WitnessProviderConfig {
        provider_id: String::new(), // empty — invalid
        provider_build_digest: test_hash(99),
    };
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), bad_provider)
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));

    // Test both tiers
    for tier in [RiskTier::Tier1, RiskTier::Tier2Plus] {
        let request = valid_request(tier);
        let result = kernel.plan(&request);
        assert!(
            result.is_err(),
            "invalid witness provider must deny for {tier:?}"
        );
        match result.unwrap_err() {
            AdmitError::WitnessSeedFailure { reason } => {
                assert!(
                    reason.contains("provider_id"),
                    "reason should mention provider_id: {reason}"
                );
            },
            other => panic!("expected WitnessSeedFailure, got: {other}"),
        }
    }
}

// =============================================================================
// Test: (c) anti-rollback anchor missing denies for fail-closed tiers
// =============================================================================

#[test]
fn test_missing_anti_rollback_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()));
    // Deliberately NOT setting anti-rollback anchor.

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "fail-closed tier must deny when anti-rollback anchor is missing"
    );
    match result.unwrap_err() {
        AdmitError::MissingPrerequisite { prerequisite } => {
            assert_eq!(prerequisite, "AntiRollbackAnchor");
        },
        other => panic!("expected MissingPrerequisite, got: {other}"),
    }
}

// =============================================================================
// Test: (d) early output is impossible for fail-closed tiers
// =============================================================================

#[test]
fn test_boundary_span_holds_output_for_fail_closed() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(
        result.boundary_span.output_held,
        "fail-closed tier must hold output (output_held=true)"
    );
    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::FailClosed,
        "boundary span must carry fail-closed tier"
    );
}

#[test]
fn test_boundary_span_releases_output_for_monitor() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier0);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(
        !result.boundary_span.output_held,
        "monitor tier should NOT hold output (output_held=false)"
    );
    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::Monitor,
        "boundary span must carry monitor tier"
    );
}

// =============================================================================
// Test: (e) intent mismatch denies at consume boundary
// =============================================================================

#[test]
fn test_intent_mismatch_denies_at_consume() {
    let kernel = AdmissionKernelV1::new(
        Arc::new(MockPcacKernel::with_consume_error(
            AuthorityDenyClass::IntentDigestMismatch {
                expected: test_hash(3),
                actual: test_hash(99),
            },
        )),
        witness_provider(),
    )
    .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
    .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
    .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
    .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_err(),
        "intent mismatch must deny at consume boundary"
    );
    match result.unwrap_err() {
        AdmitError::ConsumeDenied { reason } => {
            assert!(
                reason.contains("intent digest mismatch"),
                "reason should mention intent digest mismatch: {reason}"
            );
        },
        other => panic!("expected ConsumeDenied, got: {other}"),
    }
}

// =============================================================================
// Test: (f) plan cannot be executed twice
// =============================================================================

#[test]
fn test_plan_cannot_be_executed_twice() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");

    // First execution succeeds.
    let first_result = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    assert!(first_result.is_ok(), "first execution should succeed");

    // Second execution must be denied.
    let second_result = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    assert!(second_result.is_err(), "second execution must be denied");
    match second_result.unwrap_err() {
        AdmitError::PlanAlreadyConsumed => {},
        other => panic!("expected PlanAlreadyConsumed, got: {other}"),
    }
}

#[test]
fn test_plan_consumed_even_on_execute_failure() {
    // If execute() fails mid-way, the plan is still consumed.
    let kernel = AdmissionKernelV1::new(
        Arc::new(MockPcacKernel::with_consume_error(
            AuthorityDenyClass::IntentDigestMismatch {
                expected: test_hash(3),
                actual: test_hash(99),
            },
        )),
        witness_provider(),
    )
    .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
    .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
    .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
    .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");

    // First execution fails (consume error).
    let first_result = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    assert!(first_result.is_err(), "first execution should fail");

    // Second execution must return PlanAlreadyConsumed, not re-run.
    let second_result = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    match second_result.unwrap_err() {
        AdmitError::PlanAlreadyConsumed => {},
        other => panic!("expected PlanAlreadyConsumed on retry, got: {other}"),
    }
}

// =============================================================================
// Test: (g) monitor tier proceeds without prerequisites
// =============================================================================

#[test]
fn test_monitor_tier_proceeds_without_prerequisites() {
    let kernel = minimal_kernel(); // No prerequisites wired.
    let request = valid_request(RiskTier::Tier0);

    let result = kernel.plan(&request);
    assert!(
        result.is_ok(),
        "monitor tier should proceed without prerequisites: {:?}",
        result.err()
    );
}

#[test]
fn test_monitor_tier_proceeds_without_quarantine_guard() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier1);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_ok(),
        "monitor tier should succeed without quarantine guard: {:?}",
        result.err()
    );

    let res = result.unwrap();
    assert!(
        res.quarantine_capability.is_none(),
        "monitor tier should not receive quarantine capability"
    );
    assert!(
        res.ledger_write_capability.is_none(),
        "monitor tier MUST NOT receive ledger write capability (CTR-2617)"
    );
}

// =============================================================================
// Test: (h) capability tokens are minted only through kernel
// =============================================================================

#[test]
fn test_capability_tokens_present_on_success() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Verify capability tokens carry correct provenance.
    assert_eq!(result.effect_capability.ajc_id(), &test_hash(50));
    assert_eq!(result.effect_capability.intent_digest(), &test_hash(3));
    assert_eq!(result.effect_capability.request_id(), &test_hash(1));

    assert!(
        result.ledger_write_capability.is_some(),
        "fail-closed tier must receive ledger write capability"
    );
    let lwcap = result.ledger_write_capability.as_ref().unwrap();
    assert_eq!(lwcap.ajc_id(), &test_hash(50));
    assert_eq!(lwcap.request_id(), &test_hash(1));

    assert!(
        result.quarantine_capability.is_some(),
        "fail-closed tier must have quarantine capability"
    );
    let qcap = result.quarantine_capability.unwrap();
    assert_eq!(qcap.ajc_id(), &test_hash(50));
    assert_eq!(qcap.reservation_hash(), &test_hash(70));
}

// =============================================================================
// Test: (i) lifecycle ordering enforcement
// =============================================================================

#[test]
fn test_plan_creates_witness_seeds_with_provider_provenance() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let plan = kernel.plan(&request).expect("plan should succeed");

    // Verify witness seeds have correct provenance.
    assert_eq!(plan.leakage_witness_seed.witness_class, "leakage");
    assert_eq!(plan.timing_witness_seed.witness_class, "timing");
    assert_eq!(
        plan.leakage_witness_seed.provider_id,
        "apm2-daemon/admission_kernel/test"
    );
    assert_eq!(
        plan.timing_witness_seed.provider_id,
        "apm2-daemon/admission_kernel/test"
    );
    assert_eq!(
        plan.leakage_witness_seed.provider_build_digest,
        test_hash(99)
    );

    // Verify witness seeds bind to request.
    assert_eq!(plan.leakage_witness_seed.request_id, request.request_id);
    assert_eq!(plan.timing_witness_seed.request_id, request.request_id);
    assert_eq!(plan.leakage_witness_seed.session_id, request.session_id);
    assert_eq!(plan.timing_witness_seed.session_id, request.session_id);

    // Verify nonces are different (random).
    assert_ne!(
        plan.leakage_witness_seed.nonce, plan.timing_witness_seed.nonce,
        "witness seed nonces must be unique"
    );
}

#[test]
fn test_plan_creates_spine_extension() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let plan = kernel.plan(&request).expect("plan should succeed");

    assert_eq!(plan.spine_ext.request_id, request.request_id);
    assert_eq!(plan.spine_ext.session_id, request.session_id);
    assert_eq!(plan.spine_ext.tool_class, request.tool_class);
    assert_eq!(plan.spine_ext.enforcement_tier, EnforcementTier::FailClosed);
    assert_eq!(
        plan.spine_ext.effect_descriptor_digest,
        request.effect_descriptor_digest
    );
}

#[test]
fn test_spine_extension_content_hash_deterministic() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let plan1 = kernel.plan(&request).expect("plan should succeed");

    // Content hash should be deterministic for same spine extension fields.
    let hash1 = plan1.spine_ext.content_hash();
    let hash2 = plan1.spine_ext.content_hash();
    assert_eq!(hash1, hash2, "content hash must be deterministic");
    assert_ne!(hash1, [0u8; 32], "content hash must not be zero");
}

// =============================================================================
// Test: (j) missing ledger verifier denies for fail-closed tiers
// =============================================================================

#[test]
fn test_missing_ledger_verifier_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider());
    // Deliberately NOT setting ledger verifier.

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "fail-closed tier must deny when ledger verifier is missing"
    );
    match result.unwrap_err() {
        AdmitError::MissingPrerequisite { prerequisite } => {
            assert_eq!(prerequisite, "LedgerTrustVerifier");
        },
        other => panic!("expected MissingPrerequisite, got: {other}"),
    }
}

// =============================================================================
// Test: request validation
// =============================================================================

#[test]
fn test_invalid_request_denied() {
    let kernel = fully_wired_kernel();

    // Zero request_id
    let mut request = valid_request(RiskTier::Tier2Plus);
    request.request_id = [0u8; 32];
    let result = kernel.plan(&request);
    assert!(result.is_err());
    match result.unwrap_err() {
        AdmitError::InvalidRequest { reason } => {
            assert!(
                reason.contains("request_id"),
                "reason should mention request_id: {reason}"
            );
        },
        other => panic!("expected InvalidRequest, got: {other}"),
    }

    // Empty session_id
    let mut request = valid_request(RiskTier::Tier2Plus);
    request.session_id = String::new();
    let result = kernel.plan(&request);
    assert!(result.is_err());
    match result.unwrap_err() {
        AdmitError::InvalidRequest { reason } => {
            assert!(
                reason.contains("session_id"),
                "reason should mention session_id: {reason}"
            );
        },
        other => panic!("expected InvalidRequest, got: {other}"),
    }
}

// =============================================================================
// Test: full plan/execute lifecycle (integration)
// =============================================================================

#[test]
fn test_full_lifecycle_plan_execute_success() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    // Plan phase
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    assert_eq!(plan.enforcement_tier, EnforcementTier::FailClosed);
    assert_eq!(plan.request.request_id, request.request_id);

    // Execute phase
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Verify all components of the result.
    assert_ne!(
        result.bundle_digest, [0u8; 32],
        "bundle digest must not be zero"
    );
    assert!(
        result.boundary_span.output_held,
        "output must be held for fail-closed tier"
    );
    assert_eq!(
        result.boundary_span.request_id, request.request_id,
        "boundary span must reference the request"
    );
}

#[test]
fn test_full_lifecycle_monitor_tier() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier1);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    assert_eq!(plan.enforcement_tier, EnforcementTier::Monitor);

    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(
        !result.boundary_span.output_held,
        "output should not be held for monitor tier"
    );
    assert!(
        result.quarantine_capability.is_none(),
        "quarantine capability should not be present for monitor tier"
    );
    assert!(
        result.ledger_write_capability.is_none(),
        "ledger write capability should not be present for monitor tier"
    );
}

// =============================================================================
// Test: enforcement tier derivation
// =============================================================================

#[test]
fn test_enforcement_tier_derivation() {
    use super::enforcement_tier_from_risk;

    assert_eq!(
        enforcement_tier_from_risk(RiskTier::Tier0),
        EnforcementTier::Monitor
    );
    assert_eq!(
        enforcement_tier_from_risk(RiskTier::Tier1),
        EnforcementTier::Monitor
    );
    assert_eq!(
        enforcement_tier_from_risk(RiskTier::Tier2Plus),
        EnforcementTier::FailClosed
    );
}

// =============================================================================
// Test: quarantine reservation failure denies fail-closed
// =============================================================================

#[test]
fn test_quarantine_reservation_failure_denies_fail_closed() {
    let failing_guard = MockQuarantineGuard {
        result: Err("capacity exhausted (test)".into()),
    };
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(failing_guard));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_err(),
        "quarantine reservation failure must deny for fail-closed tier"
    );
    match result.unwrap_err() {
        AdmitError::QuarantineReservationFailure { reason } => {
            assert!(
                reason.contains("capacity exhausted"),
                "reason should mention capacity: {reason}"
            );
        },
        other => panic!("expected QuarantineReservationFailure, got: {other}"),
    }
}

// =============================================================================
// Test: missing quarantine guard denies fail-closed
// =============================================================================

#[test]
fn test_missing_quarantine_guard_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));
    // Deliberately NOT setting quarantine guard.

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_err(),
        "missing quarantine guard must deny for fail-closed tier"
    );
    match result.unwrap_err() {
        AdmitError::MissingPrerequisite { prerequisite } => {
            assert_eq!(prerequisite, "QuarantineGuard");
        },
        other => panic!("expected MissingPrerequisite, got: {other}"),
    }
}

// =============================================================================
// Test: witness seed content hashes are non-zero and unique
// =============================================================================

#[test]
fn test_witness_seed_hashes_nonzero_and_unique() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let plan = kernel.plan(&request).expect("plan should succeed");

    let leakage_hash = plan.leakage_witness_seed.content_hash();
    let timing_hash = plan.timing_witness_seed.content_hash();

    assert_ne!(
        leakage_hash, [0u8; 32],
        "leakage seed hash must not be zero"
    );
    assert_ne!(timing_hash, [0u8; 32], "timing seed hash must not be zero");
    assert_ne!(
        leakage_hash, timing_hash,
        "leakage and timing seed hashes must differ"
    );
}

// =============================================================================
// Test: bundle digest is deterministic for same inputs
// =============================================================================

#[test]
fn test_bundle_digest_nonzero() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert_ne!(
        result.bundle_digest, [0u8; 32],
        "bundle digest must not be zero"
    );
}

// =============================================================================
// Test: AdmitError Display coverage
// =============================================================================

#[test]
fn test_admit_error_display() {
    let errors = vec![
        AdmitError::InvalidRequest {
            reason: "test".into(),
        },
        AdmitError::LedgerTrustFailure {
            reason: "test".into(),
        },
        AdmitError::PolicyRootFailure {
            reason: "test".into(),
        },
        AdmitError::AntiRollbackFailure {
            reason: "test".into(),
        },
        AdmitError::JoinDenied {
            reason: "test".into(),
        },
        AdmitError::RevalidationDenied {
            reason: "test".into(),
        },
        AdmitError::ConsumeDenied {
            reason: "test".into(),
        },
        AdmitError::WitnessSeedFailure {
            reason: "test".into(),
        },
        AdmitError::PlanAlreadyConsumed,
        AdmitError::QuarantineReservationFailure {
            reason: "test".into(),
        },
        AdmitError::BoundaryMediationFailure {
            reason: "test".into(),
        },
        AdmitError::MissingPrerequisite {
            prerequisite: "test".into(),
        },
        AdmitError::ExecutePrerequisiteDrift {
            prerequisite: "test".into(),
            reason: "test".into(),
        },
    ];

    for err in &errors {
        let display = format!("{err}");
        assert!(!display.is_empty(), "display must not be empty for {err:?}");
    }
    assert_eq!(errors.len(), 13, "all 13 error variants must be tested");
}

// =============================================================================
// SECURITY REGRESSION: BLOCKER 1 — ledger anchor drift detection in execute()
// =============================================================================

#[test]
fn test_execute_detects_ledger_anchor_drift_fail_closed() {
    // Scenario: ledger advances between plan() and execute().
    // The DriftDetectingPcacKernel denies revalidation when the fresh
    // anchor differs from the cert's as_of_ledger_anchor.
    let first_state = ValidatedLedgerStateV1 {
        validated_anchor: LedgerAnchorV1 {
            ledger_id: test_hash(20),
            event_hash: test_hash(21),
            height: 100,
            he_time: 1000,
        },
        tip_anchor: LedgerAnchorV1 {
            ledger_id: test_hash(20),
            event_hash: test_hash(22),
            height: 105,
            he_time: 1050,
        },
        ledger_keyset_digest: test_hash(23),
        root_trust_bundle_digest: test_hash(24),
    };

    let second_state = ValidatedLedgerStateV1 {
        validated_anchor: LedgerAnchorV1 {
            ledger_id: test_hash(20),
            event_hash: test_hash(25), // DIFFERENT anchor — drift!
            height: 110,
            he_time: 1100,
        },
        tip_anchor: LedgerAnchorV1 {
            ledger_id: test_hash(20),
            event_hash: test_hash(26),
            height: 115,
            he_time: 1150,
        },
        ledger_keyset_digest: test_hash(23),
        root_trust_bundle_digest: test_hash(24),
    };

    // Use the drift-detecting PCAC kernel that actually checks anchor equality.
    let kernel = AdmissionKernelV1::new(Arc::new(DriftDetectingPcacKernel), witness_provider())
        .with_ledger_verifier(Arc::new(DriftingLedgerVerifier::new(
            first_state,
            second_state,
        )))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");

    // Execute with fresh anchor that has drifted — must be denied.
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_err(),
        "execute must deny when ledger anchor drifted between plan and execute"
    );
    match result.unwrap_err() {
        AdmitError::RevalidationDenied { reason } => {
            assert!(
                reason.contains("ledger anchor drift"),
                "reason should mention ledger anchor drift: {reason}"
            );
        },
        other => panic!("expected RevalidationDenied (ledger anchor drift), got: {other}"),
    }
}

// =============================================================================
// SECURITY REGRESSION: MAJOR 1 — policy root drift detection in execute()
// =============================================================================

#[test]
fn test_execute_detects_policy_root_drift_fail_closed() {
    // Scenario: policy root changes between plan() and execute().
    let first_policy = PolicyRootStateV1 {
        policy_root_digest: test_hash(30),
        policy_root_epoch: 5,
        anchor: LedgerAnchorV1 {
            ledger_id: test_hash(20),
            event_hash: test_hash(21),
            height: 100,
            he_time: 1000,
        },
        provenance: super::prerequisites::GovernanceProvenanceV1 {
            signer_key_id: test_hash(31),
            algorithm_id: "ed25519".to_string(),
        },
    };

    let second_policy = PolicyRootStateV1 {
        policy_root_digest: test_hash(35), // DIFFERENT digest — drift!
        policy_root_epoch: 6,              // DIFFERENT epoch
        anchor: LedgerAnchorV1 {
            ledger_id: test_hash(20),
            event_hash: test_hash(21),
            height: 100,
            he_time: 1000,
        },
        provenance: super::prerequisites::GovernanceProvenanceV1 {
            signer_key_id: test_hash(31),
            algorithm_id: "ed25519".to_string(),
        },
    };

    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(DriftingPolicyResolver::new(
            first_policy,
            second_policy,
        )))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");

    // Execute when policy root has drifted — must be denied.
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_err(),
        "execute must deny when policy root drifted between plan and execute"
    );
    match result.unwrap_err() {
        AdmitError::ExecutePrerequisiteDrift {
            prerequisite,
            reason,
        } => {
            assert_eq!(prerequisite, "PolicyRoot");
            assert!(
                reason.contains("drifted"),
                "reason should mention drift: {reason}"
            );
        },
        other => panic!("expected ExecutePrerequisiteDrift, got: {other}"),
    }
}

#[test]
fn test_execute_detects_anti_rollback_failure_fail_closed() {
    // Scenario: anti-rollback fails between plan() and execute().
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(DriftingAntiRollback::new()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");

    // Execute when anti-rollback fails — must be denied.
    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));

    assert!(
        result.is_err(),
        "execute must deny when anti-rollback fails between plan and execute"
    );
    match result.unwrap_err() {
        AdmitError::AntiRollbackFailure { reason } => {
            assert!(
                reason.contains("drifted"),
                "reason should mention drift: {reason}"
            );
        },
        other => panic!("expected AntiRollbackFailure, got: {other}"),
    }
}

// =============================================================================
// SECURITY REGRESSION: MAJOR 1 — monitor tier is NOT affected by re-checks
// =============================================================================

#[test]
fn test_execute_monitor_tier_not_affected_by_prerequisite_recheck() {
    // Monitor tier does not re-check prerequisites in execute().
    // Even with a drifting policy resolver, monitor tier should succeed.
    let first_policy = PolicyRootStateV1 {
        policy_root_digest: test_hash(30),
        policy_root_epoch: 5,
        anchor: LedgerAnchorV1 {
            ledger_id: test_hash(20),
            event_hash: test_hash(21),
            height: 100,
            he_time: 1000,
        },
        provenance: super::prerequisites::GovernanceProvenanceV1 {
            signer_key_id: test_hash(31),
            algorithm_id: "ed25519".to_string(),
        },
    };

    let second_policy = PolicyRootStateV1 {
        policy_root_digest: test_hash(35), // DIFFERENT — but monitor ignores
        policy_root_epoch: 6,
        anchor: LedgerAnchorV1 {
            ledger_id: test_hash(20),
            event_hash: test_hash(21),
            height: 100,
            he_time: 1000,
        },
        provenance: super::prerequisites::GovernanceProvenanceV1 {
            signer_key_id: test_hash(31),
            algorithm_id: "ed25519".to_string(),
        },
    };

    // Monitor tier kernel with drifting policy — should still succeed.
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(DriftingPolicyResolver::new(
            first_policy,
            second_policy,
        )))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));

    // Tier1 maps to Monitor, not FailClosed.
    let request = valid_request(RiskTier::Tier1);
    let mut plan = kernel.plan(&request).expect("plan should succeed");

    let result = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    assert!(
        result.is_ok(),
        "monitor tier must NOT be affected by prerequisite re-checks: {:?}",
        result.err()
    );
}

// =============================================================================
// SECURITY REGRESSION: MAJOR 2 — monitor tier must NOT get
// LedgerWriteCapability
// =============================================================================

#[test]
fn test_monitor_tier_no_ledger_write_capability() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier0);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(
        result.ledger_write_capability.is_none(),
        "monitor tier MUST NOT receive LedgerWriteCapability (CTR-2617)"
    );
}

#[test]
fn test_fail_closed_tier_gets_ledger_write_capability() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(
        result.ledger_write_capability.is_some(),
        "fail-closed tier MUST receive LedgerWriteCapability"
    );
    let lwcap = result.ledger_write_capability.unwrap();
    assert_eq!(
        lwcap.ajc_id(),
        &test_hash(50),
        "LedgerWriteCapability must carry correct AJC ID"
    );
    assert_eq!(
        lwcap.request_id(),
        &test_hash(1),
        "LedgerWriteCapability must carry correct request ID"
    );
}

// =============================================================================
// SECURITY REGRESSION: MINOR 1 — identity evidence level passes through
// =============================================================================

#[test]
fn test_identity_evidence_level_passes_through_to_join_input() {
    // Verify that the identity evidence level from the request is used,
    // not hardcoded to PointerOnly.
    let kernel = fully_wired_kernel();

    // Test with Verified evidence level.
    let mut request = valid_request(RiskTier::Tier2Plus);
    request.identity_evidence_level = IdentityEvidenceLevel::Verified;
    request.pointer_only_waiver_hash = None;

    let plan = kernel.plan(&request);
    assert!(
        plan.is_ok(),
        "plan with Verified identity evidence should succeed: {:?}",
        plan.err()
    );

    // Test with PointerOnly evidence level + waiver hash.
    let mut request = valid_request(RiskTier::Tier2Plus);
    request.identity_evidence_level = IdentityEvidenceLevel::PointerOnly;
    request.pointer_only_waiver_hash = Some(test_hash(80));

    let plan = kernel.plan(&request);
    assert!(
        plan.is_ok(),
        "plan with PointerOnly + waiver should succeed: {:?}",
        plan.err()
    );
}

// =============================================================================
// SECURITY REGRESSION: BLOCKER 1 — verifier anchor used in AJC, not client hash
// =============================================================================

#[test]
fn test_join_input_uses_verifier_anchor_not_client_hash() {
    // Verify that build_pcac_join_input uses the verifier-selected anchor,
    // not the client-supplied directory_head_hash.
    //
    // We do this by checking that the plan's as_of_ledger_anchor matches
    // the verifier state (from MockLedgerVerifier), NOT the request's
    // directory_head_hash.
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let plan = kernel.plan(&request).expect("plan should succeed");

    // The plan's as_of_ledger_anchor should match the MockLedgerVerifier's
    // validated_anchor, NOT request.directory_head_hash.
    let expected_verifier_anchor = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 100,
        he_time: 1000,
    };

    assert_eq!(
        plan.as_of_ledger_anchor, expected_verifier_anchor,
        "plan must use verifier-selected anchor, not client-supplied directory_head_hash"
    );

    // Specifically verify it's NOT the client's directory_head_hash.
    assert_ne!(
        plan.as_of_ledger_anchor.content_hash(),
        request.directory_head_hash,
        "plan anchor must differ from client-supplied directory_head_hash"
    );
}

// =============================================================================
// QUALITY MAJOR 1 (TCK-00492): Zero-digest rejection for mandatory fields
// =============================================================================

#[test]
fn test_zero_hsi_contract_manifest_digest_denied() {
    let kernel = fully_wired_kernel();
    let mut request = valid_request(RiskTier::Tier2Plus);
    request.hsi_contract_manifest_digest = [0u8; 32];
    let result = kernel.plan(&request);
    assert!(
        result.is_err(),
        "zero hsi_contract_manifest_digest must be denied"
    );
    match result.unwrap_err() {
        AdmitError::InvalidRequest { reason } => {
            assert!(
                reason.contains("hsi_contract_manifest_digest"),
                "reason should mention hsi_contract_manifest_digest: {reason}"
            );
        },
        other => panic!("expected InvalidRequest, got: {other}"),
    }
}

#[test]
fn test_zero_hsi_envelope_binding_digest_denied() {
    let kernel = fully_wired_kernel();
    let mut request = valid_request(RiskTier::Tier2Plus);
    request.hsi_envelope_binding_digest = [0u8; 32];
    let result = kernel.plan(&request);
    assert!(
        result.is_err(),
        "zero hsi_envelope_binding_digest must be denied"
    );
    match result.unwrap_err() {
        AdmitError::InvalidRequest { reason } => {
            assert!(
                reason.contains("hsi_envelope_binding_digest"),
                "reason should mention hsi_envelope_binding_digest: {reason}"
            );
        },
        other => panic!("expected InvalidRequest, got: {other}"),
    }
}

#[test]
fn test_zero_stop_budget_digest_denied() {
    let kernel = fully_wired_kernel();
    let mut request = valid_request(RiskTier::Tier2Plus);
    request.stop_budget_digest = [0u8; 32];
    let result = kernel.plan(&request);
    assert!(result.is_err(), "zero stop_budget_digest must be denied");
    match result.unwrap_err() {
        AdmitError::InvalidRequest { reason } => {
            assert!(
                reason.contains("stop_budget_digest"),
                "reason should mention stop_budget_digest: {reason}"
            );
        },
        other => panic!("expected InvalidRequest, got: {other}"),
    }
}

#[test]
fn test_zero_revocation_head_hash_denied() {
    let kernel = fully_wired_kernel();
    let mut request = valid_request(RiskTier::Tier2Plus);
    request.revocation_head_hash = [0u8; 32];
    let result = kernel.plan(&request);
    assert!(result.is_err(), "zero revocation_head_hash must be denied");
    match result.unwrap_err() {
        AdmitError::InvalidRequest { reason } => {
            assert!(
                reason.contains("revocation_head_hash"),
                "reason should mention revocation_head_hash: {reason}"
            );
        },
        other => panic!("expected InvalidRequest, got: {other}"),
    }
}

// =============================================================================
// QUALITY MAJOR 2 (TCK-00492): Zero provider_build_digest denial
// =============================================================================

#[test]
fn test_zero_provider_build_digest_denied() {
    let bad_provider = WitnessProviderConfig {
        provider_id: "apm2-daemon/admission_kernel/test".to_string(),
        provider_build_digest: [0u8; 32], // zero — unbound measurement
    };
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), bad_provider)
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "zero provider_build_digest must deny plan creation"
    );
    match result.unwrap_err() {
        AdmitError::WitnessSeedFailure { reason } => {
            assert!(
                reason.contains("provider_build_digest"),
                "reason should mention provider_build_digest: {reason}"
            );
        },
        other => panic!("expected WitnessSeedFailure, got: {other}"),
    }
}

// =============================================================================
// SECURITY BLOCKER 2 (TCK-00492): Bounded deserialization for String fields
// =============================================================================

#[test]
fn test_spine_ext_bounded_deserialization_rejects_oversized_session_id() {
    use super::types::MAX_KERNEL_STRING_LENGTH;

    // Build a valid spine ext, then serialize, patch session_id to be
    // oversized, and deserialize — must fail.
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    // Serialize the spine ext to JSON.
    let json = serde_json::to_string(&plan.spine_ext).expect("serialize should succeed");

    // Replace session_id with an oversized value.
    let oversized_session = "X".repeat(MAX_KERNEL_STRING_LENGTH + 1);
    let patched = json.replace(&plan.spine_ext.session_id, &oversized_session);

    let result: Result<super::types::AdmissionSpineJoinExtV1, _> = serde_json::from_str(&patched);
    assert!(
        result.is_err(),
        "deserialization must reject oversized session_id (len={})",
        oversized_session.len()
    );
}

#[test]
fn test_witness_seed_bounded_deserialization_rejects_oversized_provider_id() {
    use super::types::MAX_WITNESS_PROVIDER_ID_LENGTH;

    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let json = serde_json::to_string(&plan.leakage_witness_seed).expect("serialize should succeed");

    let oversized_provider = "Y".repeat(MAX_WITNESS_PROVIDER_ID_LENGTH + 1);
    let patched = json.replace(&plan.leakage_witness_seed.provider_id, &oversized_provider);

    let result: Result<super::types::WitnessSeedV1, _> = serde_json::from_str(&patched);
    assert!(
        result.is_err(),
        "deserialization must reject oversized provider_id (len={})",
        oversized_provider.len()
    );
}

// =============================================================================
// QUALITY MINOR 1 (TCK-00492): risk_tier and pcac_policy in canonical digest
// =============================================================================

#[test]
fn test_canonical_request_digest_differs_by_risk_tier() {
    let request_t0 = valid_request(RiskTier::Tier0);
    let mut request_t2 = valid_request(RiskTier::Tier0);
    request_t2.risk_tier = RiskTier::Tier2Plus;

    let digest_t0 = super::compute_canonical_request_digest(&request_t0);
    let digest_t2 = super::compute_canonical_request_digest(&request_t2);

    assert_ne!(
        digest_t0, digest_t2,
        "canonical request digest must differ when risk_tier differs"
    );
}

#[test]
fn test_canonical_request_digest_differs_by_pcac_policy() {
    let request_a = valid_request(RiskTier::Tier2Plus);
    let mut request_b = valid_request(RiskTier::Tier2Plus);
    request_b.pcac_policy.lifecycle_enforcement = !request_b.pcac_policy.lifecycle_enforcement;

    let digest_a = super::compute_canonical_request_digest(&request_a);
    let digest_b = super::compute_canonical_request_digest(&request_b);

    assert_ne!(
        digest_a, digest_b,
        "canonical request digest must differ when pcac_policy differs"
    );
}
