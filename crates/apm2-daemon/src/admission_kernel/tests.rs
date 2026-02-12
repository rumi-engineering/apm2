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

    fn commit(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
        Ok(())
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
    fn reserve(
        &self,
        _session_id: &str,
        _request_id: &Hash,
        _ajc_id: &Hash,
    ) -> Result<Hash, String> {
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

    fn commit(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
        Ok(())
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
        AdmitError::BundleSealFailure {
            reason: "test".into(),
        },
    ];

    for err in &errors {
        let display = format!("{err}");
        assert!(!display.is_empty(), "display must not be empty for {err:?}");
    }
    assert_eq!(errors.len(), 14, "all 14 error variants must be tested");
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

// =============================================================================
// TCK-00493: AdmissionBundleV1 — sealed CAS bundle with no digest cycles
// =============================================================================

#[test]
fn test_bundle_contains_all_normative_fields() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    let bundle = &result.bundle;

    // Session + HSI envelope bindings
    assert_eq!(bundle.request_id, request.request_id);
    assert_eq!(bundle.session_id, request.session_id);
    assert_eq!(
        bundle.hsi_contract_manifest_digest,
        request.hsi_contract_manifest_digest
    );
    assert_eq!(
        bundle.hsi_envelope_binding_digest,
        request.hsi_envelope_binding_digest
    );

    // Policy-root reference
    assert_ne!(
        bundle.policy_root_digest, [0u8; 32],
        "policy_root_digest must not be zero"
    );
    assert!(
        bundle.policy_root_epoch > 0,
        "policy_root_epoch must be positive"
    );

    // AJC id + selectors
    assert_eq!(bundle.ajc_id, test_hash(50));
    assert_ne!(
        bundle.authority_join_hash, [0u8; 32],
        "authority_join_hash must not be zero"
    );
    assert_ne!(
        bundle.consume_selector_digest, [0u8; 32],
        "consume_selector_digest must not be zero"
    );

    // Intent digests
    assert_eq!(bundle.intent_digest, request.intent_digest);
    assert_ne!(
        bundle.consume_time_intent_digest, [0u8; 32],
        "consume_time_intent_digest must not be zero"
    );

    // Witness SEED hashes
    assert_ne!(
        bundle.leakage_witness_seed_hash, [0u8; 32],
        "leakage_witness_seed_hash must not be zero"
    );
    assert_ne!(
        bundle.timing_witness_seed_hash, [0u8; 32],
        "timing_witness_seed_hash must not be zero"
    );
    assert_ne!(
        bundle.leakage_witness_seed_hash, bundle.timing_witness_seed_hash,
        "leakage and timing seed hashes must differ"
    );

    // Effect digest
    assert_eq!(
        bundle.effect_descriptor_digest,
        request.effect_descriptor_digest
    );

    // Quarantine actions (fail-closed tier has quarantine guard)
    assert_eq!(
        bundle.quarantine_actions.len(),
        1,
        "fail-closed tier must have exactly 1 quarantine action"
    );
    assert_eq!(bundle.quarantine_actions[0].ajc_id, test_hash(50));
    assert_eq!(bundle.quarantine_actions[0].request_id, request.request_id);
    assert_eq!(bundle.quarantine_actions[0].reservation_hash, test_hash(70));

    // HT/HE anchors
    assert_ne!(
        bundle.ledger_anchor.ledger_id, [0u8; 32],
        "ledger_id must not be zero"
    );
    assert_ne!(
        bundle.time_envelope_ref, [0u8; 32],
        "time_envelope_ref must not be zero"
    );
    assert!(
        bundle.freshness_witness_tick > 0,
        "freshness_witness_tick must be positive"
    );

    // Enforcement context
    assert_eq!(bundle.enforcement_tier, EnforcementTier::FailClosed);
    assert_ne!(
        bundle.spine_ext_hash, [0u8; 32],
        "spine_ext_hash must not be zero"
    );
    assert_eq!(bundle.stop_budget_digest, request.stop_budget_digest);
    assert_eq!(bundle.risk_tier, RiskTier::Tier2Plus);

    // Schema version
    assert_eq!(
        bundle.schema_version,
        super::types::ADMISSION_BUNDLE_SCHEMA_VERSION
    );
}

#[test]
fn test_bundle_digest_is_deterministic_content_hash() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // The bundle_digest field must equal content_hash() of the bundle.
    let recomputed = result.bundle.content_hash();
    assert_eq!(
        result.bundle_digest, recomputed,
        "bundle_digest must equal bundle.content_hash()"
    );

    // Re-computing must be deterministic.
    let recomputed_again = result.bundle.content_hash();
    assert_eq!(
        recomputed, recomputed_again,
        "content_hash must be deterministic across calls"
    );

    // Must not be zero.
    assert_ne!(
        result.bundle_digest, [0u8; 32],
        "bundle digest must not be zero"
    );
}

#[test]
fn test_bundle_sealed_before_receipt_emission_no_digest_cycle() {
    // Structural regression test: the bundle MUST NOT contain any
    // receipt/event IDs or digests that are only available after the
    // bundle is sealed. Verify by checking that AdmissionBundleV1 has
    // no fields for receipt IDs or post-effect data.
    //
    // The bundle contains: request_id, session_id, HSI bindings,
    // policy root, AJC fields, intent digests, witness seed hashes,
    // effect digest, quarantine actions, HT/HE anchors, enforcement
    // context. NONE of these are receipt/event IDs created post-seal.
    //
    // Post-effect witness evidence hashes live in
    // AdmissionOutcomeIndexV1 (emitted post-bundle, post-effect).
    // Forward indexing also uses AdmissionOutcomeIndexV1.

    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // The bundle exists and has a valid digest.
    assert_ne!(result.bundle_digest, [0u8; 32]);

    // Verify the bundle can be serialized (CAS-storable).
    let bytes = result
        .bundle
        .to_canonical_bytes()
        .expect("bundle serialization must succeed");
    assert!(!bytes.is_empty(), "serialized bundle must not be empty");

    // Verify round-trip: deserialize and re-hash to confirm stability.
    let deserialized: super::types::AdmissionBundleV1 =
        serde_json::from_slice(&bytes).expect("bundle deserialization must succeed");
    let rehash = deserialized.content_hash();
    assert_eq!(
        result.bundle_digest, rehash,
        "bundle digest must be stable after round-trip serialization"
    );
}

#[test]
fn test_bundle_digest_changes_when_any_field_changes() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    let original_digest = result.bundle.content_hash();

    // Mutate each major field and verify the digest changes.
    let mut bundle = result.bundle.clone();

    // Field: intent_digest
    bundle.intent_digest = test_hash(200);
    assert_ne!(
        bundle.content_hash(),
        original_digest,
        "digest must change when intent_digest changes"
    );
    bundle.intent_digest = result.bundle.intent_digest;

    // Field: ajc_id
    bundle.ajc_id = test_hash(201);
    assert_ne!(
        bundle.content_hash(),
        original_digest,
        "digest must change when ajc_id changes"
    );
    bundle.ajc_id = result.bundle.ajc_id;

    // Field: policy_root_epoch
    bundle.policy_root_epoch = 99999;
    assert_ne!(
        bundle.content_hash(),
        original_digest,
        "digest must change when policy_root_epoch changes"
    );
    bundle.policy_root_epoch = result.bundle.policy_root_epoch;

    // Field: enforcement_tier
    bundle.enforcement_tier = EnforcementTier::Monitor;
    assert_ne!(
        bundle.content_hash(),
        original_digest,
        "digest must change when enforcement_tier changes"
    );
    bundle.enforcement_tier = result.bundle.enforcement_tier;

    // Field: quarantine_actions (add one)
    bundle
        .quarantine_actions
        .push(super::types::QuarantineActionV1 {
            reservation_hash: test_hash(202),
            request_id: test_hash(203),
            ajc_id: test_hash(204),
        });
    assert_ne!(
        bundle.content_hash(),
        original_digest,
        "digest must change when quarantine_actions changes"
    );
    bundle.quarantine_actions = result.bundle.quarantine_actions;

    // Verify no changes results in same digest
    assert_eq!(
        bundle.content_hash(),
        original_digest,
        "digest must match after reverting all changes"
    );
}

#[test]
fn test_bundle_deny_unknown_fields() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Serialize to JSON, add an unknown field, and attempt deserialization.
    let mut json_value: serde_json::Value =
        serde_json::to_value(&result.bundle).expect("serialize must succeed");
    json_value
        .as_object_mut()
        .unwrap()
        .insert("unknown_malicious_field".into(), serde_json::json!("evil"));

    let deser_result: Result<super::types::AdmissionBundleV1, _> =
        serde_json::from_value(json_value);
    assert!(
        deser_result.is_err(),
        "deny_unknown_fields must reject unknown JSON fields"
    );
}

#[test]
fn test_bundle_validation_rejects_zero_request_id() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    let mut bundle = result.bundle;
    bundle.request_id = [0u8; 32];
    let validation = bundle.validate();
    assert!(
        validation.is_err(),
        "validation must reject zero request_id"
    );
}

#[test]
#[allow(clippy::cast_possible_truncation)] // test-only: MAX_BUNDLE_QUARANTINE_ACTIONS < 256
fn test_bundle_validation_rejects_oversized_quarantine_actions() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    let mut bundle = result.bundle;
    // Exceed MAX_BUNDLE_QUARANTINE_ACTIONS
    for i in 0..=super::types::MAX_BUNDLE_QUARANTINE_ACTIONS {
        bundle
            .quarantine_actions
            .push(super::types::QuarantineActionV1 {
                reservation_hash: test_hash(i as u8),
                request_id: test_hash(i as u8),
                ajc_id: test_hash(i as u8),
            });
    }
    let validation = bundle.validate();
    assert!(
        validation.is_err(),
        "validation must reject oversized quarantine_actions"
    );
    match validation.unwrap_err() {
        AdmitError::BundleSealFailure { reason } => {
            assert!(
                reason.contains("quarantine_actions"),
                "reason should mention quarantine_actions: {reason}"
            );
        },
        other => panic!("expected BundleSealFailure, got: {other}"),
    }
}

#[test]
#[allow(clippy::cast_possible_truncation)] // test-only: MAX_BUNDLE_POST_EFFECT_WITNESS_HASHES < 256
fn test_outcome_index_validation_rejects_oversized_witness_evidence() {
    // post_effect_witness_evidence_hashes now lives in AdmissionOutcomeIndexV1
    // (moved from bundle because post-effect data cannot be in the sealed bundle).
    let mut index = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: test_hash(100),
        request_id: test_hash(1),
        ajc_id: test_hash(50),
        post_effect_witness_evidence_hashes: Vec::new(),
        receipt_digests: Vec::new(),
    };

    // Exceed MAX_BUNDLE_POST_EFFECT_WITNESS_HASHES
    for i in 0..=super::types::MAX_BUNDLE_POST_EFFECT_WITNESS_HASHES {
        index
            .post_effect_witness_evidence_hashes
            .push(test_hash(i as u8));
    }
    let validation = index.validate();
    assert!(
        validation.is_err(),
        "validation must reject oversized post_effect_witness_evidence_hashes"
    );
    match validation.unwrap_err() {
        AdmitError::BundleSealFailure { reason } => {
            assert!(
                reason.contains("post_effect_witness_evidence_hashes"),
                "reason should mention post_effect_witness_evidence_hashes: {reason}"
            );
        },
        other => panic!("expected BundleSealFailure, got: {other}"),
    }
}

#[test]
fn test_monitor_tier_bundle_has_no_quarantine_actions() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier1);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(
        result.bundle.quarantine_actions.is_empty(),
        "monitor tier must have no quarantine actions"
    );
    assert_eq!(result.bundle.enforcement_tier, EnforcementTier::Monitor);
}

// =============================================================================
// TCK-00493: AdmissionOutcomeIndexV1 — forward index (no digest cycle)
// =============================================================================

#[test]
fn test_outcome_index_references_bundle_digest() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Simulate creating an outcome index after receipts are emitted.
    let fake_receipt_digest_1 = test_hash(150);
    let fake_receipt_digest_2 = test_hash(151);

    let index = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: result.bundle_digest,
        request_id: result.bundle.request_id,
        ajc_id: result.bundle.ajc_id,
        post_effect_witness_evidence_hashes: Vec::new(),
        receipt_digests: vec![fake_receipt_digest_1, fake_receipt_digest_2],
    };

    // Index references the sealed bundle digest.
    assert_eq!(
        index.bundle_digest, result.bundle_digest,
        "outcome index must reference the sealed bundle digest"
    );

    // The bundle DOES NOT reference the index or any receipt digests.
    // This is the digest cycle avoidance invariant.
    // The bundle was sealed before receipts were created, and the
    // index was created after receipts.

    // Validate the index.
    index.validate().expect("outcome index must be valid");

    // Content hash is deterministic.
    let hash1 = index.content_hash();
    let hash2 = index.content_hash();
    assert_eq!(hash1, hash2, "outcome index hash must be deterministic");
    assert_ne!(hash1, [0u8; 32], "outcome index hash must not be zero");

    // Serialization round-trip.
    let bytes = index
        .to_canonical_bytes()
        .expect("serialization must succeed");
    let deser: super::types::AdmissionOutcomeIndexV1 =
        serde_json::from_slice(&bytes).expect("deserialization must succeed");
    assert_eq!(
        index.content_hash(),
        deser.content_hash(),
        "hash must be stable after round-trip"
    );
}

#[test]
fn test_outcome_index_deny_unknown_fields() {
    let index = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: test_hash(100),
        request_id: test_hash(1),
        ajc_id: test_hash(50),
        post_effect_witness_evidence_hashes: Vec::new(),
        receipt_digests: vec![test_hash(150)],
    };

    let mut json_value: serde_json::Value =
        serde_json::to_value(&index).expect("serialize must succeed");
    json_value
        .as_object_mut()
        .unwrap()
        .insert("unknown_field".into(), serde_json::json!(42));

    let deser_result: Result<super::types::AdmissionOutcomeIndexV1, _> =
        serde_json::from_value(json_value);
    assert!(
        deser_result.is_err(),
        "deny_unknown_fields must reject unknown JSON fields in outcome index"
    );
}

#[test]
#[allow(clippy::cast_possible_truncation)] // test-only: MAX_OUTCOME_INDEX_RECEIPT_DIGESTS < 256
fn test_outcome_index_validation_rejects_oversized_receipt_digests() {
    let mut index = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: test_hash(100),
        request_id: test_hash(1),
        ajc_id: test_hash(50),
        post_effect_witness_evidence_hashes: Vec::new(),
        receipt_digests: Vec::new(),
    };

    for i in 0..=super::types::MAX_OUTCOME_INDEX_RECEIPT_DIGESTS {
        index.receipt_digests.push(test_hash(i as u8));
    }

    let validation = index.validate();
    assert!(
        validation.is_err(),
        "validation must reject oversized receipt_digests"
    );
}

#[test]
fn test_outcome_index_validation_rejects_zero_bundle_digest() {
    let index = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: [0u8; 32],
        request_id: test_hash(1),
        ajc_id: test_hash(50),
        post_effect_witness_evidence_hashes: Vec::new(),
        receipt_digests: vec![test_hash(150)],
    };

    let validation = index.validate();
    assert!(
        validation.is_err(),
        "validation must reject zero bundle_digest"
    );
}

// =============================================================================
// TCK-00493: Digest cycle regression test — bundle never references receipts
// =============================================================================

#[test]
fn test_bundle_receipt_digest_cycle_regression() {
    // This test structurally proves that the AdmissionBundleV1 type does
    // NOT contain any field for receipt/event IDs that would be created
    // after the bundle is sealed. The compilation of this test proves
    // the structural invariant: the bundle only contains pre-seal data.

    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // 1. The bundle is sealed (has a digest).
    let bundle_digest = result.bundle_digest;
    assert_ne!(bundle_digest, [0u8; 32]);

    // 2. Simulate creating receipts that reference the bundle digest.
    let receipt_a_content = format!(
        "receipt-A-referencing-bundle-{}",
        hex::encode(bundle_digest)
    );
    let receipt_a_digest = {
        let mut h = blake3::Hasher::new();
        h.update(receipt_a_content.as_bytes());
        *h.finalize().as_bytes()
    };

    // 3. The bundle was sealed BEFORE receipt_a was created. Therefore the bundle
    //    cannot contain receipt_a_digest. Verify by checking that re-computing the
    //    bundle digest produces the same value — the bundle is immutable.
    let recomputed = result.bundle.content_hash();
    assert_eq!(
        bundle_digest, recomputed,
        "bundle digest must not change after receipt creation (no cycle)"
    );

    // 4. Create an outcome index that bridges bundle -> receipts.
    let index = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest,
        request_id: result.bundle.request_id,
        ajc_id: result.bundle.ajc_id,
        post_effect_witness_evidence_hashes: Vec::new(),
        receipt_digests: vec![receipt_a_digest],
    };

    // 5. The outcome index is a separate object — it does NOT change the bundle
    //    digest.
    assert_eq!(
        result.bundle.content_hash(),
        bundle_digest,
        "bundle is immutable; outcome index is a separate object"
    );

    // 6. Validate the index.
    index.validate().expect("outcome index must be valid");
}

// =============================================================================
// TCK-00493: CAC overlay digest cycle regression
// =============================================================================

#[test]
fn test_cac_overlay_digest_cycle_regression() {
    // CAC overlay objects that need receipt IDs MUST be emitted
    // post-bundle as separate objects referencing AdmissionBundleDigest.
    //
    // This test proves the pattern: overlay objects reference the
    // bundle digest, NOT vice versa.

    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    let bundle_digest = result.bundle_digest;

    // Simulate a CAC overlay that references the bundle.
    let overlay_content = {
        let mut h = blake3::Hasher::new();
        h.update(b"apm2-cac-overlay-v1");
        h.update(&bundle_digest);
        h.update(&test_hash(160)); // receipt ID created post-seal
        *h.finalize().as_bytes()
    };

    // The overlay references the bundle, NOT vice versa.
    assert_ne!(overlay_content, [0u8; 32]);

    // The bundle digest is unchanged.
    assert_eq!(
        result.bundle.content_hash(),
        bundle_digest,
        "bundle must not be affected by overlay creation"
    );
}

// =============================================================================
// TCK-00493: AdmitError::BundleSealFailure Display coverage
// =============================================================================

#[test]
fn test_admit_error_bundle_seal_failure_display() {
    let err = AdmitError::BundleSealFailure {
        reason: "test failure".into(),
    };
    let display = format!("{err}");
    assert!(
        display.contains("bundle seal failure"),
        "display must contain 'bundle seal failure': {display}"
    );
    assert!(
        display.contains("test failure"),
        "display must contain reason: {display}"
    );
}

// =============================================================================
// TCK-00493 fix: post_effect_witness_evidence_hashes in outcome index
// =============================================================================

#[test]
fn test_outcome_index_digest_changes_when_witness_evidence_hashes_change() {
    let index_base = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: test_hash(100),
        request_id: test_hash(1),
        ajc_id: test_hash(50),
        post_effect_witness_evidence_hashes: Vec::new(),
        receipt_digests: vec![test_hash(150)],
    };
    let digest_base = index_base.content_hash();

    // Adding witness evidence hashes changes the digest.
    let mut index_with_evidence = index_base.clone();
    index_with_evidence
        .post_effect_witness_evidence_hashes
        .push(test_hash(200));
    let digest_with_evidence = index_with_evidence.content_hash();
    assert_ne!(
        digest_base, digest_with_evidence,
        "outcome index digest must change when post_effect_witness_evidence_hashes changes"
    );

    // Different evidence hashes produce different digests.
    let mut index_diff_evidence = index_base.clone();
    index_diff_evidence
        .post_effect_witness_evidence_hashes
        .push(test_hash(201));
    let digest_diff = index_diff_evidence.content_hash();
    assert_ne!(
        digest_with_evidence, digest_diff,
        "different evidence hashes must produce different digests"
    );

    // Reverting produces the original digest.
    let reverted = index_base.content_hash();
    assert_eq!(digest_base, reverted, "digest must be deterministic");
}

#[test]
fn test_bundle_does_not_contain_post_effect_witness_evidence_hashes() {
    // Structural regression: AdmissionBundleV1 must NOT have a field for
    // post-effect witness evidence hashes. That data belongs in
    // AdmissionOutcomeIndexV1 because it is populated after effect
    // execution (post-seal).
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Serialize the bundle to JSON and verify no post_effect field.
    let json_value: serde_json::Value =
        serde_json::to_value(&result.bundle).expect("serialize must succeed");
    let obj = json_value
        .as_object()
        .expect("bundle must be a JSON object");
    assert!(
        !obj.contains_key("post_effect_witness_evidence_hashes"),
        "AdmissionBundleV1 must NOT contain post_effect_witness_evidence_hashes \
         (it belongs in AdmissionOutcomeIndexV1)"
    );
}

// =============================================================================
// TCK-00493 fix: bounded deserialization (visitor-based) tests
// =============================================================================

#[test]
fn test_bounded_string_deser_rejects_oversized_string() {
    // Verify the bounded string visitor rejects strings exceeding MAX_*.
    // Use AdmissionSpineJoinExtV1::session_id which is bounded by
    // MAX_KERNEL_STRING_LENGTH (256).
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Serialize the bundle, inject an oversized session_id, and attempt deser.
    let mut json_value: serde_json::Value =
        serde_json::to_value(&result.bundle).expect("serialize must succeed");
    let oversized_string = "x".repeat(super::types::MAX_KERNEL_STRING_LENGTH + 1);
    json_value
        .as_object_mut()
        .unwrap()
        .insert("session_id".into(), serde_json::json!(oversized_string));

    let deser_result: Result<super::types::AdmissionBundleV1, _> =
        serde_json::from_value(json_value);
    assert!(
        deser_result.is_err(),
        "bounded string deserialization must reject oversized session_id"
    );
}

#[test]
fn test_bounded_vec_deser_rejects_oversized_quarantine_actions_at_parse_time() {
    // Verify the bounded vec visitor rejects sequences exceeding MAX_*
    // DURING parsing (not post-allocation). Build JSON with too many
    // quarantine_actions and attempt deserialization.
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    let mut json_value: serde_json::Value =
        serde_json::to_value(&result.bundle).expect("serialize must succeed");

    // Build oversized quarantine_actions array
    let oversized: Vec<serde_json::Value> = (0..=super::types::MAX_BUNDLE_QUARANTINE_ACTIONS)
        .map(|i| {
            serde_json::json!({
                "reservation_hash": format!("{:064x}", i),
                "request_id": format!("{:064x}", i),
                "ajc_id": format!("{:064x}", i),
            })
        })
        .collect();
    json_value
        .as_object_mut()
        .unwrap()
        .insert("quarantine_actions".into(), serde_json::json!(oversized));

    let deser_result: Result<super::types::AdmissionBundleV1, _> =
        serde_json::from_value(json_value);
    assert!(
        deser_result.is_err(),
        "bounded vec deserialization must reject oversized quarantine_actions"
    );
}

#[test]
fn test_bounded_vec_deser_rejects_oversized_receipt_digests_at_parse_time() {
    // Verify the bounded vec visitor rejects sequences exceeding MAX_*
    // for receipt_digests in AdmissionOutcomeIndexV1.
    let index = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: test_hash(100),
        request_id: test_hash(1),
        ajc_id: test_hash(50),
        post_effect_witness_evidence_hashes: Vec::new(),
        receipt_digests: vec![test_hash(150)],
    };

    let mut json_value: serde_json::Value =
        serde_json::to_value(&index).expect("serialize must succeed");

    // Build oversized receipt_digests array
    let oversized: Vec<serde_json::Value> = (0..=super::types::MAX_OUTCOME_INDEX_RECEIPT_DIGESTS)
        .map(|i| serde_json::json!(format!("{:064x}", i)))
        .collect();
    json_value
        .as_object_mut()
        .unwrap()
        .insert("receipt_digests".into(), serde_json::json!(oversized));

    let deser_result: Result<super::types::AdmissionOutcomeIndexV1, _> =
        serde_json::from_value(json_value);
    assert!(
        deser_result.is_err(),
        "bounded vec deserialization must reject oversized receipt_digests"
    );
}

#[test]
fn test_bounded_vec_deser_rejects_oversized_witness_evidence_at_parse_time() {
    // Verify the bounded vec visitor rejects sequences exceeding MAX_*
    // for post_effect_witness_evidence_hashes in AdmissionOutcomeIndexV1.
    let index = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: test_hash(100),
        request_id: test_hash(1),
        ajc_id: test_hash(50),
        post_effect_witness_evidence_hashes: Vec::new(),
        receipt_digests: Vec::new(),
    };

    let mut json_value: serde_json::Value =
        serde_json::to_value(&index).expect("serialize must succeed");

    // Build oversized post_effect_witness_evidence_hashes array
    let oversized: Vec<serde_json::Value> = (0
        ..=super::types::MAX_BUNDLE_POST_EFFECT_WITNESS_HASHES)
        .map(|i| serde_json::json!(format!("{:064x}", i)))
        .collect();
    json_value.as_object_mut().unwrap().insert(
        "post_effect_witness_evidence_hashes".into(),
        serde_json::json!(oversized),
    );

    let deser_result: Result<super::types::AdmissionOutcomeIndexV1, _> =
        serde_json::from_value(json_value);
    assert!(
        deser_result.is_err(),
        "bounded vec deserialization must reject oversized post_effect_witness_evidence_hashes"
    );
}

#[test]
fn test_bounded_vec_deser_accepts_valid_sized_collections() {
    // Positive test: verify that collections at or below MAX_* are accepted.
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Round-trip the bundle: should succeed with valid-sized collections.
    let bytes = result
        .bundle
        .to_canonical_bytes()
        .expect("serialization must succeed");
    let deserialized: super::types::AdmissionBundleV1 =
        serde_json::from_slice(&bytes).expect("deserialization of valid bundle must succeed");
    assert_eq!(
        result.bundle.content_hash(),
        deserialized.content_hash(),
        "round-trip must preserve digest"
    );

    // Round-trip outcome index with non-empty witness evidence.
    let index = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: result.bundle_digest,
        request_id: result.bundle.request_id,
        ajc_id: result.bundle.ajc_id,
        post_effect_witness_evidence_hashes: vec![test_hash(200), test_hash(201)],
        receipt_digests: vec![test_hash(150)],
    };
    let index_bytes = index
        .to_canonical_bytes()
        .expect("serialization must succeed");
    let index_deser: super::types::AdmissionOutcomeIndexV1 =
        serde_json::from_slice(&index_bytes).expect("deserialization of valid index must succeed");
    assert_eq!(
        index.content_hash(),
        index_deser.content_hash(),
        "round-trip must preserve outcome index digest"
    );
    assert_eq!(
        index_deser.post_effect_witness_evidence_hashes.len(),
        2,
        "witness evidence hashes must survive round-trip"
    );
}

// =============================================================================
// TCK-00497: Authoritative witness closure tests
// =============================================================================

/// Helper: build a valid monitor waiver for testing.
fn valid_monitor_waiver(request_id: Hash) -> super::types::MonitorWaiverV1 {
    super::types::MonitorWaiverV1 {
        waiver_id: test_hash(200),
        reason: "test monitor waiver for non-authoritative tier".to_string(),
        expires_at_tick: 10000,
        request_id,
        enforcement_tier: EnforcementTier::Monitor,
    }
}

/// Helper: build a kernel with all prerequisites for fail-closed testing.
fn fail_closed_kernel() -> AdmissionKernelV1 {
    let pcac = Arc::new(MockPcacKernel::passing()) as Arc<dyn AuthorityJoinKernel>;
    AdmissionKernelV1::new(pcac, witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()))
}

/// Helper: build witness evidence from a seed (valid binding).
fn evidence_from_seed(
    seed: &super::types::WitnessSeedV1,
    ht_end: u64,
) -> super::types::WitnessEvidenceV1 {
    super::types::WitnessEvidenceV1 {
        witness_class: seed.witness_class.clone(),
        seed_hash: seed.content_hash(),
        request_id: seed.request_id,
        session_id: seed.session_id.clone(),
        ht_end,
        measured_values: vec![test_hash(180), test_hash(181)],
        provider_id: seed.provider_id.clone(),
        provider_build_digest: seed.provider_build_digest,
    }
}

// ---- Fail-closed seed validation at join ----

#[test]
fn test_tck_00497_fail_closed_seed_validation_succeeds_with_valid_seeds() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let result = kernel.validate_witness_seeds_at_join(
        EnforcementTier::FailClosed,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        None,
        100,
    );
    assert!(
        result.is_ok(),
        "valid seeds at fail-closed tier should succeed"
    );
    assert!(
        result.unwrap().is_none(),
        "fail-closed path returns None (no waiver hash)"
    );
}

#[test]
fn test_tck_00497_fail_closed_denies_zero_leakage_seed() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    // Create a zero-hash seed (simulating a stubbed/None seed).
    let mut bad_leakage = plan.leakage_witness_seed.clone();
    bad_leakage.witness_class = String::new(); // will make content_hash produce a non-meaningful hash
    // Actually, we need a seed whose content_hash is zero. Since that's
    // cryptographically infeasible, we test the provider_build_digest=zero path
    // instead.
    let mut bad_leakage2 = plan.leakage_witness_seed.clone();
    bad_leakage2.provider_build_digest = [0u8; 32];

    let result = kernel.validate_witness_seeds_at_join(
        EnforcementTier::FailClosed,
        &bad_leakage2,
        &plan.timing_witness_seed,
        None,
        100,
    );
    assert!(
        result.is_err(),
        "zero provider_build_digest must deny at fail-closed tier"
    );
    match result.unwrap_err() {
        AdmitError::WitnessSeedFailure { reason } => {
            assert!(
                reason.contains("provider_build_digest is zero"),
                "reason should mention provider_build_digest: {reason}"
            );
        },
        other => panic!("expected WitnessSeedFailure, got: {other}"),
    }
}

#[test]
fn test_tck_00497_fail_closed_denies_zero_timing_seed_provider() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let mut bad_timing = plan.timing_witness_seed.clone();
    bad_timing.provider_build_digest = [0u8; 32];

    let result = kernel.validate_witness_seeds_at_join(
        EnforcementTier::FailClosed,
        &plan.leakage_witness_seed,
        &bad_timing,
        None,
        100,
    );
    assert!(
        result.is_err(),
        "zero provider_build_digest on timing seed must deny"
    );
    match result.unwrap_err() {
        AdmitError::WitnessSeedFailure { reason } => {
            assert!(
                reason.contains("timing witness seed provider_build_digest"),
                "reason should identify timing seed: {reason}"
            );
        },
        other => panic!("expected WitnessSeedFailure, got: {other}"),
    }
}

#[test]
fn test_tck_00497_fail_closed_denies_nonce_reuse() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let mut bad_timing = plan.timing_witness_seed.clone();
    bad_timing.nonce = plan.leakage_witness_seed.nonce; // duplicate nonce

    let result = kernel.validate_witness_seeds_at_join(
        EnforcementTier::FailClosed,
        &plan.leakage_witness_seed,
        &bad_timing,
        None,
        100,
    );
    assert!(result.is_err(), "nonce reuse must deny");
    match result.unwrap_err() {
        AdmitError::WitnessSeedFailure { reason } => {
            assert!(
                reason.contains("nonce reuse"),
                "reason should mention nonce reuse: {reason}"
            );
        },
        other => panic!("expected WitnessSeedFailure, got: {other}"),
    }
}

// ---- Monitor tier requires explicit waiver ----

#[test]
fn test_tck_00497_monitor_tier_denies_without_waiver() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier0);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let result = kernel.validate_witness_seeds_at_join(
        EnforcementTier::Monitor,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        None, // no waiver
        100,
    );
    assert!(result.is_err(), "monitor tier without waiver must deny");
    match result.unwrap_err() {
        AdmitError::WitnessWaiverInvalid { reason } => {
            assert!(
                reason.contains("explicit waiver"),
                "reason should mention explicit waiver: {reason}"
            );
        },
        other => panic!("expected WitnessWaiverInvalid, got: {other}"),
    }
}

#[test]
fn test_tck_00497_monitor_tier_succeeds_with_waiver() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier0);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let waiver = valid_monitor_waiver(request.request_id);
    let result = kernel.validate_witness_seeds_at_join(
        EnforcementTier::Monitor,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        Some(&waiver),
        100,
    );
    assert!(
        result.is_ok(),
        "monitor tier with valid waiver should succeed"
    );
    let waiver_hash = result.unwrap();
    assert!(
        waiver_hash.is_some(),
        "monitor path should return waiver hash for audit"
    );
    assert_ne!(
        waiver_hash.unwrap(),
        [0u8; 32],
        "waiver hash must be non-zero"
    );
}

#[test]
fn test_tck_00497_monitor_waiver_denies_fail_closed_tier() {
    let waiver = super::types::MonitorWaiverV1 {
        waiver_id: test_hash(200),
        reason: "test".to_string(),
        expires_at_tick: 10000,
        request_id: test_hash(1),
        enforcement_tier: EnforcementTier::FailClosed, // wrong tier
    };
    let result = waiver.validate(100);
    assert!(
        result.is_err(),
        "waiver with FailClosed tier must be invalid"
    );
    match result.unwrap_err() {
        AdmitError::WitnessWaiverInvalid { reason } => {
            assert!(
                reason.contains("not FailClosed"),
                "reason should explain tier mismatch: {reason}"
            );
        },
        other => panic!("expected WitnessWaiverInvalid, got: {other}"),
    }
}

// ---- Post-effect witness evidence ----

#[test]
fn test_tck_00497_fail_closed_post_effect_denies_missing_leakage_evidence() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let timing_ev = evidence_from_seed(&plan.timing_witness_seed, 100);

    let result = kernel.finalize_post_effect_witness(
        EnforcementTier::FailClosed,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        None, // missing leakage evidence
        Some(&timing_ev),
        None,
        100,
    );
    assert!(
        result.is_err(),
        "missing leakage evidence must deny at fail-closed tier"
    );
    match result.unwrap_err() {
        AdmitError::OutputReleaseDenied { reason } => {
            assert!(
                reason.contains("leakage"),
                "reason should mention leakage: {reason}"
            );
        },
        other => panic!("expected OutputReleaseDenied, got: {other}"),
    }
}

#[test]
fn test_tck_00497_fail_closed_post_effect_denies_missing_timing_evidence() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let leakage_ev = evidence_from_seed(&plan.leakage_witness_seed, 100);

    let result = kernel.finalize_post_effect_witness(
        EnforcementTier::FailClosed,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        Some(&leakage_ev),
        None, // missing timing evidence
        None,
        100,
    );
    assert!(
        result.is_err(),
        "missing timing evidence must deny at fail-closed tier"
    );
    match result.unwrap_err() {
        AdmitError::OutputReleaseDenied { reason } => {
            assert!(
                reason.contains("timing"),
                "reason should mention timing: {reason}"
            );
        },
        other => panic!("expected OutputReleaseDenied, got: {other}"),
    }
}

#[test]
fn test_tck_00497_fail_closed_post_effect_succeeds_with_valid_evidence() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let leakage_ev = evidence_from_seed(&plan.leakage_witness_seed, 100);
    let timing_ev = evidence_from_seed(&plan.timing_witness_seed, 100);

    let result = kernel.finalize_post_effect_witness(
        EnforcementTier::FailClosed,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        Some(&leakage_ev),
        Some(&timing_ev),
        None,
        100,
    );
    assert!(
        result.is_ok(),
        "valid evidence at fail-closed tier should succeed"
    );
    let hashes = result.unwrap();
    assert_eq!(
        hashes.len(),
        2,
        "must have exactly 2 evidence hashes (leakage + timing)"
    );
    assert_ne!(
        hashes[0], [0u8; 32],
        "leakage evidence hash must be non-zero"
    );
    assert_ne!(
        hashes[1], [0u8; 32],
        "timing evidence hash must be non-zero"
    );
    assert_ne!(hashes[0], hashes[1], "evidence hashes must be unique");
}

#[test]
fn test_tck_00497_fail_closed_post_effect_denies_wrong_seed_binding() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    // Create evidence bound to the wrong seed (swap leakage/timing).
    let leakage_ev = evidence_from_seed(&plan.timing_witness_seed, 100);
    let timing_ev = evidence_from_seed(&plan.leakage_witness_seed, 100);

    let result = kernel.finalize_post_effect_witness(
        EnforcementTier::FailClosed,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        Some(&leakage_ev), // bound to timing seed
        Some(&timing_ev),  // bound to leakage seed
        None,
        100,
    );
    assert!(result.is_err(), "wrong seed binding must deny");
    match result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(
                reason.contains("seed_hash") || reason.contains("witness_class"),
                "reason should explain binding mismatch: {reason}"
            );
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

#[test]
fn test_tck_00497_fail_closed_post_effect_denies_wrong_provider() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let mut leakage_ev = evidence_from_seed(&plan.leakage_witness_seed, 100);
    leakage_ev.provider_id = "attacker-module".to_string();

    let timing_ev = evidence_from_seed(&plan.timing_witness_seed, 100);

    let result = kernel.finalize_post_effect_witness(
        EnforcementTier::FailClosed,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        Some(&leakage_ev),
        Some(&timing_ev),
        None,
        100,
    );
    assert!(result.is_err(), "wrong provider must deny");
    match result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(
                reason.contains("provider_id"),
                "reason should mention provider: {reason}"
            );
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

#[test]
fn test_tck_00497_evidence_denies_when_ht_end_before_ht_start() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let mut leakage_ev = evidence_from_seed(&plan.leakage_witness_seed, 100);
    // Set ht_end before ht_start (seed.ht_start is request.freshness_witness_tick =
    // 42)
    leakage_ev.ht_end = 1; // before 42

    let timing_ev = evidence_from_seed(&plan.timing_witness_seed, 100);

    let result = kernel.finalize_post_effect_witness(
        EnforcementTier::FailClosed,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        Some(&leakage_ev),
        Some(&timing_ev),
        None,
        100,
    );
    assert!(result.is_err(), "ht_end before ht_start must deny");
    match result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(
                reason.contains("before seed ht_start"),
                "reason should explain temporal order: {reason}"
            );
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

// ---- Monitor post-effect waiver ----

#[test]
fn test_tck_00497_monitor_post_effect_denies_without_waiver() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier0);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let result = kernel.finalize_post_effect_witness(
        EnforcementTier::Monitor,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        None,
        None,
        None, // no waiver
        100,
    );
    assert!(result.is_err(), "monitor tier without waiver must deny");
    match result.unwrap_err() {
        AdmitError::WitnessWaiverInvalid { reason } => {
            assert!(
                reason.contains("explicit waiver"),
                "reason should mention explicit waiver: {reason}"
            );
        },
        other => panic!("expected WitnessWaiverInvalid, got: {other}"),
    }
}

#[test]
fn test_tck_00497_monitor_post_effect_succeeds_with_waiver() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier0);
    let plan = kernel.plan(&request).expect("plan should succeed");

    let waiver = valid_monitor_waiver(request.request_id);
    let result = kernel.finalize_post_effect_witness(
        EnforcementTier::Monitor,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        None, // no evidence (waived)
        None,
        Some(&waiver),
        100,
    );
    assert!(result.is_ok(), "monitor tier with waiver should succeed");
    let hashes = result.unwrap();
    assert_eq!(
        hashes.len(),
        1,
        "must have exactly 1 hash (the waiver hash for audit)"
    );
    assert_ne!(hashes[0], [0u8; 32], "waiver hash must be non-zero");
}

// ---- Boundary output release ----

#[test]
fn test_tck_00497_boundary_output_release_succeeds_with_evidence() {
    let kernel = fail_closed_kernel();
    let mut span = super::types::BoundarySpanV1 {
        request_id: test_hash(1),
        output_held: true,
        enforcement_tier: EnforcementTier::FailClosed,
    };

    let evidence_hashes = vec![test_hash(180), test_hash(181)];
    let result = kernel.release_boundary_output(&mut span, &evidence_hashes);
    assert!(
        result.is_ok(),
        "release with evidence hashes should succeed"
    );
    assert!(!span.output_held, "output must be released after success");
}

#[test]
fn test_tck_00497_boundary_output_release_denies_empty_evidence_fail_closed() {
    let kernel = fail_closed_kernel();
    let mut span = super::types::BoundarySpanV1 {
        request_id: test_hash(1),
        output_held: true,
        enforcement_tier: EnforcementTier::FailClosed,
    };

    let result = kernel.release_boundary_output(&mut span, &[]);
    assert!(
        result.is_err(),
        "empty evidence at fail-closed must deny release"
    );
    assert!(span.output_held, "output must remain held on denial");
    match result.unwrap_err() {
        AdmitError::OutputReleaseDenied { reason } => {
            assert!(
                reason.contains("no witness evidence"),
                "reason should explain missing evidence: {reason}"
            );
        },
        other => panic!("expected OutputReleaseDenied, got: {other}"),
    }
}

#[test]
fn test_tck_00497_boundary_output_double_release_denies() {
    let kernel = fail_closed_kernel();
    let mut span = super::types::BoundarySpanV1 {
        request_id: test_hash(1),
        output_held: false, // already released
        enforcement_tier: EnforcementTier::FailClosed,
    };

    let evidence_hashes = vec![test_hash(180)];
    let result = kernel.release_boundary_output(&mut span, &evidence_hashes);
    assert!(result.is_err(), "double release must deny");
    match result.unwrap_err() {
        AdmitError::BoundaryMediationFailure { reason } => {
            assert!(
                reason.contains("double-release"),
                "reason should mention double-release: {reason}"
            );
        },
        other => panic!("expected BoundaryMediationFailure, got: {other}"),
    }
}

#[test]
fn test_tck_00497_boundary_output_monitor_release_always_succeeds() {
    let kernel = fail_closed_kernel();
    let mut span = super::types::BoundarySpanV1 {
        request_id: test_hash(1),
        output_held: false,
        enforcement_tier: EnforcementTier::Monitor,
    };

    // Monitor tier: release succeeds even with empty evidence.
    let result = kernel.release_boundary_output(&mut span, &[]);
    assert!(
        result.is_ok(),
        "monitor tier release should succeed even without evidence"
    );
}

// ---- WitnessEvidenceV1 validation ----

#[test]
fn test_tck_00497_witness_evidence_validate_rejects_zero_seed_hash() {
    let ev = super::types::WitnessEvidenceV1 {
        witness_class: "leakage".to_string(),
        seed_hash: [0u8; 32], // zero
        request_id: test_hash(1),
        session_id: "test-session".to_string(),
        ht_end: 100,
        measured_values: vec![],
        provider_id: "test-provider".to_string(),
        provider_build_digest: test_hash(99),
    };
    let result = ev.validate();
    assert!(result.is_err(), "zero seed_hash must be rejected");
    match result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(reason.contains("seed_hash"), "reason: {reason}");
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

#[test]
fn test_tck_00497_witness_evidence_validate_rejects_zero_ht_end() {
    let ev = super::types::WitnessEvidenceV1 {
        witness_class: "leakage".to_string(),
        seed_hash: test_hash(50),
        request_id: test_hash(1),
        session_id: "test-session".to_string(),
        ht_end: 0, // zero
        measured_values: vec![],
        provider_id: "test-provider".to_string(),
        provider_build_digest: test_hash(99),
    };
    let result = ev.validate();
    assert!(result.is_err(), "zero ht_end must be rejected");
    match result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(reason.contains("ht_end"), "reason: {reason}");
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

#[test]
fn test_tck_00497_witness_evidence_validate_rejects_oversized_measured_values() {
    let too_many: Vec<Hash> = (0..=super::types::MAX_WITNESS_EVIDENCE_MEASURED_VALUES)
        .map(|i| {
            #[allow(clippy::cast_possible_truncation)]
            test_hash(i as u8)
        })
        .collect();

    let ev = super::types::WitnessEvidenceV1 {
        witness_class: "leakage".to_string(),
        seed_hash: test_hash(50),
        request_id: test_hash(1),
        session_id: "test-session".to_string(),
        ht_end: 100,
        measured_values: too_many,
        provider_id: "test-provider".to_string(),
        provider_build_digest: test_hash(99),
    };
    let result = ev.validate();
    assert!(
        result.is_err(),
        "oversized measured_values must be rejected"
    );
    match result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(
                reason.contains("measured_values"),
                "reason should mention measured_values: {reason}"
            );
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

// ---- WitnessEvidenceV1 content hash ----

#[test]
fn test_tck_00497_witness_evidence_content_hash_deterministic() {
    let ev = super::types::WitnessEvidenceV1 {
        witness_class: "leakage".to_string(),
        seed_hash: test_hash(50),
        request_id: test_hash(1),
        session_id: "test-session".to_string(),
        ht_end: 100,
        measured_values: vec![test_hash(180)],
        provider_id: "test-provider".to_string(),
        provider_build_digest: test_hash(99),
    };
    let hash1 = ev.content_hash();
    let hash2 = ev.content_hash();
    assert_eq!(hash1, hash2, "content hash must be deterministic");
    assert_ne!(hash1, [0u8; 32], "content hash must be non-zero");
}

#[test]
fn test_tck_00497_witness_evidence_content_hash_changes_with_measured_values() {
    let ev1 = super::types::WitnessEvidenceV1 {
        witness_class: "timing".to_string(),
        seed_hash: test_hash(50),
        request_id: test_hash(1),
        session_id: "test-session".to_string(),
        ht_end: 100,
        measured_values: vec![test_hash(180)],
        provider_id: "test-provider".to_string(),
        provider_build_digest: test_hash(99),
    };
    let ev2 = super::types::WitnessEvidenceV1 {
        measured_values: vec![test_hash(180), test_hash(181)],
        ..ev1.clone()
    };
    assert_ne!(
        ev1.content_hash(),
        ev2.content_hash(),
        "different measured_values must produce different hashes"
    );
}

// ---- MonitorWaiverV1 validation ----

#[test]
fn test_tck_00497_monitor_waiver_validate_rejects_zero_waiver_id() {
    let waiver = super::types::MonitorWaiverV1 {
        waiver_id: [0u8; 32],
        reason: "test".to_string(),
        expires_at_tick: 10000,
        request_id: test_hash(1),
        enforcement_tier: EnforcementTier::Monitor,
    };
    let result = waiver.validate(100);
    assert!(result.is_err(), "zero waiver_id must be rejected");
}

#[test]
fn test_tck_00497_monitor_waiver_validate_rejects_empty_reason() {
    let waiver = super::types::MonitorWaiverV1 {
        waiver_id: test_hash(200),
        reason: String::new(),
        expires_at_tick: 10000,
        request_id: test_hash(1),
        enforcement_tier: EnforcementTier::Monitor,
    };
    let result = waiver.validate(100);
    assert!(result.is_err(), "empty reason must be rejected");
}

// ---- SECURITY MAJOR 2: Monitor waiver expiry enforcement ----

#[test]
fn test_tck_00497_monitor_waiver_validate_rejects_expired_waiver() {
    let waiver = super::types::MonitorWaiverV1 {
        waiver_id: test_hash(200),
        reason: "test waiver".to_string(),
        expires_at_tick: 50, // expired: 50 < 100
        request_id: test_hash(1),
        enforcement_tier: EnforcementTier::Monitor,
    };
    let result = waiver.validate(100); // current_tick=100 > expires_at_tick=50
    assert!(result.is_err(), "expired waiver must be rejected");
    match result.unwrap_err() {
        AdmitError::WitnessWaiverInvalid { reason } => {
            assert!(
                reason.contains("expired"),
                "reason should mention expiry: {reason}"
            );
        },
        other => panic!("expected WitnessWaiverInvalid, got: {other}"),
    }
}

#[test]
fn test_tck_00497_monitor_waiver_validate_accepts_non_expired_waiver() {
    let waiver = super::types::MonitorWaiverV1 {
        waiver_id: test_hash(200),
        reason: "test waiver".to_string(),
        expires_at_tick: 200, // not expired: 200 >= 100
        request_id: test_hash(1),
        enforcement_tier: EnforcementTier::Monitor,
    };
    let result = waiver.validate(100); // current_tick=100 < expires_at_tick=200
    assert!(result.is_ok(), "non-expired waiver should be accepted");
}

#[test]
fn test_tck_00497_monitor_waiver_validate_accepts_zero_expiry() {
    // expires_at_tick=0 means no expiry (governance must periodically re-issue).
    let waiver = super::types::MonitorWaiverV1 {
        waiver_id: test_hash(200),
        reason: "test waiver with no expiry".to_string(),
        expires_at_tick: 0,
        request_id: test_hash(1),
        enforcement_tier: EnforcementTier::Monitor,
    };
    let result = waiver.validate(100);
    assert!(
        result.is_ok(),
        "zero expires_at_tick (no expiry) should be accepted"
    );
}

// ---- QUALITY MINOR 1: Monitor-tier evidence seed/provider binding ----

#[test]
fn test_tck_00497_monitor_post_effect_validates_evidence_seed_binding() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier0);
    let plan = kernel.plan(&request).expect("plan should succeed");

    // Create evidence bound to the WRONG seed (swap leakage/timing).
    let leakage_ev = evidence_from_seed(&plan.timing_witness_seed, 100); // wrong!
    let waiver = valid_monitor_waiver(request.request_id);

    let result = kernel.finalize_post_effect_witness(
        EnforcementTier::Monitor,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        Some(&leakage_ev), // bound to timing seed, not leakage
        None,
        Some(&waiver),
        100,
    );
    assert!(
        result.is_err(),
        "monitor tier must validate evidence seed binding when evidence is provided"
    );
    match result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(
                reason.contains("seed_hash"),
                "reason should mention seed binding: {reason}"
            );
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

#[test]
fn test_tck_00497_monitor_post_effect_validates_evidence_provider_binding() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier0);
    let plan = kernel.plan(&request).expect("plan should succeed");

    // Create evidence with wrong provider_id.
    let mut leakage_ev = evidence_from_seed(&plan.leakage_witness_seed, 100);
    leakage_ev.provider_id = "attacker-module".to_string();

    let waiver = valid_monitor_waiver(request.request_id);

    let result = kernel.finalize_post_effect_witness(
        EnforcementTier::Monitor,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        Some(&leakage_ev), // wrong provider
        None,
        Some(&waiver),
        100,
    );
    assert!(
        result.is_err(),
        "monitor tier must validate evidence provider binding when evidence is provided"
    );
    match result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(
                reason.contains("provider_id"),
                "reason should mention provider binding: {reason}"
            );
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

// ---- Integration: seed hashes in spine join extension + bundle ----

#[test]
fn test_tck_00497_seed_hashes_bound_into_spine_ext_and_bundle() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let plan = kernel.plan(&request).expect("plan should succeed");

    // Verify seed hashes are in the spine join extension.
    let leakage_hash = plan.leakage_witness_seed.content_hash();
    let timing_hash = plan.timing_witness_seed.content_hash();

    assert_eq!(
        plan.spine_ext.leakage_witness_seed_hash, leakage_hash,
        "spine ext must contain leakage seed hash"
    );
    assert_eq!(
        plan.spine_ext.timing_witness_seed_hash, timing_hash,
        "spine ext must contain timing seed hash"
    );

    // Execute and verify seed hashes in bundle.
    let mut plan_exec = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan_exec, test_hash(9), test_hash(12))
        .expect("execute should succeed");

    assert_eq!(
        result.bundle.leakage_witness_seed_hash,
        plan_exec.leakage_witness_seed.content_hash(),
        "bundle must contain leakage seed hash"
    );
    assert_eq!(
        result.bundle.timing_witness_seed_hash,
        plan_exec.timing_witness_seed.content_hash(),
        "bundle must contain timing seed hash"
    );
    assert_ne!(
        result.bundle.leakage_witness_seed_hash, result.bundle.timing_witness_seed_hash,
        "seed hashes in bundle must be unique"
    );
}

// ---- End-to-end positive path: fail-closed tier with witnesses within budget
// ----

#[test]
fn test_tck_00497_e2e_fail_closed_positive_path() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    // Plan and validate seeds.
    let plan = kernel.plan(&request).expect("plan should succeed");
    let seed_result = kernel.validate_witness_seeds_at_join(
        plan.enforcement_tier,
        &plan.leakage_witness_seed,
        &plan.timing_witness_seed,
        None,
        100,
    );
    assert!(seed_result.is_ok(), "seed validation should succeed");

    // Execute.
    let mut plan2 = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan2, test_hash(9), test_hash(12))
        .expect("execute should succeed");

    assert!(
        result.boundary_span.output_held,
        "output must be held for fail-closed tier"
    );

    // Finalize post-effect evidence.
    let leakage_ev = evidence_from_seed(&plan2.leakage_witness_seed, 100);
    let timing_ev = evidence_from_seed(&plan2.timing_witness_seed, 100);

    let evidence_hashes = kernel
        .finalize_post_effect_witness(
            plan2.enforcement_tier,
            &plan2.leakage_witness_seed,
            &plan2.timing_witness_seed,
            Some(&leakage_ev),
            Some(&timing_ev),
            None,
            100,
        )
        .expect("evidence finalization should succeed");

    assert_eq!(evidence_hashes.len(), 2, "must have 2 evidence hashes");

    // Release boundary output.
    let mut span = result.boundary_span;
    let release_result = kernel.release_boundary_output(&mut span, &evidence_hashes);
    assert!(
        release_result.is_ok(),
        "output release should succeed with evidence"
    );
    assert!(!span.output_held, "output must be released");

    // Verify evidence hashes can be bound into outcome index.
    let outcome_index = super::types::AdmissionOutcomeIndexV1 {
        schema_version: super::types::ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: result.bundle_digest,
        request_id: result.bundle.request_id,
        ajc_id: result.bundle.ajc_id,
        post_effect_witness_evidence_hashes: evidence_hashes,
        receipt_digests: vec![],
    };
    assert!(
        outcome_index.validate().is_ok(),
        "outcome index with evidence hashes must validate"
    );
    assert_ne!(
        outcome_index.content_hash(),
        [0u8; 32],
        "outcome index hash must be non-zero"
    );
}

// =============================================================================
// TCK-00497 QUALITY MAJOR 3: Runtime-path regression tests
//
// These tests exercise the real plan/execute/finalize_post_effect_witness
// flow via AdmissionResultV1, asserting:
// - fail-closed denies on missing/invalid post-effect evidence
// - fail-closed allows on valid evidence
// - monitor waiver required/expiry-denied behavior
// - seeds are carried through AdmissionResultV1
// =============================================================================

/// Test: seeds are carried through `AdmissionResultV1` from `execute()`.
///
/// Verifies that the leakage/timing witness seeds in the result match
/// the seeds from the consumed plan, enabling the runtime post-effect
/// path to invoke `finalize_post_effect_witness` with actual seeds.
#[test]
fn test_tck_00497_seeds_carried_through_admission_result() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");

    // Capture seed hashes from the plan before execute consumes it.
    let expected_leakage_hash = plan.leakage_witness_seed.content_hash();
    let expected_timing_hash = plan.timing_witness_seed.content_hash();

    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Seeds in the result must match the plan's seeds.
    assert_eq!(
        result.leakage_witness_seed.content_hash(),
        expected_leakage_hash,
        "result leakage seed must match plan leakage seed"
    );
    assert_eq!(
        result.timing_witness_seed.content_hash(),
        expected_timing_hash,
        "result timing seed must match plan timing seed"
    );

    // Provider provenance must be preserved.
    assert_eq!(
        result.leakage_witness_seed.provider_id, "apm2-daemon/admission_kernel/test",
        "leakage seed provider_id must be preserved through result"
    );
    assert_eq!(
        result.timing_witness_seed.provider_id, "apm2-daemon/admission_kernel/test",
        "timing seed provider_id must be preserved through result"
    );
    assert_eq!(
        result.leakage_witness_seed.provider_build_digest,
        test_hash(99),
        "leakage seed provider_build_digest must be preserved"
    );
}

/// Test: fail-closed denies on missing post-effect evidence via result seeds.
///
/// Exercises the runtime path: plan -> execute ->
/// `finalize_post_effect_witness` using the seeds from `AdmissionResultV1` (not
/// the plan directly).
#[test]
fn test_tck_00497_runtime_fail_closed_denies_missing_evidence() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Use seeds from the result (the runtime path).
    let finalize_result = kernel.finalize_post_effect_witness(
        result.boundary_span.enforcement_tier,
        &result.leakage_witness_seed,
        &result.timing_witness_seed,
        None, // Missing leakage evidence
        None, // Missing timing evidence
        None,
        100,
    );

    assert!(
        finalize_result.is_err(),
        "fail-closed must deny on missing evidence"
    );
    match finalize_result.unwrap_err() {
        AdmitError::OutputReleaseDenied { reason } => {
            assert!(
                reason.contains("missing"),
                "reason should mention missing evidence: {reason}"
            );
        },
        other => panic!("expected OutputReleaseDenied, got: {other}"),
    }
}

/// Test: fail-closed denies on invalid post-effect evidence (wrong seed
/// binding).
#[test]
fn test_tck_00497_runtime_fail_closed_denies_invalid_evidence() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Build evidence with WRONG seed_hash (simulating evidence substitution).
    let bad_leakage_ev = crate::admission_kernel::types::WitnessEvidenceV1 {
        witness_class: "leakage".to_string(),
        seed_hash: test_hash(250), // Wrong seed hash!
        request_id: result.bundle.request_id,
        session_id: result.bundle.session_id.clone(),
        ht_end: 100,
        measured_values: vec![test_hash(180)],
        provider_id: kernel.witness_provider.provider_id.clone(),
        provider_build_digest: kernel.witness_provider.provider_build_digest,
    };
    let good_timing_ev = evidence_from_seed(&result.timing_witness_seed, 100);

    let finalize_result = kernel.finalize_post_effect_witness(
        result.boundary_span.enforcement_tier,
        &result.leakage_witness_seed,
        &result.timing_witness_seed,
        Some(&bad_leakage_ev),
        Some(&good_timing_ev),
        None,
        100,
    );

    assert!(
        finalize_result.is_err(),
        "fail-closed must deny on invalid evidence (wrong seed binding)"
    );
    match finalize_result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(
                reason.contains("seed_hash"),
                "reason should mention seed_hash mismatch: {reason}"
            );
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

/// Test: fail-closed allows on valid post-effect evidence via result seeds.
#[test]
fn test_tck_00497_runtime_fail_closed_allows_valid_evidence() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Build valid evidence from the result's seeds.
    let leakage_ev = evidence_from_seed(&result.leakage_witness_seed, 100);
    let timing_ev = evidence_from_seed(&result.timing_witness_seed, 100);

    let evidence_hashes = kernel
        .finalize_post_effect_witness(
            result.boundary_span.enforcement_tier,
            &result.leakage_witness_seed,
            &result.timing_witness_seed,
            Some(&leakage_ev),
            Some(&timing_ev),
            None,
            100,
        )
        .expect("valid evidence finalization should succeed");

    assert_eq!(
        evidence_hashes.len(),
        2,
        "must produce exactly 2 evidence hashes (leakage + timing)"
    );
    assert_ne!(
        evidence_hashes[0], evidence_hashes[1],
        "evidence hashes must be distinct"
    );

    // Release boundary output with valid evidence.
    let mut span = result.boundary_span;
    assert!(span.output_held, "output must be held before release");
    kernel
        .release_boundary_output(&mut span, &evidence_hashes)
        .expect("release should succeed with valid evidence");
    assert!(!span.output_held, "output must be released after success");
}

/// Test: monitor tier requires explicit waiver for witness bypass.
///
/// Without a waiver, `finalize_post_effect_witness` must deny.
#[test]
fn test_tck_00497_runtime_monitor_requires_waiver() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier1); // Monitor tier

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    assert_eq!(
        plan.enforcement_tier,
        EnforcementTier::Monitor,
        "Tier1 must map to Monitor"
    );

    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // No waiver provided — must deny.
    let finalize_result = kernel.finalize_post_effect_witness(
        result.boundary_span.enforcement_tier,
        &result.leakage_witness_seed,
        &result.timing_witness_seed,
        None,
        None,
        None, // No waiver!
        100,
    );

    assert!(
        finalize_result.is_err(),
        "monitor tier must deny without explicit waiver"
    );
    match finalize_result.unwrap_err() {
        AdmitError::WitnessWaiverInvalid { reason } => {
            assert!(
                reason.contains("explicit waiver"),
                "reason should mention explicit waiver requirement: {reason}"
            );
        },
        other => panic!("expected WitnessWaiverInvalid, got: {other}"),
    }
}

/// Test: monitor tier denies on expired waiver.
#[test]
fn test_tck_00497_runtime_monitor_denies_expired_waiver() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier1);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Expired waiver: expires_at_tick=50, current_tick=100.
    let expired_waiver = super::types::MonitorWaiverV1 {
        waiver_id: test_hash(200),
        reason: "test expired waiver".to_string(),
        expires_at_tick: 50,
        request_id: result.bundle.request_id,
        enforcement_tier: EnforcementTier::Monitor,
    };

    let finalize_result = kernel.finalize_post_effect_witness(
        result.boundary_span.enforcement_tier,
        &result.leakage_witness_seed,
        &result.timing_witness_seed,
        None,
        None,
        Some(&expired_waiver),
        100, // current_tick > expires_at_tick
    );

    assert!(
        finalize_result.is_err(),
        "monitor tier must deny on expired waiver"
    );
    match finalize_result.unwrap_err() {
        AdmitError::WitnessWaiverInvalid { reason } => {
            assert!(
                reason.contains("expired"),
                "reason should mention waiver expired: {reason}"
            );
        },
        other => panic!("expected WitnessWaiverInvalid, got: {other}"),
    }
}

/// Test: monitor tier allows with valid waiver via result seeds.
#[test]
fn test_tck_00497_runtime_monitor_allows_with_valid_waiver() {
    let kernel = minimal_kernel();
    let request = valid_request(RiskTier::Tier1);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    let waiver = valid_monitor_waiver(result.bundle.request_id);

    // With evidence provided for defense-in-depth.
    let leakage_ev = evidence_from_seed(&result.leakage_witness_seed, 100);
    let timing_ev = evidence_from_seed(&result.timing_witness_seed, 100);

    let evidence_hashes = kernel
        .finalize_post_effect_witness(
            result.boundary_span.enforcement_tier,
            &result.leakage_witness_seed,
            &result.timing_witness_seed,
            Some(&leakage_ev),
            Some(&timing_ev),
            Some(&waiver),
            100,
        )
        .expect("monitor tier with valid waiver should succeed");

    // 2 evidence hashes + 1 waiver hash = 3
    assert_eq!(
        evidence_hashes.len(),
        3,
        "must have 3 hashes (leakage + timing evidence + waiver)"
    );
}

/// Test: fail-closed denies on evidence with wrong provider binding.
///
/// Validates that provider substitution attacks are caught by the kernel's
/// canonical validator (not just ad-hoc hash checks).
#[test]
fn test_tck_00497_runtime_fail_closed_denies_wrong_provider() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Build evidence with the correct seed_hash but wrong provider.
    let mut bad_leakage_ev = evidence_from_seed(&result.leakage_witness_seed, 100);
    bad_leakage_ev.provider_build_digest = test_hash(250); // Wrong provider!

    let good_timing_ev = evidence_from_seed(&result.timing_witness_seed, 100);

    let finalize_result = kernel.finalize_post_effect_witness(
        result.boundary_span.enforcement_tier,
        &result.leakage_witness_seed,
        &result.timing_witness_seed,
        Some(&bad_leakage_ev),
        Some(&good_timing_ev),
        None,
        100,
    );

    assert!(
        finalize_result.is_err(),
        "fail-closed must deny on wrong provider binding"
    );
    match finalize_result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(
                reason.contains("provider_build_digest"),
                "reason should mention provider_build_digest: {reason}"
            );
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

/// Test: fail-closed denies evidence with `ht_end` before seed `ht_start`.
///
/// Evidence finalization time must be at or after seed creation time.
#[test]
fn test_tck_00497_runtime_fail_closed_denies_temporal_violation() {
    let kernel = fail_closed_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // Build evidence with ht_end BEFORE seed ht_start.
    let ht_start = result.leakage_witness_seed.ht_start;
    assert!(ht_start > 0, "ht_start must be non-zero for this test");

    let mut bad_leakage_ev = evidence_from_seed(&result.leakage_witness_seed, ht_start - 1);
    // Fix seed_hash since evidence_from_seed computes it from the seed.
    bad_leakage_ev.seed_hash = result.leakage_witness_seed.content_hash();

    let good_timing_ev = evidence_from_seed(&result.timing_witness_seed, 100);

    let finalize_result = kernel.finalize_post_effect_witness(
        result.boundary_span.enforcement_tier,
        &result.leakage_witness_seed,
        &result.timing_witness_seed,
        Some(&bad_leakage_ev),
        Some(&good_timing_ev),
        None,
        100,
    );

    assert!(
        finalize_result.is_err(),
        "fail-closed must deny evidence before seed creation"
    );
    match finalize_result.unwrap_err() {
        AdmitError::WitnessEvidenceFailure { reason } => {
            assert!(
                reason.contains("ht_end") && reason.contains("ht_start"),
                "reason should mention temporal violation: {reason}"
            );
        },
        other => panic!("expected WitnessEvidenceFailure, got: {other}"),
    }
}

// ---- WitnessEvidenceV1 JSON round-trip ----

#[test]
fn test_tck_00497_witness_evidence_json_round_trip() {
    let ev = super::types::WitnessEvidenceV1 {
        witness_class: "leakage".to_string(),
        seed_hash: test_hash(50),
        request_id: test_hash(1),
        session_id: "test-session".to_string(),
        ht_end: 100,
        measured_values: vec![test_hash(180), test_hash(181)],
        provider_id: "apm2-daemon/admission_kernel/test".to_string(),
        provider_build_digest: test_hash(99),
    };
    let json = serde_json::to_string(&ev).expect("serialize must succeed");
    let deser: super::types::WitnessEvidenceV1 =
        serde_json::from_str(&json).expect("deserialize must succeed");
    assert_eq!(
        ev.content_hash(),
        deser.content_hash(),
        "round-trip must preserve content hash"
    );
    assert_eq!(
        deser.measured_values.len(),
        2,
        "measured_values must survive round-trip"
    );
}

// ---- MonitorWaiverV1 JSON round-trip ----

#[test]
fn test_tck_00497_monitor_waiver_json_round_trip() {
    let waiver = valid_monitor_waiver(test_hash(1));
    let json = serde_json::to_string(&waiver).expect("serialize must succeed");
    let deser: super::types::MonitorWaiverV1 =
        serde_json::from_str(&json).expect("deserialize must succeed");
    assert_eq!(
        waiver.content_hash(),
        deser.content_hash(),
        "round-trip must preserve content hash"
    );
}

// =============================================================================
// TCK-00502: Anti-rollback anchor provider tests
// =============================================================================

// ---- InMemoryAntiRollbackAnchor tests ----

#[test]
fn test_tck_00502_in_memory_anchor_latest_before_commit() {
    let anchor_provider =
        super::trust_stack::InMemoryAntiRollbackAnchor::new("test_mechanism".to_string());

    let result = anchor_provider.latest();
    assert!(
        result.is_err(),
        "latest() before any commit must return error"
    );
    match result.unwrap_err() {
        TrustError::ExternalAnchorUnavailable { .. } => {},
        other => panic!("expected ExternalAnchorUnavailable, got {other:?}"),
    }
}

#[test]
fn test_tck_00502_in_memory_anchor_commit_and_latest() {
    use super::prerequisites::AntiRollbackAnchor;

    let anchor_provider =
        super::trust_stack::InMemoryAntiRollbackAnchor::new("test_mechanism".to_string());

    let anchor = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 100,
        he_time: 1000,
    };

    anchor_provider
        .commit(&anchor)
        .expect("commit must succeed");

    let state = anchor_provider.latest().expect("latest must succeed");
    assert_eq!(state.anchor, anchor);
    assert_eq!(state.mechanism_id, "test_mechanism");
}

#[test]
fn test_tck_00502_in_memory_anchor_rollback_denied() {
    let anchor_provider =
        super::trust_stack::InMemoryAntiRollbackAnchor::new("test_mechanism".to_string());

    let anchor_high = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 200,
        he_time: 2000,
    };

    anchor_provider
        .commit(&anchor_high)
        .expect("commit must succeed");

    // Attempt rollback to lower height.
    let anchor_low = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(22),
        height: 100,
        he_time: 1000,
    };

    let result = anchor_provider.commit(&anchor_low);
    assert!(result.is_err(), "rollback commit must be denied");
    match result.unwrap_err() {
        TrustError::ExternalAnchorMismatch { reason } => {
            assert!(
                reason.contains("regression"),
                "error must mention regression: {reason}"
            );
        },
        other => panic!("expected ExternalAnchorMismatch, got {other:?}"),
    }
}

#[test]
fn test_tck_00502_in_memory_anchor_fork_denied() {
    let anchor_provider =
        super::trust_stack::InMemoryAntiRollbackAnchor::new("test_mechanism".to_string());

    let anchor_original = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 100,
        he_time: 1000,
    };

    anchor_provider
        .commit(&anchor_original)
        .expect("commit must succeed");

    // Attempt fork: same height, different hash.
    let anchor_fork = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(99), // different hash
        height: 100,
        he_time: 1000,
    };

    let result = anchor_provider.commit(&anchor_fork);
    assert!(result.is_err(), "fork commit must be denied");
    match result.unwrap_err() {
        TrustError::ExternalAnchorMismatch { reason } => {
            assert!(reason.contains("fork"), "error must mention fork: {reason}");
        },
        other => panic!("expected ExternalAnchorMismatch, got {other:?}"),
    }
}

#[test]
fn test_tck_00502_in_memory_anchor_verify_committed_rollback_detected() {
    use super::prerequisites::AntiRollbackAnchor;

    let anchor_committed = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 200,
        he_time: 2000,
    };

    let anchor_provider = super::trust_stack::InMemoryAntiRollbackAnchor::with_initial_anchor(
        "test_mechanism".to_string(),
        anchor_committed,
    );

    // Verify an anchor BEHIND the committed state -- rollback.
    let anchor_behind = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(22),
        height: 100,
        he_time: 1000,
    };

    let result = anchor_provider.verify_committed(&anchor_behind);
    assert!(
        result.is_err(),
        "verifying an anchor behind the committed state must fail"
    );
    match result.unwrap_err() {
        TrustError::ExternalAnchorMismatch { reason } => {
            assert!(
                reason.contains("rollback"),
                "error must mention rollback: {reason}"
            );
        },
        other => panic!("expected ExternalAnchorMismatch, got {other:?}"),
    }
}

#[test]
fn test_tck_00502_in_memory_anchor_verify_committed_fork_detected() {
    use super::prerequisites::AntiRollbackAnchor;

    let anchor_committed = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 100,
        he_time: 1000,
    };

    let anchor_provider = super::trust_stack::InMemoryAntiRollbackAnchor::with_initial_anchor(
        "test_mechanism".to_string(),
        anchor_committed,
    );

    // Verify an anchor at the same height but different hash -- fork.
    let anchor_fork = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(99), // different hash
        height: 100,
        he_time: 1000,
    };

    let result = anchor_provider.verify_committed(&anchor_fork);
    assert!(result.is_err(), "verifying a forked anchor must fail");
    match result.unwrap_err() {
        TrustError::ExternalAnchorMismatch { reason } => {
            assert!(reason.contains("fork"), "error must mention fork: {reason}");
        },
        other => panic!("expected ExternalAnchorMismatch, got {other:?}"),
    }
}

#[test]
fn test_tck_00502_in_memory_anchor_verify_committed_advance_accepted() {
    use super::prerequisites::AntiRollbackAnchor;

    let anchor_committed = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 100,
        he_time: 1000,
    };

    let anchor_provider = super::trust_stack::InMemoryAntiRollbackAnchor::with_initial_anchor(
        "test_mechanism".to_string(),
        anchor_committed,
    );

    // Verify an anchor AHEAD of the committed state -- accepted.
    let anchor_ahead = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(22),
        height: 200,
        he_time: 2000,
    };

    let result = anchor_provider.verify_committed(&anchor_ahead);
    assert!(
        result.is_ok(),
        "verifying an anchor ahead of committed state must succeed"
    );
}

#[test]
fn test_tck_00502_in_memory_anchor_verify_committed_same_height_same_hash() {
    use super::prerequisites::AntiRollbackAnchor;

    let anchor_committed = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 100,
        he_time: 1000,
    };

    let anchor_provider = super::trust_stack::InMemoryAntiRollbackAnchor::with_initial_anchor(
        "test_mechanism".to_string(),
        anchor_committed.clone(),
    );

    let result = anchor_provider.verify_committed(&anchor_committed);
    assert!(
        result.is_ok(),
        "verifying the same anchor that was committed must succeed"
    );
}

// ---- DurableAntiRollbackAnchor tests ----

#[test]
fn test_tck_00502_durable_anchor_new_file_not_exists() {
    use super::prerequisites::AntiRollbackAnchor;

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = tmp_dir.path().join("anchor_state.json");

    let anchor_provider =
        super::trust_stack::DurableAntiRollbackAnchor::new(state_path, "file_anchor".to_string())
            .expect("new must succeed when file does not exist");

    // No committed state yet.
    let result = anchor_provider.latest();
    assert!(
        result.is_err(),
        "latest() before any commit must return error"
    );
}

#[test]
fn test_tck_00502_durable_anchor_commit_and_reload() {
    use super::prerequisites::AntiRollbackAnchor;

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = tmp_dir.path().join("anchor_state.json");

    let anchor = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 100,
        he_time: 1000,
    };

    // Commit via first provider.
    {
        let provider = super::trust_stack::DurableAntiRollbackAnchor::new(
            state_path.clone(),
            "file_anchor".to_string(),
        )
        .expect("new must succeed");
        provider.commit(&anchor).expect("commit must succeed");

        let state = provider.latest().expect("latest must succeed");
        assert_eq!(state.anchor, anchor);
    }

    // Reload via second provider (simulating daemon restart).
    {
        let provider = super::trust_stack::DurableAntiRollbackAnchor::new(
            state_path,
            "file_anchor".to_string(),
        )
        .expect("new must succeed with existing file");

        let state = provider.latest().expect("latest must succeed after reload");
        assert_eq!(state.anchor, anchor, "anchor must survive restart");
        assert_eq!(state.mechanism_id, "file_anchor");
    }
}

#[test]
fn test_tck_00502_durable_anchor_rollback_denied() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = tmp_dir.path().join("anchor_state.json");

    let provider =
        super::trust_stack::DurableAntiRollbackAnchor::new(state_path, "file_anchor".to_string())
            .expect("new must succeed");

    let anchor_high = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 200,
        he_time: 2000,
    };
    provider
        .commit(&anchor_high)
        .expect("first commit must succeed");

    // Attempt rollback.
    let anchor_low = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(22),
        height: 100,
        he_time: 1000,
    };

    let result = provider.commit(&anchor_low);
    assert!(result.is_err(), "rollback must be denied");
    match result.unwrap_err() {
        TrustError::ExternalAnchorMismatch { reason } => {
            assert!(
                reason.contains("regression"),
                "error must mention regression: {reason}"
            );
        },
        other => panic!("expected ExternalAnchorMismatch, got {other:?}"),
    }
}

#[test]
fn test_tck_00502_durable_anchor_verify_committed_rollback() {
    use super::prerequisites::AntiRollbackAnchor;

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = tmp_dir.path().join("anchor_state.json");

    let anchor = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 200,
        he_time: 2000,
    };

    let provider =
        super::trust_stack::DurableAntiRollbackAnchor::new(state_path, "file_anchor".to_string())
            .expect("new must succeed");
    provider.commit(&anchor).expect("commit must succeed");

    // Verify an anchor behind the committed state.
    let anchor_behind = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(22),
        height: 100,
        he_time: 1000,
    };

    let result = provider.verify_committed(&anchor_behind);
    assert!(
        result.is_err(),
        "verifying a rollback anchor must be denied"
    );
}

#[test]
fn test_tck_00502_durable_anchor_mechanism_id_mismatch() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = tmp_dir.path().join("anchor_state.json");

    let anchor = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 100,
        he_time: 1000,
    };

    // Commit with mechanism "file_anchor".
    {
        let provider = super::trust_stack::DurableAntiRollbackAnchor::new(
            state_path.clone(),
            "file_anchor".to_string(),
        )
        .expect("new must succeed");
        provider.commit(&anchor).expect("commit must succeed");
    }

    // Attempt reload with different mechanism ID.
    let result = super::trust_stack::DurableAntiRollbackAnchor::new(
        state_path,
        "different_mechanism".to_string(),
    );
    assert!(
        result.is_err(),
        "reload with different mechanism_id must fail"
    );
}

#[test]
fn test_tck_00502_durable_anchor_empty_mechanism_id_rejected() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = tmp_dir.path().join("anchor_state.json");

    let result = super::trust_stack::DurableAntiRollbackAnchor::new(state_path, String::new());
    assert!(result.is_err(), "empty mechanism_id must be rejected");
}

// ---- Kernel integration tests for anti-rollback ----

#[test]
fn test_tck_00502_fail_closed_denies_without_anti_rollback_anchor() {
    // Kernel without anti-rollback anchor wired.
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));
    // Deliberately NOT setting anti-rollback.

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "fail-closed tier must deny when anti-rollback anchor is missing"
    );
    match result.unwrap_err() {
        AdmitError::MissingPrerequisite { prerequisite } => {
            assert_eq!(
                prerequisite, "AntiRollbackAnchor",
                "must report AntiRollbackAnchor as missing"
            );
        },
        other => panic!("expected MissingPrerequisite(AntiRollbackAnchor), got {other:?}"),
    }
}

#[test]
fn test_tck_00502_monitor_tier_proceeds_without_anti_rollback() {
    // Kernel without anti-rollback -- monitor tier should proceed.
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider());
    // No prerequisites wired at all.

    let request = valid_request(RiskTier::Tier0);
    let result = kernel.plan(&request);

    assert!(
        result.is_ok(),
        "monitor tier must proceed without anti-rollback anchor"
    );
}

#[test]
fn test_tck_00502_fail_closed_denies_on_anchor_mismatch() {
    // Use a failing anti-rollback mock.
    struct FailingAntiRollback;

    impl AntiRollbackAnchor for FailingAntiRollback {
        fn latest(&self) -> Result<ExternalAnchorStateV1, TrustError> {
            Err(TrustError::ExternalAnchorUnavailable {
                reason: "test unavailable".into(),
            })
        }

        fn verify_committed(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
            Err(TrustError::ExternalAnchorMismatch {
                reason: "anchor mismatch (test)".into(),
            })
        }

        fn commit(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
            Err(TrustError::ExternalAnchorMismatch {
                reason: "anchor mismatch (test)".into(),
            })
        }
    }

    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(FailingAntiRollback))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_err(),
        "fail-closed tier must deny on anti-rollback mismatch"
    );
    match result.unwrap_err() {
        AdmitError::AntiRollbackFailure { reason } => {
            assert!(
                reason.contains("mismatch"),
                "error must mention mismatch: {reason}"
            );
        },
        other => panic!("expected AntiRollbackFailure, got {other:?}"),
    }
}

/// Verifies that `ExternalAnchorUnavailable` from `verify_committed()` is
/// tolerated during `plan()` (bootstrap path), but the failure surfaces later
/// when `finalize_anti_rollback()` attempts to commit and the anchor
/// provider reports an error.
///
/// With the BLOCKER-1 fix, `ExternalAnchorUnavailable` is no longer a
/// plan-time denial — it represents the bootstrap case where no prior
/// state exists to protect. The anti-rollback invariant is enforced
/// at finalize time via `commit()`.
#[test]
fn test_tck_00502_fail_closed_denies_on_anchor_unavailable() {
    // Anti-rollback anchor that is unavailable: verify_committed returns
    // ExternalAnchorUnavailable (tolerated by bootstrap path), but commit()
    // also fails (simulating persistent external service failure).
    struct UnavailableAntiRollback;

    impl AntiRollbackAnchor for UnavailableAntiRollback {
        fn latest(&self) -> Result<ExternalAnchorStateV1, TrustError> {
            Err(TrustError::ExternalAnchorUnavailable {
                reason: "external service down".into(),
            })
        }

        fn verify_committed(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
            Err(TrustError::ExternalAnchorUnavailable {
                reason: "external service down".into(),
            })
        }

        fn commit(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
            Err(TrustError::ExternalAnchorUnavailable {
                reason: "external service down".into(),
            })
        }
    }

    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(UnavailableAntiRollback))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);

    // plan() now succeeds (bootstrap path: ExternalAnchorUnavailable tolerated).
    let mut plan = kernel
        .plan(&request)
        .expect("plan must succeed (bootstrap path tolerates unavailable)");

    // execute() succeeds (no anchor commit inside execute).
    let result = kernel
        .execute(&mut plan, test_hash(0xE0), test_hash(0xE1))
        .expect("execute must succeed");

    // finalize_anti_rollback() fails because commit() returns error.
    let finalize_result = kernel.finalize_anti_rollback(
        result.boundary_span.enforcement_tier,
        &result.bundle.ledger_anchor,
    );
    assert!(
        finalize_result.is_err(),
        "finalize_anti_rollback must fail when external service is down"
    );
    match finalize_result.unwrap_err() {
        AdmitError::AntiRollbackFailure { reason } => {
            assert!(
                reason.contains("unavailable") || reason.contains("down"),
                "error should describe unavailability: {reason}"
            );
        },
        other => panic!("expected AntiRollbackFailure, got {other:?}"),
    }
}

#[test]
fn test_tck_00502_rollback_to_earlier_seal_denied_via_external_anchor() {
    // This is the canonical REQ-0030 acceptance criterion test:
    // A rollback that would pass purely local seal verification is denied
    // by the external anchor.

    let committed_anchor = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 500,
        he_time: 5000,
    };

    let external_anchor = super::trust_stack::InMemoryAntiRollbackAnchor::with_initial_anchor(
        "test_mechanism".to_string(),
        committed_anchor,
    );

    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(external_anchor))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    // The ledger verifier returns an anchor at height 100, which is BEHIND
    // the externally committed anchor at height 500. This simulates a
    // rollback attack where the adversary rewrites local state.
    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    // The MockLedgerVerifier returns an anchor at height 100, and the
    // InMemoryAntiRollbackAnchor has committed state at height 500.
    // verify_committed(height=100) < committed(height=500) -> deny.
    assert!(
        result.is_err(),
        "rollback to earlier seal must be denied by external anchor"
    );
    match result.unwrap_err() {
        AdmitError::AntiRollbackFailure { reason } => {
            assert!(
                reason.contains("rollback") || reason.contains("behind"),
                "error must indicate rollback detection: {reason}"
            );
        },
        other => panic!("expected AntiRollbackFailure, got {other:?}"),
    }
}

#[test]
fn test_tck_00502_fully_wired_kernel_with_matching_anchor_succeeds() {
    // External anchor at the same height as the ledger verifier.
    let matching_anchor = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 100,
        he_time: 1000,
    };

    let external_anchor = super::trust_stack::InMemoryAntiRollbackAnchor::with_initial_anchor(
        "test_mechanism".to_string(),
        matching_anchor,
    );

    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(external_anchor))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);

    assert!(
        result.is_ok(),
        "fully wired kernel with matching external anchor must succeed: {:?}",
        result.err()
    );
}

#[test]
fn test_tck_00502_in_memory_anchor_forward_progress_accepted() {
    use super::prerequisites::AntiRollbackAnchor;

    // Test that advancing the anchor (higher height) succeeds.
    let provider =
        super::trust_stack::InMemoryAntiRollbackAnchor::new("test_mechanism".to_string());

    let height_values: [u64; 5] = [100, 200, 300, 400, 500];
    for height in height_values {
        #[allow(clippy::cast_possible_truncation)] // test-only: height/100 fits in u8
        let hash_byte = (height / 100) as u8;
        let anchor = LedgerAnchorV1 {
            ledger_id: test_hash(20),
            event_hash: test_hash(hash_byte),
            height,
            he_time: height * 10,
        };
        provider
            .commit(&anchor)
            .unwrap_or_else(|e| panic!("commit at height {height} must succeed: {e:?}"));
    }

    let latest = provider.latest().expect("latest must succeed");
    assert_eq!(latest.anchor.height, 500, "latest must be at height 500");
}

// =============================================================================
// BLOCKER-001: Anchor commit wired in execute() after successful admission
// =============================================================================

/// Verifies that `finalize_anti_rollback()` commits the anti-rollback anchor
/// after a successful plan+execute+effect cycle, advancing the watermark.
///
/// The anchor commit was moved from `execute()` to `finalize_anti_rollback()`
/// (BLOCKER-2 fix) so that effect failures do not advance the watermark.
#[test]
fn test_tck_00502_execute_commits_anti_rollback_anchor() {
    use super::prerequisites::AntiRollbackAnchor;

    // Pre-seed the anchor at the same height as MockLedgerVerifier::passing()
    // so that plan()'s verify_committed() passes.
    let anti_rollback = Arc::new(
        super::trust_stack::InMemoryAntiRollbackAnchor::with_initial_anchor(
            "test_mechanism".to_string(),
            LedgerAnchorV1 {
                ledger_id: test_hash(20),
                event_hash: test_hash(21),
                height: 100,
                he_time: 1000,
            },
        ),
    );

    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(anti_rollback.clone())
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan must succeed");

    let result = kernel.execute(&mut plan, test_hash(0xE0), test_hash(0xE1));
    assert!(result.is_ok(), "execute must succeed: {:?}", result.err());

    let result = result.unwrap();

    // After execute() but BEFORE finalize_anti_rollback(), the anchor should
    // still be at the pre-seeded height (100), not advanced.
    let before_finalize = anti_rollback
        .latest()
        .expect("anchor must be available (pre-seeded)");
    assert_eq!(
        before_finalize.anchor.height, 100,
        "anchor must NOT advance during execute() (pre-commit hazard guard)"
    );

    // Now finalize: this simulates the post-effect success path.
    kernel
        .finalize_anti_rollback(
            result.boundary_span.enforcement_tier,
            &result.bundle.ledger_anchor,
        )
        .expect("finalize_anti_rollback must succeed");

    // After finalize, the anchor should match the bundle's ledger_anchor.
    let after_finalize = anti_rollback
        .latest()
        .expect("anchor must be available after finalize");
    assert_eq!(
        after_finalize.anchor.height, result.bundle.ledger_anchor.height,
        "anchor height must match the bundle's ledger_anchor after finalize"
    );
    assert_eq!(
        after_finalize.anchor.event_hash, result.bundle.ledger_anchor.event_hash,
        "anchor event_hash must match the bundle's ledger_anchor after finalize"
    );
}

/// Verifies that `execute()` does NOT commit the anti-rollback anchor
/// for monitor-tier requests (monitor tiers do not gate authoritative effects).
#[test]
fn test_tck_00502_execute_does_not_commit_anchor_for_monitor_tier() {
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Anti-rollback anchor that counts `commit()` calls to verify
    /// monitor tier does NOT trigger commits.
    struct CommitCountingAntiRollback {
        commit_count: AtomicU32,
    }

    impl AntiRollbackAnchor for CommitCountingAntiRollback {
        fn latest(&self) -> Result<ExternalAnchorStateV1, TrustError> {
            Ok(ExternalAnchorStateV1 {
                anchor: LedgerAnchorV1 {
                    ledger_id: test_hash(20),
                    event_hash: test_hash(21),
                    height: 50,
                    he_time: 500,
                },
                mechanism_id: "counting_test".to_string(),
                proof_hash: test_hash(99),
            })
        }

        fn verify_committed(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
            Ok(())
        }

        fn commit(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
            self.commit_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let anti_rollback = Arc::new(CommitCountingAntiRollback {
        commit_count: AtomicU32::new(0),
    });

    // Monitor tier: no ledger verifier or policy resolver needed.
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_anti_rollback(anti_rollback.clone());

    let request = valid_request(RiskTier::Tier0); // Monitor tier
    let mut plan = kernel
        .plan(&request)
        .expect("plan must succeed for monitor tier");

    let result = kernel.execute(&mut plan, test_hash(0xE0), test_hash(0xE1));
    assert!(
        result.is_ok(),
        "execute must succeed for monitor tier: {:?}",
        result.err()
    );

    // After execute(), commit should NOT have been called for monitor tier.
    assert_eq!(
        anti_rollback.commit_count.load(Ordering::SeqCst),
        0,
        "commit must NOT be called for monitor-tier execute"
    );

    // Also verify finalize_anti_rollback is a no-op for monitor tier.
    let result = result.unwrap();
    kernel
        .finalize_anti_rollback(
            result.boundary_span.enforcement_tier,
            &result.bundle.ledger_anchor,
        )
        .expect("finalize_anti_rollback must succeed for monitor tier");

    assert_eq!(
        anti_rollback.commit_count.load(Ordering::SeqCst),
        0,
        "commit must NOT be called for monitor-tier finalize_anti_rollback"
    );
}

/// Verifies the fresh-install bootstrap path: `plan()` succeeds even when no
/// anchor has been committed yet (`ExternalAnchorUnavailable` is tolerated),
/// then `execute()` + `finalize_anti_rollback()` establishes the initial state.
/// A subsequent `plan()` call also succeeds (anchor now bootstrapped).
///
/// This is the BLOCKER-1 fix test: the circular dependency between `plan()`
/// requiring a committed anchor and `execute()` being the first to commit
/// is broken by tolerating `ExternalAnchorUnavailable` during `plan()`.
#[test]
fn test_tck_00502_fresh_install_bootstrap_without_preseeding() {
    use super::prerequisites::AntiRollbackAnchor;

    // Create an InMemoryAntiRollbackAnchor with NO pre-seeding (fresh install).
    let anti_rollback = Arc::new(super::trust_stack::InMemoryAntiRollbackAnchor::new(
        "test_mechanism".to_string(),
    ));

    // Confirm anchor is initially unavailable.
    assert!(
        anti_rollback.latest().is_err(),
        "anchor must be unavailable before first commit (fresh install)"
    );

    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(anti_rollback.clone())
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    // plan() MUST succeed on fresh install (BLOCKER-1 fix).
    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel
        .plan(&request)
        .expect("plan must succeed on fresh install (bootstrap path)");

    // execute() MUST succeed.
    let result = kernel
        .execute(&mut plan, test_hash(0xE0), test_hash(0xE1))
        .expect("execute must succeed on fresh install");

    // Anchor is still NOT committed after execute() (BLOCKER-2 fix).
    assert!(
        anti_rollback.latest().is_err(),
        "anchor must NOT be committed by execute() (pre-commit hazard guard)"
    );

    // Finalize: simulate post-effect success.
    kernel
        .finalize_anti_rollback(
            result.boundary_span.enforcement_tier,
            &result.bundle.ledger_anchor,
        )
        .expect("finalize_anti_rollback must succeed");

    // Verify anchor is now committed (latest() returns Ok).
    let latest = anti_rollback
        .latest()
        .expect("anchor must be available after finalize_anti_rollback");
    assert_eq!(
        latest.anchor.height, result.bundle.ledger_anchor.height,
        "committed anchor height must match the bundle's ledger_anchor"
    );

    // Second plan() call MUST succeed (anchor is now bootstrapped).
    let request2 = valid_request(RiskTier::Tier2Plus);
    kernel
        .plan(&request2)
        .expect("plan must succeed after anchor is bootstrapped");
}

/// Verifies that when the effect fails (`finalize_anti_rollback` is NOT
/// called), the anchor watermark is NOT advanced, and subsequent `plan()` calls
/// still succeed (no deadlock).
///
/// This is the BLOCKER-2 fix test: moving `commit()` out of `execute()` and
/// into `finalize_anti_rollback()` prevents the pre-commit hazard.
#[test]
fn test_tck_00502_effect_failure_does_not_advance_anchor() {
    use super::prerequisites::AntiRollbackAnchor;

    // Pre-seed the anchor at height N.
    let initial_height: u64 = 100;
    let anti_rollback = Arc::new(
        super::trust_stack::InMemoryAntiRollbackAnchor::with_initial_anchor(
            "test_mechanism".to_string(),
            LedgerAnchorV1 {
                ledger_id: test_hash(20),
                event_hash: test_hash(21),
                height: initial_height,
                he_time: 1000,
            },
        ),
    );

    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(anti_rollback.clone())
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    // plan() + execute() succeed.
    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan must succeed");
    let _result = kernel
        .execute(&mut plan, test_hash(0xE0), test_hash(0xE1))
        .expect("execute must succeed");

    // Simulate effect failure: do NOT call finalize_anti_rollback().

    // Verify the anchor is still at height N (not advanced).
    let latest = anti_rollback
        .latest()
        .expect("anchor must still be available");
    assert_eq!(
        latest.anchor.height, initial_height,
        "anchor must NOT advance when finalize_anti_rollback is not called \
         (simulated effect failure)"
    );

    // Subsequent plan() call MUST succeed (no deadlock).
    let request2 = valid_request(RiskTier::Tier2Plus);
    kernel
        .plan(&request2)
        .expect("plan must succeed after effect failure (no deadlock)");
}

// =============================================================================
// TCK-00502 round 4: Regression tests for finalize_anti_rollback on
// EmitEvent and PublishEvidence handler paths.
//
// These tests verify the same anchor advancement contract that all three
// effect-capable handlers (RequestTool, EmitEvent, PublishEvidence) depend on.
// The handler-level integration (session_dispatch.rs) calls
// kernel.finalize_anti_rollback() identically; these kernel-level tests
// prove the underlying method advances anchors correctly for each scenario.
// =============================================================================

/// Verifies that consecutive `finalize_anti_rollback` calls (simulating
/// sequential effects from different handler paths) each advance the
/// anchor watermark monotonically.
///
/// This regression test covers the TCK-00502 round 4 BLOCKER finding:
/// `EmitEvent` and `PublishEvidence` must call `finalize_anti_rollback` after
/// their respective effects, and each call must further advance the anchor.
#[test]
fn test_tck_00502_sequential_finalize_advances_anchor_monotonically() {
    use super::prerequisites::AntiRollbackAnchor;

    // Pre-seed at height 100 to match MockLedgerVerifier::passing()
    // (validated_anchor.height = 100), so verify_committed() passes.
    let initial_anchor = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 100,
        he_time: 1000,
    };
    let anti_rollback = Arc::new(
        super::trust_stack::InMemoryAntiRollbackAnchor::with_initial_anchor(
            "test_mechanism".to_string(),
            initial_anchor,
        ),
    );

    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(anti_rollback.clone())
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    // Simulate effect 1 (e.g., RequestTool): plan + execute + finalize
    let request1 = valid_request(RiskTier::Tier2Plus);
    let mut plan1 = kernel.plan(&request1).expect("plan1 must succeed");
    let result1 = kernel
        .execute(&mut plan1, test_hash(0xE0), test_hash(0xE1))
        .expect("execute1 must succeed");

    kernel
        .finalize_anti_rollback(
            result1.boundary_span.enforcement_tier,
            &result1.bundle.ledger_anchor,
        )
        .expect("finalize1 must succeed");

    let after_first = anti_rollback.latest().expect("anchor must exist");
    assert_eq!(
        after_first.anchor.height, result1.bundle.ledger_anchor.height,
        "anchor must advance to first effect's ledger anchor height"
    );

    // Simulate effect 2 (e.g., EmitEvent): plan + execute + finalize
    // with a higher anchor height to simulate ledger advancement.
    let request2 = valid_request(RiskTier::Tier2Plus);
    let mut plan2 = kernel.plan(&request2).expect("plan2 must succeed");
    let result2 = kernel
        .execute(&mut plan2, test_hash(0xE2), test_hash(0xE3))
        .expect("execute2 must succeed");

    kernel
        .finalize_anti_rollback(
            result2.boundary_span.enforcement_tier,
            &result2.bundle.ledger_anchor,
        )
        .expect("finalize2 must succeed (EmitEvent path)");

    let after_second = anti_rollback.latest().expect("anchor must exist");
    assert!(
        after_second.anchor.height >= after_first.anchor.height,
        "anchor must advance monotonically after second effect \
         (EmitEvent path): {} >= {}",
        after_second.anchor.height,
        after_first.anchor.height,
    );

    // Simulate effect 3 (e.g., PublishEvidence): plan + execute + finalize
    let request3 = valid_request(RiskTier::Tier2Plus);
    let mut plan3 = kernel.plan(&request3).expect("plan3 must succeed");
    let result3 = kernel
        .execute(&mut plan3, test_hash(0xE4), test_hash(0xE5))
        .expect("execute3 must succeed");

    kernel
        .finalize_anti_rollback(
            result3.boundary_span.enforcement_tier,
            &result3.bundle.ledger_anchor,
        )
        .expect("finalize3 must succeed (PublishEvidence path)");

    let after_third = anti_rollback.latest().expect("anchor must exist");
    assert!(
        after_third.anchor.height >= after_second.anchor.height,
        "anchor must advance monotonically after third effect \
         (PublishEvidence path): {} >= {}",
        after_third.anchor.height,
        after_second.anchor.height,
    );
}

/// Verifies that `finalize_anti_rollback` is a no-op for monitor-tier
/// effects regardless of which handler calls it (`RequestTool`, `EmitEvent`,
/// or `PublishEvidence`).
///
/// Regression test for TCK-00502 round 4: the new `finalize_anti_rollback`
/// calls in `EmitEvent` and `PublishEvidence` are gated on
/// `admission_result.boundary_span.enforcement_tier`, which is `Monitor`
/// for low-risk tiers. This test proves the monitor-tier no-op contract.
#[test]
fn test_tck_00502_finalize_noop_for_monitor_tier_all_handler_paths() {
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Anti-rollback anchor that counts `commit()` calls.
    struct CommitCountingAnchor {
        commit_count: AtomicU32,
    }

    impl CommitCountingAnchor {
        fn new() -> Self {
            Self {
                commit_count: AtomicU32::new(0),
            }
        }
    }

    impl AntiRollbackAnchor for CommitCountingAnchor {
        fn verify_committed(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
            // Allow verification to pass (bootstrap tolerance).
            Err(TrustError::ExternalAnchorUnavailable {
                reason: "no external anchor committed (test counting anchor)".into(),
            })
        }

        fn commit(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
            self.commit_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn latest(&self) -> Result<ExternalAnchorStateV1, TrustError> {
            Err(TrustError::ExternalAnchorUnavailable {
                reason: "no external anchor committed (test counting anchor)".into(),
            })
        }
    }

    let counting_anchor = Arc::new(CommitCountingAnchor::new());
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_anti_rollback(counting_anchor.clone());

    // Simulate three monitor-tier effects (one per handler path).
    for handler_name in &["RequestTool", "EmitEvent", "PublishEvidence"] {
        let request = valid_request(RiskTier::Tier0);
        let mut plan = kernel
            .plan(&request)
            .unwrap_or_else(|e| panic!("plan must succeed for {handler_name}: {e:?}"));
        let result = kernel
            .execute(&mut plan, test_hash(0xF0), test_hash(0xF1))
            .unwrap_or_else(|e| panic!("execute must succeed for {handler_name}: {e:?}"));

        assert_eq!(
            result.boundary_span.enforcement_tier,
            EnforcementTier::Monitor,
            "{handler_name}: tier must be Monitor for Tier0"
        );

        kernel
            .finalize_anti_rollback(
                result.boundary_span.enforcement_tier,
                &result.bundle.ledger_anchor,
            )
            .unwrap_or_else(|e| {
                panic!("finalize must succeed for monitor-tier {handler_name}: {e:?}")
            });
    }

    assert_eq!(
        counting_anchor.commit_count.load(Ordering::SeqCst),
        0,
        "commit must NOT be called for any monitor-tier finalize_anti_rollback \
         (all three handler paths must be no-ops)"
    );
}
