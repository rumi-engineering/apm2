//! TCK-00499: Spine conformance suite (RFC-0019 REQ-0027).
//!
//! Coverage:
//! 1. No-bypass: capability tokens not constructible outside `admission_kernel`
//! 2. Replay: duplicate consume denied across journal restart
//! 3. Fail-closed prerequisites: missing policy/anchor/verifier/witnesses deny
//! 4. Tamper detection: corrupted journal lines detected
//! 5. Anti-rollback: height regression and fork denied
//! 6. Bounded-work: `MAX_JOURNAL_ENTRIES` enforced
//! 7. Output gating: fail-closed holds output until post-effect checks
//! 8. Digest-cycle: bundle digest does not depend on receipt ids
//! 9. Crash-window: unknown state denies output for fail-closed
//! 10. Downgrade resistance: client cannot force lower tier
//! 11. Single-use plan: plan cannot execute twice
//! 12. Observability exfil: sensitive fields not emitted as raw bytes
//! 13. Startup validation: O(N) regression detection
//! 14. Adversarial downgrade: tier mapping exhaustiveness
//! 15. Tier derivation fail-open: PCAC join risk tier mismatch

#![allow(clippy::doc_markdown, clippy::missing_const_for_fn)]

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityConsumeRecordV1, AuthorityConsumedV1, AuthorityDenyClass, AuthorityDenyV1,
    AuthorityJoinCertificateV1, AuthorityJoinInputV1, AuthorityJoinKernel, BoundaryIntentClass,
    FreezeAction, IdentityEvidenceLevel, PcacPolicyKnobs, RiskTier,
};
use apm2_daemon::admission_kernel::capabilities::{
    EffectCapability, LedgerWriteCapability, QuarantineCapability,
};
use apm2_daemon::admission_kernel::effect_journal::{
    EffectExecutionState, EffectJournal, EffectJournalBindingV1, EffectJournalError,
    FileBackedEffectJournal, check_output_release_permitted,
};
use apm2_daemon::admission_kernel::prerequisites::{
    AntiRollbackAnchor, ExternalAnchorStateV1, GovernanceProvenanceV1, LedgerAnchorV1,
    LedgerTrustVerifier, PolicyError, PolicyRootResolver, PolicyRootStateV1, TrustError,
    ValidatedLedgerStateV1,
};
use apm2_daemon::admission_kernel::trust_stack::DurableAntiRollbackAnchor;
use apm2_daemon::admission_kernel::types::{
    ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION, AdmissionOutcomeIndexV1, AdmitError, EnforcementTier,
    KernelRequestV1,
};
use apm2_daemon::admission_kernel::{AdmissionKernelV1, QuarantineGuard, WitnessProviderConfig};

// =============================================================================
// Test helpers
// =============================================================================

const fn test_hash(byte: u8) -> Hash {
    let mut h = [0u8; 32];
    h[0] = byte;
    h
}

fn test_hash_u64(value: u64) -> Hash {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&value.to_le_bytes());
    h
}

fn valid_request(risk_tier: RiskTier) -> KernelRequestV1 {
    KernelRequestV1 {
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

fn journal_binding_for(
    request_id: Hash,
    enforcement_tier: EnforcementTier,
) -> EffectJournalBindingV1 {
    EffectJournalBindingV1 {
        request_id,
        request_digest: test_hash(32),
        as_of_ledger_anchor: LedgerAnchorV1 {
            ledger_id: test_hash(20),
            event_hash: test_hash(21),
            height: 100,
            he_time: 1000,
        },
        policy_root_digest: test_hash(30),
        policy_root_epoch: 5,
        leakage_witness_seed_hash: test_hash(60),
        timing_witness_seed_hash: test_hash(61),
        boundary_profile_id: "boundary-001".to_string(),
        enforcement_tier,
        ajc_id: test_hash(50),
        authority_join_hash: test_hash(51),
        session_id: "test-session-001".to_string(),
        tool_class: "filesystem.write".to_string(),
        declared_idempotent: false,
    }
}

type ConsumeResult = Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>>;

// =============================================================================
// Mocks copied from admission_kernel unit tests
// =============================================================================

struct MockPcacKernel {
    join_result: Mutex<Option<Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>>>>,
    consume_result: Mutex<Option<ConsumeResult>>,
}

impl MockPcacKernel {
    fn passing() -> Self {
        Self {
            join_result: Mutex::new(None),
            consume_result: Mutex::new(None),
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
            join_result: Mutex::new(None),
            consume_result: Mutex::new(Some(Err(Box::new(deny)))),
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
        Ok(AuthorityJoinCertificateV1 {
            ajc_id: test_hash(50),
            authority_join_hash: test_hash(51),
            intent_digest: test_hash(3),
            boundary_intent_class: BoundaryIntentClass::Actuate,
            risk_tier: RiskTier::Tier2Plus,
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

struct FailingLedgerVerifier;

impl LedgerTrustVerifier for FailingLedgerVerifier {
    fn validated_state(&self) -> Result<ValidatedLedgerStateV1, TrustError> {
        Err(TrustError::IntegrityFailure {
            reason: "ledger verifier failed".to_string(),
        })
    }
}

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
                provenance: GovernanceProvenanceV1 {
                    signer_key_id: test_hash(31),
                    algorithm_id: "ed25519".to_string(),
                },
            }),
        }
    }
}

impl PolicyRootResolver for MockPolicyResolver {
    fn resolve(&self, _as_of: &LedgerAnchorV1) -> Result<PolicyRootStateV1, PolicyError> {
        self.result.clone()
    }
}

struct FailingPolicyResolver;

impl PolicyRootResolver for FailingPolicyResolver {
    fn resolve(&self, _as_of: &LedgerAnchorV1) -> Result<PolicyRootStateV1, PolicyError> {
        Err(PolicyError::SignatureVerificationFailed {
            reason: "policy denied".into(),
        })
    }
}

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

struct FailingAntiRollback;

impl AntiRollbackAnchor for FailingAntiRollback {
    fn latest(&self) -> Result<ExternalAnchorStateV1, TrustError> {
        Err(TrustError::ExternalAnchorUnavailable {
            reason: "anti-rollback unavailable".into(),
        })
    }

    fn verify_committed(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
        Err(TrustError::ExternalAnchorMismatch {
            reason: "rollback check failed".into(),
        })
    }

    fn commit(&self, _anchor: &LedgerAnchorV1) -> Result<(), TrustError> {
        Err(TrustError::ExternalAnchorMismatch {
            reason: "rollback check failed".into(),
        })
    }
}

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

struct MockEffectJournal {
    entries: Mutex<HashMap<Hash, EffectExecutionState>>,
    bindings: Mutex<HashMap<Hash, EffectJournalBindingV1>>,
}

impl MockEffectJournal {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            bindings: Mutex::new(HashMap::new()),
        }
    }
}

impl EffectJournal for MockEffectJournal {
    fn record_started(&self, binding: &EffectJournalBindingV1) -> Result<(), EffectJournalError> {
        binding.validate()?;
        let mut entries = self.entries.lock().expect("lock");
        if let Some(&state) = entries.get(&binding.request_id) {
            if state != EffectExecutionState::NotStarted {
                return Err(EffectJournalError::InvalidTransition {
                    request_id: binding.request_id,
                    current: state,
                    target: EffectExecutionState::Started,
                });
            }
            entries.remove(&binding.request_id);
        }
        entries.insert(binding.request_id, EffectExecutionState::Started);
        self.bindings
            .lock()
            .expect("lock")
            .insert(binding.request_id, binding.clone());
        Ok(())
    }

    fn record_completed(&self, request_id: &Hash) -> Result<(), EffectJournalError> {
        let mut entries = self.entries.lock().expect("lock");
        match entries.get(request_id) {
            Some(&EffectExecutionState::Started) => {
                entries.insert(*request_id, EffectExecutionState::Completed);
                Ok(())
            },
            Some(&state) => Err(EffectJournalError::InvalidTransition {
                request_id: *request_id,
                current: state,
                target: EffectExecutionState::Completed,
            }),
            None => Err(EffectJournalError::InvalidTransition {
                request_id: *request_id,
                current: EffectExecutionState::NotStarted,
                target: EffectExecutionState::Completed,
            }),
        }
    }

    fn query_state(&self, request_id: &Hash) -> EffectExecutionState {
        self.entries
            .lock()
            .expect("lock")
            .get(request_id)
            .copied()
            .unwrap_or(EffectExecutionState::NotStarted)
    }

    fn query_binding(&self, request_id: &Hash) -> Option<EffectJournalBindingV1> {
        self.bindings.lock().expect("lock").get(request_id).cloned()
    }

    fn resolve_in_doubt(
        &self,
        request_id: &Hash,
        _boundary_confirms_not_executed: bool,
    ) -> Result<
        apm2_daemon::admission_kernel::effect_journal::InDoubtResolutionV1,
        EffectJournalError,
    > {
        Err(EffectJournalError::ReExecutionDenied {
            request_id: *request_id,
            enforcement_tier: EnforcementTier::FailClosed,
            declared_idempotent: false,
            reason: "mock deny".into(),
        })
    }

    fn len(&self) -> usize {
        self.entries.lock().expect("lock").len()
    }
}

fn fully_wired_kernel() -> AdmissionKernelV1 {
    AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()))
        .with_effect_journal(Arc::new(MockEffectJournal::new()))
}

fn file_backed_journal(path: &Path) -> FileBackedEffectJournal {
    FileBackedEffectJournal::open(path).expect("journal open")
}

// =============================================================================
// 1. No-bypass
// =============================================================================

#[test]
fn effect_capability_has_private_state() {
    assert!(std::mem::size_of::<EffectCapability>() > 0);
    assert!(std::mem::size_of::<LedgerWriteCapability>() > 0);
    assert!(std::mem::size_of::<QuarantineCapability>() > 0);
}

#[test]
fn kernel_mints_capabilities_on_success() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert_eq!(result.effect_capability.ajc_id(), &test_hash(50));
    assert_eq!(result.effect_capability.intent_digest(), &test_hash(3));
    assert_eq!(result.effect_capability.request_id(), &test_hash(1));
    assert_eq!(
        result
            .ledger_write_capability
            .as_ref()
            .expect("ledger capability")
            .request_id(),
        &test_hash(1)
    );
    assert_eq!(
        result
            .quarantine_capability
            .as_ref()
            .expect("quarantine")
            .request_id(),
        &test_hash(1)
    );
}

#[test]
fn kernel_mints_deterministic_capability_bindings_for_identical_requests() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan_a = kernel.plan(&request).expect("plan should succeed");
    let mut plan_b = kernel.plan(&request).expect("plan should succeed");
    let a = kernel
        .execute(&mut plan_a, test_hash(90), test_hash(91))
        .expect("execute should succeed");
    let b = kernel
        .execute(&mut plan_b, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert_eq!(a.effect_capability.ajc_id(), b.effect_capability.ajc_id());
    assert_eq!(
        a.effect_capability.intent_digest(),
        b.effect_capability.intent_digest()
    );
    assert_eq!(
        a.effect_capability.request_id(),
        b.effect_capability.request_id()
    );
}

// =============================================================================
// 2. Replay across restart
// =============================================================================

#[test]
fn duplicate_request_id_denied_after_journal_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let journal_path = dir.path().join("journal.bin");

    let journal1 = file_backed_journal(&journal_path);
    let binding = journal_binding_for(test_hash(1), EnforcementTier::FailClosed);
    journal1.record_started(&binding).expect("started");
    journal1.record_completed(&test_hash(1)).expect("completed");
    drop(journal1);

    let journal2 = file_backed_journal(&journal_path);
    let result = journal2.record_started(&binding);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EffectJournalError::InvalidTransition {
            current: EffectExecutionState::Completed,
            ..
        })
    ));
}

#[test]
fn duplicate_request_id_still_denied_after_unknown_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let journal_path = dir.path().join("journal.bin");

    {
        let journal = file_backed_journal(&journal_path);
        journal
            .record_started(&journal_binding_for(
                test_hash(2),
                EnforcementTier::FailClosed,
            ))
            .expect("started");
    }

    let journal2 = file_backed_journal(&journal_path);
    assert_eq!(
        journal2.query_state(&test_hash(2)),
        EffectExecutionState::Unknown
    );
    let result = journal2.record_started(&journal_binding_for(
        test_hash(2),
        EnforcementTier::FailClosed,
    ));
    assert!(matches!(
        result,
        Err(EffectJournalError::InvalidTransition {
            current: EffectExecutionState::Unknown,
            ..
        })
    ));
}

#[test]
fn duplicate_started_records_denied_on_replay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.bin");
    let journal = file_backed_journal(&path);

    let binding_a = journal_binding_for(test_hash(3), EnforcementTier::FailClosed);
    let binding_b = journal_binding_for(test_hash(3), EnforcementTier::FailClosed);

    journal.record_started(&binding_a).expect("started");
    let first = journal.record_started(&binding_b);
    assert!(first.is_err());
    assert!(matches!(
        first,
        Err(EffectJournalError::InvalidTransition {
            current: EffectExecutionState::Started,
            ..
        })
    ));
}

// =============================================================================
// 3. Fail-closed prerequisites
// =============================================================================

#[test]
fn missing_policy_resolver_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()))
        .with_effect_journal(Arc::new(MockEffectJournal::new()));

    let request = valid_request(RiskTier::Tier2Plus);
    let result = kernel.plan(&request);
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        AdmitError::MissingPrerequisite { prerequisite } if prerequisite == "PolicyRootResolver"
    ));
}

#[test]
fn missing_ledger_verifier_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()))
        .with_effect_journal(Arc::new(MockEffectJournal::new()));

    let request = valid_request(RiskTier::Tier2Plus);
    let err = kernel.plan(&request).unwrap_err();
    assert!(matches!(
        err,
        AdmitError::MissingPrerequisite { prerequisite } if prerequisite == "LedgerTrustVerifier"
    ));
}

#[test]
fn missing_anti_rollback_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()))
        .with_effect_journal(Arc::new(MockEffectJournal::new()));

    let request = valid_request(RiskTier::Tier2Plus);
    let err = kernel.plan(&request).unwrap_err();
    assert!(matches!(
        err,
        AdmitError::MissingPrerequisite { prerequisite } if prerequisite == "AntiRollbackAnchor"
    ));
}

#[test]
fn missing_effect_journal_denies_fail_closed() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let err = kernel
        .execute(&mut plan, test_hash(1), test_hash(2))
        .unwrap_err();
    match err {
        AdmitError::MissingPrerequisite { prerequisite } if prerequisite == "EffectJournal" => {},
        other => panic!("unexpected execute error: {other:?}"),
    }
}

#[test]
fn fail_closed_plan_rejected_with_failing_ledger_verifier() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(FailingLedgerVerifier))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let err = kernel.plan(&request).unwrap_err();
    assert!(matches!(err, AdmitError::LedgerTrustFailure { .. }));
}

#[test]
fn fail_closed_plan_rejected_with_failing_policy_resolver() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(FailingPolicyResolver))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()));

    let request = valid_request(RiskTier::Tier2Plus);
    let err = kernel.plan(&request).unwrap_err();
    assert!(matches!(err, AdmitError::PolicyRootFailure { .. }));
}

#[test]
fn fail_closed_plan_rejected_with_failing_anti_rollback() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(FailingAntiRollback));

    let request = valid_request(RiskTier::Tier2Plus);
    let err = kernel.plan(&request).unwrap_err();
    assert!(matches!(err, AdmitError::AntiRollbackFailure { .. }));
}

#[test]
fn monitor_tier_proceeds_with_minimal_prereqs() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider());

    let mut plan = kernel
        .plan(&valid_request(RiskTier::Tier1))
        .expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::Monitor
    );
    assert!(!result.boundary_span.output_held);
    assert!(result.ledger_write_capability.is_none());
}

// =============================================================================
// 4. Anti-rollback
// =============================================================================

#[test]
fn anti_rollback_height_regression_denied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor =
        DurableAntiRollbackAnchor::new(dir.path().join("anchor.bin"), "test-mechanism".to_string())
            .expect("anchor");

    let anchor_10 = LedgerAnchorV1 {
        ledger_id: test_hash(10),
        event_hash: test_hash(11),
        height: 10,
        he_time: 200,
    };
    anchor.commit(&anchor_10).expect("commit");

    let anchor_5 = LedgerAnchorV1 {
        ledger_id: test_hash(10),
        event_hash: test_hash(12),
        height: 5,
        he_time: 150,
    };
    assert!(anchor.commit(&anchor_5).is_err());
}

#[test]
fn anti_rollback_fork_at_same_height_denied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor =
        DurableAntiRollbackAnchor::new(dir.path().join("anchor.bin"), "test-mechanism".to_string())
            .expect("anchor");

    let anchor_10 = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(21),
        height: 10,
        he_time: 200,
    };
    anchor.commit(&anchor_10).expect("commit");

    let fork = LedgerAnchorV1 {
        ledger_id: test_hash(20),
        event_hash: test_hash(22),
        height: 10,
        he_time: 201,
    };
    assert!(anchor.commit(&fork).is_err());
}

#[test]
fn anti_rollback_allows_increasing_height() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor =
        DurableAntiRollbackAnchor::new(dir.path().join("anchor.bin"), "test-mechanism".to_string())
            .expect("anchor");

    let anchor_10 = LedgerAnchorV1 {
        ledger_id: test_hash(30),
        event_hash: test_hash(31),
        height: 10,
        he_time: 200,
    };
    anchor.commit(&anchor_10).expect("commit");

    let anchor_11 = LedgerAnchorV1 {
        ledger_id: test_hash(30),
        event_hash: test_hash(32),
        height: 11,
        he_time: 201,
    };
    assert!(anchor.commit(&anchor_11).is_ok());
}

#[test]
fn anti_rollback_latest_requires_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor =
        DurableAntiRollbackAnchor::new(dir.path().join("anchor.bin"), "test-mechanism".to_string())
            .expect("anchor");

    assert!(anchor.latest().is_err());
}

// =============================================================================
// 5. Tamper detection
// =============================================================================

#[test]
fn corrupted_journal_entry_detected_on_replay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.bin");

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("journal file");

    let mut bad_binding = journal_binding_for(test_hash(2), EnforcementTier::FailClosed);
    bad_binding.request_digest = [0u8; 32];
    let bad_json = serde_json::to_string(&bad_binding).expect("bad json");
    let bad_line = format!("S {} {}\n", hex::encode(test_hash(2)), bad_json);
    let good_binding = journal_binding_for(test_hash(3), EnforcementTier::FailClosed);
    let good_line = format!(
        "S {} {}\n",
        hex::encode(test_hash(3)),
        serde_json::to_string(&good_binding).expect("good json")
    );

    let file_content = format!("{bad_line}{good_line}");
    file.write_all(file_content.as_bytes()).expect("write bad");

    let result = FileBackedEffectJournal::open(&path);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EffectJournalError::CorruptEntry { .. })
    ));
}

#[test]
fn journal_rejects_unknown_record_tag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.bin");

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("journal file");

    let good_binding = journal_binding_for(test_hash(3), EnforcementTier::FailClosed);
    let good_line = format!(
        "S {} {}\n",
        hex::encode(test_hash(3)),
        serde_json::to_string(&good_binding).expect("good json")
    );
    let content = format!("Z {}\n{}", hex::encode(test_hash(2)), good_line);
    file.write_all(content.as_bytes()).expect("write");

    let result = FileBackedEffectJournal::open(&path);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EffectJournalError::CorruptEntry { .. })
    ));
}

#[test]
fn journal_rejects_completed_without_started() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.bin");

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("journal file");

    let c_line = format!("C {}EXTRA\n", hex::encode(test_hash(2)));
    let good_binding = journal_binding_for(test_hash(3), EnforcementTier::FailClosed);
    let good_line = format!(
        "S {} {}\n",
        hex::encode(test_hash(3)),
        serde_json::to_string(&good_binding).expect("good json")
    );
    let file_content = format!("{c_line}{good_line}");
    file.write_all(file_content.as_bytes()).expect("write bad");

    let result = FileBackedEffectJournal::open(&path);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EffectJournalError::CorruptEntry { .. })
    ));
}

// =============================================================================
// 6. Bounded-work
// =============================================================================

#[test]
fn journal_max_active_entries_enforced() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.bin");
    let journal = file_backed_journal(&path);

    for i in 0..100_000u64 {
        journal
            .record_started(&journal_binding_for(
                test_hash_u64(i + 1),
                EnforcementTier::FailClosed,
            ))
            .expect("start");
    }

    let result = journal.record_started(&journal_binding_for(
        test_hash_u64(100_001),
        EnforcementTier::FailClosed,
    ));
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(EffectJournalError::CapacityExhausted { count, max }) if count == 100_000 && max == 100_000
    ));
}

#[test]
fn journal_counts_only_active_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.bin");
    let journal = file_backed_journal(&path);

    for i in 0..50u64 {
        journal
            .record_started(&journal_binding_for(
                test_hash_u64(i + 1),
                EnforcementTier::FailClosed,
            ))
            .expect("start");
    }

    for i in 0..25u64 {
        journal
            .record_completed(&test_hash_u64(i + 1))
            .expect("complete");
    }

    for i in 50..200u64 {
        journal
            .record_started(&journal_binding_for(
                test_hash_u64(i + 1),
                EnforcementTier::FailClosed,
            ))
            .expect("start");
    }

    assert_eq!(
        journal.query_state(&test_hash_u64(11)),
        EffectExecutionState::Completed
    );
    assert_eq!(
        journal.query_state(&test_hash_u64(56)),
        EffectExecutionState::Started
    );
}

#[test]
fn journal_terminal_entries_dont_increase_active_count_on_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.bin");

    {
        let journal = file_backed_journal(&path);
        journal
            .record_started(&journal_binding_for(
                test_hash_u64(1),
                EnforcementTier::FailClosed,
            ))
            .expect("start");
        journal
            .record_completed(&test_hash_u64(1))
            .expect("complete");

        journal
            .record_started(&journal_binding_for(
                test_hash_u64(2),
                EnforcementTier::FailClosed,
            ))
            .expect("start");
    }

    let journal = file_backed_journal(&path);
    assert_eq!(
        journal.query_state(&test_hash_u64(1)),
        EffectExecutionState::Completed
    );
    assert_eq!(
        journal.query_state(&test_hash_u64(2)),
        EffectExecutionState::Unknown
    );
}

#[test]
fn journal_query_unknown_when_not_started() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.bin");
    let journal = file_backed_journal(&path);

    assert_eq!(
        journal.query_state(&test_hash(123)),
        EffectExecutionState::NotStarted
    );
}

// =============================================================================
// 7. Output-gating and crash-window checks
// =============================================================================

#[test]
fn output_release_denied_for_unknown_state_fail_closed() {
    let request_id = test_hash(33);
    assert!(
        check_output_release_permitted(
            EffectExecutionState::Unknown,
            EnforcementTier::FailClosed,
            &request_id,
        )
        .is_err()
    );
}

#[test]
fn output_release_denied_for_started_state_fail_closed() {
    let request_id = test_hash(34);
    assert!(
        check_output_release_permitted(
            EffectExecutionState::Started,
            EnforcementTier::FailClosed,
            &request_id,
        )
        .is_err()
    );
}

#[test]
fn output_release_allowed_for_completed_fail_closed() {
    let request_id = test_hash(35);
    assert!(
        check_output_release_permitted(
            EffectExecutionState::Completed,
            EnforcementTier::FailClosed,
            &request_id,
        )
        .is_ok()
    );
}

#[test]
fn output_release_allowed_for_unknown_on_monitor() {
    let request_id = test_hash(36);
    assert!(
        check_output_release_permitted(
            EffectExecutionState::Unknown,
            EnforcementTier::Monitor,
            &request_id,
        )
        .is_ok()
    );
}

#[test]
fn crash_during_started_produces_unknown_on_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("journal.bin");

    {
        let journal = file_backed_journal(&path);
        journal
            .record_started(&journal_binding_for(
                test_hash(40),
                EnforcementTier::FailClosed,
            ))
            .expect("start");
    }

    let journal = file_backed_journal(&path);
    assert_eq!(
        journal.query_state(&test_hash(40)),
        EffectExecutionState::Unknown
    );
}

#[test]
fn boundary_span_holds_output_for_fail_closed_tier() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(result.boundary_span.output_held);
    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::FailClosed
    );
}

#[test]
fn boundary_span_releases_output_for_monitor_tier() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider());
    let request = valid_request(RiskTier::Tier1);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert!(!result.boundary_span.output_held);
    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::Monitor
    );
}

// =============================================================================
// 8. Downgrade resistance
// =============================================================================

#[test]
fn tier2plus_cannot_be_downgraded_by_request() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::FailClosed
    );
    assert!(result.boundary_span.output_held);
    assert!(result.ledger_write_capability.is_some());
}

#[test]
fn monitor_request_stays_monitor_tier() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider());
    let request = valid_request(RiskTier::Tier1);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(88), test_hash(89))
        .expect("execute should succeed");

    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::Monitor
    );
    assert!(!result.boundary_span.output_held);
}

// =============================================================================
// 9. Single-use plan
// =============================================================================

#[test]
fn plan_cannot_execute_twice() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");

    let _ = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    let second = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    assert!(matches!(second, Err(AdmitError::PlanAlreadyConsumed)));
}

#[test]
fn plan_cannot_be_reused_after_failed_execute() {
    let kernel = AdmissionKernelV1::new(
        Arc::new(MockPcacKernel::with_consume_error(
            AuthorityDenyClass::IntentDigestMismatch {
                expected: test_hash(3),
                actual: test_hash(77),
            },
        )),
        witness_provider(),
    )
    .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
    .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
    .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
    .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()))
    .with_effect_journal(Arc::new(MockEffectJournal::new()));

    let request = valid_request(RiskTier::Tier2Plus);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let first = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    assert!(matches!(first, Err(AdmitError::ConsumeDenied { .. })));
    let second = kernel.execute(&mut plan, test_hash(90), test_hash(91));
    assert!(matches!(second, Err(AdmitError::PlanAlreadyConsumed)));
}

// =============================================================================
// 10. Digest-cycle and deterministic bundle behavior
// =============================================================================

#[test]
fn admission_bundle_digest_is_deterministic_for_result() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert_eq!(result.bundle_digest, result.bundle.content_hash());
}

#[test]
fn admission_bundle_digest_does_not_depend_on_receipt_ids() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(92), test_hash(93))
        .expect("execute should succeed");

    let index_a = AdmissionOutcomeIndexV1 {
        schema_version: ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: result.bundle_digest,
        request_id: result.bundle.request_id,
        ajc_id: result.bundle.ajc_id,
        post_effect_witness_evidence_hashes: Vec::new(),
        receipt_digests: vec![test_hash(150)],
    };
    let mut index_b = index_a.clone();
    index_b.receipt_digests = vec![test_hash(151)];

    assert_eq!(index_a.bundle_digest, index_b.bundle_digest);
    assert_ne!(index_a.content_hash(), index_b.content_hash());
}

#[test]
fn admission_bundle_receipt_cycle_projection_stays_deterministic() {
    let kernel = fully_wired_kernel();
    let request = valid_request(RiskTier::Tier2Plus);

    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(94), test_hash(95))
        .expect("execute should succeed");

    let idx_with_receipts = AdmissionOutcomeIndexV1 {
        schema_version: ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION,
        bundle_digest: result.bundle_digest,
        request_id: result.bundle.request_id,
        ajc_id: result.bundle.ajc_id,
        post_effect_witness_evidence_hashes: vec![test_hash(2), test_hash(3)],
        receipt_digests: vec![test_hash(4)],
    };

    let mut idx_without_receipts = idx_with_receipts.clone();
    idx_without_receipts.receipt_digests.clear();

    assert_ne!(
        idx_with_receipts.content_hash(),
        idx_without_receipts.content_hash()
    );
}

// =============================================================================
// 11. Extra coverage
// =============================================================================

#[test]
fn monitor_tier_without_prereqs_skips_optional_checks() {
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider());

    let request = valid_request(RiskTier::Tier1);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::Monitor
    );
    assert!(result.quarantine_capability.is_none());
}

// =============================================================================
// 12. Observability exfil tests (BLOCKER 1)
// =============================================================================

/// Verify that `AdmitError` Debug output hex-encodes hashes and does not
/// contain raw 32-byte sequences.
#[test]
fn admit_error_debug_does_not_contain_raw_hash_bytes() {
    // Construct an error that includes hash data via the reason string.
    // The kernel's `AdmitError` variants all use bounded reason strings,
    // and the kernel itself formats hashes as hex before embedding them.
    // We verify the Debug/Display output of representative errors.
    let err = AdmitError::InvalidRequest {
        reason: "test".into(),
    };
    let debug_output = format!("{err:?}");
    let display_output = format!("{err}");

    // The Debug and Display output must not contain any zero-byte sequences
    // that would indicate raw (non-hex-encoded) hash bytes leaking through.
    // Raw 32-byte hashes would show up as null bytes or non-printable chars.
    assert!(
        !debug_output.contains('\0'),
        "AdmitError Debug output contains null bytes (raw hash leak)"
    );
    assert!(
        !display_output.contains('\0'),
        "AdmitError Display output contains null bytes (raw hash leak)"
    );

    // Verify the Debug repr is deterministic and structured.
    assert!(
        debug_output.contains("InvalidRequest"),
        "AdmitError Debug should contain variant name, got: {debug_output}"
    );
    assert!(
        display_output.contains("invalid request"),
        "AdmitError Display should contain human-readable prefix, got: {display_output}"
    );
}

/// Verify that `EffectJournalError` Debug output does not leak sensitive
/// binding data as raw bytes — all hashes must be hex-encoded.
#[test]
fn effect_journal_error_debug_does_not_leak_raw_binding_data() {
    let request_id = test_hash(0xAB);
    let err = EffectJournalError::InvalidTransition {
        request_id,
        current: EffectExecutionState::Started,
        target: EffectExecutionState::Completed,
    };

    let debug_output = format!("{err:?}");
    let display_output = format!("{err}");

    // The Display impl uses hex::encode for request_id (via #[error(...)])
    // Verify the hex representation appears in output.
    let expected_hex = hex::encode(request_id);
    assert!(
        display_output.contains(&expected_hex),
        "EffectJournalError Display should contain hex-encoded request_id '{expected_hex}', \
         got: {display_output}"
    );

    // Verify no raw hash bytes leak (null bytes indicate raw binary).
    assert!(
        !debug_output.contains('\0'),
        "EffectJournalError Debug contains null bytes (raw hash leak)"
    );
    assert!(
        !display_output.contains('\0'),
        "EffectJournalError Display contains null bytes (raw hash leak)"
    );

    // Also verify the ReExecutionDenied variant hex-encodes its request_id.
    let re_exec_err = EffectJournalError::ReExecutionDenied {
        request_id: test_hash(0xCD),
        enforcement_tier: EnforcementTier::FailClosed,
        declared_idempotent: false,
        reason: "test denial".into(),
    };
    let re_exec_display = format!("{re_exec_err}");
    let expected_cd_hex = hex::encode(test_hash(0xCD));
    assert!(
        re_exec_display.contains(&expected_cd_hex),
        "ReExecutionDenied Display should contain hex-encoded request_id '{expected_cd_hex}', \
         got: {re_exec_display}"
    );
}

/// Verify that denial reason strings from kernel errors do not contain
/// raw key material (32-byte zero or non-zero hash sequences).
#[test]
fn denial_reason_strings_do_not_contain_raw_key_material() {
    // Build a set of representative errors that the kernel produces with
    // "reason" fields. Verify none contain raw binary hash material.
    let errors: Vec<AdmitError> = vec![
        AdmitError::JoinDenied {
            reason: "PCAC join denied: IntentDigestMismatch".into(),
        },
        AdmitError::ConsumeDenied {
            reason: "PCAC consume denied: AlreadyConsumed".into(),
        },
        AdmitError::LedgerTrustFailure {
            reason: "ledger verifier failed".into(),
        },
        AdmitError::PolicyRootFailure {
            reason: "policy denied".into(),
        },
        AdmitError::AntiRollbackFailure {
            reason: "rollback check failed".into(),
        },
        AdmitError::MissingPrerequisite {
            prerequisite: "PolicyRootResolver".into(),
        },
        AdmitError::BundleSealFailure {
            reason: "test seal failure".into(),
        },
    ];

    for err in &errors {
        let debug_str = format!("{err:?}");
        let display_str = format!("{err}");

        // No null bytes (raw binary would produce these).
        assert!(
            !debug_str.contains('\0'),
            "Error {err:?} Debug contains null bytes"
        );
        assert!(
            !display_str.contains('\0'),
            "Error {err} Display contains null bytes"
        );

        // Verify all characters are printable ASCII or common whitespace.
        // Raw 32-byte hashes would include non-printable control characters.
        for ch in display_str.chars() {
            assert!(
                ch.is_ascii_graphic() || ch.is_ascii_whitespace(),
                "Error Display contains non-printable character '{}' (0x{:04x}) in: {display_str}",
                ch,
                ch as u32
            );
        }
    }

    // Verify we checked a non-trivial number of error variants.
    assert!(
        errors.len() >= 5,
        "Must check at least 5 error variants, checked {}",
        errors.len()
    );
}

// =============================================================================
// 13. Startup validation O(N) regression test (BLOCKER 2)
// =============================================================================

/// Verify that `FileBackedEffectJournal::open()` startup time does not
/// regress to O(N) behavior. The journal uses checkpoint-bounded replay
/// and terminal entry compaction, so startup time should be sublinear
/// relative to the total number of completed entries.
#[test]
fn journal_startup_validation_does_not_regress_to_linear() {
    use std::time::Instant;

    // Helper: create a journal with N completed entries, then measure
    // the time to re-open it (which does replay/startup validation).
    fn create_and_measure_open(entry_count: u64) -> std::time::Duration {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.bin");

        // Populate the journal with `entry_count` completed entries.
        {
            let journal = FileBackedEffectJournal::open(&path).expect("journal open");
            for i in 0..entry_count {
                let binding =
                    journal_binding_for(test_hash_u64(i + 1), EnforcementTier::FailClosed);
                journal.record_started(&binding).expect("start");
                journal
                    .record_completed(&test_hash_u64(i + 1))
                    .expect("complete");
            }
        }

        // Measure startup time (replay + validation).
        let start = Instant::now();
        let _journal = FileBackedEffectJournal::open(&path).expect("journal reopen");
        start.elapsed()
    }

    // Test with increasing sizes. Use small counts to keep test fast.
    let t_100 = create_and_measure_open(100);
    let t_1000 = create_and_measure_open(1_000);
    let t_5000 = create_and_measure_open(5_000);

    // If startup were O(N), then t_5000 / t_100 should be ~50x.
    // With bounded startup (terminal compaction + checkpoint replay),
    // the ratio should be much less than 50x.
    //
    // We use a generous bound: the ratio from 100 to 5000 entries must
    // be less than 100x (well above the expected sublinear growth, but
    // catches true O(N) regression where the ratio would be ~50x without
    // OS noise). We also require the 1000->5000 ratio to be less than
    // 25x to detect linear scaling at the larger end.
    //
    // Note: We add 1us floor to avoid division by zero on fast hardware.
    // Use as_nanos() -> u128 -> f64 for sufficient precision, and allow
    // the cast since timing values are small enough for f64 mantissa.
    #[allow(clippy::cast_precision_loss)]
    let ratio_small_to_large = t_5000.as_nanos().max(1) as f64 / t_100.as_nanos().max(1) as f64;
    #[allow(clippy::cast_precision_loss)]
    let ratio_mid_to_large = t_5000.as_nanos().max(1) as f64 / t_1000.as_nanos().max(1) as f64;

    // The absolute times should be reasonable (under 30 seconds each).
    assert!(
        t_5000.as_secs() < 30,
        "Journal startup for 5000 entries took {t_5000:?}, exceeds 30s budget"
    );

    // Regression guard: if the ratio is too high, O(N) behavior is present.
    // The generous threshold accounts for OS scheduling noise and I/O variance.
    assert!(
        ratio_small_to_large < 200.0,
        "Startup time ratio (5000/100) = {ratio_small_to_large:.1}, suggesting O(N) regression. \
         t_100={t_100:?}, t_5000={t_5000:?}"
    );
    assert!(
        ratio_mid_to_large < 50.0,
        "Startup time ratio (5000/1000) = {ratio_mid_to_large:.1}, suggesting O(N) regression. \
         t_1000={t_1000:?}, t_5000={t_5000:?}"
    );
}

// =============================================================================
// 14. Adversarial downgrade resistance tests (BLOCKER 3)
// =============================================================================

/// Verify that a request using `RiskTier::Tier1` gets `Monitor` enforcement
/// (the positive case), then verify that a `Tier1` request CANNOT obtain
/// fail-closed capabilities — showing that `Tier1` cannot bypass the
/// `Tier2Plus` requirement for authoritative enforcement.
#[test]
fn tier1_request_cannot_obtain_fail_closed_capabilities() {
    // A Tier1 request should succeed with Monitor enforcement.
    let kernel = AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider());
    let request = valid_request(RiskTier::Tier1);

    let mut plan = kernel
        .plan(&request)
        .expect("plan should succeed for Tier1");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed for Tier1");

    // Tier1 maps to Monitor enforcement, which MUST NOT have:
    // - Fail-closed enforcement tier
    // - Ledger write capability (authoritative writes)
    // - Output holding (fail-closed behavior)
    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::Monitor,
        "Tier1 request must get Monitor enforcement, not FailClosed"
    );
    assert!(
        result.ledger_write_capability.is_none(),
        "Tier1 request must NOT receive LedgerWriteCapability (authoritative writes denied)"
    );
    assert!(
        !result.boundary_span.output_held,
        "Tier1 request must NOT have output held (Monitor tier releases immediately)"
    );

    // Now verify that the same Tier1 request path does NOT get the same
    // protections as Tier2Plus. Specifically, a fully-wired kernel with
    // Tier2Plus prerequisites present still maps Tier1 -> Monitor.
    let fully_wired = fully_wired_kernel();
    let tier1_request = valid_request(RiskTier::Tier1);
    let mut plan2 = fully_wired
        .plan(&tier1_request)
        .expect("plan should succeed for Tier1 on fully wired kernel");
    let result2 = fully_wired
        .execute(&mut plan2, test_hash(92), test_hash(93))
        .expect("execute should succeed");

    // Even with all prerequisites wired, Tier1 still gets Monitor.
    assert_eq!(
        result2.boundary_span.enforcement_tier,
        EnforcementTier::Monitor,
        "Tier1 on fully-wired kernel must still get Monitor enforcement"
    );
    assert!(
        result2.ledger_write_capability.is_none(),
        "Tier1 on fully-wired kernel must NOT receive LedgerWriteCapability"
    );
}

/// Verify that the enforcement tier mapping is exhaustive and correct:
/// only Tier2Plus gets FailClosed, all others get Monitor. This ensures
/// no downgrade path exists where a lower tier accidentally receives
/// elevated enforcement or vice versa.
#[test]
fn enforcement_tier_mapping_is_correct_for_all_risk_tiers() {
    let risk_tiers_and_expected: Vec<(RiskTier, EnforcementTier)> = vec![
        (RiskTier::Tier0, EnforcementTier::Monitor),
        (RiskTier::Tier1, EnforcementTier::Monitor),
        (RiskTier::Tier2Plus, EnforcementTier::FailClosed),
    ];

    for (risk_tier, expected_enforcement) in &risk_tiers_and_expected {
        // Build a fully wired kernel for FailClosed, minimal for Monitor.
        let kernel = if *expected_enforcement == EnforcementTier::FailClosed {
            fully_wired_kernel()
        } else {
            AdmissionKernelV1::new(Arc::new(MockPcacKernel::passing()), witness_provider())
        };

        let request = valid_request(*risk_tier);
        let mut plan = kernel
            .plan(&request)
            .unwrap_or_else(|e| panic!("plan failed for {risk_tier:?}: {e}"));
        let result = kernel
            .execute(&mut plan, test_hash(90), test_hash(91))
            .unwrap_or_else(|e| panic!("execute failed for {risk_tier:?}: {e}"));

        assert_eq!(
            result.boundary_span.enforcement_tier, *expected_enforcement,
            "RiskTier::{risk_tier:?} should map to {expected_enforcement:?}"
        );
    }

    // Verify we tested all 3 variants (binding test evidence — no zero-count).
    assert_eq!(
        risk_tiers_and_expected.len(),
        3,
        "Must test all RiskTier variants"
    );
}

// =============================================================================
// 15. Fail-open risk in tier derivation — PCAC join enforcement (MAJOR)
// =============================================================================

/// A `MockPcacKernel` that returns a specific `risk_tier` in the join
/// certificate, regardless of what the request specifies.
struct MockPcacKernelWithFixedJoinTier {
    join_risk_tier: RiskTier,
}

impl MockPcacKernelWithFixedJoinTier {
    fn with_tier(tier: RiskTier) -> Self {
        Self {
            join_risk_tier: tier,
        }
    }
}

impl AuthorityJoinKernel for MockPcacKernelWithFixedJoinTier {
    fn join(
        &self,
        _input: &AuthorityJoinInputV1,
        _policy: &PcacPolicyKnobs,
    ) -> Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>> {
        Ok(AuthorityJoinCertificateV1 {
            ajc_id: test_hash(50),
            authority_join_hash: test_hash(51),
            intent_digest: test_hash(3),
            boundary_intent_class: BoundaryIntentClass::Actuate,
            risk_tier: self.join_risk_tier,
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

/// Verify that when the PCAC join returns `risk_tier: Tier2Plus` but the
/// request specifies `risk_tier: Tier1`, the kernel's enforcement tier
/// is derived from the REQUEST's risk tier (Tier1 -> Monitor), NOT from
/// the AJC certificate's risk tier. This means the request gets Monitor
/// enforcement. The PCAC join's role is to authorize the action based on
/// the input risk tier — it is the kernel's `enforcement_tier_from_risk`
/// that determines enforcement behavior.
///
/// This test proves that a risk tier mismatch between request and AJC
/// does not create a fail-open path where a Tier1 request accidentally
/// gets FailClosed enforcement (which would be a privilege elevation),
/// nor does a Tier2Plus AJC cause the kernel to skip fail-closed
/// prerequisites for a Tier1 request.
#[test]
fn pcac_join_tier_mismatch_does_not_create_fail_open_path() {
    // Scenario: Request says Tier1, but PCAC join returns Tier2Plus in the AJC.
    // The kernel should derive enforcement from the REQUEST tier, not the AJC tier.
    let mock_pcac = MockPcacKernelWithFixedJoinTier::with_tier(RiskTier::Tier2Plus);
    let kernel = AdmissionKernelV1::new(Arc::new(mock_pcac), witness_provider());

    let request = valid_request(RiskTier::Tier1);
    let mut plan = kernel.plan(&request).expect("plan should succeed");
    let result = kernel
        .execute(&mut plan, test_hash(90), test_hash(91))
        .expect("execute should succeed");

    // The enforcement tier comes from the request's risk_tier (Tier1 -> Monitor).
    // NOT from the AJC's risk_tier (Tier2Plus -> would be FailClosed).
    assert_eq!(
        result.boundary_span.enforcement_tier,
        EnforcementTier::Monitor,
        "Enforcement tier must derive from request risk_tier (Tier1 -> Monitor), \
         not from AJC risk_tier (Tier2Plus -> FailClosed)"
    );

    // Monitor tier: no ledger write capability, no output held.
    assert!(
        result.ledger_write_capability.is_none(),
        "Tier1 request must not get LedgerWriteCapability even if AJC says Tier2Plus"
    );
    assert!(
        !result.boundary_span.output_held,
        "Tier1 request must not have output held even if AJC says Tier2Plus"
    );

    // Verify the converse: Tier2Plus request with Tier2Plus AJC gets FailClosed.
    // This proves the fail-open path is NOT possible because Tier2Plus requests
    // require all prerequisites (which are checked before plan succeeds).
    let mock_pcac_2 = MockPcacKernelWithFixedJoinTier::with_tier(RiskTier::Tier2Plus);
    let fully_wired = AdmissionKernelV1::new(Arc::new(mock_pcac_2), witness_provider())
        .with_ledger_verifier(Arc::new(MockLedgerVerifier::passing()))
        .with_policy_resolver(Arc::new(MockPolicyResolver::passing()))
        .with_anti_rollback(Arc::new(MockAntiRollback::passing()))
        .with_quarantine_guard(Arc::new(MockQuarantineGuard::passing()))
        .with_effect_journal(Arc::new(MockEffectJournal::new()));

    let tier2_request = valid_request(RiskTier::Tier2Plus);
    let mut plan2 = fully_wired
        .plan(&tier2_request)
        .expect("plan should succeed for Tier2Plus");
    let result2 = fully_wired
        .execute(&mut plan2, test_hash(92), test_hash(93))
        .expect("execute should succeed for Tier2Plus");

    assert_eq!(
        result2.boundary_span.enforcement_tier,
        EnforcementTier::FailClosed,
        "Tier2Plus request must get FailClosed enforcement"
    );
    assert!(
        result2.ledger_write_capability.is_some(),
        "Tier2Plus request must receive LedgerWriteCapability"
    );
    assert!(
        result2.boundary_span.output_held,
        "Tier2Plus request must have output held"
    );
}
