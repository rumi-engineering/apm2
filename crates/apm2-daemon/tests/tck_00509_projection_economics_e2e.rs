//! TCK-00509: End-to-end projection replay economics and lifecycle tests.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use apm2_core::crypto::{EventHasher, Hash, Signer};
use apm2_core::economics::{MultiSinkIdentitySnapshotV1, SinkIdentityEntry};
use apm2_core::pcac::{
    AuthorityJoinInputV1, BoundaryIntentClass, IdentityEvidenceLevel, PcacPolicyKnobs, RiskTier,
};
use apm2_daemon::pcac::{InProcessKernel, LifecycleGate};
use apm2_daemon::projection::continuity_resolver::{
    ResolvedContinuityProfile, ResolvedContinuityWindow,
};
use apm2_daemon::projection::intent_buffer::{IntentBuffer, IntentLifecycleArtifacts};
use apm2_daemon::projection::worker::AdmissionTelemetry;
use apm2_daemon::projection::{
    ContinuityProfileResolver, DENY_REPLAY_ECONOMICS_GATE, DENY_REPLAY_HORIZON_OUT_OF_WINDOW,
    DENY_REPLAY_LIFECYCLE_GATE, DENY_REPLAY_PROJECTION_EFFECT, DeferredReplayWorker,
    DeferredReplayWorkerConfig, IntentVerdict, ProjectionIntent, ReplayCycleResult,
    ReplayProjectionEffect,
};
use rusqlite::Connection;

const REPLAY_BATCH_SIZE: usize = 16;
const PRIVILEGED_REGISTER_RECOVERY_PREFIX: &str = "pcac-privileged-register-recovery-evidence";

const fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn domain_tagged_hash(handler_prefix: &str, hash_type: &str, data: &[&[u8]]) -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    let tag = format!("{handler_prefix}-{hash_type}-v1");
    hasher.update(tag.as_bytes());
    for chunk in data {
        hasher.update(chunk);
    }
    *hasher.finalize().as_bytes()
}

fn backlog_digest_from_digests(digests: &[&[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for digest in digests {
        hasher.update(*digest);
    }
    *hasher.finalize().as_bytes()
}

fn build_authority_join_input(
    intent_id: &str,
    work_id: &str,
    changeset_digest: &[u8; 32],
    ledger_head: &[u8; 32],
    eval_tick: u64,
    time_authority_ref: [u8; 32],
    revocation_head: [u8; 32],
) -> AuthorityJoinInputV1 {
    let intent_digest = EventHasher::hash_content(changeset_digest);
    let scope_witness_hash = EventHasher::hash_content(ledger_head);
    let freshness_policy_hash = EventHasher::hash_content(ledger_head);
    let freshness_tick = eval_tick.max(1);
    let capability_manifest_hash = EventHasher::hash_content(changeset_digest);
    let identity_proof_hash = EventHasher::hash_content(work_id.as_bytes());
    let ledger_anchor = EventHasher::hash_content(intent_id.as_bytes());

    let join_tick_bytes = freshness_tick.to_le_bytes();
    let leakage_witness_hash = domain_tagged_hash(
        PRIVILEGED_REGISTER_RECOVERY_PREFIX,
        "boundary_leakage_witness_hash",
        &[&intent_digest, &scope_witness_hash, &join_tick_bytes],
    );
    let timing_witness_hash = domain_tagged_hash(
        PRIVILEGED_REGISTER_RECOVERY_PREFIX,
        "boundary_timing_witness_hash",
        &[&time_authority_ref, &ledger_anchor, &join_tick_bytes],
    );

    AuthorityJoinInputV1 {
        session_id: intent_id.to_string(),
        holon_id: None,
        intent_digest,
        boundary_intent_class: BoundaryIntentClass::Actuate,
        capability_manifest_hash,
        scope_witness_hashes: vec![scope_witness_hash],
        lease_id: work_id.to_string(),
        permeability_receipt_hash: None,
        identity_proof_hash,
        identity_evidence_level: IdentityEvidenceLevel::Verified,
        pointer_only_waiver_hash: None,
        directory_head_hash: revocation_head,
        freshness_policy_hash,
        freshness_witness_tick: freshness_tick,
        stop_budget_profile_digest: capability_manifest_hash,
        pre_actuation_receipt_hashes: Vec::new(),
        leakage_witness_hash,
        timing_witness_hash,
        risk_tier: RiskTier::Tier2Plus,
        determinism_class: apm2_core::pcac::DeterminismClass::Deterministic,
        time_envelope_ref: time_authority_ref,
        as_of_ledger_anchor: ledger_anchor,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum ResolverMode {
    Allow,
    MissingProfile,
    MissingSnapshot,
}

struct TestContinuityResolver {
    mode: ResolverMode,
    profile: ResolvedContinuityProfile,
    window: ResolvedContinuityWindow,
    snapshot: MultiSinkIdentitySnapshotV1,
}

impl TestContinuityResolver {
    fn new(signer: &Signer) -> Self {
        let identities = vec![
            SinkIdentityEntry {
                sink_id: "sink-a".to_string(),
                identity_digest: EventHasher::hash_content(b"sink-a"),
            },
            SinkIdentityEntry {
                sink_id: "sink-b".to_string(),
                identity_digest: EventHasher::hash_content(b"sink-b"),
            },
        ];

        let mut snapshot = MultiSinkIdentitySnapshotV1 {
            sink_identities: identities,
            snapshot_digest: [0u8; 32],
        };
        snapshot.snapshot_digest = snapshot.compute_digest();

        Self {
            mode: ResolverMode::Allow,
            profile: ResolvedContinuityProfile {
                sink_id: "test-boundary".to_string(),
                outage_window_ticks: 2_000,
                replay_window_ticks: 1_000,
                churn_tolerance: 1,
                partition_tolerance: 1,
                trusted_signer_keys: vec![signer.public_key_bytes()],
            },
            window: ResolvedContinuityWindow {
                boundary_id: "test-boundary".to_string(),
                outage_window_ticks: 2_000,
                replay_window_ticks: 1_000,
            },
            snapshot,
        }
    }

    fn with_missing_profile(signer: &Signer) -> Self {
        let mut resolver = Self::new(signer);
        resolver.mode = ResolverMode::MissingProfile;
        resolver
    }

    fn with_missing_snapshot(signer: &Signer) -> Self {
        let mut resolver = Self::new(signer);
        resolver.mode = ResolverMode::MissingSnapshot;
        resolver
    }
}

impl ContinuityProfileResolver for TestContinuityResolver {
    fn resolve_continuity_profile(&self, _sink_id: &str) -> Option<ResolvedContinuityProfile> {
        match self.mode {
            ResolverMode::Allow | ResolverMode::MissingSnapshot => Some(self.profile.clone()),
            ResolverMode::MissingProfile => None,
        }
    }

    fn resolve_sink_snapshot(&self, _sink_id: &str) -> Option<MultiSinkIdentitySnapshotV1> {
        match self.mode {
            ResolverMode::Allow => Some(self.snapshot.clone()),
            ResolverMode::MissingProfile | ResolverMode::MissingSnapshot => None,
        }
    }

    fn resolve_continuity_window(&self, _boundary_id: &str) -> Option<ResolvedContinuityWindow> {
        Some(self.window.clone())
    }
}

struct SpyReplayProjectionEffect {
    calls: Arc<Mutex<Vec<String>>>,
    fail_reason: Arc<Mutex<Option<String>>>,
}

impl SpyReplayProjectionEffect {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            fail_reason: Arc::new(Mutex::new(None)),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .expect("projection call log lock should be available")
            .clone()
    }

    fn call_count(&self) -> usize {
        self.calls
            .lock()
            .expect("projection call log lock should be available")
            .len()
    }

    fn set_fail_reason(&self, reason: Option<&str>) {
        let mut lock = self
            .fail_reason
            .lock()
            .expect("projection fail reason lock should be available");
        *lock = reason.map(str::to_string);
    }

    fn never_called(&self) -> bool {
        self.calls().is_empty()
    }
}

impl ReplayProjectionEffect for SpyReplayProjectionEffect {
    fn execute_projection(
        &self,
        work_id: &str,
        _changeset_digest: [u8; 32],
        _ledger_head: [u8; 32],
        _status: apm2_daemon::projection::ProjectedStatus,
    ) -> Result<(), String> {
        self.calls
            .lock()
            .expect("projection call log lock should be available")
            .push(work_id.to_string());

        let fail_reason = self
            .fail_reason
            .lock()
            .expect("projection fail reason lock should be available")
            .clone();

        if let Some(reason) = fail_reason {
            return Err(reason);
        }

        Ok(())
    }
}

struct Harness {
    intent_conn: Arc<Mutex<Connection>>,
    intent_buffer: Arc<IntentBuffer>,
    resolver: Arc<dyn ContinuityProfileResolver>,
    gate_signer: Arc<Signer>,
    lifecycle_gate: Arc<LifecycleGate>,
    worker: DeferredReplayWorker,
    effect: Arc<SpyReplayProjectionEffect>,
    telemetry: Arc<AdmissionTelemetry>,
}

impl Harness {
    fn new(
        resolver: Arc<dyn ContinuityProfileResolver>,
        kernel_start_tick: u64,
        gate_signer: Arc<Signer>,
    ) -> Self {
        let intent_conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory DB should open"),
        ));
        let intent_buffer = Arc::new(
            IntentBuffer::new(Arc::clone(&intent_conn))
                .expect("intent buffer should initialize in-memory"),
        );
        let tick_kernel = Arc::new(InProcessKernel::new(kernel_start_tick));
        let kernel: Arc<dyn apm2_core::pcac::AuthorityJoinKernel> = tick_kernel.clone();
        let lifecycle_gate = Arc::new(LifecycleGate::with_tick_kernel(kernel, tick_kernel));
        let telemetry = Arc::new(AdmissionTelemetry::new());
        let effect = Arc::new(SpyReplayProjectionEffect::new());
        let effect_trait: Arc<dyn ReplayProjectionEffect> = effect.clone();
        let config =
            DeferredReplayWorkerConfig::new("test-boundary".to_string(), "test-actor".to_string())
                .with_batch_size(REPLAY_BATCH_SIZE);

        let worker = DeferredReplayWorker::new(
            config,
            Arc::clone(&intent_buffer),
            Arc::clone(&resolver),
            Arc::clone(&gate_signer),
            lifecycle_gate.clone(),
            telemetry.clone(),
            effect_trait,
        )
        .expect("deferred replay worker should initialize");

        Self {
            intent_conn,
            intent_buffer,
            resolver,
            gate_signer,
            lifecycle_gate,
            worker,
            effect,
            telemetry,
        }
    }

    fn reset_lifecycle_gate_for_replay(&mut self, kernel_start_tick: u64) {
        let tick_kernel = Arc::new(InProcessKernel::new(kernel_start_tick));
        let kernel: Arc<dyn apm2_core::pcac::AuthorityJoinKernel> = tick_kernel.clone();
        self.lifecycle_gate = Arc::new(LifecycleGate::with_tick_kernel(kernel, tick_kernel));
        let effect: Arc<dyn ReplayProjectionEffect> = self.effect.clone();
        self.worker = DeferredReplayWorker::new(
            self.worker.config().clone(),
            Arc::clone(&self.intent_buffer),
            Arc::clone(&self.resolver),
            Arc::clone(&self.gate_signer),
            Arc::clone(&self.lifecycle_gate),
            Arc::clone(&self.telemetry),
            effect,
        )
        .expect("replay worker should reinitialize for retry");
    }

    fn insert_intent(
        &self,
        intent_id: &str,
        work_id: &str,
        changeset_digest: [u8; 32],
        ledger_head: [u8; 32],
        eval_tick: u64,
    ) -> bool {
        self.intent_buffer
            .insert(
                intent_id,
                work_id,
                &changeset_digest,
                &ledger_head,
                "success",
                eval_tick,
                eval_tick,
            )
            .expect("insert should not fail")
    }

    fn insert_backlog(&self, intent_id: &str, work_id: &str, replay_horizon_tick: u64) -> bool {
        self.intent_buffer
            .insert_backlog(intent_id, work_id, &digest(0xAA), replay_horizon_tick)
            .expect("insert_backlog should not fail")
    }

    fn insert_intent_with_backlog(
        &self,
        intent_id: &str,
        work_id: &str,
        changeset: [u8; 32],
        ledger_head: [u8; 32],
        eval_tick: u64,
        replay_horizon_tick: u64,
    ) -> bool {
        if !self.insert_intent(intent_id, work_id, changeset, ledger_head, eval_tick) {
            return false;
        }

        assert!(
            self.insert_backlog(intent_id, work_id, replay_horizon_tick),
            "backlog insertion should succeed when intent insert succeeds"
        );

        true
    }

    fn drain(
        &self,
        current_tick: u64,
        time_authority_ref: [u8; 32],
        window_ref: [u8; 32],
        current_revocation_head: [u8; 32],
    ) -> ReplayCycleResult {
        self.worker
            .drain_cycle(
                current_tick,
                time_authority_ref,
                window_ref,
                current_revocation_head,
            )
            .expect("drain cycle should succeed")
    }

    fn intent(&self, intent_id: &str) -> Option<ProjectionIntent> {
        self.intent_buffer
            .get_intent(intent_id)
            .expect("intent lookup should not fail")
    }

    fn effect_calls(&self) -> Vec<String> {
        self.effect.calls()
    }

    fn set_effect_fail_reason(&self, reason: Option<&str>) {
        self.effect.set_fail_reason(reason);
    }

    fn reset_pending_for_replay(&self, intent_id: &str) {
        let conn = self
            .intent_conn
            .lock()
            .expect("intent DB lock should be available for state reset");
        conn.execute(
            "UPDATE projection_intents
             SET verdict = 'pending', deny_reason = ''
             WHERE intent_id = ?1",
            [intent_id],
        )
        .expect("intent should be moved back to pending state");

        conn.execute(
            "UPDATE deferred_replay_backlog
             SET converged = 0
             WHERE intent_id = ?1",
            [intent_id],
        )
        .expect("backlog should be re-armed for retry");
    }

    fn lifecycle_revoked_count(&self) -> u64 {
        self.telemetry
            .lifecycle_revoked_count
            .load(Ordering::Relaxed)
    }

    fn lifecycle_stale_count(&self) -> u64 {
        self.telemetry.lifecycle_stale_count.load(Ordering::Relaxed)
    }

    fn lifecycle_consumed_count(&self) -> u64 {
        self.telemetry
            .lifecycle_consumed_count
            .load(Ordering::Relaxed)
    }

    fn lifecycle_artifacts_direct(&self, intent_id: &str) -> Option<IntentLifecycleArtifacts> {
        let conn = self
            .intent_conn
            .lock()
            .expect("intent DB lock should be available for artifact query");
        let bytes_to_array = |v: Vec<u8>| -> Option<[u8; 32]> { v.as_slice().try_into().ok() };
        let row = conn
            .query_row(
                "SELECT lifecycle_ajc_id, lifecycle_intent_digest, lifecycle_consume_selector_digest, lifecycle_consume_tick, lifecycle_time_envelope_ref
                 FROM projection_intents
                 WHERE intent_id = ?1
                   AND lifecycle_ajc_id IS NOT NULL
                   AND lifecycle_intent_digest IS NOT NULL
                   AND lifecycle_consume_selector_digest IS NOT NULL
                   AND lifecycle_consume_tick IS NOT NULL
                   AND lifecycle_time_envelope_ref IS NOT NULL",
                [intent_id],
                |row| {
                    let ajc: Vec<u8> = row.get(0)?;
                    let intent: Vec<u8> = row.get(1)?;
                    let selector: Vec<u8> = row.get(2)?;
                    let tick: i64 = row.get(3)?;
                    let envelope: Vec<u8> = row.get(4)?;

                    Ok((
                        bytes_to_array(ajc),
                        bytes_to_array(intent),
                        bytes_to_array(selector),
                        tick,
                        bytes_to_array(envelope),
                    ))
                },
            )
            .ok()?;
        let (ajc_id, intent_digest, consume_selector_digest, consume_tick, time_envelope_ref) = row;
        let (
            Some(ajc_id),
            Some(intent_digest),
            Some(consume_selector_digest),
            Some(time_envelope_ref),
        ) = (
            ajc_id,
            intent_digest,
            consume_selector_digest,
            time_envelope_ref,
        )
        else {
            return None;
        };
        let consume_tick = u64::try_from(consume_tick).ok()?;

        Some(IntentLifecycleArtifacts {
            ajc_id,
            intent_digest,
            consume_selector_digest,
            consume_tick,
            time_envelope_ref,
        })
    }

    fn assert_no_projection_call(&self) {
        assert!(
            self.effect.never_called(),
            "projection effect must not be called"
        );
    }

    fn preconsume_intent_token(
        &self,
        intent_id: &str,
        eval_tick: u64,
        time_authority_ref: [u8; 32],
        revocation_head: [u8; 32],
    ) {
        let intent = self
            .intent(intent_id)
            .expect("intent should exist before preconsumption");

        let join_input = build_authority_join_input(
            &intent.intent_id,
            &intent.work_id,
            &intent.changeset_digest,
            &intent.ledger_head,
            eval_tick,
            time_authority_ref,
            revocation_head,
        );

        let policy = PcacPolicyKnobs::default();
        self.lifecycle_gate.advance_tick(eval_tick);
        let cert = self
            .lifecycle_gate
            .join_and_revalidate(
                &join_input,
                time_authority_ref,
                EventHasher::hash_content(intent.intent_id.as_bytes()),
                revocation_head,
                &policy,
            )
            .expect("join_and_revalidate should succeed for preconsume");

        self.lifecycle_gate.advance_tick(eval_tick);
        self.lifecycle_gate
            .revalidate_before_execution(
                &cert,
                time_authority_ref,
                EventHasher::hash_content(intent.intent_id.as_bytes()),
                revocation_head,
                &policy,
            )
            .expect("revalidate_before_execution should succeed for preconsume");

        self.lifecycle_gate.advance_tick(eval_tick);
        let (consumed_witness, consume_record) = self
            .lifecycle_gate
            .consume_before_effect(
                &cert,
                intent_digest_for_join(&intent),
                join_input.boundary_intent_class,
                true,
                time_authority_ref,
                revocation_head,
                &policy,
            )
            .expect("consume_before_effect should mark token consumed before drain");

        let _ = (consumed_witness, consume_record);
    }

    fn set_backlog_pending(&self, intent_id: &str) {
        let conn = self
            .intent_conn
            .lock()
            .expect("intent DB lock should be available for backlog mutation");
        conn.execute(
            "UPDATE deferred_replay_backlog
             SET converged = 0
             WHERE intent_id = ?1",
            [intent_id],
        )
        .expect("backlog entry should be made non-converged for replay attempt");
    }
}

fn intent_digest_for_join(intent: &ProjectionIntent) -> Hash {
    EventHasher::hash_content(&intent.changeset_digest)
}

fn ledger_anchor(intent_id: &str) -> Hash {
    EventHasher::hash_content(intent_id.as_bytes())
}

fn assert_projected_path(artifact: &IntentLifecycleArtifacts, intent: &ProjectionIntent) {
    assert_ne!(artifact.ajc_id, [0u8; 32]);
    assert_ne!(artifact.time_envelope_ref, [0u8; 32]);
    assert_eq!(artifact.intent_digest, intent_digest_for_join(intent));
}

fn assert_deny_with_reason(
    harness: &Harness,
    intent_id: &str,
    reason_prefix: &str,
    reason_substring: Option<&str>,
    result: &ReplayCycleResult,
) {
    let intent = harness
        .intent(intent_id)
        .expect("intent should still exist after deny path");
    assert!(
        result.denied_count > 0 || result.expired_count > 0,
        "expected at least one denied/expired intent: replayed={replayed}, skipped={skipped}, denied={denied}, expired={expired}, verdict={verdict}, reason={reason}",
        replayed = result.replayed_count,
        skipped = result.skipped_count,
        denied = result.denied_count,
        expired = result.expired_count,
        verdict = intent.verdict,
        reason = intent.deny_reason,
    );
    assert_eq!(intent.verdict, IntentVerdict::Denied);
    assert!(
        intent.deny_reason.contains(reason_prefix),
        "unexpected deny reason: {}",
        intent.deny_reason
    );

    if let Some(reason_substring) = reason_substring {
        let reason_lower = intent.deny_reason.to_lowercase();
        let has_substring = match reason_substring {
            "revoked" => reason_lower.contains("revoked") || reason_lower.contains("revocation"),
            "stale" => {
                reason_lower.contains("stale")
                    || reason_lower.contains("freshness")
                    || reason_lower.contains("expired")
            },
            "consumed" => reason_lower.contains("consumed"),
            other => reason_lower.contains(other),
        };
        assert!(
            has_substring,
            "deny reason must contain `{reason_substring}`: {}",
            intent.deny_reason
        );
    }
}

#[test]
fn test_happy_path_economics_allow_lifecycle_allow_projects() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let revocation_head = digest(0x55);

    let inserted = harness.insert_intent_with_backlog(
        "intent-happy-001",
        "work-happy-001",
        digest(0x10),
        digest(0x55),
        100,
        100,
    );
    assert!(inserted);

    let result = harness.drain(100, digest(0xAA), digest(0xBB), revocation_head);

    assert!(result.replayed_count > 0);
    let calls = harness.effect_calls();
    assert_eq!(calls.as_slice(), ["work-happy-001"]);

    let intent = harness
        .intent("intent-happy-001")
        .expect("intent should exist");
    assert_eq!(intent.verdict, IntentVerdict::Admitted);
    assert!(result.converged);

    let artifacts = harness
        .lifecycle_artifacts_direct("intent-happy-001")
        .expect("lifecycle artifacts should be attached");
    assert_projected_path(&artifacts, &intent);
}

#[test]
fn test_deny_stale_temporal_authority() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let stale_before = harness.lifecycle_stale_count();
    let revoked_before = harness.lifecycle_revoked_count();
    let consumed_before = harness.lifecycle_consumed_count();
    let stale_eval_tick = 10u64;
    let revocation_head = digest(0x56);
    let inserted = harness.insert_intent_with_backlog(
        "intent-stale-temporal-001",
        "work-stale-temporal-001",
        digest(0x11),
        revocation_head,
        stale_eval_tick,
        stale_eval_tick,
    );
    assert!(inserted);

    let stale_replay_tick =
        stale_eval_tick + PcacPolicyKnobs::default().freshness_max_age_ticks + 1;

    let result = harness.drain(
        stale_replay_tick,
        digest(0xAA),
        digest(0xBB),
        revocation_head,
    );

    assert_deny_with_reason(
        &harness,
        "intent-stale-temporal-001",
        DENY_REPLAY_LIFECYCLE_GATE,
        Some("stale"),
        &result,
    );
    assert_eq!(harness.lifecycle_stale_count(), stale_before + 1);
    assert_eq!(harness.lifecycle_revoked_count(), revoked_before);
    assert_eq!(harness.lifecycle_consumed_count(), consumed_before);
}

#[test]
fn test_deny_missing_continuity_profile() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::with_missing_profile(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let revocation_head = digest(0x57);

    let inserted = harness.insert_intent_with_backlog(
        "intent-missing-profile-001",
        "work-missing-profile-001",
        digest(0x12),
        revocation_head,
        100,
        100,
    );
    assert!(inserted);

    let result = harness.drain(100, digest(0xAA), digest(0xBB), revocation_head);

    assert_deny_with_reason(
        &harness,
        "intent-missing-profile-001",
        DENY_REPLAY_ECONOMICS_GATE,
        None,
        &result,
    );
    harness.assert_no_projection_call();
}

#[test]
fn test_deny_missing_snapshot() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::with_missing_snapshot(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let revocation_head = digest(0x67);

    let inserted = harness.insert_intent_with_backlog(
        "intent-missing-snapshot-001",
        "work-missing-snapshot-001",
        digest(0x1C),
        revocation_head,
        100,
        100,
    );
    assert!(inserted);

    let result = harness.drain(100, digest(0xAA), digest(0xBB), revocation_head);

    assert_deny_with_reason(
        &harness,
        "intent-missing-snapshot-001",
        DENY_REPLAY_ECONOMICS_GATE,
        Some("snapshot"),
        &result,
    );
    harness.assert_no_projection_call();
}

#[test]
fn test_lifecycle_deny_revoked_authority() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let revoked_before = harness.lifecycle_revoked_count();
    let stale_before = harness.lifecycle_stale_count();
    let consumed_before = harness.lifecycle_consumed_count();
    let revoked_ledger_head = digest(0x58);

    let issued_revocation_head = revoked_ledger_head;
    let current_revocation_head = ledger_anchor("intent-revoked-001-current");

    let inserted = harness.insert_intent_with_backlog(
        "intent-revoked-001",
        "work-revoked-001",
        digest(0x13),
        revoked_ledger_head,
        100,
        100,
    );
    assert!(inserted);

    harness.preconsume_intent_token(
        "intent-revoked-001",
        100,
        digest(0xAA),
        issued_revocation_head,
    );

    let result = harness.drain(100, digest(0xAA), digest(0xBB), current_revocation_head);

    assert_deny_with_reason(
        &harness,
        "intent-revoked-001",
        DENY_REPLAY_LIFECYCLE_GATE,
        Some("revoked"),
        &result,
    );
    assert_eq!(harness.lifecycle_revoked_count(), revoked_before + 1);
    assert_eq!(harness.lifecycle_stale_count(), stale_before);
    assert_eq!(harness.lifecycle_consumed_count(), consumed_before);
}

#[test]
fn test_lifecycle_deny_consumed_token() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let revoked_before = harness.lifecycle_revoked_count();
    let stale_before = harness.lifecycle_stale_count();
    let revocation_head = digest(0x59);

    let inserted = harness.insert_intent_with_backlog(
        "intent-consumed-001",
        "work-consumed-001",
        digest(0x14),
        revocation_head,
        200,
        200,
    );
    assert!(inserted);

    let preconsume_tick = 200;
    let time_authority_ref = digest(0xAA);

    // Pre-consume the lifecycle token in the same gate before replay.
    harness.preconsume_intent_token(
        "intent-consumed-001",
        preconsume_tick,
        time_authority_ref,
        revocation_head,
    );

    let result = harness.drain(
        preconsume_tick,
        time_authority_ref,
        digest(0xBB),
        revocation_head,
    );

    assert_deny_with_reason(
        &harness,
        "intent-consumed-001",
        DENY_REPLAY_LIFECYCLE_GATE,
        Some("consumed"),
        &result,
    );
    assert_eq!(harness.lifecycle_consumed_count(), 1);
    assert_eq!(harness.lifecycle_revoked_count(), revoked_before);
    assert_eq!(harness.lifecycle_stale_count(), stale_before);
}

#[test]
fn test_lifecycle_deny_stale_authority_freshness() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let stale_before = harness.lifecycle_stale_count();
    let revoked_before = harness.lifecycle_revoked_count();
    let consumed_before = harness.lifecycle_consumed_count();
    let eval_tick = 150u64;
    let revocation_head = digest(0x5A);

    let inserted = harness.insert_intent_with_backlog(
        "intent-stale-freshness-001",
        "work-stale-freshness-001",
        digest(0x15),
        revocation_head,
        eval_tick,
        eval_tick,
    );
    assert!(inserted);

    let stale_replay_tick = eval_tick + PcacPolicyKnobs::default().freshness_max_age_ticks + 1;

    let result = harness.drain(
        stale_replay_tick,
        digest(0xAA),
        digest(0xBB),
        revocation_head,
    );

    assert_deny_with_reason(
        &harness,
        "intent-stale-freshness-001",
        DENY_REPLAY_LIFECYCLE_GATE,
        Some("stale"),
        &result,
    );
    assert_eq!(harness.lifecycle_stale_count(), stale_before + 1);
    assert_eq!(harness.lifecycle_revoked_count(), revoked_before);
    assert_eq!(harness.lifecycle_consumed_count(), consumed_before);
}

#[test]
fn test_outage_recovery_replay_in_order() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let mut harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let replay_tick = 300u64;
    let current_revocation_head = digest(0x60);
    let authority_ref = digest(0xAA);
    let window_ref = digest(0xBB);

    let intents = [
        (
            "intent-order-001",
            "work-order-001",
            digest(0x16),
            current_revocation_head,
        ),
        (
            "intent-order-002",
            "work-order-002",
            digest(0x17),
            current_revocation_head,
        ),
        (
            "intent-order-003",
            "work-order-003",
            digest(0x18),
            current_revocation_head,
        ),
    ];

    let replay_horizon_tick = replay_tick - 1;
    for (intent_id, work_id, digest, ledger_head) in intents {
        assert!(harness.insert_intent_with_backlog(
            intent_id,
            work_id,
            digest,
            ledger_head,
            replay_tick,
            replay_horizon_tick,
        ));
    }

    harness.set_effect_fail_reason(Some("outage: sink unavailable"));
    let pending_before_first_outage = harness
        .intent_buffer
        .query_pending_backlog(10)
        .expect("pending backlog should be queryable before outage drain");
    assert_eq!(pending_before_first_outage.len(), 3);

    let first = harness.drain(
        replay_tick,
        authority_ref,
        window_ref,
        current_revocation_head,
    );

    assert_eq!(first.denied_count, 3);
    assert_eq!(first.replayed_count, 0);
    assert!(first.converged);
    assert!(first.convergence_receipt.is_some());
    let first_receipt = first
        .convergence_receipt
        .expect("failed outage drain should still emit receipt");
    assert_eq!(first_receipt.boundary_id, "test-boundary");
    assert_eq!(first_receipt.backlog_digest, first.backlog_digest);
    assert_eq!(first_receipt.replayed_item_count, 0);
    assert!(first_receipt.converged);

    let outage_calls = harness.effect_calls();
    assert_eq!(
        outage_calls,
        vec![
            "work-order-001".to_string(),
            "work-order-002".to_string(),
            "work-order-003".to_string(),
        ]
    );

    let denied_after_outage = harness
        .intent_buffer
        .query_by_verdict(IntentVerdict::Denied, 10)
        .expect("denied intents should be queryable after projection outage");
    assert_eq!(denied_after_outage.len(), 3);

    let pending_after_outage = harness
        .intent_buffer
        .query_pending_backlog(10)
        .expect("pending backlog query should succeed");
    assert!(pending_after_outage.is_empty());

    for intent_id in ["intent-order-001", "intent-order-002", "intent-order-003"] {
        let intent = harness.intent(intent_id).expect("intent should exist");
        assert_eq!(intent.verdict, IntentVerdict::Denied);
        assert!(intent.deny_reason.contains(DENY_REPLAY_PROJECTION_EFFECT));
    }

    let denied_calls = harness.effect_calls();
    assert_eq!(denied_calls.len(), 3);

    harness.set_effect_fail_reason(None);

    for intent_id in ["intent-order-001", "intent-order-002", "intent-order-003"] {
        harness.reset_pending_for_replay(intent_id);
    }
    harness.reset_lifecycle_gate_for_replay(replay_tick);

    let pending_after_reset = harness
        .intent_buffer
        .query_pending_backlog(10)
        .expect("pending backlog query should show replay-ready intents");
    assert_eq!(pending_after_reset.len(), 3);

    let second = harness.drain(
        replay_tick,
        authority_ref,
        window_ref,
        current_revocation_head,
    );

    assert_eq!(second.replayed_count, 3);
    assert!(second.converged);
    assert_eq!(
        second.denied_count, 0,
        "recovery pass should not deny replayed intents"
    );

    let calls = harness.effect_calls();
    assert_eq!(
        calls,
        vec![
            "work-order-001".to_string(),
            "work-order-002".to_string(),
            "work-order-003".to_string(),
            "work-order-001".to_string(),
            "work-order-002".to_string(),
            "work-order-003".to_string(),
        ]
    );

    assert_eq!(
        second.backlog_digest,
        backlog_digest_from_digests(&[&digest(0x16), &digest(0x17), &digest(0x18),])
    );

    let receipt = second
        .convergence_receipt
        .expect("recovery cycle should emit receipt");
    assert_eq!(receipt.replayed_item_count, 3);
    assert!(receipt.converged);
    assert_eq!(receipt.backlog_digest, second.backlog_digest);
    assert_eq!(receipt.boundary_id, "test-boundary");
    assert_eq!(second.denied_count, 0);
}

#[test]
fn test_outage_revoked_authority_replay_deny() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let revoked_before = harness.lifecycle_revoked_count();
    let revoked_ledger_head = digest(0x64);

    let inserted = harness.insert_intent_with_backlog(
        "intent-outage-revoked-001",
        "work-outage-revoked-001",
        digest(0x19),
        revoked_ledger_head,
        400,
        400,
    );
    assert!(inserted);

    let issued_revocation_head = revoked_ledger_head;
    let current_revocation_head = ledger_anchor("intent-outage-revoked-001-current");

    harness.preconsume_intent_token(
        "intent-outage-revoked-001",
        400,
        digest(0xAA),
        issued_revocation_head,
    );

    let result = harness.drain(400, digest(0xAA), digest(0xBB), current_revocation_head);

    assert_deny_with_reason(
        &harness,
        "intent-outage-revoked-001",
        DENY_REPLAY_LIFECYCLE_GATE,
        Some("revoked"),
        &result,
    );
    assert_eq!(harness.lifecycle_revoked_count(), revoked_before + 1);
}

#[test]
fn test_window_expiration() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let revocation_head = digest(0x65);

    let inserted = harness.insert_intent_with_backlog(
        "intent-expired-001",
        "work-expired-001",
        digest(0x1A),
        revocation_head,
        5,
        5,
    );
    assert!(inserted);

    // Resolver replay window is 1_000 ticks, so this is far beyond window
    // and should expire as DENY_REPLAY_HORIZON_OUT_OF_WINDOW.
    let result = harness.drain(5_000, digest(0xAA), digest(0xBB), revocation_head);

    let intent = harness
        .intent("intent-expired-001")
        .expect("intent should exist");
    assert_eq!(intent.verdict, IntentVerdict::Denied);
    assert!(result.denied_count > 0 || result.expired_count > 0);
    assert!(
        intent
            .deny_reason
            .contains(DENY_REPLAY_HORIZON_OUT_OF_WINDOW)
    );
    harness.assert_no_projection_call();
}

#[test]
fn test_idempotency_same_work_changeset() {
    let signer = Arc::new(Signer::generate());
    let resolver = Arc::new(TestContinuityResolver::new(&signer));
    let harness = Harness::new(resolver, 0, Arc::clone(&signer));
    let revocation_head = digest(0x66);

    assert!(harness.insert_intent_with_backlog(
        "intent-idempotent-001",
        "work-idempotent",
        digest(0x1B),
        revocation_head,
        600,
        600,
    ));

    let second = harness.insert_intent(
        "intent-idempotent-002",
        "work-idempotent",
        digest(0x1B),
        revocation_head,
        600,
    );
    assert!(!second, "same (work_id, changeset) must be rejected");

    let first = harness.drain(600, digest(0xAA), digest(0xBB), revocation_head);

    assert_eq!(first.replayed_count, 1);
    assert_eq!(harness.effect.call_count(), 1);
    assert!(first.convergence_receipt.is_some());
    let first_receipt = first
        .convergence_receipt
        .expect("initial run should emit convergence receipt");
    assert_eq!(first_receipt.replayed_item_count, 1);
    assert!(first_receipt.converged);

    harness.set_backlog_pending("intent-idempotent-001");

    let second = harness.drain(600, digest(0xAA), digest(0xBB), revocation_head);

    assert_eq!(second.skipped_count, 1);
    assert_eq!(second.replayed_count, 0);
    assert_eq!(second.denied_count, 0);
    assert!(second.convergence_receipt.is_some());
    let second_receipt = second
        .convergence_receipt
        .expect("second run should emit convergence receipt");
    assert_eq!(second_receipt.replayed_item_count, 0);
    assert!(second_receipt.converged);
    assert_eq!(harness.effect.call_count(), 1);

    let intent = harness
        .intent("intent-idempotent-001")
        .expect("intent should exist");
    assert_eq!(intent.verdict, IntentVerdict::Admitted);

    let maybe_already_projected = harness
        .intent_buffer
        .query_by_verdict(IntentVerdict::Admitted, 10)
        .expect("query by verdict should succeed")
        .into_iter()
        .any(|i| i.intent_id == "intent-idempotent-001");
    assert!(maybe_already_projected);
}
