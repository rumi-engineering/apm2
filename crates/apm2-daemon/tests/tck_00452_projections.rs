//! TCK-00452: Auditor/Orchestrator launch projection integration tests.
//!
//! Validates digest-first determinism, replay-consistent projection payloads,
//! and fail-closed uncertainty semantics when lineage/liveness evidence is
//! missing.

use std::collections::BTreeSet;

use apm2_core::fac::{AuditorLaunchProjectionV1, OrchestratorLaunchProjectionV1};
use apm2_daemon::protocol::dispatch::PrivilegedPcacLifecycleArtifacts;
use apm2_daemon::protocol::{
    AuditorLaunchProjectionRequest, ConnectionContext, OrchestratorLaunchProjectionRequest,
    PeerCredentials, PrivilegedDispatcher, PrivilegedResponse, ProjectionUncertaintyFlag,
    encode_auditor_launch_projection_request, encode_orchestrator_launch_projection_request,
};

fn privileged_ctx() -> ConnectionContext {
    ConnectionContext::privileged_session_open(Some(PeerCredentials {
        uid: 1000,
        gid: 1000,
        pid: Some(4520),
    }))
}

const fn hash32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn assert_digest_matches(digest: &[u8], canonical_projection_json: &[u8]) {
    assert_eq!(
        digest.len(),
        32,
        "projection_digest must be exactly 32 bytes"
    );
    assert_eq!(
        digest,
        blake3::hash(canonical_projection_json).as_bytes(),
        "projection_digest must match canonical_projection_json hash"
    );
}

fn decode_uncertainty_flags(raw_flags: &[i32]) -> BTreeSet<ProjectionUncertaintyFlag> {
    raw_flags
        .iter()
        .map(|raw| {
            ProjectionUncertaintyFlag::try_from(*raw)
                .expect("projection uncertainty flag should decode")
        })
        .collect()
}

fn emit_review_receipt_with_tick(
    dispatcher: &PrivilegedDispatcher,
    receipt_id: &str,
    consume_tick: u64,
    timestamp_ns: u64,
) {
    let lifecycle = PrivilegedPcacLifecycleArtifacts {
        ajc_id: hash32(0x61),
        intent_digest: hash32(0x62),
        consume_tick,
        time_envelope_ref: hash32(0x63),
        consume_selector_digest: hash32(0x64),
    };

    dispatcher
        .event_emitter()
        .emit_review_receipt(
            "LEASE-TCK-00452",
            receipt_id,
            &hash32(0x11),
            &hash32(0x12),
            &hash32(0x13),
            &hash32(0x14),
            &hash32(0x15),
            "actor:reviewer",
            timestamp_ns,
            &hash32(0x16),
            "cas://time-envelope/00452",
            Some(&lifecycle),
        )
        .expect("review receipt event should persist");
}

#[test]
fn test_auditor_projection_is_digest_first_and_replay_consistent() {
    let dispatcher = PrivilegedDispatcher::new();
    emit_review_receipt_with_tick(&dispatcher, "RCP-00452-001", 41, 1_000_000_000);

    let request = AuditorLaunchProjectionRequest {};
    let frame = encode_auditor_launch_projection_request(&request);

    let first = match dispatcher
        .dispatch(&frame, &privileged_ctx())
        .expect("auditor projection request should dispatch")
    {
        PrivilegedResponse::AuditorLaunchProjection(resp) => resp,
        other => panic!("expected AuditorLaunchProjection response, got: {other:?}"),
    };

    let second = match dispatcher
        .dispatch(&frame, &privileged_ctx())
        .expect("auditor projection request should dispatch")
    {
        PrivilegedResponse::AuditorLaunchProjection(resp) => resp,
        other => panic!("expected AuditorLaunchProjection response, got: {other:?}"),
    };

    assert_eq!(
        first, second,
        "replaying the same ledger state must produce identical auditor projection payloads"
    );
    assert_digest_matches(&first.projection_digest, &first.canonical_projection_json);
    assert_eq!(first.authoritative_receipt_count, 1);
    assert_eq!(first.complete_lineage_receipt_count, 1);
    assert_eq!(first.boundary_conformant_receipt_count, 1);
    assert!(first.lineage_complete);
    assert!(first.boundary_conformant);
    assert!(first.uncertainty_flags.is_empty());
    assert!(first.admissible);

    let canonical_projection: AuditorLaunchProjectionV1 =
        serde_json::from_slice(&first.canonical_projection_json)
            .expect("canonical projection JSON should decode");
    assert_eq!(
        canonical_projection.authoritative_receipt_count,
        first.authoritative_receipt_count
    );
    assert_eq!(
        canonical_projection.complete_lineage_receipt_count,
        first.complete_lineage_receipt_count
    );
    assert_eq!(
        canonical_projection.boundary_conformant_receipt_count,
        first.boundary_conformant_receipt_count
    );
    assert_eq!(canonical_projection.admissible, first.admissible);
}

#[test]
fn test_projections_fail_closed_when_evidence_is_missing() {
    let dispatcher = PrivilegedDispatcher::new();

    let auditor = match dispatcher
        .dispatch(
            &encode_auditor_launch_projection_request(&AuditorLaunchProjectionRequest {}),
            &privileged_ctx(),
        )
        .expect("auditor projection request should dispatch")
    {
        PrivilegedResponse::AuditorLaunchProjection(resp) => resp,
        other => panic!("expected AuditorLaunchProjection response, got: {other:?}"),
    };
    assert_digest_matches(
        &auditor.projection_digest,
        &auditor.canonical_projection_json,
    );
    assert_eq!(auditor.authoritative_receipt_count, 0);
    assert!(!auditor.lineage_complete);
    assert!(!auditor.boundary_conformant);
    assert!(!auditor.admissible);

    let mut expected_auditor_flags = BTreeSet::new();
    expected_auditor_flags.insert(ProjectionUncertaintyFlag::MissingLineageEvidence);
    expected_auditor_flags.insert(ProjectionUncertaintyFlag::BoundaryConformanceUnverifiable);
    assert_eq!(
        decode_uncertainty_flags(&auditor.uncertainty_flags),
        expected_auditor_flags,
        "auditor projection must fail closed on missing lineage/boundary evidence"
    );

    let orchestrator = match dispatcher
        .dispatch(
            &encode_orchestrator_launch_projection_request(&OrchestratorLaunchProjectionRequest {}),
            &privileged_ctx(),
        )
        .expect("orchestrator projection request should dispatch")
    {
        PrivilegedResponse::OrchestratorLaunchProjection(resp) => resp,
        other => panic!("expected OrchestratorLaunchProjection response, got: {other:?}"),
    };
    assert_digest_matches(
        &orchestrator.projection_digest,
        &orchestrator.canonical_projection_json,
    );
    assert_eq!(orchestrator.active_runs, 0);
    assert_eq!(orchestrator.last_authoritative_receipt_tick, None);
    assert_eq!(orchestrator.restart_count, 0);
    assert!(!orchestrator.admissible);

    let mut expected_orchestrator_flags = BTreeSet::new();
    expected_orchestrator_flags.insert(ProjectionUncertaintyFlag::MissingLivenessEvidence);
    expected_orchestrator_flags.insert(ProjectionUncertaintyFlag::MissingAuthoritativeReceiptTick);
    assert_eq!(
        decode_uncertainty_flags(&orchestrator.uncertainty_flags),
        expected_orchestrator_flags,
        "orchestrator projection must fail closed on missing liveness/receipt tick evidence"
    );
}

#[test]
fn test_orchestrator_projection_reports_liveness_tick_restart_and_is_deterministic() {
    let dispatcher = PrivilegedDispatcher::new();
    let role_spec_hash = hash32(0x46);

    dispatcher
        .event_emitter()
        .emit_session_started(
            "sess-00452-A",
            "W-00452",
            "LEASE-TCK-00452",
            "actor:orchestrator",
            &hash32(0x45),
            Some(&role_spec_hash),
            1_000_000_100,
            None,
            None,
            None,
        )
        .expect("first session_started should persist");
    dispatcher
        .event_emitter()
        .emit_session_started(
            "sess-00452-B",
            "W-00452",
            "LEASE-TCK-00452",
            "actor:orchestrator",
            &hash32(0x47),
            Some(&role_spec_hash),
            1_000_000_200,
            None,
            None,
            None,
        )
        .expect("second session_started should persist");
    dispatcher
        .event_emitter()
        .emit_session_terminated(
            "sess-00452-A",
            "W-00452",
            1,
            "non-zero exit to count restart",
            "actor:orchestrator",
            1_000_000_300,
        )
        .expect("session_terminated should persist");

    emit_review_receipt_with_tick(&dispatcher, "RCP-00452-101", 77, 1_000_000_400);
    emit_review_receipt_with_tick(&dispatcher, "RCP-00452-102", 99, 1_000_000_500);

    let frame =
        encode_orchestrator_launch_projection_request(&OrchestratorLaunchProjectionRequest {});

    let first = match dispatcher
        .dispatch(&frame, &privileged_ctx())
        .expect("orchestrator projection request should dispatch")
    {
        PrivilegedResponse::OrchestratorLaunchProjection(resp) => resp,
        other => panic!("expected OrchestratorLaunchProjection response, got: {other:?}"),
    };
    let second = match dispatcher
        .dispatch(&frame, &privileged_ctx())
        .expect("orchestrator projection request should dispatch")
    {
        PrivilegedResponse::OrchestratorLaunchProjection(resp) => resp,
        other => panic!("expected OrchestratorLaunchProjection response, got: {other:?}"),
    };

    assert_eq!(
        first, second,
        "replaying the same ledger state must produce identical orchestrator projection payloads"
    );
    assert_digest_matches(&first.projection_digest, &first.canonical_projection_json);
    assert_eq!(first.active_runs, 1);
    assert_eq!(first.last_authoritative_receipt_tick, Some(99));
    assert_eq!(first.restart_count, 1);
    assert!(first.uncertainty_flags.is_empty());
    assert!(first.admissible);

    let canonical_projection: OrchestratorLaunchProjectionV1 =
        serde_json::from_slice(&first.canonical_projection_json)
            .expect("canonical projection JSON should decode");
    assert_eq!(canonical_projection.active_runs, first.active_runs);
    assert_eq!(
        canonical_projection.last_authoritative_receipt_tick,
        first.last_authoritative_receipt_tick
    );
    assert_eq!(canonical_projection.restart_count, first.restart_count);
    assert_eq!(canonical_projection.admissible, first.admissible);
}
