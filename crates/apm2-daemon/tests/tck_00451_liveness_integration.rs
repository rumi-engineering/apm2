#![allow(missing_docs)]

use std::sync::Arc;

use apm2_core::crypto::Signer;
use apm2_core::liveness::{
    HealthVerdict, LivenessDenialReason, LivenessHeartbeatReceiptV1, check_liveness_for_progression,
};
use apm2_daemon::gate::{GateOrchestrator, GateOrchestratorConfig};
use apm2_daemon::protocol::dispatch::build_liveness_heartbeat;

#[test]
fn test_orchestrator_denies_progression_on_stale_heartbeat() {
    let orchestrator = GateOrchestrator::new(
        GateOrchestratorConfig {
            max_heartbeat_age_ticks: 5,
            ..GateOrchestratorConfig::default()
        },
        Arc::new(Signer::generate()),
    );

    let heartbeat = LivenessHeartbeatReceiptV1 {
        run_id: "run-integration-001".to_string(),
        episode_id: [0x11; 32],
        emitted_at_tick: 10,
        time_envelope_ref: [0x22; 32],
        health_verdict: HealthVerdict::Healthy,
        restart_count: 0,
        max_restarts: 3,
        uptime_ms: 1_000,
        detail: Some("ok".to_string()),
    };

    let denial = orchestrator
        .check_liveness_gate(&heartbeat, 20)
        .expect_err("stale heartbeat must deny progression");
    assert_eq!(denial.reason, LivenessDenialReason::StaleHeartbeat);
}

#[test]
fn test_dispatch_builds_valid_heartbeat() {
    let episode_id = [0xAB; 32];
    let heartbeat =
        build_liveness_heartbeat(&episode_id, "run-dispatch-001", 42, HealthVerdict::Healthy);

    assert_eq!(heartbeat.run_id, "run-dispatch-001");
    assert_eq!(heartbeat.episode_id, episode_id);
    assert_eq!(heartbeat.emitted_at_tick, 42);
    assert_eq!(heartbeat.time_envelope_ref, episode_id);
    assert_eq!(heartbeat.health_verdict, HealthVerdict::Healthy);
    assert_eq!(heartbeat.restart_count, 0);
    assert!(heartbeat.max_restarts > 0);
    assert!(heartbeat.has_valid_bounds());

    check_liveness_for_progression(&heartbeat, 43, 10)
        .expect("fresh healthy heartbeat from dispatcher must be accepted");
}
