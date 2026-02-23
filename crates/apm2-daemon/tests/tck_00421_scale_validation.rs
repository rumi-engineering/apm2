//! TCK-00421: Digest-first scale validation.
//!
//! Validates:
//! - Summary-first supervision with selector-first retrieval at high evidence
//!   fan-out
//! - Bounded control-plane payload/queue behavior with explicit backpressure
//!   accounting
//! - Replay + anti-entropy projection recovery under loss/retry without
//!   duplicate side-effects

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use apm2_core::consensus::{AntiEntropyError, SyncEvent, verify_sync_catchup};
use apm2_core::crypto::{EventHasher, Hash, Signer, VerifyingKey};
use apm2_core::fac::{LossProfile, ReviewOutcome, SummaryReceipt, SummaryReceiptBuilder};
use apm2_core::ledger::{COMMIT_NOTIFICATION_CHANNEL_CAPACITY, CommitNotification, EventRecord};
use apm2_core::pcac::{AuthorityJoinKernel, RiskTier, VerifierEconomicsProfile};
use apm2_core::reducer::{Reducer, ReducerContext};
use apm2_core::work::{ReplayEquivalenceChecker, WorkReducer, WorkReducerState, helpers};
use apm2_daemon::pcac::{InProcessKernel, LifecycleGate};
use apm2_daemon::protocol::{
    ResourceError, ResourceQuotaConfig, SubscriptionRegistry, SubscriptionState, TopicPattern,
    create_commit_notification_channel,
};
use serde::Serialize;

const SCALE_RECEIPT_COUNT: usize = 2_048;
const SELECTORS_PER_RECEIPT: usize = 8;
const SIMULATED_TRANSCRIPT_BYTES_PER_RECEIPT: usize = 16 * 1024;
const CONTROL_PLANE_CHANNEL_OVERFLOW_ATTEMPTS: usize = 128;

#[derive(Debug)]
struct SummaryScaleFixture {
    receipts: Vec<SummaryReceipt>,
    selector_index: HashMap<String, Vec<usize>>,
    verifying_key: VerifyingKey,
    simulated_transcript_bytes: usize,
}

#[derive(Debug, Serialize)]
struct SummaryScaleEvidence {
    receipt_count: usize,
    selector_count: usize,
    summary_total_bytes: usize,
    simulated_transcript_total_bytes: usize,
    selector_query_match_count: usize,
    selector_query_candidates_scanned: usize,
    selector_query_p95_us: u64,
    selector_query_id_digest: String,
}

#[derive(Debug, Default, Serialize)]
struct ControlPlaneEvidence {
    reserve_attempts: usize,
    reserve_successes: usize,
    payload_rejections: usize,
    queue_full_rejections: usize,
    bytes_rejections: usize,
    rate_rejections: usize,
    channel_queue_accepts: usize,
    channel_backpressure_drops: usize,
    max_observed_queue_depth: usize,
    max_observed_bytes_in_flight: usize,
}

#[derive(Debug, Serialize)]
struct ReplayRecoveryEvidence {
    projection_loss_prefix_len: usize,
    anti_entropy_batch_len: usize,
    replay_deduplicated_events: usize,
    replay_applied_events: usize,
    replay_duplicate_side_effects: usize,
    replay_matches_expected: bool,
    anti_entropy_corruption_detected: bool,
}

#[derive(Clone, Copy)]
enum ControlPlaneAction {
    Reserve(usize),
    DequeueOne,
}

fn blake3_hash(input: impl AsRef<[u8]>) -> Hash {
    *blake3::hash(input.as_ref()).as_bytes()
}

fn elapsed_us_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn p95(samples: &mut [u64]) -> u64 {
    assert!(!samples.is_empty(), "p95 requires non-empty sample set");
    samples.sort_unstable();
    let idx = ((samples.len() * 95).div_ceil(100)).saturating_sub(1);
    samples[idx]
}

fn build_summary_scale_fixture(
    receipt_count: usize,
    selectors_per_receipt: usize,
) -> SummaryScaleFixture {
    let signer = Signer::generate();
    let verifying_key = signer.verifying_key();

    let mut receipts = Vec::with_capacity(receipt_count);
    let mut selector_index: HashMap<String, Vec<usize>> = HashMap::new();

    for i in 0..receipt_count {
        let gate_selector = match i % 3 {
            0 => "gate:aat",
            1 => "gate:quality",
            _ => "gate:security",
        };
        let tier_selector = match i % 3 {
            0 => "tier:0",
            1 => "tier:1",
            _ => "tier:2",
        };
        let phase_selector = format!("phase:{}", i % 8);
        let work_selector = format!("work:{}", i % 256);

        let mut selectors = vec![
            gate_selector.to_string(),
            tier_selector.to_string(),
            phase_selector,
            work_selector,
        ];

        let mut filler_index = 0usize;
        while selectors.len() < selectors_per_receipt {
            selectors.push(format!("axis:{filler_index}:{}", i % 32));
            filler_index += 1;
        }

        let summary = SummaryReceiptBuilder::new()
            .review_id(format!("review-{i:05}"))
            .changeset_digest(blake3_hash(format!("changeset:{i}")))
            .outcome(if i % 5 == 0 {
                ReviewOutcome::Commented
            } else {
                ReviewOutcome::Approved
            })
            .tool_log_index_hash(blake3_hash(format!("tool-log:{i}")))
            .artifact_bundle_hash(blake3_hash(format!("artifact-bundle:{i}")))
            .loss_profile(
                LossProfile::default()
                    .with_review_text_omitted(true)
                    .with_tool_logs_omitted(true)
                    .with_comments_aggregated(true)
                    .with_tool_count_summarized(u64::try_from(16 + (i % 5)).expect("fits in u64"))
                    .with_files_affected(u64::try_from(2 + (i % 7)).expect("fits in u64"))
                    .with_lines_changed(u64::try_from(40 + (i % 80)).expect("fits in u64")),
            )
            .selectors(selectors.clone())
            .time_envelope_ref(blake3_hash(format!("time-envelope:{i}")))
            .build_and_sign(&signer)
            .expect("summary fixture receipt should be valid");

        for selector in &selectors {
            selector_index.entry(selector.clone()).or_default().push(i);
        }

        receipts.push(summary);
    }

    SummaryScaleFixture {
        receipts,
        selector_index,
        verifying_key,
        simulated_transcript_bytes: receipt_count
            .saturating_mul(SIMULATED_TRANSCRIPT_BYTES_PER_RECEIPT),
    }
}

fn select_receipts_by_all_selectors<'a>(
    fixture: &'a SummaryScaleFixture,
    required_selectors: &[&str],
) -> (Vec<&'a SummaryReceipt>, usize) {
    if required_selectors.is_empty() {
        return (fixture.receipts.iter().collect(), fixture.receipts.len());
    }

    let mut posting_lists: Vec<&Vec<usize>> = required_selectors
        .iter()
        .filter_map(|selector| fixture.selector_index.get(*selector))
        .collect();

    if posting_lists.len() != required_selectors.len() {
        return (Vec::new(), 0);
    }

    posting_lists.sort_by_key(|list| list.len());
    let candidate_list = posting_lists[0];

    let mut matches = Vec::new();
    for index in candidate_list {
        let receipt = &fixture.receipts[*index];
        if required_selectors
            .iter()
            .all(|selector| receipt.has_selector(selector))
        {
            matches.push(receipt);
        }
    }

    (matches, candidate_list.len())
}

fn summary_total_bytes(receipts: &[SummaryReceipt]) -> usize {
    receipts
        .iter()
        .map(|receipt| {
            serde_json::to_vec(receipt)
                .expect("summary receipt serialization must succeed")
                .len()
        })
        .sum()
}

fn event_record(
    event_type: &str,
    session_id: &str,
    actor_id: &str,
    payload: Vec<u8>,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    EventRecord::with_timestamp(event_type, session_id, actor_id, payload, timestamp_ns)
        .with_seq_id(seq_id)
}

fn dotted_opened_event(
    work_id: &str,
    actor_id: &str,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    let payload = helpers::work_opened_payload(work_id, "TICKET", vec![1, 2, 3], vec![], vec![]);
    event_record(
        "work.opened",
        work_id,
        actor_id,
        payload,
        timestamp_ns,
        seq_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn dotted_transition_event(
    work_id: &str,
    actor_id: &str,
    from_state: &str,
    to_state: &str,
    rationale_code: &str,
    previous_transition_count: u32,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    let payload = helpers::work_transitioned_payload_with_sequence(
        work_id,
        from_state,
        to_state,
        rationale_code,
        previous_transition_count,
    );
    event_record(
        "work.transitioned",
        work_id,
        actor_id,
        payload,
        timestamp_ns,
        seq_id,
    )
}

fn dotted_pr_associated_event(
    work_id: &str,
    actor_id: &str,
    pr_number: u64,
    commit_sha: &str,
    timestamp_ns: u64,
    seq_id: u64,
) -> EventRecord {
    let payload = helpers::work_pr_associated_payload(work_id, pr_number, commit_sha);
    event_record(
        "work.pr_associated",
        work_id,
        actor_id,
        payload,
        timestamp_ns,
        seq_id,
    )
}

fn reduce_expected_state(events: &[EventRecord]) -> WorkReducerState {
    let mut reducer = WorkReducer::new();
    let ctx = ReducerContext::new(1);
    for event in events {
        reducer
            .apply(event, &ctx)
            .expect("expected-state replay must succeed");
    }
    reducer.state().clone()
}

fn records_to_sync_events(records: &[EventRecord], starting_prev_hash: Hash) -> Vec<SyncEvent> {
    let mut prev_hash = starting_prev_hash;
    let mut sync_events = Vec::with_capacity(records.len());

    for (idx, record) in records.iter().enumerate() {
        let seq_id = record
            .seq_id
            .unwrap_or_else(|| u64::try_from(idx + 1).expect("sequence index must fit in u64"));
        let event_hash = EventHasher::hash_event(&record.payload, &prev_hash);

        sync_events.push(SyncEvent {
            seq_id,
            event_type: record.event_type.clone(),
            payload: record.payload.clone(),
            prev_hash,
            event_hash,
            timestamp_ns: record.timestamp_ns,
        });

        prev_hash = event_hash;
    }

    sync_events
}

const fn permissive_anti_entropy_profile() -> VerifierEconomicsProfile {
    VerifierEconomicsProfile {
        p95_join_us: u64::MAX,
        p95_verify_receipt_us: u64::MAX,
        p95_validate_bindings_us: u64::MAX,
        p95_classify_fact_us: u64::MAX,
        p95_replay_lifecycle_us: u64::MAX,
        p95_anti_entropy_us: u64::MAX,
        p95_revalidate_us: u64::MAX,
        p95_consume_us: u64::MAX,
        max_proof_checks: u64::MAX,
    }
}

#[test]
fn summary_first_supervision_scales_without_transcript_fanout() {
    let fixture = build_summary_scale_fixture(SCALE_RECEIPT_COUNT, SELECTORS_PER_RECEIPT);

    for receipt in &fixture.receipts {
        assert!(
            receipt.verify_signature(&fixture.verifying_key).is_ok(),
            "all summary receipts must remain verifiable under scale"
        );
        assert!(
            receipt.loss_profile.tool_logs_omitted,
            "summary fixture must model transcript-free supervision"
        );
        assert!(
            receipt.loss_profile.review_text_omitted,
            "summary fixture must omit full review text"
        );
        assert!(
            receipt.summary_text.is_none(),
            "summary fixture should avoid transcript fan-out payloads"
        );
    }

    let selector_query = ["gate:security", "tier:2", "phase:3"];
    let (matches, candidates_scanned) = select_receipts_by_all_selectors(&fixture, &selector_query);

    let expected_matches = (0..SCALE_RECEIPT_COUNT)
        .filter(|index| index % 3 == 2 && index % 8 == 3)
        .count();

    assert_eq!(
        matches.len(),
        expected_matches,
        "selector query should deterministically return expected subset"
    );
    assert!(
        candidates_scanned < fixture.receipts.len() / 3,
        "selector-first retrieval should bound scan set under fan-out"
    );

    let mut query_samples = Vec::new();
    for _ in 0..96 {
        let start = Instant::now();
        let (_matched, _scanned) = select_receipts_by_all_selectors(&fixture, &selector_query);
        query_samples.push(elapsed_us_since(start));
    }
    let selector_query_p95_us = p95(&mut query_samples);
    assert!(
        selector_query_p95_us < 1_000_000,
        "selector-first query should stay within bounded runtime envelope"
    );

    let summary_total_bytes = summary_total_bytes(&fixture.receipts);
    assert!(
        summary_total_bytes < fixture.simulated_transcript_bytes / 8,
        "summary payload should remain substantially smaller than transcript fan-out"
    );

    let selector_query_id_digest = {
        let review_ids = matches
            .iter()
            .map(|receipt| receipt.review_id.as_str())
            .collect::<Vec<_>>()
            .join("|");
        hex::encode(blake3::hash(review_ids.as_bytes()).as_bytes())
    };

    let evidence = SummaryScaleEvidence {
        receipt_count: fixture.receipts.len(),
        selector_count: fixture.selector_index.len(),
        summary_total_bytes,
        simulated_transcript_total_bytes: fixture.simulated_transcript_bytes,
        selector_query_match_count: matches.len(),
        selector_query_candidates_scanned: candidates_scanned,
        selector_query_p95_us,
        selector_query_id_digest,
    };

    println!(
        "TCK-00421 SUMMARY_EVIDENCE {}",
        serde_json::to_string(&evidence).expect("evidence JSON serialization should succeed")
    );
}

#[test]
fn control_plane_growth_is_bounded_and_observable_under_stress() {
    let config = ResourceQuotaConfig {
        max_queue_depth: 4,
        max_bytes_in_flight: 200,
        max_pulse_payload_bytes: 64,
        max_burst_pulses: 4,
        max_pulses_per_sec: 1,
        ..ResourceQuotaConfig::for_testing()
    };

    let registry = SubscriptionRegistry::new(config);
    let connection_id = "conn-tck-00421";

    registry
        .register_connection(connection_id)
        .expect("connection registration should succeed");
    registry
        .add_subscription(
            connection_id,
            SubscriptionState::new(
                "sub-tck-00421",
                "client-sub-tck-00421",
                vec![TopicPattern::parse("ledger.head").expect("pattern parse should succeed")],
                0,
            ),
        )
        .expect("subscription registration should succeed");

    let mut evidence = ControlPlaneEvidence::default();
    let mut in_flight_payloads: VecDeque<usize> = VecDeque::new();

    let actions = [
        ControlPlaneAction::Reserve(80), // PayloadTooLarge
        ControlPlaneAction::Reserve(50),
        ControlPlaneAction::Reserve(50),
        ControlPlaneAction::Reserve(50),
        ControlPlaneAction::Reserve(50),
        ControlPlaneAction::Reserve(50), // QueueFull
        ControlPlaneAction::DequeueOne,
        ControlPlaneAction::Reserve(60), // BytesInFlightExceeded
        ControlPlaneAction::Reserve(40), // RateLimitExceeded (after burst consumption)
    ];

    for action in actions {
        match action {
            ControlPlaneAction::Reserve(payload_size) => {
                evidence.reserve_attempts = evidence.reserve_attempts.saturating_add(1);
                match registry.try_reserve_enqueue(connection_id, payload_size) {
                    Ok(()) => {
                        evidence.reserve_successes = evidence.reserve_successes.saturating_add(1);
                        in_flight_payloads.push_back(payload_size);
                    },
                    Err(error) => match error {
                        ResourceError::PayloadTooLarge { .. } => {
                            evidence.payload_rejections =
                                evidence.payload_rejections.saturating_add(1);
                        },
                        ResourceError::QueueFull { .. } => {
                            evidence.queue_full_rejections =
                                evidence.queue_full_rejections.saturating_add(1);
                        },
                        ResourceError::BytesInFlightExceeded { .. } => {
                            evidence.bytes_rejections = evidence.bytes_rejections.saturating_add(1);
                        },
                        ResourceError::RateLimitExceeded { .. } => {
                            evidence.rate_rejections = evidence.rate_rejections.saturating_add(1);
                        },
                        other => panic!("unexpected resource error: {other:?}"),
                    },
                }
            },
            ControlPlaneAction::DequeueOne => {
                if let Some(payload_size) = in_flight_payloads.pop_front() {
                    registry.record_dequeue(connection_id, payload_size);
                }
            },
        }

        let stats = registry
            .connection_stats(connection_id)
            .expect("connection stats should be present");
        evidence.max_observed_queue_depth =
            evidence.max_observed_queue_depth.max(stats.queue_depth);
        evidence.max_observed_bytes_in_flight = evidence
            .max_observed_bytes_in_flight
            .max(stats.bytes_in_flight);

        assert!(
            stats.queue_depth <= config.max_queue_depth,
            "queue depth must remain bounded by configured limit"
        );
        assert!(
            stats.bytes_in_flight <= config.max_bytes_in_flight,
            "bytes-in-flight must remain bounded by configured limit"
        );
    }

    while let Some(payload_size) = in_flight_payloads.pop_front() {
        registry.record_dequeue(connection_id, payload_size);
    }

    let drained = registry
        .connection_stats(connection_id)
        .expect("connection stats should be present after drain");
    assert_eq!(drained.queue_depth, 0, "queue should fully drain");
    assert_eq!(
        drained.bytes_in_flight, 0,
        "bytes-in-flight should fully drain"
    );

    let (notification_sender, _notification_receiver) = create_commit_notification_channel();
    for seq in 0..(COMMIT_NOTIFICATION_CHANNEL_CAPACITY + CONTROL_PLANE_CHANNEL_OVERFLOW_ATTEMPTS) {
        let seq_id = u64::try_from(seq + 1).expect("sequence should fit in u64");
        let notification = CommitNotification::new(
            seq_id,
            blake3_hash(format!("notification:{seq}")),
            "LedgerEvent",
            "kernel",
        );

        match notification_sender.try_send(notification) {
            Ok(()) => {
                evidence.channel_queue_accepts = evidence.channel_queue_accepts.saturating_add(1);
            },
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                evidence.channel_backpressure_drops =
                    evidence.channel_backpressure_drops.saturating_add(1);
            },
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                panic!("notification channel unexpectedly closed while measuring bounds");
            },
        }
    }

    assert!(
        evidence.payload_rejections > 0,
        "payload limit enforcement must be observable"
    );
    assert!(
        evidence.queue_full_rejections > 0,
        "queue depth backpressure must be observable"
    );
    assert!(
        evidence.bytes_rejections > 0,
        "bytes-in-flight backpressure must be observable"
    );
    assert!(
        evidence.rate_rejections > 0,
        "rate-limit backpressure must be observable"
    );
    assert_eq!(
        evidence.channel_queue_accepts, COMMIT_NOTIFICATION_CHANNEL_CAPACITY,
        "notification queue should accept exactly its bounded capacity"
    );
    assert_eq!(
        evidence.channel_backpressure_drops, CONTROL_PLANE_CHANNEL_OVERFLOW_ATTEMPTS,
        "overflow attempts beyond channel capacity should be dropped"
    );

    println!(
        "TCK-00421 CONTROL_PLANE_EVIDENCE {}",
        serde_json::to_string(&evidence).expect("evidence JSON serialization should succeed")
    );
}

#[test]
fn replay_and_anti_entropy_recover_projection_without_duplicate_side_effects() {
    let work_id = "W-TCK-00421-RECOVERY";
    let actor_id = "actor:tck-00421";

    // A changeset_published event is required before the IN_PROGRESS -> REVIEW
    // transition because TCK-00672 enforces fail-closed latest-changeset
    // admission: the work reducer denies review-start when no
    // ChangeSetPublished has been observed for the work (CSID-004).
    let changeset_digest = blake3_hash(format!("changeset:{work_id}"));
    let changeset_published_payload = serde_json::json!({
        "work_id": work_id,
        "changeset_digest": hex::encode(changeset_digest),
    })
    .to_string()
    .into_bytes();

    let full_records = vec![
        dotted_opened_event(work_id, actor_id, 10_000, 1),
        dotted_transition_event(work_id, actor_id, "OPEN", "CLAIMED", "claim", 0, 10_100, 2),
        dotted_transition_event(
            work_id,
            actor_id,
            "CLAIMED",
            "IN_PROGRESS",
            "start",
            1,
            10_200,
            3,
        ),
        dotted_pr_associated_event(work_id, actor_id, 901, "abc123def456", 10_300, 4),
        // ChangeSetPublished establishes the authoritative changeset identity
        // for this work, which is required for the review-start gate (CSID-004).
        event_record(
            "changeset_published",
            work_id,
            actor_id,
            changeset_published_payload,
            10_350,
            5,
        ),
        dotted_transition_event(
            work_id,
            actor_id,
            "IN_PROGRESS",
            "REVIEW",
            "ready_for_review",
            2,
            10_400,
            6,
        ),
    ];
    // Number of work.* events that mutate reducer state (changeset_published
    // is not a work.* event, so it is processed by observe_changeset_bound_event
    // but not counted by ReplayEquivalenceChecker as an applied work event).
    let expected_work_event_count = 5usize;

    let expected_state = reduce_expected_state(&full_records);
    let full_sync = records_to_sync_events(&full_records, [0u8; 32]);

    let projection_loss_prefix_len = 2usize;
    let projection_prefix = full_records[..projection_loss_prefix_len].to_vec();
    let catchup_records = full_records[projection_loss_prefix_len..].to_vec();
    let catchup_sync = full_sync[projection_loss_prefix_len..].to_vec();

    let expected_prev_hash = full_sync[projection_loss_prefix_len - 1].event_hash;
    let expected_start_seq_id = catchup_sync
        .first()
        .map(|event| event.seq_id)
        .expect("catchup sync should not be empty");

    let digest = blake3_hash("tck-00421:anti-entropy");

    verify_sync_catchup(
        Some(&digest),
        Some(&digest),
        &catchup_sync,
        &expected_prev_hash,
        Some(expected_start_seq_id),
        None,
        None,
    )
    .expect("anti-entropy catchup verification should pass for valid transfer");

    let tick_kernel = Arc::new(
        InProcessKernel::new(50_000).with_verifier_economics(permissive_anti_entropy_profile()),
    );
    let kernel_trait: Arc<dyn AuthorityJoinKernel> = tick_kernel.clone();
    let gate = LifecycleGate::with_tick_kernel(kernel_trait, Arc::clone(&tick_kernel));

    gate.enforce_anti_entropy_economics(
        RiskTier::Tier2Plus,
        Some(&digest),
        Some(&digest),
        &catchup_sync,
        &expected_prev_hash,
        Some(expected_start_seq_id),
        None,
        None,
        None,
        blake3_hash("tck-00421:time-envelope"),
        blake3_hash("tck-00421:ledger-anchor"),
        50_001,
    )
    .expect("lifecycle gate anti-entropy economics should pass for valid transfer");

    let mut replay_stream = projection_prefix;
    replay_stream.extend(catchup_records.iter().cloned());
    replay_stream.extend(catchup_records.iter().cloned()); // retry/restart duplicate delivery

    let mut checker = ReplayEquivalenceChecker::new();
    let replay = checker
        .verify_replay_equivalence(&replay_stream, &expected_state)
        .expect("replay recovery should succeed");

    assert!(
        replay.matches,
        "projection replay after loss + catchup should converge"
    );
    assert_eq!(
        replay.applied_event_count, expected_work_event_count,
        "applied transition side effects should match exactly one full lifecycle \
         (changeset_published is not a work.* event and is not counted)"
    );
    assert_eq!(
        replay.deduplicated_event_count,
        catchup_sync.len(),
        "retry/restart duplicates should be deduplicated"
    );
    assert_eq!(
        replay.duplicate_side_effects, 0,
        "retry/restart/partial-loss recovery must not duplicate side effects"
    );

    let mut corrupted_catchup = catchup_sync.clone();
    corrupted_catchup[0].prev_hash = [0xFF; 32];

    let corruption_error = verify_sync_catchup(
        Some(&digest),
        Some(&digest),
        &corrupted_catchup,
        &expected_prev_hash,
        Some(expected_start_seq_id),
        None,
        None,
    )
    .expect_err("corrupted catchup batch must fail verification");

    assert!(
        matches!(
            corruption_error,
            AntiEntropyError::HashChainBroken { .. }
                | AntiEntropyError::EventVerificationFailed { .. }
                | AntiEntropyError::SeqIdContinuityBroken { .. }
        ),
        "anti-entropy verifier should detect corruption under loss injection"
    );

    let evidence = ReplayRecoveryEvidence {
        projection_loss_prefix_len,
        anti_entropy_batch_len: catchup_sync.len(),
        replay_deduplicated_events: replay.deduplicated_event_count,
        replay_applied_events: replay.applied_event_count,
        replay_duplicate_side_effects: replay.duplicate_side_effects,
        replay_matches_expected: replay.matches,
        anti_entropy_corruption_detected: true,
    };

    println!(
        "TCK-00421 REPLAY_EVIDENCE {}",
        serde_json::to_string(&evidence).expect("evidence JSON serialization should succeed")
    );
}
