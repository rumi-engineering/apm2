//! TCK-00444: Reviewer telemetry contract and bounded projection visibility.
//!
//! Coverage:
//! - Versioned lifecycle schema normalization
//! - Append-only NDJSON with rotation
//! - Strict parser compatibility (`sha_update` legacy alias)
//! - Fail-closed behavior for missing/malformed telemetry
//! - 1Hz summary rate limiting

use std::fs;
use std::time::{Duration, Instant};

use apm2_daemon::telemetry::reviewer::{
    DEFAULT_REVIEWER_ROTATE_BYTES, ProjectionSummary, ProjectionSummaryEmitter,
    REVIEWER_TELEMETRY_SCHEMA, REVIEWER_TELEMETRY_SCHEMA_VERSION, ReviewerLifecycleEventKind,
    ReviewerProjectionFilter, ReviewerTelemetryError, ReviewerTelemetryHealth,
    ReviewerTelemetryWriter, read_reviewer_projection_events, reviewer_events_rotated_path,
};

fn lifecycle_event(
    event: &str,
    seq: u64,
    reason: Option<&str>,
    head_sha: &str,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "ts": "2026-02-10T12:00:00Z",
        "event": event,
        "review_type": "security",
        "pr_number": 444,
        "head_sha": head_sha,
        "seq": seq,
        "run_id": "pr444-security-s1-abcdef12",
        "restart_count": 1,
    });
    if let Some(reason) = reason
        && let Some(object) = value.as_object_mut()
    {
        object.insert("reason".to_string(), serde_json::json!(reason));
    }
    value
}

#[test]
fn lifecycle_events_are_canonicalized_with_versioned_schema() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let events_path = temp.path().join("review_events.ndjson");
    let writer = ReviewerTelemetryWriter::new(events_path.clone())
        .with_rotate_bytes(DEFAULT_REVIEWER_ROTATE_BYTES);

    writer
        .append_value(&lifecycle_event(
            "stall_detected",
            1,
            None,
            "abcdef1234567890",
        ))
        .expect("lifecycle event append should succeed");

    let content = fs::read_to_string(&events_path).expect("event stream should be readable");
    let first_line = content
        .lines()
        .next()
        .expect("one lifecycle line should be emitted");
    let parsed: serde_json::Value =
        serde_json::from_str(first_line).expect("emitted NDJSON should be parseable");

    assert_eq!(parsed["schema"], REVIEWER_TELEMETRY_SCHEMA);
    assert_eq!(parsed["schema_version"], REVIEWER_TELEMETRY_SCHEMA_VERSION);
    assert_eq!(parsed["event"], "stall_detected");
    assert_eq!(parsed["reason_code"], "stall_detected");
}

#[test]
fn ndjson_writer_rotates_and_reader_merges_rotated_plus_current() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let events_path = temp.path().join("review_events.ndjson");
    let writer = ReviewerTelemetryWriter::new(events_path.clone()).with_rotate_bytes(220);

    let first = lifecycle_event("run_start", 1, None, "abcdef1234567890");
    let mut second = lifecycle_event("run_crash", 2, Some("run_crash"), "abcdef1234567890");
    if let Some(object) = second.as_object_mut() {
        object.insert(
            "detail".to_string(),
            serde_json::json!("longer payload to force rotation boundary crossing"),
        );
    }

    writer
        .append_value(&first)
        .expect("first append should succeed");
    writer
        .append_value(&second)
        .expect("second append should succeed");

    let rotated = reviewer_events_rotated_path(&events_path);
    assert!(rotated.exists(), "rotation should produce a .1 stream");

    let filter = ReviewerProjectionFilter::new(444).with_max_events(32);
    let parsed =
        read_reviewer_projection_events(&events_path, &filter).expect("strict read should succeed");
    assert!(
        parsed.events.len() >= 2,
        "reader should include both rotated and current lifecycle records"
    );
    assert_eq!(parsed.latest_seq, 2);
}

#[test]
fn projection_summary_emitter_is_bounded_to_one_hz() {
    let mut emitter = ProjectionSummaryEmitter::new(Duration::from_secs(1));
    let summary = ProjectionSummary::from_projection(
        "abcdef1234567890",
        "abcdef1234567890",
        "alive:model/backend:r0:abcdef1",
        "none",
        "run_start",
    );

    let now = Instant::now();
    assert!(
        emitter.emit_if_due(now, &summary).is_some(),
        "first summary should always emit"
    );
    assert!(
        emitter
            .emit_if_due(now + Duration::from_millis(200), &summary)
            .is_none(),
        "second summary inside interval must be suppressed"
    );
    assert!(
        emitter
            .emit_if_due(now + Duration::from_secs(1), &summary)
            .is_some(),
        "summary should emit once interval budget is restored"
    );
}

#[test]
fn missing_telemetry_blocks_authoritative_progression_fail_closed() {
    assert!(
        ReviewerTelemetryHealth::Missing.blocks_authoritative_progression(true),
        "missing telemetry must block terminal projection progression"
    );
    assert!(
        !ReviewerTelemetryHealth::Missing.blocks_authoritative_progression(false),
        "missing telemetry may be tolerated before terminal progression is attempted"
    );
}

#[test]
fn malformed_telemetry_is_detected_and_blocks_authoritative_progression() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let events_path = temp.path().join("review_events.ndjson");
    fs::write(&events_path, "{not-json}\n").expect("fixture write should succeed");

    let filter = ReviewerProjectionFilter::new(444).with_max_events(8);
    let err = read_reviewer_projection_events(&events_path, &filter)
        .expect_err("malformed NDJSON must fail strict parser");
    match err {
        ReviewerTelemetryError::Malformed { .. } => {
            assert!(
                ReviewerTelemetryHealth::Malformed.blocks_authoritative_progression(true),
                "malformed telemetry must fail closed for authoritative projection"
            );
        },
        other => panic!("expected malformed telemetry error, got {other:?}"),
    }
}

#[test]
fn trailing_partial_telemetry_line_is_ignored() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let events_path = temp.path().join("review_events.ndjson");
    let complete = serde_json::json!({
        "ts": "2026-02-10T12:00:00Z",
        "event": "run_start",
        "review_type": "security",
        "pr_number": 444,
        "head_sha": "0123456789abcdef0123456789abcdef01234567",
        "seq": 1,
    });
    let partial = serde_json::json!({
        "ts": "2026-02-10T12:00:01Z",
        "event": "run_complete",
        "review_type": "security",
        "pr_number": 444,
        "head_sha": "0123456789abcdef0123456789abcdef01234567",
        "seq": 2,
        "verdict": "PASS",
    })
    .to_string();
    let partial = &partial[..partial.len() / 2];

    let mut content = String::new();
    content.push_str(&serde_json::to_string(&complete).expect("complete event should serialize"));
    content.push('\n');
    content.push_str(partial);

    fs::write(&events_path, content).expect("fixture write");

    let filter = ReviewerProjectionFilter::new(444).with_max_events(8);
    let parsed = read_reviewer_projection_events(&events_path, &filter)
        .expect("partial trailing line should be ignored");
    assert_eq!(
        parsed.events.len(),
        1,
        "only complete lifecycle events should be parsed"
    );
    assert_eq!(parsed.latest_seq, 1);
}

#[test]
fn trailing_partial_telemetry_line_with_newline_is_ignored() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let events_path = temp.path().join("review_events.ndjson");
    let complete = serde_json::json!({
        "ts": "2026-02-10T12:00:00Z",
        "event": "run_start",
        "review_type": "security",
        "pr_number": 444,
        "head_sha": "0123456789abcdef0123456789abcdef01234567",
        "seq": 1,
    });
    let partial = serde_json::json!({
        "ts": "2026-02-10T12:00:01Z",
        "event": "run_complete",
        "review_type": "security",
        "pr_number": 444,
        "head_sha": "0123456789abcdef0123456789abcdef01234567",
        "seq": 2,
        "verdict": "PASS",
    })
    .to_string();
    let partial = &partial[..partial.len() / 2];

    let mut content = String::new();
    content.push_str(&serde_json::to_string(&complete).expect("complete event should serialize"));
    content.push('\n');
    content.push_str(partial);
    content.push('\n');

    fs::write(&events_path, content).expect("fixture write");

    let filter = ReviewerProjectionFilter::new(444).with_max_events(8);
    let parsed = read_reviewer_projection_events(&events_path, &filter)
        .expect("partial trailing line should be ignored even with trailing newline");
    assert_eq!(
        parsed.events.len(),
        1,
        "only complete lifecycle events should be parsed"
    );
    assert_eq!(parsed.latest_seq, 1);
}

#[test]
fn rotated_partial_telemetry_line_is_not_ignored() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let events_path = temp.path().join("review_events.ndjson");
    let rotated = reviewer_events_rotated_path(&events_path);
    let active = serde_json::json!({
        "ts": "2026-02-10T12:00:00Z",
        "event": "run_start",
        "review_type": "security",
        "pr_number": 444,
        "head_sha": "0123456789abcdef0123456789abcdef01234567",
        "seq": 1,
    });
    let partial = "{not-json";

    fs::write(&rotated, partial).expect("rotated fixture write");
    fs::write(
        &events_path,
        serde_json::to_string(&active).expect("serialize active event"),
    )
    .expect("active fixture write");

    let filter = ReviewerProjectionFilter::new(444).with_max_events(8);
    let err = read_reviewer_projection_events(&events_path, &filter)
        .expect_err("malformed rotated line should not be ignored");
    match err {
        ReviewerTelemetryError::Malformed { .. } => {},
        other => panic!("expected malformed telemetry error, got {other:?}"),
    }
}

#[test]
fn parser_accepts_legacy_sha_update_alias_and_normalizes_kind() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let events_path = temp.path().join("review_events.ndjson");
    let legacy = serde_json::json!({
        "ts": "2026-02-10T12:05:00Z",
        "event": "sha_update",
        "review_type": "security",
        "pr_number": 444,
        "head_sha": "abcdef1234567890",
        "seq": 4,
        "reason": "sha_update",
        "old_sha": "abcdef1234567890",
        "new_sha": "0123456789abcdef",
    });
    fs::write(
        &events_path,
        format!(
            "{}\n",
            serde_json::to_string(&legacy).expect("legacy fixture should serialize")
        ),
    )
    .expect("legacy fixture should write");

    let filter = ReviewerProjectionFilter::new(444).with_max_events(8);
    let parsed =
        read_reviewer_projection_events(&events_path, &filter).expect("legacy alias should parse");
    let last = parsed
        .events
        .last()
        .expect("parsed stream should include the legacy alias event");
    assert_eq!(last.lifecycle.event, ReviewerLifecycleEventKind::ShaDrift);
    assert_eq!(last.raw["event"], "sha_drift");
}

#[test]
fn parser_rejects_lifecycle_event_missing_required_seq() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let events_path = temp.path().join("review_events.ndjson");
    let malformed = serde_json::json!({
        "ts": "2026-02-10T12:10:00Z",
        "event": "run_crash",
        "review_type": "security",
        "pr_number": 444,
        "head_sha": "abcdef1234567890",
        "reason": "run_crash",
    });
    fs::write(
        &events_path,
        format!(
            "{}\n",
            serde_json::to_string(&malformed).expect("malformed fixture should serialize")
        ),
    )
    .expect("malformed fixture should write");

    let filter = ReviewerProjectionFilter::new(444).with_max_events(8);
    let err = read_reviewer_projection_events(&events_path, &filter)
        .expect_err("required seq omission must fail strict parser");
    match err {
        ReviewerTelemetryError::Malformed { detail, .. } => {
            assert!(
                detail.contains("missing seq"),
                "error detail should identify missing seq: {detail}"
            );
        },
        other => panic!("expected malformed error for missing seq, got {other:?}"),
    }
}
