//! Tests for the ledger storage layer.

use std::thread;

use tempfile::TempDir;

use super::*;

/// Helper to create a temporary ledger for testing.
fn temp_ledger() -> (Ledger, TempDir) {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = dir.path().join("test_ledger.db");
    let ledger = Ledger::open(&path).expect("failed to open ledger");
    (ledger, dir)
}

#[test]
fn test_create_ledger() {
    let (ledger, _dir) = temp_ledger();

    let stats = ledger.stats().expect("failed to get stats");
    assert_eq!(stats.event_count, 0);
    assert_eq!(stats.artifact_count, 0);
    assert_eq!(stats.max_seq_id, 0);
}

#[test]
fn test_in_memory_ledger() {
    let ledger = Ledger::in_memory().expect("failed to create in-memory ledger");

    let stats = ledger.stats().expect("failed to get stats");
    assert_eq!(stats.event_count, 0);
}

#[test]
fn test_append_single_event() {
    let (ledger, _dir) = temp_ledger();

    let event = EventRecord::new(
        "test.event",
        "session-1",
        "actor-1",
        b"test payload".to_vec(),
    );
    let seq_id = ledger.append(&event).expect("failed to append event");

    assert_eq!(seq_id, 1);

    let stats = ledger.stats().expect("failed to get stats");
    assert_eq!(stats.event_count, 1);
    assert_eq!(stats.max_seq_id, 1);
}

#[test]
fn test_append_preserves_order() {
    let (ledger, _dir) = temp_ledger();

    let seq1 = ledger
        .append(&EventRecord::new(
            "event.1",
            "session-1",
            "actor-1",
            b"first".to_vec(),
        ))
        .expect("failed to append");
    let seq2 = ledger
        .append(&EventRecord::new(
            "event.2",
            "session-1",
            "actor-1",
            b"second".to_vec(),
        ))
        .expect("failed to append");
    let seq3 = ledger
        .append(&EventRecord::new(
            "event.3",
            "session-1",
            "actor-1",
            b"third".to_vec(),
        ))
        .expect("failed to append");

    assert_eq!(seq1, 1);
    assert_eq!(seq2, 2);
    assert_eq!(seq3, 3);

    // Verify order via read
    let events = ledger.read_from(0, 10).expect("failed to read");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].seq_id, Some(1));
    assert_eq!(events[1].seq_id, Some(2));
    assert_eq!(events[2].seq_id, Some(3));
}

#[test]
fn test_append_batch() {
    let (ledger, _dir) = temp_ledger();

    let events = vec![
        EventRecord::new("batch.1", "session-1", "actor-1", b"first".to_vec()),
        EventRecord::new("batch.2", "session-1", "actor-1", b"second".to_vec()),
        EventRecord::new("batch.3", "session-1", "actor-1", b"third".to_vec()),
    ];

    let seq_ids = ledger
        .append_batch(&events)
        .expect("failed to append batch");

    assert_eq!(seq_ids, vec![1, 2, 3]);

    let stats = ledger.stats().expect("failed to get stats");
    assert_eq!(stats.event_count, 3);
}

#[test]
fn test_read_from_cursor() {
    let (ledger, _dir) = temp_ledger();

    // Append 5 events
    for i in 1..=5 {
        ledger
            .append(&EventRecord::new(
                format!("event.{i}"),
                "session-1",
                "actor-1",
                format!("payload-{i}").into_bytes(),
            ))
            .expect("failed to append");
    }

    // Read from cursor 3
    let events = ledger.read_from(3, 10).expect("failed to read");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].seq_id, Some(3));
    assert_eq!(events[1].seq_id, Some(4));
    assert_eq!(events[2].seq_id, Some(5));
}

#[test]
fn test_read_with_limit() {
    let (ledger, _dir) = temp_ledger();

    // Append 10 events
    for i in 1..=10 {
        ledger
            .append(&EventRecord::new("event", "session-1", "actor-1", vec![i]))
            .expect("failed to append");
    }

    // Read with limit 3
    let events = ledger.read_from(1, 3).expect("failed to read");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].seq_id, Some(1));
    assert_eq!(events[2].seq_id, Some(3));
}

#[test]
fn test_read_one() {
    let (ledger, _dir) = temp_ledger();

    let event = EventRecord::new(
        "test.read",
        "session-1",
        "actor-1",
        b"payload data".to_vec(),
    );
    let seq_id = ledger.append(&event).expect("failed to append");

    let read_event = ledger.read_one(seq_id).expect("failed to read");

    assert_eq!(read_event.seq_id, Some(seq_id));
    assert_eq!(read_event.event_type, "test.read");
    assert_eq!(read_event.session_id, "session-1");
    assert_eq!(read_event.actor_id, "actor-1");
    assert_eq!(read_event.payload, b"payload data");
}

#[test]
fn test_read_one_not_found() {
    let (ledger, _dir) = temp_ledger();

    let result = ledger.read_one(999);

    assert!(matches!(
        result,
        Err(LedgerError::EventNotFound { seq_id: 999 })
    ));
}

#[test]
fn test_read_session() {
    let (ledger, _dir) = temp_ledger();

    // Append events to different sessions
    ledger
        .append(&EventRecord::new(
            "event.1",
            "session-a",
            "actor-1",
            b"a1".to_vec(),
        ))
        .unwrap();
    ledger
        .append(&EventRecord::new(
            "event.2",
            "session-b",
            "actor-1",
            b"b1".to_vec(),
        ))
        .unwrap();
    ledger
        .append(&EventRecord::new(
            "event.3",
            "session-a",
            "actor-1",
            b"a2".to_vec(),
        ))
        .unwrap();
    ledger
        .append(&EventRecord::new(
            "event.4",
            "session-b",
            "actor-1",
            b"b2".to_vec(),
        ))
        .unwrap();
    ledger
        .append(&EventRecord::new(
            "event.5",
            "session-a",
            "actor-1",
            b"a3".to_vec(),
        ))
        .unwrap();

    // Read session-a
    let events_for_a = ledger
        .read_session("session-a", 100)
        .expect("failed to read");
    assert_eq!(events_for_a.len(), 3);
    assert_eq!(events_for_a[0].payload, b"a1");
    assert_eq!(events_for_a[1].payload, b"a2");
    assert_eq!(events_for_a[2].payload, b"a3");

    // Read session-b
    let events_for_b = ledger
        .read_session("session-b", 100)
        .expect("failed to read");
    assert_eq!(events_for_b.len(), 2);
}

#[test]
fn test_read_by_type() {
    let (ledger, _dir) = temp_ledger();

    ledger
        .append(&EventRecord::new(
            "session.start",
            "s1",
            "actor-1",
            b"".to_vec(),
        ))
        .unwrap();
    ledger
        .append(&EventRecord::new(
            "tool.request",
            "s1",
            "actor-1",
            b"".to_vec(),
        ))
        .unwrap();
    ledger
        .append(&EventRecord::new(
            "tool.response",
            "s1",
            "actor-1",
            b"".to_vec(),
        ))
        .unwrap();
    ledger
        .append(&EventRecord::new(
            "tool.request",
            "s1",
            "actor-1",
            b"".to_vec(),
        ))
        .unwrap();
    ledger
        .append(&EventRecord::new(
            "session.end",
            "s1",
            "actor-1",
            b"".to_vec(),
        ))
        .unwrap();

    let tool_requests = ledger
        .read_by_type("tool.request", 0, 100)
        .expect("failed to read");
    assert_eq!(tool_requests.len(), 2);
    assert_eq!(tool_requests[0].seq_id, Some(2));
    assert_eq!(tool_requests[1].seq_id, Some(4));
}

#[test]
fn test_artifact_ref_crud() {
    let (ledger, _dir) = temp_ledger();

    // First create an event
    let seq_id = ledger
        .append(&EventRecord::new(
            "event.with.artifact",
            "session-1",
            "actor-1",
            b"".to_vec(),
        ))
        .expect("failed to append");

    // Add artifact reference
    let artifact = ArtifactRef::new(
        seq_id,
        vec![0xab; 32], // mock hash
        "application/json",
        1024,
        "/cas/ab/cd/abcd1234",
    );
    let artifact_id = ledger
        .add_artifact_ref(&artifact)
        .expect("failed to add artifact");
    assert_eq!(artifact_id, 1);

    // Retrieve artifacts for event
    let artifacts = ledger
        .get_artifacts_for_event(seq_id)
        .expect("failed to get artifacts");
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].content_type, "application/json");
    assert_eq!(artifacts[0].size_bytes, 1024);
}

#[test]
fn test_find_artifact_by_hash() {
    let (ledger, _dir) = temp_ledger();

    let seq_id = ledger
        .append(&EventRecord::new(
            "event",
            "session-1",
            "actor-1",
            b"".to_vec(),
        ))
        .unwrap();

    let hash = vec![0xde, 0xad, 0xbe, 0xef];
    let artifact = ArtifactRef::new(
        seq_id,
        hash.clone(),
        "text/plain",
        256,
        "/cas/de/ad/deadbeef",
    );
    ledger.add_artifact_ref(&artifact).unwrap();

    // Find by hash
    let found = ledger
        .find_artifact_by_hash(&hash)
        .expect("failed to find")
        .expect("artifact not found");
    assert_eq!(found.content_type, "text/plain");
    assert_eq!(found.size_bytes, 256);

    // Not found
    let not_found = ledger
        .find_artifact_by_hash(&[0x00; 32])
        .expect("failed to query");
    assert!(not_found.is_none());
}

#[test]
fn test_multiple_artifacts_per_event() {
    let (ledger, _dir) = temp_ledger();

    let seq_id = ledger
        .append(&EventRecord::new(
            "event",
            "session-1",
            "actor-1",
            b"".to_vec(),
        ))
        .unwrap();

    // Add multiple artifacts
    for i in 0..3 {
        let artifact = ArtifactRef::new(
            seq_id,
            vec![i; 32],
            format!("type/{i}"),
            (u64::from(i) + 1) * 100,
            format!("/cas/{i}"),
        );
        ledger.add_artifact_ref(&artifact).unwrap();
    }

    let artifacts = ledger.get_artifacts_for_event(seq_id).unwrap();
    assert_eq!(artifacts.len(), 3);
}

#[test]
fn test_wal_mode_enabled() {
    let (ledger, _dir) = temp_ledger();

    let is_wal = ledger.verify_wal_mode().expect("failed to verify WAL mode");
    assert!(is_wal, "WAL mode should be enabled");
}

#[test]
fn test_concurrent_read_with_wal() {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = dir.path().join("concurrent_test.db");

    let ledger = Ledger::open(&path).expect("failed to open ledger");

    // Append some initial events
    for i in 1..=10 {
        ledger
            .append(&EventRecord::new(
                "init.event",
                "session-1",
                "actor-1",
                vec![i],
            ))
            .unwrap();
    }

    // Create a reader
    let reader = ledger.open_reader().expect("failed to open reader");

    // Start a thread that writes more events
    let write_ledger = Ledger::open(&path).expect("failed to open write ledger");
    let write_handle = thread::spawn(move || {
        for i in 11..=20 {
            write_ledger
                .append(&EventRecord::new(
                    "write.event",
                    "session-2",
                    "actor-1",
                    vec![i],
                ))
                .unwrap();
            thread::sleep(std::time::Duration::from_millis(5));
        }
    });

    // Concurrent read while writing
    let mut read_count = 0;
    for _ in 0..5 {
        let events = reader.read_from(1, 100).expect("failed to read");
        read_count = events.len();
        thread::sleep(std::time::Duration::from_millis(10));
    }

    write_handle.join().expect("write thread panicked");

    // Final read should see all events
    let final_events = reader.read_from(1, 100).expect("failed to read");
    assert_eq!(final_events.len(), 20);
    assert!(read_count > 0, "concurrent reads should succeed");
}

#[test]
fn test_head_sync() {
    let (ledger, _dir) = temp_ledger();

    assert_eq!(ledger.head_sync().unwrap(), 0);

    ledger
        .append(&EventRecord::new("e", "s", "a", vec![]))
        .unwrap();
    assert_eq!(ledger.head_sync().unwrap(), 1);

    ledger
        .append(&EventRecord::new("e", "s", "a", vec![]))
        .unwrap();
    ledger
        .append(&EventRecord::new("e", "s", "a", vec![]))
        .unwrap();
    assert_eq!(ledger.head_sync().unwrap(), 3);
}

#[test]
fn test_stats() {
    let (ledger, _dir) = temp_ledger();

    // Append events and artifacts
    for i in 1..=5 {
        let seq_id = ledger
            .append(&EventRecord::new("event", "session", "actor", vec![i]))
            .unwrap();

        if i % 2 == 0 {
            ledger
                .add_artifact_ref(&ArtifactRef::new(seq_id, vec![i; 32], "type", 100, "/path"))
                .unwrap();
        }
    }

    let stats = ledger.stats().expect("failed to get stats");
    assert_eq!(stats.event_count, 5);
    assert_eq!(stats.artifact_count, 2);
    assert_eq!(stats.max_seq_id, 5);
    assert!(stats.db_size_bytes > 0);
}

#[test]
fn test_event_timestamp_preserved() {
    let ledger = Ledger::in_memory().unwrap();

    let timestamp_ns = 1_700_000_000_000_000_000u64;
    let event =
        EventRecord::with_timestamp("test", "session", "actor", b"data".to_vec(), timestamp_ns);

    let seq_id = ledger.append(&event).unwrap();
    let read_event = ledger.read_one(seq_id).unwrap();

    assert_eq!(read_event.timestamp_ns, timestamp_ns);
}

#[test]
fn test_payload_preserved() {
    let ledger = Ledger::in_memory().unwrap();

    // Test with various payload types
    let payloads = vec![
        vec![],                       // empty
        b"simple ascii".to_vec(),     // ascii
        vec![0, 1, 2, 255, 254, 253], // binary
        b"{\"json\": true}".to_vec(), // json
        vec![0u8; 10000],             // large
    ];

    for payload in payloads {
        let event = EventRecord::new("test", "session", "actor", payload.clone());
        let seq_id = ledger.append(&event).unwrap();
        let read_event = ledger.read_one(seq_id).unwrap();
        assert_eq!(read_event.payload, payload);
    }
}

#[test]
fn test_empty_ledger_reads() {
    let ledger = Ledger::in_memory().unwrap();

    let events = ledger.read_from(0, 100).unwrap();
    assert!(events.is_empty());

    let events = ledger.read_session("nonexistent", 100).unwrap();
    assert!(events.is_empty());

    let events = ledger.read_by_type("nonexistent", 0, 100).unwrap();
    assert!(events.is_empty());
}

#[test]
fn test_reader_isolation() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("reader_isolation.db");

    let ledger = Ledger::open(&path).unwrap();

    // Add initial events
    for i in 1..=5 {
        ledger
            .append(&EventRecord::new("event", "session", "actor", vec![i]))
            .unwrap();
    }

    // Create reader
    let reader = ledger.open_reader().unwrap();

    // Reader should see 5 events
    let events = reader.read_from(1, 100).unwrap();
    assert_eq!(events.len(), 5);

    // Add more events via main connection
    for i in 6..=10 {
        ledger
            .append(&EventRecord::new("event", "session", "actor", vec![i]))
            .unwrap();
    }

    // Reader should now see all 10 (WAL provides snapshot isolation per query)
    let events = reader.read_from(1, 100).unwrap();
    assert_eq!(events.len(), 10);
}

#[test]
fn test_actor_id_preserved() {
    let ledger = Ledger::in_memory().unwrap();

    let event = EventRecord::new("test", "session-1", "actor-456", b"payload".to_vec());
    let seq_id = ledger.append(&event).unwrap();

    let read_event = ledger.read_one(seq_id).unwrap();
    assert_eq!(read_event.actor_id, "actor-456");
    assert_eq!(read_event.record_version, CURRENT_RECORD_VERSION);
}

// =============================================================================
// TCK-00182: RFC-0014 Consensus Column Tests
// =============================================================================

/// Test that new consensus fields default to None when creating events.
#[test]
fn tck_00182_consensus_fields_default_to_none() {
    let ledger = Ledger::in_memory().unwrap();

    let event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
    let seq_id = ledger.append(&event).unwrap();

    let read_event = ledger.read_one(seq_id).unwrap();

    // All RFC-0014 consensus fields should be None by default
    assert!(read_event.consensus_epoch.is_none());
    assert!(read_event.consensus_round.is_none());
    assert!(read_event.quorum_cert.is_none());
    assert!(read_event.schema_digest.is_none());
    assert!(read_event.canonicalizer_id.is_none());
    assert!(read_event.canonicalizer_version.is_none());
    assert!(read_event.hlc_wall_time.is_none());
    assert!(read_event.hlc_counter.is_none());
}

/// Test that consensus fields can be set and are preserved through storage.
#[test]
fn tck_00182_consensus_fields_preserved() {
    let ledger = Ledger::in_memory().unwrap();

    let mut event = EventRecord::new("consensus.event", "session-1", "actor-1", b"{}".to_vec());

    // Set all consensus fields
    event.consensus_epoch = Some(42);
    event.consensus_round = Some(7);
    event.quorum_cert = Some(vec![0xde, 0xad, 0xbe, 0xef]);
    event.schema_digest = Some(vec![0xab; 32]);
    event.canonicalizer_id = Some("jcs".to_string());
    event.canonicalizer_version = Some("1.0.0".to_string());
    event.hlc_wall_time = Some(1_700_000_000_000_000_000);
    event.hlc_counter = Some(5);

    let seq_id = ledger.append(&event).unwrap();
    let read_event = ledger.read_one(seq_id).unwrap();

    // Verify all fields are preserved
    assert_eq!(read_event.consensus_epoch, Some(42));
    assert_eq!(read_event.consensus_round, Some(7));
    assert_eq!(read_event.quorum_cert, Some(vec![0xde, 0xad, 0xbe, 0xef]));
    assert_eq!(read_event.schema_digest, Some(vec![0xab; 32]));
    assert_eq!(read_event.canonicalizer_id, Some("jcs".to_string()));
    assert_eq!(read_event.canonicalizer_version, Some("1.0.0".to_string()));
    assert_eq!(read_event.hlc_wall_time, Some(1_700_000_000_000_000_000));
    assert_eq!(read_event.hlc_counter, Some(5));
}

/// Test that existing events without consensus fields remain readable.
#[test]
fn tck_00182_existing_events_readable() {
    let ledger = Ledger::in_memory().unwrap();

    // Create events without consensus fields (simulating pre-RFC-0014 events)
    let event1 = EventRecord::new("legacy.event", "session-1", "actor-1", b"data".to_vec());
    let seq1 = ledger.append(&event1).unwrap();

    // Create event with consensus fields
    let mut event2 = EventRecord::new("new.event", "session-1", "actor-1", b"data".to_vec());
    event2.consensus_epoch = Some(1);
    let seq2 = ledger.append(&event2).unwrap();

    // Both events should be readable
    let read1 = ledger.read_one(seq1).unwrap();
    let read2 = ledger.read_one(seq2).unwrap();

    // Legacy event has None for consensus fields
    assert!(read1.consensus_epoch.is_none());
    assert_eq!(read1.payload, b"data");

    // New event has consensus fields
    assert_eq!(read2.consensus_epoch, Some(1));
    assert_eq!(read2.payload, b"data");
}

/// Test batch append with consensus fields.
#[test]
fn tck_00182_batch_append_with_consensus_fields() {
    let ledger = Ledger::in_memory().unwrap();

    let mut batch_evt_1 = EventRecord::new("batch.1", "session-1", "actor-1", b"first".to_vec());
    batch_evt_1.consensus_epoch = Some(1);
    batch_evt_1.consensus_round = Some(0);

    let mut batch_evt_2 = EventRecord::new("batch.2", "session-1", "actor-1", b"second".to_vec());
    batch_evt_2.consensus_epoch = Some(1);
    batch_evt_2.consensus_round = Some(1);

    let batch_evt_3 = EventRecord::new("batch.3", "session-1", "actor-1", b"third".to_vec());
    // No consensus fields

    let seq_ids = ledger
        .append_batch(&[batch_evt_1, batch_evt_2, batch_evt_3])
        .unwrap();
    assert_eq!(seq_ids.len(), 3);

    let read_events = ledger.read_from(1, 10).unwrap();
    assert_eq!(read_events.len(), 3);

    assert_eq!(read_events[0].consensus_epoch, Some(1));
    assert_eq!(read_events[0].consensus_round, Some(0));

    assert_eq!(read_events[1].consensus_epoch, Some(1));
    assert_eq!(read_events[1].consensus_round, Some(1));

    assert!(read_events[2].consensus_epoch.is_none());
    assert!(read_events[2].consensus_round.is_none());
}

/// Test migration runs successfully on existing database (idempotent).
#[test]
fn tck_00182_migration_idempotent() {
    // Create ledger twice - migration should run both times without error
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("migration_test.db");

    {
        let ledger = Ledger::open(&path).unwrap();
        let event = EventRecord::new("test", "session", "actor", b"data".to_vec());
        ledger.append(&event).unwrap();
    }

    // Reopen - migration should be idempotent
    {
        let ledger = Ledger::open(&path).unwrap();
        let events = ledger.read_from(1, 10).unwrap();
        assert_eq!(events.len(), 1);

        // Should be able to write events with consensus fields
        let mut event = EventRecord::new("test2", "session", "actor", b"data2".to_vec());
        event.consensus_epoch = Some(5);
        ledger.append(&event).unwrap();

        let events = ledger.read_from(1, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].consensus_epoch, Some(5));
    }
}

/// Test `read_session` includes consensus fields.
#[test]
fn tck_00182_read_session_includes_consensus_fields() {
    let ledger = Ledger::in_memory().unwrap();

    let mut event = EventRecord::new("test", "session-abc", "actor", b"data".to_vec());
    event.schema_digest = Some(vec![0x12; 32]);
    event.canonicalizer_id = Some("protobuf-sorted".to_string());
    ledger.append(&event).unwrap();

    let events = ledger.read_session("session-abc", 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].schema_digest, Some(vec![0x12; 32]));
    assert_eq!(
        events[0].canonicalizer_id,
        Some("protobuf-sorted".to_string())
    );
}

/// Test `read_by_type` includes consensus fields.
#[test]
fn tck_00182_read_by_type_includes_consensus_fields() {
    let ledger = Ledger::in_memory().unwrap();

    let mut event = EventRecord::new("consensus.proposal", "session", "actor", b"data".to_vec());
    event.hlc_wall_time = Some(1_234_567_890_000_000_000);
    event.hlc_counter = Some(42);
    ledger.append(&event).unwrap();

    let events = ledger.read_by_type("consensus.proposal", 0, 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].hlc_wall_time, Some(1_234_567_890_000_000_000));
    assert_eq!(events[0].hlc_counter, Some(42));
}

/// Test `LedgerReader` includes consensus fields.
#[test]
fn tck_00182_reader_includes_consensus_fields() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("reader_test.db");

    let ledger = Ledger::open(&path).unwrap();

    let mut event = EventRecord::new("test", "session", "actor", b"data".to_vec());
    event.quorum_cert = Some(vec![0x01, 0x02, 0x03]);
    let seq_id = ledger.append(&event).unwrap();

    let reader = ledger.open_reader().unwrap();

    // read_from
    let events = reader.read_from(1, 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].quorum_cert, Some(vec![0x01, 0x02, 0x03]));

    // read_one
    let event = reader.read_one(seq_id).unwrap();
    assert_eq!(event.quorum_cert, Some(vec![0x01, 0x02, 0x03]));
}
