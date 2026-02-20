//! Tests for the ledger storage layer.

use std::thread;

use rusqlite::{Connection, params};
use tempfile::TempDir;

use super::*;

/// Helper to create a temporary ledger for testing.
fn temp_ledger() -> (Ledger, TempDir) {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = dir.path().join("test_ledger.db");
    let ledger = Ledger::open(&path).expect("failed to open ledger");
    (ledger, dir)
}

fn create_legacy_ledger_events_table(conn: &Connection) {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ledger_events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            work_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            payload BLOB NOT NULL,
            signature BLOB NOT NULL,
            timestamp_ns INTEGER NOT NULL
        )",
        [],
    )
    .expect("failed to create legacy ledger_events table");
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
// TCK-00398: Legacy ledger_events Compatibility Bridge
// =============================================================================

#[test]
fn tck_00398_reads_legacy_ledger_events_when_events_empty() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("legacy_compat.db");

    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-1",
                "work_claimed",
                "work-123",
                "actor-1",
                br#"{"work_id":"work-123","role":"implementer"}"#,
                vec![0xAA_u8, 0xBB_u8],
                100_u64
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-2",
                "episode_spawned",
                "episode-001",
                "daemon",
                br#"{"work_id":"work-123","episode_id":"episode-001"}"#,
                vec![0xCC_u8, 0xDD_u8],
                200_u64
            ],
        )
        .unwrap();
    }

    let ledger = Ledger::open(&path).unwrap();
    let all = ledger.read_from(1, 10).unwrap();

    assert_eq!(all.len(), 2);
    assert_eq!(all[0].seq_id, Some(1));
    assert_eq!(all[1].seq_id, Some(2));
    assert_eq!(all[0].event_type, "work_claimed");
    assert_eq!(all[0].session_id, "work-123");
    assert_eq!(all[1].event_type, "episode_spawned");
    assert_eq!(all[1].session_id, "episode-001");
    assert_eq!(all[0].record_version, CURRENT_RECORD_VERSION);
    assert_eq!(all[0].signature, Some(vec![0xAA, 0xBB]));

    let by_type = ledger.read_by_type("episode_spawned", 1, 10).unwrap();
    assert_eq!(by_type.len(), 1);
    assert_eq!(by_type[0].session_id, "episode-001");

    let by_session = ledger.read_session("work-123", 10).unwrap();
    assert_eq!(by_session.len(), 1);
    assert_eq!(by_session[0].event_type, "work_claimed");

    assert_eq!(ledger.head_sync().unwrap(), 2);

    // Idempotency: reopening should keep the same compatibility behavior.
    let reopened = Ledger::open(&path).unwrap();
    let reopened_events = reopened.read_from(1, 10).unwrap();
    assert_eq!(reopened_events.len(), 2);
}

#[test]
fn tck_00398_fails_closed_on_ambiguous_dual_table_state() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ambiguous_compat.db");

    // Seed canonical events table with one row.
    {
        let ledger = Ledger::open(&path).unwrap();
        ledger
            .append(&EventRecord::new(
                "canonical.event",
                "session-1",
                "actor-1",
                b"canonical".to_vec(),
            ))
            .unwrap();
    }

    // Seed legacy table with one row to create an ambiguous read source.
    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-legacy-1",
                "work_claimed",
                "work-ambiguous",
                "actor-legacy",
                br#"{"work_id":"work-ambiguous"}"#,
                vec![0x01_u8, 0x02_u8],
                123_u64
            ],
        )
        .unwrap();
    }

    let Err(err) = Ledger::open(&path) else {
        panic!("mixed table state must fail closed");
    };
    assert!(
        matches!(err, LedgerError::AmbiguousSchemaState { .. }),
        "unexpected error: {err:?}"
    );
}

#[test]
fn tck_00398_rejects_legacy_schema_type_mismatch() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("legacy_schema_mismatch.db");

    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "CREATE TABLE ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES ('EVT-1', 'work_claimed', 'work-1', 'actor-1', '{\"work_id\":\"work-1\"}', x'ABCD', 1)",
            [],
        )
        .unwrap();
    }

    let Err(err) = Ledger::open(&path) else {
        panic!("type mismatch must fail closed");
    };
    assert!(
        matches!(err, LedgerError::LegacySchemaMismatch { .. }),
        "unexpected error: {err:?}"
    );
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

// =============================================================================
// TCK-00265: Signature Verification on Ledger Ingestion
// =============================================================================

/// Helper to create a properly signed event for testing.
///
/// This implements the correct signing approach per RFC-0017 DD-006:
/// 1. Derive `actor_id` from verifying key
/// 2. Sign the domain-prefixed payload (consistent with
///    `DomainSeparatedCanonical`)
/// 3. Set `prev_hash` to the current ledger tip
fn create_signed_event(
    ledger: &Ledger,
    signer: &crate::crypto::Signer,
    event_type: &str,
    session_id: &str,
    payload: Vec<u8>,
) -> EventRecord {
    // Derive actor_id from verifying key (identity binding)
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Get the previous hash for chain linking
    let prev_hash = ledger.last_event_hash().unwrap();

    // Get the domain prefix for the event type
    let domain_prefix = get_test_domain_prefix(event_type);

    // Sign the payload with domain separation (consistent with
    // DomainSeparatedCanonical)
    let signature = crate::fac::sign_with_domain(signer, domain_prefix, &payload);

    let mut event = EventRecord::new(event_type, session_id, &actor_id, payload);
    event.prev_hash = Some(prev_hash);
    event.signature = Some(signature.to_bytes().to_vec());
    // event_hash will be computed by append_verified
    event
}

/// Helper to get domain prefix for test event types.
fn get_test_domain_prefix(event_type: &str) -> &'static [u8] {
    match event_type {
        "tool_decided" => crate::events::TOOL_DECIDED_DOMAIN_PREFIX,
        "tool_executed" => crate::events::TOOL_EXECUTED_DOMAIN_PREFIX,
        "session_terminated" => crate::events::SESSION_TERMINATED_DOMAIN_PREFIX,
        "work_claimed" => crate::events::WORK_CLAIMED_DOMAIN_PREFIX,
        "episode_spawned" => crate::events::EPISODE_SPAWNED_DOMAIN_PREFIX,
        "merge_receipt" => crate::events::MERGE_RECEIPT_DOMAIN_PREFIX,
        _ => panic!("Unknown event type in test: {event_type}"),
    }
}

/// Test that unsigned events are rejected (ADV-007).
#[test]
fn tck_00265_unsigned_event_rejected() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Derive actor_id from verifying key
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Create an event without a signature
    let prev_hash = ledger.last_event_hash().unwrap();
    let payload = b"payload".to_vec();

    let mut event = EventRecord::new("tool_decided", "session-1", &actor_id, payload);
    event.prev_hash = Some(prev_hash);
    // No signature

    // Attempt to append with verification should fail
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_err());
    assert!(matches!(result, Err(LedgerError::UnsignedEvent { .. })));
}

/// Test that events with empty signature are rejected.
#[test]
fn tck_00265_empty_signature_rejected() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Derive actor_id from verifying key
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Create an event with an empty signature
    let prev_hash = ledger.last_event_hash().unwrap();
    let payload = b"payload".to_vec();

    let mut event = EventRecord::new("tool_decided", "session-1", &actor_id, payload);
    event.prev_hash = Some(prev_hash);
    event.signature = Some(vec![]); // Empty signature

    // Attempt to append with verification should fail
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_err());
    assert!(matches!(result, Err(LedgerError::UnsignedEvent { .. })));
}

/// Test that events with invalid signatures are rejected.
#[test]
fn tck_00265_invalid_signature_rejected() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();
    let wrong_signer = Signer::generate();

    // Derive actor_id from signer (the one we'll verify with)
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Create event with correct actor_id but sign with wrong key
    let prev_hash = ledger.last_event_hash().unwrap();
    let payload = b"payload".to_vec();

    // Sign with wrong_signer but use signer's actor_id
    let signature = crate::fac::sign_with_domain(
        &wrong_signer,
        crate::events::TOOL_DECIDED_DOMAIN_PREFIX,
        &payload,
    );

    let mut event = EventRecord::new("tool_decided", "session-1", &actor_id, payload);
    event.prev_hash = Some(prev_hash);
    event.signature = Some(signature.to_bytes().to_vec());

    // Attempt to append with verification should fail (wrong key)
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_err());
    assert!(matches!(result, Err(LedgerError::SignatureInvalid { .. })));
}

/// Test that events with tampered payload are rejected.
#[test]
fn tck_00265_tampered_event_rejected() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Derive actor_id from verifying key
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Create and sign an event with original payload
    let prev_hash = ledger.last_event_hash().unwrap();
    let original_payload = b"original payload".to_vec();

    // Sign the original payload
    let signature = crate::fac::sign_with_domain(
        &signer,
        crate::events::TOOL_DECIDED_DOMAIN_PREFIX,
        &original_payload,
    );

    // Create event with tampered payload but original signature
    let tampered_payload = b"tampered payload".to_vec();
    let mut event = EventRecord::new("tool_decided", "session-1", &actor_id, tampered_payload);
    event.prev_hash = Some(prev_hash);
    event.signature = Some(signature.to_bytes().to_vec());

    // Attempt to append with verification should fail (signature won't match
    // tampered payload)
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_err());
    assert!(matches!(result, Err(LedgerError::SignatureInvalid { .. })));
}

/// Test that properly signed events are accepted.
#[test]
fn tck_00265_valid_signature_accepted() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Create and properly sign an event using the helper
    let event = create_signed_event(
        &ledger,
        &signer,
        "tool_decided",
        "session-1",
        b"payload".to_vec(),
    );

    // Append with verification should succeed
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_ok());
    let seq_id = result.unwrap();
    assert_eq!(seq_id, 1);

    // Verify the event was stored
    let stored_event = ledger.read_one(seq_id).unwrap();
    assert_eq!(stored_event.payload, b"payload");
    assert!(stored_event.signature.is_some());
    assert!(stored_event.event_hash.is_some());
}

/// Test that malformed signatures are rejected.
#[test]
fn tck_00265_malformed_signature_rejected() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Derive actor_id from verifying key
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Create event with correct fields but malformed signature
    let prev_hash = ledger.last_event_hash().unwrap();
    let payload = b"payload".to_vec();

    let mut event = EventRecord::new("tool_decided", "session-1", &actor_id, payload);
    event.prev_hash = Some(prev_hash);
    event.signature = Some(vec![0x42; 32]); // Wrong length (should be 64)

    // Attempt to append with verification should fail
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_err());
    assert!(matches!(result, Err(LedgerError::SignatureInvalid { .. })));
}

/// Test that signatures with wrong domain prefix are rejected.
#[test]
fn tck_00265_wrong_domain_prefix_rejected() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Derive actor_id from verifying key
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Create event with correct fields
    let prev_hash = ledger.last_event_hash().unwrap();
    let payload = b"payload".to_vec();

    // Sign with a different domain prefix than the event_type requires
    let signature = crate::fac::sign_with_domain(
        &signer,
        crate::events::TOOL_EXECUTED_DOMAIN_PREFIX, // Wrong prefix for tool_decided!
        &payload,
    );

    let mut event = EventRecord::new("tool_decided", "session-1", &actor_id, payload);
    event.prev_hash = Some(prev_hash);
    event.signature = Some(signature.to_bytes().to_vec());

    // Attempt to append with verification should fail (wrong domain)
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_err());
    assert!(matches!(result, Err(LedgerError::SignatureInvalid { .. })));
}

/// Test multiple valid signed events can be appended with chain linking.
#[test]
fn tck_00265_multiple_signed_events() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Append multiple properly signed events
    for i in 0u64..5 {
        let payload = format!("payload-{i}").into_bytes();
        let event = create_signed_event(&ledger, &signer, "tool_decided", "session-1", payload);

        let result = ledger.append_verified(&event, &signer.verifying_key());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), i + 1);
    }

    // Verify all events were stored
    let stats = ledger.stats().unwrap();
    assert_eq!(stats.event_count, 5);
}

/// Test that `actor_id` mismatch is rejected (identity binding).
#[test]
fn tck_00265_actor_id_mismatch_rejected() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Create event with wrong actor_id (not derived from verifying key)
    let prev_hash = ledger.last_event_hash().unwrap();
    let payload = b"payload".to_vec();

    // Sign correctly but use wrong actor_id
    let signature =
        crate::fac::sign_with_domain(&signer, crate::events::TOOL_DECIDED_DOMAIN_PREFIX, &payload);

    let mut event = EventRecord::new(
        "tool_decided",
        "session-1",
        "wrong-actor-id", // Not derived from verifying key
        payload,
    );
    event.prev_hash = Some(prev_hash);
    event.signature = Some(signature.to_bytes().to_vec());

    // Attempt to append with verification should fail (actor_id mismatch)
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_err());
    assert!(matches!(result, Err(LedgerError::SignatureInvalid { .. })));
}

/// Test that missing `event_hash` is computed and stored (not rejected).
#[test]
fn tck_00265_missing_event_hash_computed() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Derive actor_id from verifying key
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Create event without event_hash
    let prev_hash = ledger.last_event_hash().unwrap();
    let payload = b"payload".to_vec();

    // Sign the payload with domain prefix
    let signature =
        crate::fac::sign_with_domain(&signer, crate::events::TOOL_DECIDED_DOMAIN_PREFIX, &payload);

    let mut event = EventRecord::new("tool_decided", "session-1", &actor_id, payload);
    event.prev_hash = Some(prev_hash);
    // No event_hash set - append_verified will compute it
    event.signature = Some(signature.to_bytes().to_vec());

    // Attempt to append with verification should succeed (event_hash is computed)
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_ok());
    let seq_id = result.unwrap();

    // Verify the event was stored with computed event_hash
    let stored_event = ledger.read_one(seq_id).unwrap();
    assert!(stored_event.event_hash.is_some());
    assert_eq!(stored_event.event_hash.as_ref().unwrap().len(), 32);
}

/// Test that oversized payload is rejected (denial-of-service protection).
#[test]
fn tck_00265_oversized_payload_rejected() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Derive actor_id from verifying key
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    // Create an oversized payload
    let payload = vec![0u8; Ledger::MAX_VERIFIED_PAYLOAD_SIZE + 1];

    let mut event = EventRecord::new("tool_decided", "session-1", &actor_id, payload);
    event.signature = Some(vec![0u8; 64]); // Dummy signature

    // Attempt to append with verification should fail (payload too large)
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_err());
    assert!(matches!(result, Err(LedgerError::SignatureInvalid { .. })));
}

/// Test that chain verification works with events appended via
/// `append_verified`.
#[test]
fn tck_00265_chain_verification_consistency() {
    use crate::crypto::{EventHasher, Signer};

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Append multiple events using append_verified
    for i in 0u64..3 {
        let payload = format!("payload-{i}").into_bytes();
        let event = create_signed_event(&ledger, &signer, "tool_decided", "session-1", payload);
        ledger
            .append_verified(&event, &signer.verifying_key())
            .unwrap();
    }

    // Now verify the chain using verify_chain
    // Note: verify_chain verifies the hash chain (prev_hash linkage), but signature
    // verification is over the payload with domain prefix (not event_hash).
    // This test verifies that the hash chain is correctly maintained.
    let verify_result = ledger.verify_chain(
        |payload, prev_hash| {
            let prev: [u8; 32] = prev_hash.try_into().unwrap();
            EventHasher::hash_event(payload, &prev).to_vec()
        },
        |_event_hash, signature_bytes| {
            // Signature verification would need to be over the payload, not event_hash.
            // For this test, we just verify the signature parses correctly.
            crate::crypto::parse_signature(signature_bytes).is_ok()
        },
    );

    assert!(
        verify_result.is_ok(),
        "Chain verification should succeed for events appended via append_verified"
    );
}

/// Test that unknown event types are rejected per RFC-0017 DD-006.
#[test]
fn tck_00265_unknown_event_type_rejected() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // Derive actor_id from verifying key
    let actor_id = hex::encode(signer.verifying_key().as_bytes());

    let prev_hash = ledger.last_event_hash().unwrap();
    let payload = b"payload".to_vec();

    // Sign with some arbitrary prefix (doesn't matter, will fail on event type
    // lookup)
    let signature =
        crate::fac::sign_with_domain(&signer, crate::events::TOOL_DECIDED_DOMAIN_PREFIX, &payload);

    let mut event = EventRecord::new(
        "unknown.event.type", // Unknown event type
        "session-1",
        &actor_id,
        payload,
    );
    event.prev_hash = Some(prev_hash);
    event.signature = Some(signature.to_bytes().to_vec());

    // Attempt to append with verification should fail (unknown event type)
    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(result.is_err());
    match result {
        Err(LedgerError::SignatureInvalid { details, .. }) => {
            assert!(
                details.contains("unknown event type"),
                "Error should mention unknown event type: {details}"
            );
        },
        other => panic!("Expected SignatureInvalid, got {other:?}"),
    }
}

/// Test that chain integrity violation is detected (`prev_hash` mismatch).
#[test]
fn tck_00265_chain_integrity_violation_detected() {
    use crate::crypto::Signer;

    let ledger = Ledger::in_memory().unwrap();
    let signer = Signer::generate();

    // First, append a valid event to establish a ledger tip
    let event1 = create_signed_event(
        &ledger,
        &signer,
        "tool_decided",
        "session-1",
        b"first payload".to_vec(),
    );
    ledger
        .append_verified(&event1, &signer.verifying_key())
        .unwrap();

    // Now try to append an event with wrong prev_hash (pointing to genesis instead
    // of tip)
    let actor_id = hex::encode(signer.verifying_key().as_bytes());
    let payload = b"second payload".to_vec();

    // Sign the payload correctly
    let signature =
        crate::fac::sign_with_domain(&signer, crate::events::TOOL_DECIDED_DOMAIN_PREFIX, &payload);

    let mut event2 = EventRecord::new("tool_decided", "session-1", &actor_id, payload);
    // Use genesis hash instead of the actual tip
    event2.prev_hash = Some(vec![0u8; 32]);
    event2.signature = Some(signature.to_bytes().to_vec());

    // Attempt to append should fail with chain integrity violation
    let result = ledger.append_verified(&event2, &signer.verifying_key());

    assert!(result.is_err());
    assert!(
        matches!(result, Err(LedgerError::ChainIntegrityViolation { .. })),
        "Expected ChainIntegrityViolation, got {result:?}"
    );
}

// =============================================================================
// TCK-00398: Legacy-mode write rejection (fail-closed)
//
// Security review BLOCKERs:
// 1. Fail-closed invariant bypassable after initialization — write paths always
//    append to canonical `events`, creating split truth in legacy mode.
// 2. Hash-chain continuity unsound in legacy mode — `last_event_hash` reads
//    from the compat view where `event_hash` is always NULL, returning genesis
//    hash.
//
// Quality review MAJOR: same root cause as BLOCKER #1.
//
// Fix: All write APIs and `last_event_hash` return `LegacyModeReadOnly` when
// `read_mode == LegacyLedgerEvents`.
// =============================================================================

/// Helper: create a legacy-only ledger on disk and open it.
fn open_legacy_only_ledger() -> (Ledger, TempDir) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("legacy_write_guard.db");

    // Seed a legacy `ledger_events` table with at least one row so the
    // ledger opens in `LegacyLedgerEvents` mode.
    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-legacy-1",
                "work_claimed",
                "work-1",
                "actor-1",
                br#"{"work_id":"work-1"}"#,
                vec![0xAA_u8],
                100_u64
            ],
        )
        .unwrap();
    }

    let ledger = Ledger::open(&path).expect("open legacy ledger");
    (ledger, dir)
}

/// `append` must be rejected in legacy compatibility mode.
#[test]
fn tck_00398_legacy_mode_append_rejected() {
    let (ledger, _dir) = open_legacy_only_ledger();

    let event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
    let result = ledger.append(&event);

    assert!(
        matches!(result, Err(LedgerError::LegacyModeReadOnly)),
        "append must fail closed in legacy mode, got {result:?}"
    );
}

/// `append_batch` must be rejected in legacy compatibility mode.
#[test]
fn tck_00398_legacy_mode_append_batch_rejected() {
    let (ledger, _dir) = open_legacy_only_ledger();

    let events = vec![
        EventRecord::new("batch.1", "session-1", "actor-1", b"first".to_vec()),
        EventRecord::new("batch.2", "session-1", "actor-1", b"second".to_vec()),
    ];
    let result = ledger.append_batch(&events);

    assert!(
        matches!(result, Err(LedgerError::LegacyModeReadOnly)),
        "append_batch must fail closed in legacy mode, got {result:?}"
    );
}

/// `append_signed` must be rejected in legacy compatibility mode.
#[test]
fn tck_00398_legacy_mode_append_signed_rejected() {
    let (ledger, _dir) = open_legacy_only_ledger();

    let event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());
    let result = ledger.append_signed(event, |p, h| [p, h].concat(), <[u8]>::to_vec);

    assert!(
        matches!(result, Err(LedgerError::LegacyModeReadOnly)),
        "append_signed must fail closed in legacy mode, got {result:?}"
    );
}

/// `append_verified` must be rejected in legacy compatibility mode.
#[test]
fn tck_00398_legacy_mode_append_verified_rejected() {
    use crate::crypto::Signer;

    let (ledger, _dir) = open_legacy_only_ledger();
    let signer = Signer::generate();

    let actor_id = hex::encode(signer.verifying_key().as_bytes());
    let payload = b"payload".to_vec();

    let signature =
        crate::fac::sign_with_domain(&signer, crate::events::TOOL_DECIDED_DOMAIN_PREFIX, &payload);

    let mut event = EventRecord::new("tool_decided", "session-1", &actor_id, payload);
    event.prev_hash = Some(vec![0u8; 32]);
    event.signature = Some(signature.to_bytes().to_vec());

    let result = ledger.append_verified(&event, &signer.verifying_key());

    assert!(
        matches!(result, Err(LedgerError::LegacyModeReadOnly)),
        "append_verified must fail closed in legacy mode, got {result:?}"
    );
}

/// `last_event_hash` must be rejected in legacy compatibility mode because
/// the compatibility view always returns NULL for `event_hash`, making the
/// returned hash unsound (always genesis).
#[test]
fn tck_00398_legacy_mode_last_event_hash_rejected() {
    let (ledger, _dir) = open_legacy_only_ledger();

    let result = ledger.last_event_hash();

    assert!(
        matches!(result, Err(LedgerError::LegacyModeReadOnly)),
        "last_event_hash must fail closed in legacy mode, got {result:?}"
    );
}

/// Read operations must still succeed in legacy compatibility mode.
/// Only writes are blocked.
#[test]
fn tck_00398_legacy_mode_reads_still_work() {
    let (ledger, _dir) = open_legacy_only_ledger();

    // read_from should succeed
    let events = ledger.read_from(1, 10).unwrap();
    assert_eq!(events.len(), 1, "should read legacy events");
    assert_eq!(events[0].event_type, "work_claimed");

    // read_one should succeed
    let event = ledger.read_one(1).unwrap();
    assert_eq!(event.event_type, "work_claimed");

    // read_session should succeed
    let by_session = ledger.read_session("work-1", 10).unwrap();
    assert_eq!(by_session.len(), 1);

    // read_by_type should succeed
    let by_type = ledger.read_by_type("work_claimed", 1, 10).unwrap();
    assert_eq!(by_type.len(), 1);

    // head_sync should succeed
    let head = ledger.head_sync().unwrap();
    assert_eq!(head, 1);

    // stats should succeed
    let stats = ledger.stats().unwrap();
    assert_eq!(stats.event_count, 1);
}

// =============================================================================
// TCK-00630: RFC-0032 Phase 0 — Legacy Migration with Hash Chain
// =============================================================================

/// Helper: check if a `SQLite` table exists (test-local, avoids private
/// method).
fn test_table_exists(conn: &Connection, table_name: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1",
        params![table_name],
        |_row| Ok(()),
    )
    .is_ok()
}

/// Helper: initialize canonical schema on a raw connection so migration has
/// the `events` table available.
fn init_schema(conn: &Connection) {
    // Open and immediately drop a Ledger to ensure schema is applied.
    // This is a shortcut: SCHEMA_SQL is private, but Ledger::open applies it.
    // For direct `Connection` usage, embed the minimal required schema.
    conn.execute_batch(include_str!("schema.sql")).unwrap();
}

/// Helper: seed a legacy `ledger_events` table with N rows.
fn seed_legacy_table(conn: &Connection, count: usize) {
    create_legacy_ledger_events_table(conn);
    for i in 1..=count {
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                format!("EVT-{i}"),
                "work_claimed",
                format!("work-{i}"),
                format!("actor-{i}"),
                format!(r#"{{"work_id":"work-{i}","index":{i}}}"#).as_bytes(),
                vec![0xAA_u8, u8::try_from(i).unwrap()],
                i64::try_from(i).unwrap() * 1_000_000_000_i64,
            ],
        )
        .unwrap();
    }
}

/// Migration on a fresh DB (no `ledger_events` table) is a no-op.
#[test]
fn tck_00630_migration_fresh_db_noop() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("fresh.db");

    // Open a fresh ledger (creates `events` but no `ledger_events`).
    let _ledger = Ledger::open(&path).unwrap();

    // Run migration against a fresh connection.
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
        .unwrap();
    let stats = migrate_legacy_ledger_events(&conn).unwrap();

    assert!(stats.already_migrated);
    assert_eq!(stats.rows_migrated, 0);
}

/// Migration copies legacy rows into `events` with a contiguous hash chain.
#[test]
fn tck_00630_migration_copies_rows_with_hash_chain() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("migrate.db");

    // Seed legacy data.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 5);
    }

    // Open via Ledger to ensure schema is initialized (creates `events` table).
    // This will be in legacy-read mode since `ledger_events` has rows.
    let ledger = Ledger::open(&path).unwrap();

    // Confirm we are in legacy read mode (write should fail).
    let write_result = ledger.append(&EventRecord::new(
        "test.event",
        "session",
        "actor",
        b"payload".to_vec(),
    ));
    assert!(
        matches!(write_result, Err(LedgerError::LegacyModeReadOnly)),
        "pre-migration: should be in legacy read-only mode"
    );
    drop(ledger);

    // Run migration on a direct connection.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();

        assert!(!stats.already_migrated);
        assert_eq!(stats.rows_migrated, 5);

        // Verify `ledger_events` still exists but is now empty
        // (preserved as a write-compatible sink for legacy writers).
        assert!(
            test_table_exists(&conn, "ledger_events"),
            "ledger_events should still exist (emptied, not renamed)"
        );
        let legacy_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            legacy_count, 0,
            "ledger_events should be empty after migration"
        );

        // Verify `ledger_events_legacy_frozen` exists with the audit copy.
        assert!(
            test_table_exists(&conn, "ledger_events_legacy_frozen"),
            "frozen table should exist for audit"
        );
        let frozen_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ledger_events_legacy_frozen",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            frozen_count, 5,
            "frozen table should have all migrated rows"
        );

        // Verify hash chain continuity in `events`.
        let mut stmt = conn
            .prepare("SELECT payload, prev_hash, event_hash FROM events ORDER BY seq_id ASC")
            .unwrap();
        let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(rows.len(), 5);

        let mut expected_prev = crate::crypto::EventHasher::GENESIS_PREV_HASH;
        for (i, (payload, prev_hash, event_hash)) in rows.iter().enumerate() {
            assert_eq!(
                prev_hash.as_slice(),
                expected_prev.as_slice(),
                "row {i}: prev_hash mismatch"
            );

            let computed = crate::crypto::EventHasher::hash_event(payload, &expected_prev);
            assert_eq!(
                event_hash.as_slice(),
                computed.as_slice(),
                "row {i}: event_hash mismatch"
            );

            // No NULL event_hash.
            assert_eq!(event_hash.len(), 32, "row {i}: event_hash must be 32 bytes");

            expected_prev = computed;
        }
    }

    // Reopen via Ledger — should now be in canonical mode.
    let ledger = Ledger::open(&path).unwrap();
    let events = ledger.read_from(1, 100).unwrap();
    assert_eq!(events.len(), 5);
    assert_eq!(events[0].event_type, "work_claimed");
    assert_eq!(events[0].session_id, "work-1");
    assert_eq!(events[0].record_version, CURRENT_RECORD_VERSION);

    // Writes should now succeed.
    let seq_id = ledger
        .append(&EventRecord::new(
            "post_migration.event",
            "session-new",
            "actor-new",
            b"new payload".to_vec(),
        ))
        .unwrap();
    assert_eq!(seq_id, 6);
}

/// Migration is idempotent: running twice does not duplicate rows.
#[test]
fn tck_00630_migration_idempotent() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("idempotent.db");

    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 3);
    }

    // First migration.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 3);
        assert!(!stats.already_migrated);
    }

    // Second migration — should be a no-op.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 0);
        assert!(stats.already_migrated);
    }

    // Verify row count is still 3 (not 6).
    {
        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 3);
    }
}

/// Migration fails fast on ambiguous state (both `events` and `ledger_events`
/// have rows).
#[test]
fn tck_00630_migration_fails_on_ambiguous_state() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ambiguous.db");

    // Seed canonical events.
    {
        let ledger = Ledger::open(&path).unwrap();
        ledger
            .append(&EventRecord::new(
                "canonical.event",
                "session-1",
                "actor-1",
                b"canonical".to_vec(),
            ))
            .unwrap();
    }

    // Seed legacy table.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 2);
    }

    // Migration should fail with AmbiguousSchemaState.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let result = migrate_legacy_ledger_events(&conn);
        assert!(
            matches!(result, Err(LedgerError::AmbiguousSchemaState { .. })),
            "should fail on ambiguous state, got {result:?}"
        );
    }
}

/// Migration preserves signature bytes and column mapping
/// (`work_id` -> `session_id`).
#[test]
fn tck_00630_migration_preserves_columns() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("columns.db");

    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-SIG-1",
                "episode_spawned",
                "work-999",
                "actor-42",
                br#"{"episode_id":"ep-1"}"#,
                vec![0xDE_u8, 0xAD, 0xBE, 0xEF],
                42_000_000_000_i64,
            ],
        )
        .unwrap();
    }

    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 1);
    }

    let ledger = Ledger::open(&path).unwrap();
    let events = ledger.read_from(1, 10).unwrap();
    assert_eq!(events.len(), 1);

    let event = &events[0];
    assert_eq!(event.event_type, "episode_spawned");
    assert_eq!(event.session_id, "work-999"); // work_id -> session_id
    assert_eq!(event.actor_id, "actor-42");
    assert_eq!(event.signature, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    assert_eq!(event.timestamp_ns, 42_000_000_000);
    assert_eq!(event.record_version, CURRENT_RECORD_VERSION);
    assert!(event.prev_hash.is_some());
    assert!(event.event_hash.is_some());
    assert_eq!(event.event_hash.as_ref().unwrap().len(), 32);
}

/// Regression test: `LegacyModeReadOnly` pre-migration disappears
/// post-migration.
#[test]
fn tck_00630_legacy_read_only_resolved_after_migration() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("readonly_regression.db");

    // Seed legacy data.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 2);
    }

    // Pre-migration: open ledger, confirm LegacyModeReadOnly.
    {
        let ledger = Ledger::open(&path).unwrap();
        let result = ledger.append(&EventRecord::new("test", "s", "a", b"payload".to_vec()));
        assert!(
            matches!(result, Err(LedgerError::LegacyModeReadOnly)),
            "pre-migration: writes must be rejected, got {result:?}"
        );

        // Reads work.
        let events = ledger.read_from(1, 10).unwrap();
        assert_eq!(events.len(), 2);
    }

    // Run migration.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 2);
    }

    // Post-migration: open ledger, confirm canonical mode.
    {
        let ledger = Ledger::open(&path).unwrap();

        // Reads still work.
        let events = ledger.read_from(1, 10).unwrap();
        assert_eq!(events.len(), 2);

        // Writes now succeed.
        let seq_id = ledger
            .append(&EventRecord::new(
                "post_migration",
                "session-new",
                "actor-new",
                b"new".to_vec(),
            ))
            .unwrap();
        assert_eq!(seq_id, 3);

        // head_sync is correct.
        assert_eq!(ledger.head_sync().unwrap(), 3);
    }
}

/// After migration, `determine_read_mode` returns `CanonicalEvents`
/// (not `LegacyLedgerEvents` or `AmbiguousSchemaState`).
#[test]
fn tck_00630_determine_read_mode_canonical_after_migration() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("readmode.db");

    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 3);
    }

    // Run migration.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        migrate_legacy_ledger_events(&conn).unwrap();
    }

    // Open a fresh Ledger — should be canonical mode (no error, no legacy).
    let ledger = Ledger::open(&path).unwrap();

    // Verify all events are readable via canonical path.
    let events = ledger.read_from(1, 100).unwrap();
    assert_eq!(events.len(), 3);

    // Verify hash chain via verify_chain.
    let verify_result = ledger.verify_chain(
        |payload, prev_hash| {
            let prev: [u8; 32] = prev_hash.try_into().unwrap();
            crate::crypto::EventHasher::hash_event(payload, &prev).to_vec()
        },
        |_event_hash, _signature| true, // Signature verification out of scope.
    );
    assert!(
        verify_result.is_ok(),
        "hash chain verification should pass after migration"
    );
}

/// Migration of an empty `ledger_events` table works (rename-only, no hash
/// chain).
#[test]
fn tck_00630_migration_empty_legacy_table() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty_legacy.db");

    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
        // No rows inserted.
    }

    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();

        assert!(!stats.already_migrated);
        assert_eq!(stats.rows_migrated, 0);

        // Verify `ledger_events` still exists (preserved but empty) and
        // `ledger_events_legacy_frozen` was created as audit copy.
        assert!(test_table_exists(&conn, "ledger_events"));
        assert!(test_table_exists(&conn, "ledger_events_legacy_frozen"));
    }

    // Ledger opens cleanly in canonical mode.
    let ledger = Ledger::open(&path).unwrap();
    let events = ledger.read_from(1, 10).unwrap();
    assert!(events.is_empty());

    // Writes succeed.
    let seq_id = ledger
        .append(&EventRecord::new("test", "s", "a", b"data".to_vec()))
        .unwrap();
    assert_eq!(seq_id, 1);
}

/// Migration rejects mismatched legacy schema.
#[test]
fn tck_00630_migration_rejects_bad_schema() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("bad_schema.db");

    {
        let conn = Connection::open(&path).unwrap();
        // Create a table with wrong column types.
        conn.execute(
            "CREATE TABLE ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger_events VALUES ('E1', 'test', 'w1', 'a1', '{}', x'AA', 100)",
            [],
        )
        .unwrap();
    }

    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let result = migrate_legacy_ledger_events(&conn);
        assert!(
            matches!(result, Err(LedgerError::LegacySchemaMismatch { .. })),
            "should reject bad schema, got {result:?}"
        );
    }
}

/// After migration, appending signed events continues the hash chain from
/// the migrated tail.
#[test]
fn tck_00630_post_migration_hash_chain_continuity() {
    use crate::crypto::EventHasher;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("continuity.db");

    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 3);
    }

    // Migrate.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        migrate_legacy_ledger_events(&conn).unwrap();
    }

    // Open ledger, append new events using append_signed.
    let ledger = Ledger::open(&path).unwrap();

    // Get the last event hash (tail of migrated chain).
    let tail_hash = ledger.last_event_hash().unwrap();
    assert_eq!(tail_hash.len(), 32);
    // Tail hash should NOT be genesis (since we migrated 3 rows).
    assert_ne!(tail_hash, vec![0u8; 32]);

    // Append a new event via append_signed.
    let new_event = EventRecord::new(
        "post_migration.signed",
        "session-new",
        "actor-new",
        b"new payload".to_vec(),
    );
    let seq_id = ledger
        .append_signed(
            new_event,
            |payload, prev_hash| {
                let prev: [u8; 32] = prev_hash.try_into().unwrap();
                EventHasher::hash_event(payload, &prev).to_vec()
            },
            <[u8]>::to_vec, // Dummy signer for test.
        )
        .unwrap();
    assert_eq!(seq_id, 4);

    // Verify the full chain (migrated + new).
    let verify_result = ledger.verify_chain(
        |payload, prev_hash| {
            let prev: [u8; 32] = prev_hash.try_into().unwrap();
            EventHasher::hash_event(payload, &prev).to_vec()
        },
        |_event_hash, _signature| true,
    );
    assert!(
        verify_result.is_ok(),
        "full chain (migrated + new) should verify"
    );
}

/// Regression: if `ledger_events_legacy_frozen` exists AND a live
/// `ledger_events` table also exists with rows (recreated by a legacy
/// writer after the initial migration), the migration MUST idempotently
/// re-migrate those rows into `events` continuing the hash chain from
/// the current tail, then re-empty `ledger_events`.  This prevents
/// a restart-fatal error while preserving chain continuity.
#[test]
fn tck_00630_remigration_frozen_plus_live_legacy_succeeds() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("frozen_plus_live.db");

    // Step 1: Seed legacy data and perform an initial migration.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 3);
    }
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 3);
        assert!(!stats.already_migrated);

        // Verify: `ledger_events` still exists (empty), `ledger_events_legacy_frozen`
        // exists.
        assert!(test_table_exists(&conn, "ledger_events"));
        let live_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            live_count, 0,
            "ledger_events should be empty after migration"
        );
        assert!(test_table_exists(&conn, "ledger_events_legacy_frozen"));
    }

    // Step 2: Simulate a legacy writer inserting rogue rows into the
    // still-existing (but empty) `ledger_events` table.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-ROGUE-1",
                "work_claimed",
                "work-rogue",
                "actor-rogue",
                br#"{"rogue":true}"#,
                vec![0xBB_u8, 0x01],
                99_000_000_000_i64,
            ],
        )
        .unwrap();
    }

    // Step 3: Re-migration succeeds, appending 1 row to events.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 1, "should re-migrate the 1 rogue row");
        assert!(!stats.already_migrated);

        // ledger_events should now be empty again.
        let live_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(live_count, 0, "ledger_events should be re-emptied");

        // events should have 3 (initial) + 1 (re-migrated) = 4 rows.
        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events_count, 4, "events should have 4 rows total");
    }

    // Step 4: Verify hash chain integrity across the full chain.
    let ledger = Ledger::open(&path).unwrap();
    let verify_result = ledger.verify_chain(
        |payload, prev_hash| {
            let prev: [u8; 32] = prev_hash.try_into().unwrap();
            crate::crypto::EventHasher::hash_event(payload, &prev).to_vec()
        },
        |_event_hash, _signature| true,
    );
    assert!(
        verify_result.is_ok(),
        "hash chain should be intact after re-migration: {verify_result:?}"
    );
}

/// Regression: if `ledger_events_legacy_frozen` exists AND `ledger_events`
/// is recreated but empty (zero rows), the migration returns
/// `already_migrated = true` (this is the benign case).
#[test]
fn tck_00630_migration_frozen_plus_empty_live_legacy_ok() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("frozen_plus_empty.db");

    // Initial migration.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 2);
    }
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 2);
    }

    // Recreate `ledger_events` but leave it empty.
    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
        // No rows inserted — table exists but is empty.
    }

    // Migration should succeed as already_migrated = true.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert!(
            stats.already_migrated,
            "empty recreated ledger_events should be treated as already migrated"
        );
        assert_eq!(stats.rows_migrated, 0);
    }
}

/// `init_canonical_schema` is idempotent and creates the `events` table.
#[test]
fn tck_00630_init_canonical_schema_idempotent() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("canon_schema.db");

    let conn = Connection::open(&path).unwrap();

    // First call creates the table.
    init_canonical_schema(&conn).unwrap();
    assert!(test_table_exists(&conn, "events"));

    // Second call is a no-op.
    init_canonical_schema(&conn).unwrap();

    // Events table is functional.
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

/// Integration: daemon startup migration path — seed legacy data, apply
/// canonical schema, run migration, then confirm canonical appendability.
#[test]
fn tck_00630_daemon_startup_migration_integration() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("daemon_startup.db");

    // Seed legacy data (simulates pre-migration daemon database).
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 4);
    }

    // Simulate daemon startup: init canonical schema + migrate.
    {
        let conn = Connection::open(&path).unwrap();
        init_canonical_schema(&conn).unwrap();
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 4);
        assert!(!stats.already_migrated);
    }

    // Open via Ledger and confirm canonical mode + appendability.
    let ledger = Ledger::open(&path).unwrap();

    // Should be able to write (not in legacy read-only mode).
    let seq_id = ledger
        .append(&EventRecord::new(
            "post_migration.daemon",
            "session-daemon",
            "actor-daemon",
            b"daemon payload".to_vec(),
        ))
        .unwrap();
    // 4 migrated + 1 new = seq_id 5.
    assert_eq!(seq_id, 5);

    // All 5 events readable.
    let events = ledger.read_from(1, 100).unwrap();
    assert_eq!(events.len(), 5);
}

/// BLOCKER 1 regression: on a pre-canonicalized DB where `init_schema`
/// has already created an empty `ledger_events` table, migration must be
/// a no-op (not `AmbiguousSchemaState`).
///
/// Counterexample: daemon startup calls `init_schema_with_signing_key`
/// first (which creates `ledger_events` via `CREATE TABLE IF NOT EXISTS`),
/// then `init_canonical_schema` (which creates `events`), then populates
/// `events`, then calls `migrate_legacy_ledger_events`.  The old code
/// returned `AmbiguousSchemaState` because `events_rows > 0`, even
/// though `ledger_events` had zero rows.
#[test]
fn tck_00630_blocker1_canonical_db_with_empty_legacy_table_is_noop() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("blocker1_pre_canonical.db");

    // Step 1: Create a canonical DB with events.
    {
        let ledger = Ledger::open(&path).unwrap();
        ledger
            .append(&EventRecord::new(
                "canonical.event",
                "session-1",
                "actor-1",
                b"canonical payload".to_vec(),
            ))
            .unwrap();
    }

    // Step 2: Simulate daemon `init_schema_with_signing_key` creating
    // an empty `ledger_events` table (as it does on every startup).
    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
        // No rows — just the table schema.
    }

    // Step 3: Run migration — MUST be a no-op, not AmbiguousSchemaState.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert!(
            stats.already_migrated,
            "canonical DB + empty ledger_events should be already_migrated, got {stats:?}"
        );
        assert_eq!(stats.rows_migrated, 0);
    }

    // Step 4: Ledger opens cleanly in canonical mode.
    let ledger = Ledger::open(&path).unwrap();
    let events = ledger.read_from(1, 100).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "canonical.event");

    // Step 5: Writes still succeed.
    let seq_id = ledger
        .append(&EventRecord::new(
            "post_check.event",
            "session-2",
            "actor-2",
            b"new payload".to_vec(),
        ))
        .unwrap();
    assert_eq!(seq_id, 2);
}

/// BLOCKER 2 regression: after migration, legacy writers can still INSERT
/// into `ledger_events` without crashing.  On next startup, the migration
/// idempotently re-migrates the new rows into `events` and re-empties
/// `ledger_events`.  The daemon restarts cleanly.
#[test]
fn tck_00630_blocker2_legacy_writers_survive_after_migration() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("blocker2_legacy_writers.db");

    // Step 1: Seed legacy data and migrate.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 3);
    }
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 3);
    }

    // Step 2: Verify `ledger_events` still exists and is empty.
    {
        let conn = Connection::open(&path).unwrap();
        assert!(
            test_table_exists(&conn, "ledger_events"),
            "ledger_events must still exist after migration"
        );
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0, "ledger_events should be empty after migration");
    }

    // Step 3: Legacy writer INSERTs into `ledger_events` — must NOT crash.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, \
             payload, signature, timestamp_ns) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-POST-MIG-1",
                "work_claimed",
                "work-post",
                "actor-post",
                br#"{"post_migration":true}"#,
                vec![0xCC_u8, 0x01],
                200_000_000_000_i64,
            ],
        )
        .expect("legacy writer INSERT must not crash after migration");
    }

    // Step 4: On next "startup", migration re-migrates the 1 rogue row.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(
            stats.rows_migrated, 1,
            "should re-migrate the 1 post-cutover legacy row"
        );
        assert!(!stats.already_migrated);

        // ledger_events is empty again.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0, "ledger_events should be re-emptied");

        // events has 3 (initial) + 1 (re-migrated) = 4.
        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events_count, 4);
    }

    // Step 5: Ledger opens cleanly and writes succeed.
    let ledger = Ledger::open(&path).unwrap();
    let events = ledger.read_from(1, 100).unwrap();
    assert_eq!(events.len(), 4);

    let seq_id = ledger
        .append(&EventRecord::new(
            "post_remigration.event",
            "session-post",
            "actor-post",
            b"post remigration".to_vec(),
        ))
        .unwrap();
    assert_eq!(
        seq_id, 5,
        "should be 5th event after 3 initial + 1 remigrated"
    );
}

/// BLOCKER 2 regression: after migration + restart with no legacy writes,
/// migration is a no-op and the daemon operates in canonical mode.
#[test]
fn tck_00630_blocker2_restart_after_migration_no_legacy_writes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("blocker2_restart.db");

    // Step 1: Seed legacy data and migrate.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 2);
    }
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 2);
    }

    // Step 2: Simulate daemon restart — init_schema + migrate again.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert!(
            stats.already_migrated,
            "second startup should be a no-op migration"
        );
        assert_eq!(stats.rows_migrated, 0);
    }

    // Step 3: Ledger is in canonical mode, reads and writes work.
    let ledger = Ledger::open(&path).unwrap();
    let events = ledger.read_from(1, 100).unwrap();
    assert_eq!(events.len(), 2);

    let seq_id = ledger
        .append(&EventRecord::new(
            "restart.event",
            "session-restart",
            "actor-restart",
            b"restart payload".to_vec(),
        ))
        .unwrap();
    assert_eq!(seq_id, 3);
}

/// BLOCKER 1+2 combined: full daemon startup sequence on a canonical DB
/// where `init_schema_with_signing_key` creates empty `ledger_events`,
/// `init_canonical_schema` creates `events` (already has rows from
/// previous startup), and migration is called.  Validates the exact
/// daemon startup codepath from main.rs.
#[test]
fn tck_00630_blocker1_blocker2_full_daemon_startup_canonical_db() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("full_daemon_startup.db");

    // First "daemon lifetime": seed legacy data, migrate, emit new events.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 3);
    }
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 3);
    }
    // Emit some canonical events (simulates daemon runtime).
    {
        let ledger = Ledger::open(&path).unwrap();
        ledger
            .append(&EventRecord::new(
                "runtime.event",
                "session-runtime",
                "actor-runtime",
                b"runtime payload".to_vec(),
            ))
            .unwrap();
    }

    // Second "daemon lifetime" restart: same startup sequence as main.rs:
    // 1. init_schema_with_signing_key (creates `ledger_events` IF NOT EXISTS)
    // 2. init_canonical_schema (creates `events` IF NOT EXISTS)
    // 3. migrate_legacy_ledger_events
    {
        let conn = Connection::open(&path).unwrap();

        // (1) Simulates SqliteLedgerEventEmitter::init_schema_with_signing_key
        create_legacy_ledger_events_table(&conn);

        // (2) init_canonical_schema
        init_schema(&conn);

        // (3) migrate — must be no-op, not AmbiguousSchemaState
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert!(
            stats.already_migrated,
            "second startup on canonical DB must be no-op, got {stats:?}"
        );
        assert_eq!(stats.rows_migrated, 0);
    }

    // Verify ledger is fully operational in canonical mode.
    let ledger = Ledger::open(&path).unwrap();
    let events = ledger.read_from(1, 100).unwrap();
    // 3 migrated + 1 runtime = 4
    assert_eq!(events.len(), 4);

    let seq_id = ledger
        .append(&EventRecord::new(
            "second_startup.event",
            "session-2nd",
            "actor-2nd",
            b"second startup".to_vec(),
        ))
        .unwrap();
    assert_eq!(seq_id, 5);
}

/// Re-migration hash chain continuation: after initial migration +
/// legacy writes to `ledger_events`, the re-migration appends from the
/// tail of the hashed chain in `events` (not from genesis).
#[test]
fn tck_00630_remigration_hash_chain_continues_from_tail() {
    use crate::crypto::EventHasher;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("remig_chain_tail.db");

    // Step 1: Initial migration of 3 legacy rows (gives 3 hashed events).
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 3);
    }
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 3);
    }

    // Capture the tail hash after initial migration (event #3's hash).
    let tail_hash_before: Vec<u8> = {
        let conn = Connection::open(&path).unwrap();
        conn.query_row(
            "SELECT event_hash FROM events WHERE event_hash IS NOT NULL \
             ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        tail_hash_before.len(),
        32,
        "migration must produce 32-byte hashes"
    );

    // Step 2: Legacy writer inserts a post-cutover row.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-POSTCUTOVER-1",
                "gate_lease_issued",
                "work-post",
                "actor-post",
                br#"{"lease":"post-cutover"}"#,
                vec![0xDD_u8, 0x01],
                300_000_000_000_i64,
            ],
        )
        .unwrap();
    }

    // Step 3: Re-migration.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 1);
    }

    // Step 4: Verify the re-migrated event's prev_hash equals tail_hash_before.
    {
        let conn = Connection::open(&path).unwrap();
        // Event #4 is the re-migrated row (last by rowid).
        let prev_hash_of_remigrated: Vec<u8> = conn
            .query_row(
                "SELECT prev_hash FROM events ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            prev_hash_of_remigrated, tail_hash_before,
            "re-migrated event's prev_hash must equal the tail hash before re-migration"
        );

        // Verify event_hash is correctly computed.
        let (payload, event_hash): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT payload, event_hash FROM events ORDER BY rowid DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let prev: [u8; 32] = tail_hash_before.as_slice().try_into().unwrap();
        let expected_hash = EventHasher::hash_event(&payload, &prev);
        assert_eq!(
            event_hash,
            expected_hash.as_slice(),
            "re-migrated event_hash must be computed from tail prev_hash"
        );
    }

    // Step 5: Full chain verification (all events have hashes from migration).
    let ledger = Ledger::open(&path).unwrap();
    let verify_result = ledger.verify_chain(
        |payload, prev_hash| {
            let prev: [u8; 32] = prev_hash.try_into().unwrap();
            EventHasher::hash_event(payload, &prev).to_vec()
        },
        |_event_hash, _signature| true,
    );
    assert!(
        verify_result.is_ok(),
        "full chain (initial migration + re-migrated) must verify"
    );
}

/// Re-migration is idempotent: re-migrating after a re-migration (with no
/// new legacy rows) is a no-op and does not duplicate rows.
#[test]
fn tck_00630_remigration_idempotent_no_duplicates() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("remig_idempotent.db");

    // Step 1: Initial migration.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 2);
    }
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 2);
    }

    // Step 2: Legacy writer inserts 1 post-cutover row.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-REMIG-1",
                "work_claimed",
                "work-remig",
                "actor-remig",
                br#"{"remig":1}"#,
                vec![0xEE_u8, 0x01],
                400_000_000_000_i64,
            ],
        )
        .unwrap();
    }

    // Step 3: First re-migration.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 1, "first re-migration migrates 1 row");
        assert!(!stats.already_migrated);

        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events_count, 3, "2 initial + 1 re-migrated = 3");
    }

    // Step 4: Second re-migration (no new legacy rows) — must be no-op.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert!(
            stats.already_migrated,
            "second re-migration should be no-op"
        );
        assert_eq!(stats.rows_migrated, 0);

        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events_count, 3, "no duplicates: still 3 rows");
    }

    // Step 5: Third re-migration — still no-op.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert!(stats.already_migrated);
        assert_eq!(stats.rows_migrated, 0);

        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            events_count, 3,
            "no duplicates: still 3 rows after third run"
        );
    }
}

/// `AmbiguousSchemaState` still fires when `events > 0, legacy > 0,
/// frozen NOT exists` (initial ambiguity — no prior migration).
#[test]
fn tck_00630_ambiguous_schema_state_without_frozen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ambiguous_no_frozen.db");

    // Step 1: Create both tables with rows but NO frozen table.
    {
        let conn = Connection::open(&path).unwrap();
        // Create canonical events table and insert a row.
        init_schema(&conn);
        conn.execute(
            "INSERT INTO events (event_type, session_id, actor_id, record_version, \
             payload, timestamp_ns, prev_hash, event_hash, signature) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                "canonical.event",
                "session-1",
                "actor-1",
                1_i64,
                b"canonical payload",
                1_000_000_000_i64,
                vec![0_u8; 32],
                vec![1_u8; 32],
                Vec::<u8>::new(),
            ],
        )
        .unwrap();

        // Create legacy table with rows.
        seed_legacy_table(&conn, 2);
    }

    // Step 2: Verify frozen does NOT exist.
    {
        let conn = Connection::open(&path).unwrap();
        assert!(
            !test_table_exists(&conn, "ledger_events_legacy_frozen"),
            "frozen table must NOT exist for this test"
        );
    }

    // Step 3: Migration MUST fail with AmbiguousSchemaState.
    {
        let conn = Connection::open(&path).unwrap();
        let result = migrate_legacy_ledger_events(&conn);
        assert!(
            matches!(
                result,
                Err(LedgerError::AmbiguousSchemaState {
                    events_rows: 1,
                    legacy_rows: 2,
                })
            ),
            "expected AmbiguousSchemaState(events=1, legacy=2), got {result:?}"
        );
    }
}

/// Full daemon lifecycle: migrate -> runtime writes (canonical + legacy) ->
/// restart -> re-migrate -> runtime writes -> restart -> no-op.
/// Validates the complete production scenario end-to-end.
#[test]
fn tck_00630_full_lifecycle_migrate_write_restart_remigrate() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("full_lifecycle.db");

    // === First daemon lifetime ===
    // Seed legacy data.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 3);
    }
    // Startup: init schema + migrate.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 3);
    }
    // Runtime: canonical events via Ledger + legacy events via
    // SqliteLedgerEventEmitter.
    {
        let ledger = Ledger::open(&path).unwrap();
        ledger
            .append(&EventRecord::new(
                "runtime.canonical",
                "session-rt",
                "actor-rt",
                b"canonical runtime".to_vec(),
            ))
            .unwrap();
    }
    // Legacy writer during runtime.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-RT-LEGACY-1",
                "gate_lease_issued",
                "work-rt",
                "actor-rt",
                br#"{"lease":"runtime"}"#,
                vec![0xFF_u8, 0x01],
                500_000_000_000_i64,
            ],
        )
        .unwrap();
    }

    // === Second daemon lifetime (restart) ===
    // Startup: init schema + re-migrate.
    {
        let conn = Connection::open(&path).unwrap();
        // Simulate daemon init_schema_with_signing_key (creates ledger_events IF NOT
        // EXISTS).
        create_legacy_ledger_events_table(&conn);
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(
            stats.rows_migrated, 1,
            "re-migrates the 1 runtime legacy row"
        );
        assert!(!stats.already_migrated);
    }
    // Runtime: more canonical events.
    {
        let ledger = Ledger::open(&path).unwrap();
        ledger
            .append(&EventRecord::new(
                "runtime2.canonical",
                "session-rt2",
                "actor-rt2",
                b"second runtime".to_vec(),
            ))
            .unwrap();
    }

    // === Third daemon lifetime (restart, no legacy writes) ===
    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert!(stats.already_migrated, "no legacy rows, should be no-op");
        assert_eq!(stats.rows_migrated, 0);
    }

    // Final verification: 3 initial + 1 canonical + 1 re-migrated + 1 canonical =
    // 6.
    let ledger = Ledger::open(&path).unwrap();
    let events = ledger.read_from(1, 100).unwrap();
    assert_eq!(
        events.len(),
        6,
        "3 initial + 1 canonical + 1 remig + 1 canonical = 6"
    );

    // Verify the hashed subset of the chain (migrated + re-migrated events
    // have proper hashes; unsigned Ledger::append events have NULL hashes
    // and are excluded from cryptographic verification).
    // Check that all 4 hashed events (3 initial + 1 re-migrated) form a
    // valid chain.
    {
        let conn = Connection::open(&path).unwrap();
        let hashed_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_hash IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            hashed_count, 4,
            "3 initial migration + 1 re-migration = 4 hashed events"
        );
    }
}

/// Regression: frozen snapshot has rows but canonical `events` chain is empty.
/// This indicates data loss after a prior successful migration.  Must fail
/// closed with `MigrationPartialState`.
#[test]
fn tck_00630_frozen_exists_events_empty_frozen_nonempty_fails_closed() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("frozen_nonempty_events_empty.db");

    // Step 1: Perform a normal migration of 3 legacy rows.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 3);
    }
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 3);
    }

    // Step 2: Simulate data loss — delete all rows from `events`.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DELETE FROM events").unwrap();
        // Verify: frozen has rows, events is empty.
        let frozen_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ledger_events_legacy_frozen",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(frozen_count > 0, "frozen snapshot must have rows");
        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events_count, 0, "events must be empty for this test");
    }

    // Step 3: Re-create `ledger_events` (simulates daemon restart with
    // init_schema_with_signing_key that does CREATE TABLE IF NOT EXISTS).
    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
    }

    // Step 4: Migration must fail closed.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let result = migrate_legacy_ledger_events(&conn);
        assert!(
            matches!(result, Err(LedgerError::MigrationPartialState { .. })),
            "expected MigrationPartialState error for frozen-nonempty + events-empty, got: {result:?}"
        );
        // Verify the error message mentions data loss.
        if let Err(LedgerError::MigrationPartialState { message }) = result {
            assert!(
                message.contains("data loss"),
                "error message should mention data loss: {message}"
            );
        }
    }
}

/// Regression: frozen snapshot is empty AND canonical `events` is empty.
/// This means the original legacy table was empty when migrated — valid no-op.
#[test]
fn tck_00630_frozen_exists_events_empty_frozen_empty_noop() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("frozen_empty_events_empty.db");

    // Step 1: Perform a migration with an empty legacy table (0 rows).
    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
        // Don't insert any rows — empty legacy table.
    }
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 0);
        assert!(!stats.already_migrated, "first migration of empty table");
    }

    // Verify state: frozen exists (empty), events is empty.
    {
        let conn = Connection::open(&path).unwrap();
        let frozen_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ledger_events_legacy_frozen'",
                [],
                |row| row.get::<_, i64>(0).map(|v| v > 0),
            )
            .unwrap();
        assert!(frozen_exists, "frozen table must exist after migration");
        let frozen_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ledger_events_legacy_frozen",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(frozen_count, 0, "frozen snapshot must be empty");
        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events_count, 0, "events must be empty");
    }

    // Step 2: Re-create `ledger_events` (simulates daemon restart).
    {
        let conn = Connection::open(&path).unwrap();
        create_legacy_ledger_events_table(&conn);
    }

    // Step 3: Migration should succeed as a no-op (already_migrated = true).
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert!(
            stats.already_migrated,
            "empty-frozen + empty-events should be treated as already migrated"
        );
        assert_eq!(stats.rows_migrated, 0);
    }
}

/// Regression (TCK-00630 R5): frozen snapshot has rows, canonical `events` is
/// empty, but `ledger_events` has live rows (simulating truncation + rogue
/// write).  The old code checked `live_legacy_rows` BEFORE `events_rows`
/// inside the `frozen_exists` branch, allowing re-migration to bypass the
/// fail-closed `MigrationPartialState` guard.  After the fix, `events_rows`
/// is checked FIRST — this scenario must always fail closed.
#[test]
fn tck_00630_frozen_nonempty_events_empty_live_legacy_nonzero_fails_closed() {
    let dir = TempDir::new().unwrap();
    let path = dir
        .path()
        .join("frozen_nonempty_events_empty_live_nonzero.db");

    // Step 1: Perform a normal migration of 3 legacy rows.
    {
        let conn = Connection::open(&path).unwrap();
        seed_legacy_table(&conn, 3);
    }
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 3);
        assert!(!stats.already_migrated);
    }

    // Step 2: Simulate data loss — delete all rows from `events`.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DELETE FROM events").unwrap();

        // Verify preconditions: frozen has rows, events is empty.
        let frozen_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ledger_events_legacy_frozen",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(frozen_count, 3, "frozen snapshot must have 3 rows");
        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(events_count, 0, "events must be empty after truncation");
    }

    // Step 3: Simulate rogue write — insert a new row into `ledger_events`.
    // This is the key differentiator from the existing test: live_legacy > 0.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO ledger_events \
             (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "EVT-ROGUE-TRUNC",
                "work_claimed",
                "work-rogue",
                "actor-rogue",
                br#"{"rogue_after_truncation":true}"#,
                vec![0xCC_u8, 0x01],
                200_000_000_000_i64,
            ],
        )
        .unwrap();

        // Verify: live legacy has 1 row.
        let live_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            live_count, 1,
            "ledger_events must have 1 rogue row for this test"
        );
    }

    // Step 4: Migration must fail closed — NOT re-migrate the rogue row.
    {
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn);
        let result = migrate_legacy_ledger_events(&conn);
        assert!(
            matches!(result, Err(LedgerError::MigrationPartialState { .. })),
            "expected MigrationPartialState for frozen-nonempty + events-empty + \
             live-legacy-nonzero, got: {result:?}"
        );
        // Verify the error message includes diagnostic context.
        if let Err(LedgerError::MigrationPartialState { message }) = result {
            assert!(
                message.contains("data loss"),
                "error message should mention data loss: {message}"
            );
            assert!(
                message.contains("events_rows=0"),
                "error message should include events_rows=0 diagnostic: {message}"
            );
        }
    }
}
