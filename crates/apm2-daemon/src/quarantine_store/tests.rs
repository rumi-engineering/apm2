// AGENT-AUTHORED (TCK-00496)
//! Tests for quarantine store: priority-aware eviction, saturation-safe
//! insertion, per-session quota isolation, restart-safe persistence,
//! durable capacity guard, and adversarial flood tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::store::*;
use crate::admission_kernel::QuarantineGuard;

// =============================================================================
// Test Helpers
// =============================================================================

fn test_hash(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn small_config() -> QuarantineStoreConfig {
    QuarantineStoreConfig {
        max_global_entries: 8,
        max_per_session_entries: 4,
        max_tracked_sessions: 4,
    }
}

fn tiny_config() -> QuarantineStoreConfig {
    QuarantineStoreConfig {
        max_global_entries: 4,
        max_per_session_entries: 2,
        max_tracked_sessions: 16,
    }
}

/// Deterministic tick provider for tests.
fn make_tick_provider(start: u64) -> (Arc<AtomicU64>, Box<dyn Fn() -> u64 + Send + Sync>) {
    let tick = Arc::new(AtomicU64::new(start));
    let tick_clone = Arc::clone(&tick);
    let provider = Box::new(move || tick_clone.load(Ordering::Relaxed));
    (tick, provider)
}

fn create_temp_db() -> tempfile::NamedTempFile {
    tempfile::NamedTempFile::new().expect("failed to create temp file")
}

// =============================================================================
// In-Memory Store: Basic Operations
// =============================================================================

#[test]
fn store_new_is_empty() {
    let store = QuarantineStore::new();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
}

#[test]
fn store_insert_and_lookup() {
    let mut store = QuarantineStore::with_config(small_config());
    let result = store
        .insert(
            "session-1",
            QuarantinePriority::Normal,
            test_hash(1),
            test_hash(2),
            test_hash(3),
            100,
            200,
            "test reason",
            100,
        )
        .unwrap();
    let id = result.entry_id;
    assert!(result.evicted_id.is_none()); // No eviction on non-full store

    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
    assert_eq!(store.session_count("session-1"), 1);

    let entry = store.find_by_reservation_hash(&test_hash(3));
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().id, id);
    assert_eq!(entry.unwrap().session_id, "session-1");
    assert_eq!(entry.unwrap().priority, QuarantinePriority::Normal);
}

#[test]
fn store_remove() {
    let mut store = QuarantineStore::with_config(small_config());
    let id = store
        .insert(
            "session-1",
            QuarantinePriority::Normal,
            test_hash(1),
            test_hash(2),
            test_hash(3),
            100,
            200,
            "test",
            100,
        )
        .unwrap()
        .entry_id;

    assert!(store.remove(id));
    assert_eq!(store.len(), 0);
    assert_eq!(store.session_count("session-1"), 0);

    // Double remove returns false
    assert!(!store.remove(id));
}

// =============================================================================
// Priority-Aware Eviction
// =============================================================================

#[test]
fn eviction_prefers_expired_entries() {
    let mut store = QuarantineStore::with_config(tiny_config());

    // Fill with entries: 2 expired, 2 active
    // Entry 1: expired at tick 50, priority High
    store
        .insert(
            "s1",
            QuarantinePriority::High,
            test_hash(1),
            test_hash(11),
            test_hash(21),
            10,
            50,
            "expired-high",
            100, // current_tick > expires_at_tick
        )
        .unwrap();
    // Entry 2: expired at tick 60, priority Critical
    store
        .insert(
            "s1",
            QuarantinePriority::Critical,
            test_hash(2),
            test_hash(12),
            test_hash(22),
            10,
            60,
            "expired-critical",
            100,
        )
        .unwrap();
    // Entry 3: active until tick 500, priority Low
    store
        .insert(
            "s2",
            QuarantinePriority::Low,
            test_hash(3),
            test_hash(13),
            test_hash(23),
            100,
            500,
            "active-low",
            100,
        )
        .unwrap();
    // Entry 4: active until tick 500, priority Normal
    store
        .insert(
            "s2",
            QuarantinePriority::Normal,
            test_hash(4),
            test_hash(14),
            test_hash(24),
            100,
            500,
            "active-normal",
            100,
        )
        .unwrap();

    assert_eq!(store.len(), 4);

    // Insert a Low priority entry at tick 100 — should evict the oldest expired
    // entry (entry 1), regardless of its High priority
    let insert_result = store
        .insert(
            "s3",
            QuarantinePriority::Low,
            test_hash(5),
            test_hash(15),
            test_hash(25),
            100,
            500,
            "new-low",
            100,
        )
        .unwrap();
    let new_id = insert_result.entry_id;
    // Verify eviction was reported (entry 1 had id=1)
    assert!(
        insert_result.evicted_id.is_some(),
        "eviction should be reported"
    );

    assert_eq!(store.len(), 4);
    // Expired entry 1 (High priority) should have been evicted
    assert!(store.find_by_reservation_hash(&test_hash(21)).is_none());
    // New entry should exist
    assert!(store.find_by_reservation_hash(&test_hash(25)).is_some());
    assert_eq!(
        store.find_by_reservation_hash(&test_hash(25)).unwrap().id,
        new_id
    );
}

#[test]
fn eviction_never_evicts_higher_or_equal_priority_unexpired() {
    let mut store = QuarantineStore::with_config(tiny_config());

    // Fill with 4 Normal priority active entries
    for i in 0..4u8 {
        store
            .insert(
                &format!("s{i}"),
                QuarantinePriority::Normal,
                test_hash(i),
                test_hash(10 + i),
                test_hash(20 + i),
                100,
                500,
                "active-normal",
                100,
            )
            .unwrap();
    }

    assert_eq!(store.len(), 4);

    // Try to insert a Low priority entry — should fail because all active
    // entries have Normal priority (>= Low), and none are expired
    let result = store.insert(
        "s-new",
        QuarantinePriority::Low,
        test_hash(50),
        test_hash(60),
        test_hash(70),
        100,
        500,
        "cannot-evict",
        100,
    );

    assert!(matches!(
        result,
        Err(QuarantineStoreError::Saturated {
            incoming_priority: QuarantinePriority::Low
        })
    ));

    // Same-priority insertion should also fail (never evict >= priority)
    let result = store.insert(
        "s-new",
        QuarantinePriority::Normal,
        test_hash(51),
        test_hash(61),
        test_hash(71),
        100,
        500,
        "cannot-evict-same",
        100,
    );

    assert!(matches!(
        result,
        Err(QuarantineStoreError::Saturated {
            incoming_priority: QuarantinePriority::Normal
        })
    ));
}

#[test]
fn eviction_evicts_lowest_priority_when_no_expired() {
    let mut store = QuarantineStore::with_config(tiny_config());

    // Fill: 1 Low, 1 Normal, 2 High
    store
        .insert(
            "s1",
            QuarantinePriority::Low,
            test_hash(1),
            test_hash(11),
            test_hash(21),
            100,
            500,
            "low",
            100,
        )
        .unwrap();
    store
        .insert(
            "s1",
            QuarantinePriority::Normal,
            test_hash(2),
            test_hash(12),
            test_hash(22),
            100,
            500,
            "normal",
            100,
        )
        .unwrap();
    store
        .insert(
            "s2",
            QuarantinePriority::High,
            test_hash(3),
            test_hash(13),
            test_hash(23),
            100,
            500,
            "high-1",
            100,
        )
        .unwrap();
    store
        .insert(
            "s2",
            QuarantinePriority::High,
            test_hash(4),
            test_hash(14),
            test_hash(24),
            100,
            500,
            "high-2",
            100,
        )
        .unwrap();

    assert_eq!(store.len(), 4);

    // Insert Critical — should evict the Low entry (lowest priority)
    store
        .insert(
            "s3",
            QuarantinePriority::Critical,
            test_hash(5),
            test_hash(15),
            test_hash(25),
            100,
            500,
            "critical",
            100,
        )
        .unwrap();

    assert_eq!(store.len(), 4);
    // Low entry should be evicted
    assert!(store.find_by_reservation_hash(&test_hash(21)).is_none());
    // Normal and High entries should remain
    assert!(store.find_by_reservation_hash(&test_hash(22)).is_some());
    assert!(store.find_by_reservation_hash(&test_hash(23)).is_some());
    assert!(store.find_by_reservation_hash(&test_hash(24)).is_some());
}

#[test]
fn eviction_tiebreaker_is_oldest_entry() {
    let mut store = QuarantineStore::with_config(tiny_config());

    // Fill with 4 Low priority entries
    for i in 0..4u8 {
        store
            .insert(
                &format!("s{i}"),
                QuarantinePriority::Low,
                test_hash(i),
                test_hash(10 + i),
                test_hash(20 + i),
                100 + u64::from(i),
                500,
                "low",
                100,
            )
            .unwrap();
    }

    // Insert Normal — should evict oldest Low (id=1, lowest ID)
    store
        .insert(
            "s-new",
            QuarantinePriority::Normal,
            test_hash(50),
            test_hash(60),
            test_hash(70),
            110,
            500,
            "normal",
            110,
        )
        .unwrap();

    // First Low entry (reservation_hash = test_hash(20)) should be evicted
    assert!(store.find_by_reservation_hash(&test_hash(20)).is_none());
    // Others should remain
    assert!(store.find_by_reservation_hash(&test_hash(21)).is_some());
    assert!(store.find_by_reservation_hash(&test_hash(22)).is_some());
    assert!(store.find_by_reservation_hash(&test_hash(23)).is_some());
}

// =============================================================================
// Saturation-Safe Insertion (Fail-Closed)
// =============================================================================

#[test]
fn saturation_denies_when_all_entries_higher_priority() {
    let mut store = QuarantineStore::with_config(tiny_config());

    // Fill with Critical priority entries
    for i in 0..4u8 {
        store
            .insert(
                &format!("s{i}"),
                QuarantinePriority::Critical,
                test_hash(i),
                test_hash(10 + i),
                test_hash(20 + i),
                100,
                500,
                "critical",
                100,
            )
            .unwrap();
    }

    // All priorities below Critical should be denied
    for priority in [
        QuarantinePriority::Low,
        QuarantinePriority::Normal,
        QuarantinePriority::High,
        QuarantinePriority::Critical,
    ] {
        let result = store.insert(
            "s-new",
            priority,
            test_hash(50),
            test_hash(60),
            test_hash(70),
            100,
            500,
            "denied",
            100,
        );
        assert!(
            matches!(result, Err(QuarantineStoreError::Saturated { .. })),
            "expected Saturated for priority {priority:?}, got {result:?}"
        );
    }
}

// =============================================================================
// Per-Session Quota Isolation
// =============================================================================

#[test]
fn per_session_quota_enforced() {
    let mut store = QuarantineStore::with_config(small_config());

    // Fill session-1 to its quota (4 entries)
    for i in 0..4u8 {
        store
            .insert(
                "session-1",
                QuarantinePriority::Normal,
                test_hash(i),
                test_hash(10 + i),
                test_hash(20 + i),
                100,
                500,
                "test",
                100,
            )
            .unwrap();
    }

    assert_eq!(store.session_count("session-1"), 4);

    // Fifth insert from session-1 should fail
    let result = store.insert(
        "session-1",
        QuarantinePriority::Normal,
        test_hash(50),
        test_hash(60),
        test_hash(70),
        100,
        500,
        "over-quota",
        100,
    );

    assert!(matches!(
        result,
        Err(QuarantineStoreError::SessionQuotaExceeded {
            session_id,
            count: 4,
            max: 4,
        }) if session_id == "session-1"
    ));

    // But session-2 can still insert
    store
        .insert(
            "session-2",
            QuarantinePriority::Normal,
            test_hash(51),
            test_hash(61),
            test_hash(71),
            100,
            500,
            "other-session",
            100,
        )
        .unwrap();

    assert_eq!(store.session_count("session-2"), 1);
}

#[test]
fn adversarial_session_cannot_exhaust_global_capacity() {
    let config = QuarantineStoreConfig {
        max_global_entries: 16,
        max_per_session_entries: 4,
        max_tracked_sessions: 8,
    };
    let mut store = QuarantineStore::with_config(config);

    // Adversarial session tries to fill all 16 slots but is limited to 4
    for i in 0..4u8 {
        store
            .insert(
                "adversary",
                QuarantinePriority::Normal,
                test_hash(i),
                test_hash(10 + i),
                test_hash(20 + i),
                100,
                500,
                "flood",
                100,
            )
            .unwrap();
    }

    // 5th attempt from adversary is denied
    assert!(
        store
            .insert(
                "adversary",
                QuarantinePriority::Normal,
                test_hash(50),
                test_hash(60),
                test_hash(70),
                100,
                500,
                "flood",
                100,
            )
            .is_err()
    );

    // Legitimate sessions can still use the remaining 12 slots
    for i in 0..3u8 {
        let session = format!("legit-{i}");
        for j in 0..4u8 {
            let idx = 100 + i * 10 + j;
            store
                .insert(
                    &session,
                    QuarantinePriority::Normal,
                    test_hash(idx),
                    test_hash(idx + 50),
                    test_hash(idx + 100),
                    100,
                    500,
                    "legitimate",
                    100,
                )
                .unwrap();
        }
    }

    assert_eq!(store.len(), 16);
    assert_eq!(store.session_count("adversary"), 4);
    assert_eq!(store.session_count("legit-0"), 4);
    assert_eq!(store.session_count("legit-1"), 4);
    assert_eq!(store.session_count("legit-2"), 4);
}

// =============================================================================
// Expiry and Eviction
// =============================================================================

#[test]
fn evict_expired_removes_only_expired() {
    let mut store = QuarantineStore::with_config(small_config());

    // Insert 2 expired and 2 active entries
    store
        .insert(
            "s1",
            QuarantinePriority::Normal,
            test_hash(1),
            test_hash(11),
            test_hash(21),
            10,
            50,
            "expired",
            100,
        )
        .unwrap();
    store
        .insert(
            "s1",
            QuarantinePriority::Normal,
            test_hash(2),
            test_hash(12),
            test_hash(22),
            10,
            60,
            "expired",
            100,
        )
        .unwrap();
    store
        .insert(
            "s2",
            QuarantinePriority::Normal,
            test_hash(3),
            test_hash(13),
            test_hash(23),
            100,
            500,
            "active",
            100,
        )
        .unwrap();
    store
        .insert(
            "s2",
            QuarantinePriority::Normal,
            test_hash(4),
            test_hash(14),
            test_hash(24),
            100,
            500,
            "active",
            100,
        )
        .unwrap();

    let evicted = store.evict_expired(100);
    assert_eq!(evicted, 2);
    assert_eq!(store.len(), 2);
    assert_eq!(store.session_count("s1"), 0);
    assert_eq!(store.session_count("s2"), 2);
}

// =============================================================================
// Input Validation (DoS Protection)
// =============================================================================

#[test]
fn rejects_oversized_session_id() {
    let mut store = QuarantineStore::with_config(small_config());
    let long_id = "x".repeat(MAX_SESSION_ID_LENGTH + 1);

    let result = store.insert(
        &long_id,
        QuarantinePriority::Normal,
        test_hash(1),
        test_hash(2),
        test_hash(3),
        100,
        200,
        "test",
        100,
    );

    assert!(matches!(
        result,
        Err(QuarantineStoreError::SessionIdTooLong { .. })
    ));
}

#[test]
fn rejects_oversized_reason() {
    let mut store = QuarantineStore::with_config(small_config());
    let long_reason = "x".repeat(MAX_REASON_LENGTH + 1);

    let result = store.insert(
        "session-1",
        QuarantinePriority::Normal,
        test_hash(1),
        test_hash(2),
        test_hash(3),
        100,
        200,
        &long_reason,
        100,
    );

    assert!(matches!(
        result,
        Err(QuarantineStoreError::ReasonTooLong { .. })
    ));
}

#[test]
fn rejects_too_many_sessions() {
    let config = QuarantineStoreConfig {
        max_global_entries: 100,
        max_per_session_entries: 10,
        max_tracked_sessions: 2,
    };
    let mut store = QuarantineStore::with_config(config);

    // Insert into 2 sessions
    store
        .insert(
            "s1",
            QuarantinePriority::Normal,
            test_hash(1),
            test_hash(11),
            test_hash(21),
            100,
            500,
            "test",
            100,
        )
        .unwrap();
    store
        .insert(
            "s2",
            QuarantinePriority::Normal,
            test_hash(2),
            test_hash(12),
            test_hash(22),
            100,
            500,
            "test",
            100,
        )
        .unwrap();

    // Third session should be rejected
    let result = store.insert(
        "s3",
        QuarantinePriority::Normal,
        test_hash(3),
        test_hash(13),
        test_hash(23),
        100,
        500,
        "test",
        100,
    );

    assert!(matches!(
        result,
        Err(QuarantineStoreError::TooManySessions { count: 2, max: 2 })
    ));

    // Existing session can still insert
    store
        .insert(
            "s1",
            QuarantinePriority::Normal,
            test_hash(4),
            test_hash(14),
            test_hash(24),
            100,
            500,
            "test",
            100,
        )
        .unwrap();
}

// =============================================================================
// Priority Ordering
// =============================================================================

#[test]
fn priority_ordering_correct() {
    assert!(QuarantinePriority::Low < QuarantinePriority::Normal);
    assert!(QuarantinePriority::Normal < QuarantinePriority::High);
    assert!(QuarantinePriority::High < QuarantinePriority::Critical);
}

#[test]
fn priority_tag_roundtrip() {
    for tag in 0..=3u8 {
        let priority = QuarantinePriority::from_tag(tag).unwrap();
        assert_eq!(priority.as_tag(), tag);
    }
    assert!(QuarantinePriority::from_tag(4).is_none());
    assert!(QuarantinePriority::from_tag(255).is_none());
}

// =============================================================================
// SQLite Backend
// =============================================================================

#[test]
fn sqlite_persist_and_load() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    let entry = QuarantineEntry {
        id: 1,
        session_id: "session-1".to_string(),
        priority: QuarantinePriority::High,
        request_id: test_hash(1),
        bundle_digest: test_hash(2),
        reservation_hash: test_hash(3),
        created_at_tick: 100,
        expires_at_tick: 500,
        reason: "test persist".to_string(),
    };

    backend.persist_entry(&entry).unwrap();

    let loaded = backend.load_all().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, 1);
    assert_eq!(loaded[0].session_id, "session-1");
    assert_eq!(loaded[0].priority, QuarantinePriority::High);
    assert_eq!(loaded[0].request_id, test_hash(1));
    assert_eq!(loaded[0].bundle_digest, test_hash(2));
    assert_eq!(loaded[0].reservation_hash, test_hash(3));
    assert_eq!(loaded[0].created_at_tick, 100);
    assert_eq!(loaded[0].expires_at_tick, 500);
    assert_eq!(loaded[0].reason, "test persist");
}

#[test]
fn sqlite_remove_entry() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    let entry = QuarantineEntry {
        id: 42,
        session_id: "s1".to_string(),
        priority: QuarantinePriority::Normal,
        request_id: test_hash(1),
        bundle_digest: test_hash(2),
        reservation_hash: test_hash(3),
        created_at_tick: 100,
        expires_at_tick: 500,
        reason: "test".to_string(),
    };

    backend.persist_entry(&entry).unwrap();
    assert_eq!(backend.load_all().unwrap().len(), 1);

    backend.remove_entry(42).unwrap();
    assert_eq!(backend.load_all().unwrap().len(), 0);
}

#[test]
fn sqlite_remove_expired() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    // Persist expired and active entries
    backend
        .persist_entry(&QuarantineEntry {
            id: 1,
            session_id: "s1".to_string(),
            priority: QuarantinePriority::Normal,
            request_id: test_hash(1),
            bundle_digest: test_hash(11),
            reservation_hash: test_hash(21),
            created_at_tick: 10,
            expires_at_tick: 50,
            reason: "expired".to_string(),
        })
        .unwrap();
    backend
        .persist_entry(&QuarantineEntry {
            id: 2,
            session_id: "s2".to_string(),
            priority: QuarantinePriority::High,
            request_id: test_hash(2),
            bundle_digest: test_hash(12),
            reservation_hash: test_hash(22),
            created_at_tick: 100,
            expires_at_tick: 500,
            reason: "active".to_string(),
        })
        .unwrap();

    let removed = backend.remove_expired(100).unwrap();
    assert_eq!(removed, 1);

    let remaining = backend.load_all().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, 2);
}

#[test]
fn sqlite_load_bounded_by_max() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    // Insert more than MAX_GLOBAL_ENTRIES (but we'll check it doesn't load more).
    // IDs start at 1 (load_all rejects id <= 0 as corrupted).
    for i in 1..=10u8 {
        backend
            .persist_entry(&QuarantineEntry {
                id: u64::from(i),
                session_id: format!("s{i}"),
                priority: QuarantinePriority::Normal,
                request_id: test_hash(i),
                bundle_digest: test_hash(10 + i),
                reservation_hash: test_hash(20 + i),
                created_at_tick: 100,
                expires_at_tick: 500,
                reason: "test".to_string(),
            })
            .unwrap();
    }

    let loaded = backend.load_all().unwrap();
    // Should be bounded by MAX_GLOBAL_ENTRIES (4096) but we only inserted 10
    assert_eq!(loaded.len(), 10);
}

/// Regression test (SECURITY MINOR 1): quarantine database files must have
/// 0600 permissions so other system users cannot read session metadata.
#[cfg(unix)]
#[test]
fn sqlite_open_sets_restrictive_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = create_temp_db();
    let _backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    let metadata = std::fs::metadata(tmp.path()).unwrap();
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "quarantine DB should have 0600 permissions, got {mode:o}"
    );
}

// =============================================================================
// Restart-Safe Persistence (DurableQuarantineGuard)
// =============================================================================

#[test]
fn durable_guard_persists_and_recovers() {
    let tmp = create_temp_db();

    let (tick, tick_provider) = make_tick_provider(100);

    // Create guard, insert entries
    {
        let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let guard = DurableQuarantineGuard::new(backend, small_config())
            .unwrap()
            .with_tick_provider(tick_provider)
            .with_default_ttl_ticks(1000);

        guard
            .insert(
                "session-1",
                QuarantinePriority::High,
                test_hash(1),
                test_hash(2),
                500,
                "persistent entry",
            )
            .unwrap();
        guard
            .insert(
                "session-2",
                QuarantinePriority::Normal,
                test_hash(3),
                test_hash(4),
                500,
                "another entry",
            )
            .unwrap();

        assert_eq!(guard.len(), 2);
    }

    // Simulate restart — create new guard from same database
    {
        let (_, tick_provider2) = make_tick_provider(200);
        let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let guard = DurableQuarantineGuard::new(backend, small_config())
            .unwrap()
            .with_tick_provider(tick_provider2);

        // Entries should be recovered
        assert_eq!(guard.len(), 2);
        assert_eq!(guard.session_count("session-1"), 1);
        assert_eq!(guard.session_count("session-2"), 1);
    }

    let _ = tick; // keep tick alive
}

#[test]
fn durable_guard_fails_closed_on_persistence_error() {
    // This test verifies that if persistence fails, the in-memory insertion
    // is rolled back (fail-closed behavior).

    // We can test this by using a read-only database path
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    let (tick, tick_provider) = make_tick_provider(100);
    let guard = DurableQuarantineGuard::new(backend, small_config())
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(1000);

    // Normal insert should succeed
    let result = guard.insert(
        "session-1",
        QuarantinePriority::Normal,
        test_hash(1),
        test_hash(2),
        500,
        "test",
    );
    assert!(result.is_ok());
    assert_eq!(guard.len(), 1);

    let _ = tick;
}

// =============================================================================
// QuarantineGuard Trait Implementation
// =============================================================================

#[test]
fn guard_trait_reserve_succeeds() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let (tick, tick_provider) = make_tick_provider(100);

    let guard = DurableQuarantineGuard::new(backend, small_config())
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(1000);

    let result = guard.reserve("test-session", &test_hash(1), &test_hash(2));
    assert!(result.is_ok());

    let reservation_hash = result.unwrap();
    assert_ne!(reservation_hash, [0u8; 32]); // Non-zero reservation hash

    assert_eq!(guard.len(), 1);
    assert_eq!(guard.session_count("test-session"), 1);

    let _ = tick;
}

#[test]
fn guard_trait_reserve_fails_when_saturated() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let (tick, tick_provider) = make_tick_provider(100);

    let config = QuarantineStoreConfig {
        max_global_entries: 2,
        max_per_session_entries: 64,
        max_tracked_sessions: 64,
    };

    let guard = DurableQuarantineGuard::new(backend, config)
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(1000)
        .with_default_priority(QuarantinePriority::Normal);

    // Fill to capacity
    guard
        .reserve("session-a", &test_hash(1), &test_hash(11))
        .unwrap();
    guard
        .reserve("session-b", &test_hash(2), &test_hash(12))
        .unwrap();

    // Third reservation should fail (all entries are same priority, unexpired)
    let result = guard.reserve("session-c", &test_hash(3), &test_hash(13));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("saturated"));

    let _ = tick;
}

/// Regression test: `session_id` through the trait interface isolates
/// per-session quotas. Before the fix (SECURITY MAJOR 1), all trait-level calls
/// used a hardcoded "kernel" `default_session_id`, so all sessions shared a
/// single per-session quota of 64 instead of the global 4096.
#[test]
fn guard_trait_reserve_uses_provided_session_id_for_quota() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let (tick, tick_provider) = make_tick_provider(100);

    let config = QuarantineStoreConfig {
        max_global_entries: 16,
        max_per_session_entries: 2,
        max_tracked_sessions: 8,
    };

    let guard = DurableQuarantineGuard::new(backend, config)
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(1000)
        .with_default_priority(QuarantinePriority::Normal);

    // Session A fills its per-session quota of 2
    guard
        .reserve("session-a", &test_hash(1), &test_hash(11))
        .unwrap();
    guard
        .reserve("session-a", &test_hash(2), &test_hash(12))
        .unwrap();

    // Session A cannot reserve more (quota = 2)
    let result = guard.reserve("session-a", &test_hash(3), &test_hash(13));
    assert!(result.is_err(), "session-a should be at quota");
    assert!(
        result.unwrap_err().contains("per-session quota"),
        "error should mention per-session quota"
    );

    // Session B can still reserve (independent quota)
    guard
        .reserve("session-b", &test_hash(4), &test_hash(14))
        .unwrap();
    guard
        .reserve("session-b", &test_hash(5), &test_hash(15))
        .unwrap();

    assert_eq!(guard.session_count("session-a"), 2);
    assert_eq!(guard.session_count("session-b"), 2);
    assert_eq!(guard.len(), 4);

    // Session C can also reserve (proves quota isolation, not shared bucket)
    guard
        .reserve("session-c", &test_hash(6), &test_hash(16))
        .unwrap();
    assert_eq!(guard.session_count("session-c"), 1);
    assert_eq!(guard.len(), 5);

    let _ = tick;
}

// =============================================================================
// Adversarial Flood Tests
// =============================================================================

#[test]
fn adversarial_flood_single_session() {
    let config = QuarantineStoreConfig {
        max_global_entries: 100,
        max_per_session_entries: 10,
        max_tracked_sessions: 50,
    };
    let mut store = QuarantineStore::with_config(config);

    // Adversary tries to flood from one session
    let mut successes = 0;
    let mut failures = 0;
    for i in 0..50u8 {
        match store.insert(
            "adversary",
            QuarantinePriority::Normal,
            test_hash(i),
            test_hash(i + 100),
            test_hash(i + 200),
            100,
            500,
            "flood",
            100,
        ) {
            Ok(_) => successes += 1,
            Err(_) => failures += 1,
        }
    }

    assert_eq!(successes, 10); // Capped at per-session quota
    assert_eq!(failures, 40);
    assert_eq!(store.session_count("adversary"), 10);

    // Other sessions can still use remaining capacity
    let mut other_successes = 0;
    for i in 0..10u8 {
        if store
            .insert(
                &format!("legit-{i}"),
                QuarantinePriority::Normal,
                test_hash(i.wrapping_add(50)),
                test_hash(i.wrapping_add(150)),
                test_hash(i.wrapping_add(200)),
                100,
                500,
                "legitimate",
                100,
            )
            .is_ok()
        {
            other_successes += 1;
        }
    }

    assert_eq!(other_successes, 10);
    assert_eq!(store.len(), 20);
}

#[test]
fn adversarial_flood_many_sessions() {
    let config = QuarantineStoreConfig {
        max_global_entries: 32,
        max_per_session_entries: 4,
        max_tracked_sessions: 8,
    };
    let mut store = QuarantineStore::with_config(config);

    // Adversary creates many sessions (but is limited by max_tracked_sessions)
    let mut session_successes = 0;
    let mut session_failures = 0;
    for i in 0..20u8 {
        let session = format!("adversary-{i}");
        match store.insert(
            &session,
            QuarantinePriority::Low,
            test_hash(i),
            test_hash(i + 50),
            test_hash(i + 100),
            100,
            500,
            "flood",
            100,
        ) {
            Ok(_) => session_successes += 1,
            Err(_) => session_failures += 1,
        }
    }

    // Only 8 sessions allowed
    assert_eq!(session_successes, 8);
    assert_eq!(session_failures, 12);
}

// =============================================================================
// Restart Persistence Tests
// =============================================================================

#[test]
fn restart_preserves_priority_and_expiry() {
    let tmp = create_temp_db();

    // Create entries with varying priorities and expiry
    {
        let (_, tick_provider) = make_tick_provider(100);
        let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let guard = DurableQuarantineGuard::new(backend, small_config())
            .unwrap()
            .with_tick_provider(tick_provider);

        guard
            .insert(
                "s1",
                QuarantinePriority::Low,
                test_hash(1),
                test_hash(2),
                100,
                "low entry",
            )
            .unwrap();
        guard
            .insert(
                "s2",
                QuarantinePriority::Critical,
                test_hash(3),
                test_hash(4),
                1000,
                "critical entry",
            )
            .unwrap();
    }

    // Verify directly from backend that priorities survived persistence
    {
        let verify_backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let loaded = verify_backend.load_all().unwrap();
        assert_eq!(loaded.len(), 2);
        let low = loaded.iter().find(|e| e.session_id == "s1").unwrap();
        assert_eq!(low.priority, QuarantinePriority::Low);
        let critical = loaded.iter().find(|e| e.session_id == "s2").unwrap();
        assert_eq!(critical.priority, QuarantinePriority::Critical);
    }

    // Recover after restart via guard's public API
    {
        let (_, tick_provider) = make_tick_provider(200);
        let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let guard = DurableQuarantineGuard::new(backend, small_config())
            .unwrap()
            .with_tick_provider(tick_provider);

        assert_eq!(guard.len(), 2);
        assert_eq!(guard.session_count("s1"), 1);
        assert_eq!(guard.session_count("s2"), 1);
    }
}

#[test]
fn restart_evicts_expired_after_recovery() {
    let tmp = create_temp_db();

    // Create entries, some already expired at recovery time
    {
        let (_, tick_provider) = make_tick_provider(100);
        let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let guard = DurableQuarantineGuard::new(backend, small_config())
            .unwrap()
            .with_tick_provider(tick_provider);

        guard
            .insert(
                "s1",
                QuarantinePriority::Normal,
                test_hash(1),
                test_hash(2),
                50,
                "will-expire",
            )
            .unwrap();
        guard
            .insert(
                "s2",
                QuarantinePriority::Normal,
                test_hash(3),
                test_hash(4),
                5000,
                "will-survive",
            )
            .unwrap();
    }

    // Recover at a later tick — entry with TTL 50 should now be expired
    {
        let (_, tick_provider) = make_tick_provider(300);
        let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let guard = DurableQuarantineGuard::new(backend, small_config())
            .unwrap()
            .with_tick_provider(tick_provider);

        // Both entries loaded initially
        assert_eq!(guard.len(), 2);

        // Evict expired
        let evicted = guard.evict_expired().unwrap();
        assert_eq!(evicted, 1);
        assert_eq!(guard.len(), 1);
    }
}

// =============================================================================
// Entry Expiry
// =============================================================================

#[test]
fn entry_expiry_check() {
    let entry = QuarantineEntry {
        id: 1,
        session_id: "s1".to_string(),
        priority: QuarantinePriority::Normal,
        request_id: test_hash(1),
        bundle_digest: test_hash(2),
        reservation_hash: test_hash(3),
        created_at_tick: 100,
        expires_at_tick: 200,
        reason: "test".to_string(),
    };

    assert!(!entry.is_expired_at(100));
    assert!(!entry.is_expired_at(199));
    assert!(entry.is_expired_at(200));
    assert!(entry.is_expired_at(300));
}

// =============================================================================
// Reservation Hash Determinism
// =============================================================================

#[test]
fn reservation_hash_is_deterministic() {
    use super::store::compute_reservation_hash;

    let h1 = compute_reservation_hash(&test_hash(1), &test_hash(2), 100);
    let h2 = compute_reservation_hash(&test_hash(1), &test_hash(2), 100);
    assert_eq!(h1, h2);

    // Different inputs produce different hashes
    let h3 = compute_reservation_hash(&test_hash(1), &test_hash(2), 101);
    assert_ne!(h1, h3);

    let h4 = compute_reservation_hash(&test_hash(1), &test_hash(3), 100);
    assert_ne!(h1, h4);
}

// =============================================================================
// DurableQuarantineGuard: Remove and Evict
// =============================================================================

#[test]
fn durable_guard_remove() {
    let tmp = create_temp_db();
    let (tick, tick_provider) = make_tick_provider(100);
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let guard = DurableQuarantineGuard::new(backend, small_config())
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(1000);

    let (id, _hash) = guard
        .insert(
            "s1",
            QuarantinePriority::Normal,
            test_hash(1),
            test_hash(2),
            500,
            "test",
        )
        .unwrap();

    assert_eq!(guard.len(), 1);
    assert!(guard.remove(id).unwrap());
    assert_eq!(guard.len(), 0);
    assert!(!guard.remove(id).unwrap()); // Already removed

    // Verify also removed from SQLite
    let backend2 = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let loaded = backend2.load_all().unwrap();
    assert_eq!(loaded.len(), 0);

    let _ = tick;
}

#[test]
fn durable_guard_evict_expired() {
    let tmp = create_temp_db();
    let (tick, tick_provider) = make_tick_provider(100);
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let guard = DurableQuarantineGuard::new(backend, small_config())
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(50); // Short TTL

    guard
        .insert(
            "s1",
            QuarantinePriority::Normal,
            test_hash(1),
            test_hash(2),
            50, // expires at tick 150
            "short-lived",
        )
        .unwrap();

    guard
        .insert(
            "s1",
            QuarantinePriority::Normal,
            test_hash(3),
            test_hash(4),
            5000, // expires at tick 5100
            "long-lived",
        )
        .unwrap();

    assert_eq!(guard.len(), 2);

    // Advance tick past first entry's expiry
    tick.store(200, Ordering::Relaxed);

    let evicted = guard.evict_expired().unwrap();
    assert_eq!(evicted, 1);
    assert_eq!(guard.len(), 1);
}

// =============================================================================
// Restore Entry
// =============================================================================

#[test]
fn restore_entry_advances_next_id() {
    let mut store = QuarantineStore::with_config(small_config());

    let entry = QuarantineEntry {
        id: 100,
        session_id: "s1".to_string(),
        priority: QuarantinePriority::Normal,
        request_id: test_hash(1),
        bundle_digest: test_hash(2),
        reservation_hash: test_hash(3),
        created_at_tick: 100,
        expires_at_tick: 500,
        reason: "restored".to_string(),
    };

    store.restore_entry(entry).unwrap();
    assert_eq!(store.len(), 1);
    assert_eq!(store.session_count("s1"), 1);

    // Next insert should get ID > 100
    let id = store
        .insert(
            "s2",
            QuarantinePriority::Normal,
            test_hash(4),
            test_hash(5),
            test_hash(6),
            200,
            600,
            "new",
            200,
        )
        .unwrap()
        .entry_id;
    assert!(id > 100);
}

// =============================================================================
// Regression: SECURITY BLOCKER 1 — Ghost Record Prevention
// =============================================================================

/// Regression test: when `DurableQuarantineGuard::insert` triggers eviction,
/// the evicted entry must be removed from both in-memory store AND `SQLite`
/// backend. Before this fix, evicted entries remained as "ghost" records in
/// the database, consuming capacity permanently on restart via `load_all`.
#[test]
fn eviction_removes_ghost_records_from_sqlite() {
    let tmp = create_temp_db();
    let (tick, tick_provider) = make_tick_provider(100);

    // Use a tiny config so we can fill it quickly
    let config = QuarantineStoreConfig {
        max_global_entries: 2,
        max_per_session_entries: 4,
        max_tracked_sessions: 8,
    };

    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let guard = DurableQuarantineGuard::new(backend, config.clone())
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(1000);

    // Fill to capacity with Low priority entries
    guard
        .insert(
            "s1",
            QuarantinePriority::Low,
            test_hash(1),
            test_hash(11),
            500,
            "entry-1",
        )
        .unwrap();
    guard
        .insert(
            "s2",
            QuarantinePriority::Low,
            test_hash(2),
            test_hash(12),
            500,
            "entry-2",
        )
        .unwrap();

    // Verify SQLite has 2 entries
    {
        let verify_backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let loaded = verify_backend.load_all().unwrap();
        assert_eq!(
            loaded.len(),
            2,
            "SQLite should have 2 entries before eviction"
        );
    }

    // Insert a High priority entry — this should evict one Low entry
    guard
        .insert(
            "s3",
            QuarantinePriority::High,
            test_hash(3),
            test_hash(13),
            500,
            "entry-3-evicts-low",
        )
        .unwrap();

    assert_eq!(
        guard.len(),
        2,
        "in-memory store should still have 2 entries"
    );

    // CRITICAL: Verify SQLite also has exactly 2 entries (not 3).
    // Before the fix, the evicted Low entry would remain as a ghost record.
    {
        let verify_backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let loaded = verify_backend.load_all().unwrap();
        assert_eq!(
            loaded.len(),
            2,
            "SQLite should have 2 entries after eviction (no ghost records)"
        );
        // Verify the new entry is present
        assert!(
            loaded.iter().any(|e| e.reason == "entry-3-evicts-low"),
            "new entry should be in SQLite"
        );
    }

    // CRITICAL: Simulate restart — recovered guard should have exactly 2
    // entries, not 3 (which would happen if ghost records existed).
    {
        let (_, tick_provider2) = make_tick_provider(200);
        let backend2 = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let guard2 = DurableQuarantineGuard::new(backend2, config)
            .unwrap()
            .with_tick_provider(tick_provider2);

        assert_eq!(
            guard2.len(),
            2,
            "after restart, store should have 2 entries (no ghost capacity loss)"
        );
    }

    let _ = tick;
}

/// Regression test: eviction triggered by expired entries during insert must
/// also clean the evicted entry from `SQLite`.
#[test]
fn expired_eviction_during_insert_removes_from_sqlite() {
    let tmp = create_temp_db();
    let (tick, tick_provider) = make_tick_provider(100);

    let config = QuarantineStoreConfig {
        max_global_entries: 2,
        max_per_session_entries: 4,
        max_tracked_sessions: 8,
    };

    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let guard = DurableQuarantineGuard::new(backend, config.clone())
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(50); // Short TTL

    // Fill to capacity — both entries will expire at tick 150
    guard
        .insert(
            "s1",
            QuarantinePriority::Normal,
            test_hash(1),
            test_hash(11),
            50, // expires at tick 150
            "will-expire-1",
        )
        .unwrap();
    guard
        .insert(
            "s2",
            QuarantinePriority::Normal,
            test_hash(2),
            test_hash(12),
            50, // expires at tick 150
            "will-expire-2",
        )
        .unwrap();

    // Advance past expiry
    tick.store(200, Ordering::Relaxed);

    // Insert a new entry — should evict one expired entry to make room
    guard
        .insert(
            "s3",
            QuarantinePriority::Normal,
            test_hash(3),
            test_hash(13),
            500,
            "fresh-entry",
        )
        .unwrap();

    // Verify SQLite has exactly 2 entries (1 expired + 1 fresh), not 3
    {
        let verify_backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let loaded = verify_backend.load_all().unwrap();
        assert_eq!(
            loaded.len(),
            2,
            "SQLite should have 2 entries (evicted expired entry removed)"
        );
    }

    // Restart should recover exactly 2 entries
    {
        let (_, tick_provider2) = make_tick_provider(200);
        let backend2 = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let guard2 = DurableQuarantineGuard::new(backend2, config)
            .unwrap()
            .with_tick_provider(tick_provider2);
        assert_eq!(guard2.len(), 2);
    }
}

/// Regression test: the trait-level `reserve()` also cleans evicted entries
/// from `SQLite` when eviction occurs.
#[test]
fn trait_reserve_cleans_evicted_from_sqlite() {
    let tmp = create_temp_db();
    let (tick, tick_provider) = make_tick_provider(100);

    let config = QuarantineStoreConfig {
        max_global_entries: 2,
        max_per_session_entries: 4,
        max_tracked_sessions: 8,
    };

    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let guard = DurableQuarantineGuard::new(backend, config)
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(50) // short TTL
        .with_default_priority(QuarantinePriority::Normal);

    // Fill via trait interface
    guard
        .reserve("session-a", &test_hash(1), &test_hash(11))
        .unwrap();
    guard
        .reserve("session-b", &test_hash(2), &test_hash(12))
        .unwrap();

    // Advance past expiry
    tick.store(200, Ordering::Relaxed);

    // Reserve another — should evict one expired entry
    guard
        .reserve("session-c", &test_hash(3), &test_hash(13))
        .unwrap();

    // Verify SQLite has exactly 2 entries, not 3
    {
        let verify_backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        let loaded = verify_backend.load_all().unwrap();
        assert_eq!(
            loaded.len(),
            2,
            "SQLite should have 2 entries via trait reserve (no ghost records)"
        );
    }
}

// =============================================================================
// Regression: SECURITY MAJOR 1 — Constant-Time Hash Comparison
// =============================================================================

/// Verify that `find_by_reservation_hash` returns the correct entry
/// even when using constant-time comparison (correctness test).
#[test]
fn find_by_reservation_hash_constant_time_correctness() {
    let mut store = QuarantineStore::with_config(small_config());

    // Insert multiple entries with distinct reservation hashes
    for i in 0..4u8 {
        store
            .insert(
                &format!("s{i}"),
                QuarantinePriority::Normal,
                test_hash(i),
                test_hash(10 + i),
                test_hash(20 + i), // reservation hash
                100,
                500,
                "test",
                100,
            )
            .unwrap();
    }

    // Find each by reservation hash
    for i in 0..4u8 {
        let entry = store.find_by_reservation_hash(&test_hash(20 + i));
        assert!(
            entry.is_some(),
            "should find entry with reservation hash {}",
            20 + i
        );
        assert_eq!(entry.unwrap().session_id, format!("s{i}"));
    }

    // Non-existent hash returns None
    assert!(store.find_by_reservation_hash(&test_hash(99)).is_none());
}

/// Verify that `find_by_reservation_hash` scans ALL entries (no short-circuit)
/// by checking that the last inserted entry is found correctly.
#[test]
fn find_by_reservation_hash_finds_last_entry() {
    let mut store = QuarantineStore::with_config(small_config());

    // Insert 8 entries (max capacity of small_config)
    for i in 0..8u8 {
        store
            .insert(
                &format!("s{}", i % 4),
                QuarantinePriority::Normal,
                test_hash(i),
                test_hash(10 + i),
                test_hash(20 + i),
                100,
                500,
                "test",
                100,
            )
            .unwrap();
    }

    // Find the last-inserted entry (tests full scan, no short-circuit)
    let entry = store.find_by_reservation_hash(&test_hash(27));
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().session_id, "s3");
}

// =============================================================================
// InsertResult: evicted_id tracking
// =============================================================================

/// Verify that `InsertResult.evicted_id` is `None` when no eviction occurs
/// and `Some(id)` when eviction occurs.
#[test]
fn insert_result_reports_evicted_id() {
    let mut store = QuarantineStore::with_config(tiny_config()); // max_global=4

    // Fill without eviction
    for i in 0..4u8 {
        let result = store
            .insert(
                &format!("s{i}"),
                QuarantinePriority::Low,
                test_hash(i),
                test_hash(10 + i),
                test_hash(20 + i),
                100,
                500,
                "test",
                100,
            )
            .unwrap();
        assert!(
            result.evicted_id.is_none(),
            "no eviction expected for entry {i}"
        );
    }

    // Insert with eviction (High priority evicts one Low)
    let result = store
        .insert(
            "s-high",
            QuarantinePriority::High,
            test_hash(50),
            test_hash(60),
            test_hash(70),
            100,
            500,
            "high-priority",
            100,
        )
        .unwrap();
    assert!(result.evicted_id.is_some(), "eviction should be reported");
    // The evicted entry should be the oldest Low (id=1)
    assert_eq!(result.evicted_id.unwrap(), 1);
}

/// Verify that `InsertResult.evicted_entry` carries the full evicted entry
/// data for rollback purposes.
#[test]
fn insert_result_carries_evicted_entry_for_rollback() {
    let mut store = QuarantineStore::with_config(tiny_config()); // max_global=4

    // Fill with Low priority entries
    for i in 0..4u8 {
        store
            .insert(
                &format!("s{i}"),
                QuarantinePriority::Low,
                test_hash(i),
                test_hash(10 + i),
                test_hash(20 + i),
                100,
                500,
                "low",
                100,
            )
            .unwrap();
    }

    // Insert with eviction (High priority evicts one Low)
    let result = store
        .insert(
            "s-high",
            QuarantinePriority::High,
            test_hash(50),
            test_hash(60),
            test_hash(70),
            100,
            500,
            "high-priority",
            100,
        )
        .unwrap();

    assert!(
        result.evicted_entry.is_some(),
        "evicted_entry must carry full entry data"
    );
    let evicted = result.evicted_entry.unwrap();
    assert_eq!(evicted.id, 1, "oldest Low entry should be evicted");
    assert_eq!(evicted.priority, QuarantinePriority::Low);
    assert_eq!(evicted.session_id, "s0");
}

// =============================================================================
// QUALITY MAJOR 1: Atomic Rollback on Eviction-Delete Failure
// =============================================================================

/// Regression test (QUALITY MAJOR 1): when `remove_entry(evicted_id)` fails
/// after an eviction-triggering insert, the rollback must restore the evicted
/// entry back into the in-memory store. Without this fix, the evicted entry
/// exists in `SQLite` but not in memory, causing divergence.
#[test]
fn eviction_delete_failure_restores_evicted_entry_in_memory() {
    let tmp = create_temp_db();
    let (tick, tick_provider) = make_tick_provider(100);

    let config = QuarantineStoreConfig {
        max_global_entries: 2,
        max_per_session_entries: 4,
        max_tracked_sessions: 8,
    };

    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let guard = DurableQuarantineGuard::new(backend, config)
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(1000);

    // Fill to capacity with Low priority entries
    guard
        .insert(
            "s1",
            QuarantinePriority::Low,
            test_hash(1),
            test_hash(11),
            500,
            "entry-1-low",
        )
        .unwrap();
    guard
        .insert(
            "s2",
            QuarantinePriority::Low,
            test_hash(2),
            test_hash(12),
            500,
            "entry-2-low",
        )
        .unwrap();

    assert_eq!(guard.len(), 2);
    assert_eq!(guard.session_count("s1"), 1);
    assert_eq!(guard.session_count("s2"), 1);

    // Now sabotage the database by dropping the quarantine_entries table.
    // This will cause `remove_entry` to fail because the table no longer exists.
    {
        let sabotage_conn = rusqlite::Connection::open(tmp.path()).unwrap();
        sabotage_conn
            .execute_batch("DROP TABLE quarantine_entries")
            .unwrap();
    }

    // Try to insert a High priority entry -- this will trigger eviction of
    // a Low entry in memory, then fail when trying to delete the evicted
    // entry from SQLite. The rollback must:
    // 1. Remove the newly inserted entry from memory
    // 2. Restore the evicted entry back into memory
    let result = guard.insert(
        "s3",
        QuarantinePriority::High,
        test_hash(3),
        test_hash(13),
        500,
        "entry-3-high-fails",
    );

    // Insert should fail due to persistence error
    assert!(
        result.is_err(),
        "insert should fail when backend remove_entry fails"
    );
    assert!(matches!(
        result,
        Err(QuarantineStoreError::PersistenceError { .. })
    ));

    // CRITICAL: In-memory store should be unchanged -- both original entries
    // should still be present. The evicted entry must have been restored.
    assert_eq!(
        guard.len(),
        2,
        "in-memory store should have 2 entries after rollback (evicted entry restored)"
    );
    assert_eq!(
        guard.session_count("s1"),
        1,
        "session s1 count should be preserved after rollback"
    );
    assert_eq!(
        guard.session_count("s2"),
        1,
        "session s2 count should be preserved after rollback"
    );
    // The new entry (s3) should NOT be in memory
    assert_eq!(
        guard.session_count("s3"),
        0,
        "failed insert session s3 should not be in memory"
    );

    let _ = tick;
}

/// Regression test: trait-level `reserve()` also restores evicted entries
/// on eviction-delete failure (same fix as `insert()`).
#[test]
fn trait_reserve_eviction_delete_failure_restores_evicted_entry() {
    let tmp = create_temp_db();
    let (tick, tick_provider) = make_tick_provider(100);

    let config = QuarantineStoreConfig {
        max_global_entries: 2,
        max_per_session_entries: 4,
        max_tracked_sessions: 8,
    };

    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let guard = DurableQuarantineGuard::new(backend, config)
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(50) // Short TTL
        .with_default_priority(QuarantinePriority::Normal);

    // Fill via trait interface — both expire at tick 150
    guard
        .reserve("session-a", &test_hash(1), &test_hash(11))
        .unwrap();
    guard
        .reserve("session-b", &test_hash(2), &test_hash(12))
        .unwrap();
    assert_eq!(guard.len(), 2);

    // Advance past expiry so next reserve will trigger eviction
    tick.store(200, Ordering::Relaxed);

    // Sabotage the database
    {
        let sabotage_conn = rusqlite::Connection::open(tmp.path()).unwrap();
        sabotage_conn
            .execute_batch("DROP TABLE quarantine_entries")
            .unwrap();
    }

    // Reserve should fail, but in-memory state should be restored
    let result = guard.reserve("session-c", &test_hash(3), &test_hash(13));
    assert!(result.is_err(), "reserve should fail with broken backend");

    // In-memory store should still have the 2 original entries
    assert_eq!(
        guard.len(),
        2,
        "in-memory store should have 2 entries after trait-reserve rollback"
    );
    assert_eq!(guard.session_count("session-a"), 1);
    assert_eq!(guard.session_count("session-b"), 1);
    assert_eq!(guard.session_count("session-c"), 0);
}

// =============================================================================
// QUALITY MAJOR 2: Fail-Closed Validation for Signed Integer Fields
// =============================================================================

/// Regression test (QUALITY MAJOR 2): `load_all` must reject rows with
/// negative `id`, `created_at_tick`, or `expires_at_tick` values. Without
/// validation, negative i64 values silently become huge u64 values via
/// `as u64`, breaking expiry logic (e.g., -1 becomes `u64::MAX`, meaning never
/// expires).
#[test]
fn load_all_rejects_negative_id() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    // Manually insert a row with negative id (simulating corruption/tampering)
    {
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        conn.execute(
            "INSERT INTO quarantine_entries
             (id, session_id, priority, request_id, bundle_digest,
              reservation_hash, created_at_tick, expires_at_tick, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                -1i64,
                "s1",
                1u8,
                vec![0u8; 32],
                vec![0u8; 32],
                vec![0u8; 32],
                100i64,
                500i64,
                "negative-id",
            ],
        )
        .unwrap();
    }

    let result = backend.load_all();
    assert!(
        result.is_err(),
        "load_all should reject rows with negative id"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, QuarantineStoreError::PersistenceError { .. }),
        "error should be PersistenceError, got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("must be positive"),
        "error message should mention positive requirement: {msg}"
    );
}

#[test]
fn load_all_rejects_negative_created_at_tick() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    {
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        conn.execute(
            "INSERT INTO quarantine_entries
             (id, session_id, priority, request_id, bundle_digest,
              reservation_hash, created_at_tick, expires_at_tick, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                1i64,
                "s1",
                1u8,
                vec![0u8; 32],
                vec![0u8; 32],
                vec![0u8; 32],
                -100i64,
                500i64,
                "negative-created-at",
            ],
        )
        .unwrap();
    }

    let result = backend.load_all();
    assert!(
        result.is_err(),
        "load_all should reject rows with negative created_at_tick"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("must be non-negative"),
        "error should mention non-negative: {msg}"
    );
}

#[test]
fn load_all_rejects_negative_expires_at_tick() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    {
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        conn.execute(
            "INSERT INTO quarantine_entries
             (id, session_id, priority, request_id, bundle_digest,
              reservation_hash, created_at_tick, expires_at_tick, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                1i64,
                "s1",
                1u8,
                vec![0u8; 32],
                vec![0u8; 32],
                vec![0u8; 32],
                100i64,
                -50i64,
                "negative-expires-at",
            ],
        )
        .unwrap();
    }

    let result = backend.load_all();
    assert!(
        result.is_err(),
        "load_all should reject rows with negative expires_at_tick"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("must be non-negative"),
        "error should mention non-negative: {msg}"
    );
}

#[test]
fn load_all_rejects_expires_before_created() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    {
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        conn.execute(
            "INSERT INTO quarantine_entries
             (id, session_id, priority, request_id, bundle_digest,
              reservation_hash, created_at_tick, expires_at_tick, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                1i64,
                "s1",
                1u8,
                vec![0u8; 32],
                vec![0u8; 32],
                vec![0u8; 32],
                500i64,
                100i64,
                "expires-before-created",
            ],
        )
        .unwrap();
    }

    let result = backend.load_all();
    assert!(
        result.is_err(),
        "load_all should reject rows where expires_at_tick < created_at_tick"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("expires_at_tick"),
        "error should mention expires_at_tick: {msg}"
    );
}

#[test]
fn load_all_rejects_zero_id() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    {
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        conn.execute(
            "INSERT INTO quarantine_entries
             (id, session_id, priority, request_id, bundle_digest,
              reservation_hash, created_at_tick, expires_at_tick, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                0i64,
                "s1",
                1u8,
                vec![0u8; 32],
                vec![0u8; 32],
                vec![0u8; 32],
                100i64,
                500i64,
                "zero-id",
            ],
        )
        .unwrap();
    }

    let result = backend.load_all();
    assert!(result.is_err(), "load_all should reject rows with id=0");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("must be positive"),
        "error should mention positive: {msg}"
    );
}

/// Positive test: valid rows with id > 0 and non-negative tick values load
/// correctly after the validation changes.
#[test]
fn load_all_accepts_valid_positive_values() {
    let tmp = create_temp_db();
    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();

    let entry = QuarantineEntry {
        id: 42,
        session_id: "valid-session".to_string(),
        priority: QuarantinePriority::High,
        request_id: test_hash(1),
        bundle_digest: test_hash(2),
        reservation_hash: test_hash(3),
        created_at_tick: 0, // zero is valid (non-negative)
        expires_at_tick: 100,
        reason: "valid entry".to_string(),
    };

    backend.persist_entry(&entry).unwrap();

    let loaded = backend.load_all().unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, 42);
    assert_eq!(loaded[0].created_at_tick, 0);
    assert_eq!(loaded[0].expires_at_tick, 100);
}

// =============================================================================
// QUALITY MINOR 1: Persistence Failure Exercises Failure Path
// =============================================================================

/// Deterministic test that forces `persist_entry` to fail after successful
/// in-memory insertion, then asserts that the in-memory state is rolled back
/// to maintain memory/DB consistency (fail-closed).
#[test]
fn persist_entry_failure_rolls_back_in_memory_state() {
    let tmp = create_temp_db();
    let (tick, tick_provider) = make_tick_provider(100);

    let config = QuarantineStoreConfig {
        max_global_entries: 4,
        max_per_session_entries: 4,
        max_tracked_sessions: 8,
    };

    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let guard = DurableQuarantineGuard::new(backend, config)
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(1000);

    // Successful insert
    guard
        .insert(
            "s1",
            QuarantinePriority::Normal,
            test_hash(1),
            test_hash(11),
            500,
            "entry-1",
        )
        .unwrap();
    assert_eq!(guard.len(), 1);

    // Sabotage DB to make persist_entry fail
    {
        let sabotage_conn = rusqlite::Connection::open(tmp.path()).unwrap();
        sabotage_conn
            .execute_batch("DROP TABLE quarantine_entries")
            .unwrap();
    }

    // This insert should fail at persist_entry (no eviction involved)
    let result = guard.insert(
        "s2",
        QuarantinePriority::Normal,
        test_hash(2),
        test_hash(12),
        500,
        "entry-2-fails",
    );

    assert!(
        result.is_err(),
        "insert should fail when persist_entry fails"
    );
    assert!(matches!(
        result,
        Err(QuarantineStoreError::PersistenceError { .. })
    ));

    // In-memory state should be rolled back to just the first entry
    // (the new entry should have been removed from memory)
    assert_eq!(
        guard.len(),
        1,
        "in-memory store should have 1 entry after persist_entry rollback"
    );
    assert_eq!(
        guard.session_count("s1"),
        1,
        "session s1 should still be present"
    );
    assert_eq!(
        guard.session_count("s2"),
        0,
        "session s2 should not be present after rollback"
    );

    let _ = tick;
}

/// Deterministic test that forces `remove_entry` to fail during eviction,
/// then asserts full memory/DB parity: the evicted entry is restored, the
/// new entry is removed, and session counts are correct.
#[test]
fn remove_entry_failure_during_eviction_preserves_full_state_parity() {
    let tmp = create_temp_db();
    let (tick, tick_provider) = make_tick_provider(100);

    let config = QuarantineStoreConfig {
        max_global_entries: 2,
        max_per_session_entries: 4,
        max_tracked_sessions: 8,
    };

    let backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
    let guard = DurableQuarantineGuard::new(backend, config)
        .unwrap()
        .with_tick_provider(tick_provider)
        .with_default_ttl_ticks(1000);

    // Fill to capacity
    guard
        .insert(
            "session-alpha",
            QuarantinePriority::Low,
            test_hash(1),
            test_hash(11),
            500,
            "alpha",
        )
        .unwrap();
    guard
        .insert(
            "session-beta",
            QuarantinePriority::Low,
            test_hash(2),
            test_hash(12),
            500,
            "beta",
        )
        .unwrap();

    // Verify DB has 2 entries before sabotage
    {
        let verify_backend = SqliteQuarantineBackend::open(tmp.path()).unwrap();
        assert_eq!(verify_backend.load_all().unwrap().len(), 2);
    }

    // Sabotage: drop table so remove_entry will fail
    {
        let sabotage_conn = rusqlite::Connection::open(tmp.path()).unwrap();
        sabotage_conn
            .execute_batch("DROP TABLE quarantine_entries")
            .unwrap();
    }

    // Attempt insert that requires eviction — should fail
    let result = guard.insert(
        "session-gamma",
        QuarantinePriority::High,
        test_hash(3),
        test_hash(13),
        500,
        "gamma-triggers-eviction",
    );

    assert!(result.is_err());

    // State parity assertions:
    // 1. In-memory store has exactly 2 entries (evicted restored, new removed)
    assert_eq!(guard.len(), 2);
    // 2. Original sessions preserved
    assert_eq!(guard.session_count("session-alpha"), 1);
    assert_eq!(guard.session_count("session-beta"), 1);
    // 3. New session not present
    assert_eq!(guard.session_count("session-gamma"), 0);

    let _ = tick;
}
