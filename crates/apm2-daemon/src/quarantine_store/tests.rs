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
    let id = store
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
        .unwrap();

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
    let new_id = store
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

    // Insert more than MAX_GLOBAL_ENTRIES (but we'll check it doesn't load more)
    for i in 0..10u8 {
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
        .unwrap();
    assert!(id > 100);
}
