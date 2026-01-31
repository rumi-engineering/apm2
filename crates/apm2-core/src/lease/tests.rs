//! Tests for the lease module.
//!
//! Note: Tests use the legacy `lease_issued_payload` and
//! `lease_renewed_payload` functions to verify backwards compatibility with
//! events that lack tick data. This tests the SEC-CTRL-FAC-0015 fail-closed
//! behavior.

#![allow(deprecated)]

use super::error::LeaseError;
use super::reducer::{LeaseReducer, helpers};
use super::state::{LeaseState, ReleaseReason};
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

fn create_event(event_type: &str, session_id: &str, payload: Vec<u8>) -> EventRecord {
    EventRecord::with_timestamp(event_type, session_id, "actor-1", payload, 1_000_000_000)
}

fn create_event_at(
    event_type: &str,
    session_id: &str,
    payload: Vec<u8>,
    timestamp: u64,
) -> EventRecord {
    EventRecord::with_timestamp(event_type, session_id, "actor-1", payload, timestamp)
}

// =============================================================================
// LeaseIssued Tests
// =============================================================================

#[test]
fn test_lease_reducer_new() {
    let reducer = LeaseReducer::new();
    assert!(reducer.state().is_empty());
    assert_eq!(reducer.name(), "lease-registrar");
}

#[test]
fn test_lease_issued_creates_lease() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1, 2, 3, 4], // registrar signature
    );
    let event = create_event("lease.issued", "session-1", payload);

    reducer.apply(&event, &ctx).unwrap();

    let lease = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease.lease_id, "lease-1");
    assert_eq!(lease.work_id, "work-1");
    assert_eq!(lease.actor_id, "actor-1");
    assert_eq!(lease.state, LeaseState::Active);
    assert_eq!(lease.issued_at, 1_000_000_000);
    assert_eq!(lease.expires_at, 2_000_000_000);
    assert_eq!(lease.registrar_signature, vec![1, 2, 3, 4]);
    assert_eq!(lease.renewal_count, 0);
    assert!(lease.is_active());
    assert!(!lease.is_terminal());
}

#[test]
fn test_lease_issued_tracked_by_work_id() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1, 2, 3],
    );
    let event = create_event("lease.issued", "session-1", payload);

    reducer.apply(&event, &ctx).unwrap();

    // Should be able to look up by work ID
    let active_lease = reducer.state().get_active_lease_for_work("work-1").unwrap();
    assert_eq!(active_lease.lease_id, "lease-1");
    assert!(reducer.state().has_active_lease("work-1"));
    assert!(!reducer.state().has_active_lease("work-2"));
}

#[test]
fn test_duplicate_lease_id_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // First lease
    let payload1 = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1, 2, 3],
    );
    reducer
        .apply(&create_event("lease.issued", "s1", payload1), &ctx)
        .unwrap();

    // Try to create another lease with same ID (different work)
    let payload2 = helpers::lease_issued_payload(
        "lease-1", // Same lease ID
        "work-2",  // Different work
        "actor-2",
        1_000_000_000,
        2_000_000_000,
        vec![4, 5, 6],
    );
    let result = reducer.apply(&create_event("lease.issued", "s2", payload2), &ctx);
    assert!(matches!(result, Err(LeaseError::LeaseAlreadyExists { .. })));
}

#[test]
fn test_work_already_leased_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // First lease for work-1
    let payload1 = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1, 2, 3],
    );
    reducer
        .apply(&create_event("lease.issued", "s1", payload1), &ctx)
        .unwrap();

    // Try to create another lease for same work
    let payload2 = helpers::lease_issued_payload(
        "lease-2", // Different lease ID
        "work-1",  // Same work ID
        "actor-2",
        1_000_000_000,
        2_000_000_000,
        vec![4, 5, 6],
    );
    let result = reducer.apply(&create_event("lease.issued", "s2", payload2), &ctx);
    assert!(matches!(result, Err(LeaseError::WorkAlreadyLeased { .. })));
}

#[test]
fn test_lease_issued_missing_signature_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![], // Empty signature
    );
    let result = reducer.apply(&create_event("lease.issued", "s", payload), &ctx);
    assert!(matches!(result, Err(LeaseError::MissingSignature { .. })));
}

// =============================================================================
// LeaseRenewed Tests
// =============================================================================

#[test]
fn test_lease_renewed_extends_expiration() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1, 2, 3],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // Renew lease
    let renew_payload = helpers::lease_renewed_payload(
        "lease-1",
        3_000_000_000, // Extended expiration
        vec![4, 5, 6], // New signature
    );
    reducer
        .apply(&create_event("lease.renewed", "s", renew_payload), &ctx)
        .unwrap();

    let lease = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease.state, LeaseState::Active);
    assert_eq!(lease.expires_at, 3_000_000_000);
    assert_eq!(lease.renewal_count, 1);
    assert_eq!(lease.registrar_signature, vec![4, 5, 6]);
    assert!(lease.last_renewed_at.is_some());
}

#[test]
fn test_lease_renewed_multiple_times() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // First renewal
    let renew1 = helpers::lease_renewed_payload("lease-1", 3_000_000_000, vec![2]);
    reducer
        .apply(&create_event("lease.renewed", "s", renew1), &ctx)
        .unwrap();

    // Second renewal
    let renew2 = helpers::lease_renewed_payload("lease-1", 4_000_000_000, vec![3]);
    reducer
        .apply(&create_event("lease.renewed", "s", renew2), &ctx)
        .unwrap();

    // Third renewal
    let renew3 = helpers::lease_renewed_payload("lease-1", 5_000_000_000, vec![4]);
    reducer
        .apply(&create_event("lease.renewed", "s", renew3), &ctx)
        .unwrap();

    let lease = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease.state, LeaseState::Active);
    assert_eq!(lease.expires_at, 5_000_000_000);
    assert_eq!(lease.renewal_count, 3);
}

#[test]
fn test_lease_renewed_unknown_lease_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::lease_renewed_payload("unknown-lease", 3_000_000_000, vec![1, 2, 3]);
    let result = reducer.apply(&create_event("lease.renewed", "s", payload), &ctx);
    assert!(matches!(result, Err(LeaseError::LeaseNotFound { .. })));
}

#[test]
fn test_lease_renewed_not_extending_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue lease expiring at 2_000_000_000
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // Try to "renew" with earlier expiration
    let renew_payload = helpers::lease_renewed_payload(
        "lease-1",
        1_500_000_000, // Earlier than current expiration
        vec![2],
    );
    let result = reducer.apply(&create_event("lease.renewed", "s", renew_payload), &ctx);
    assert!(matches!(
        result,
        Err(LeaseError::RenewalDoesNotExtend { .. })
    ));

    // Try to "renew" with same expiration
    let renew_same = helpers::lease_renewed_payload(
        "lease-1",
        2_000_000_000, // Same as current
        vec![3],
    );
    let result = reducer.apply(&create_event("lease.renewed", "s", renew_same), &ctx);
    assert!(matches!(
        result,
        Err(LeaseError::RenewalDoesNotExtend { .. })
    ));
}

#[test]
fn test_lease_renewed_missing_signature_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // Try to renew without signature
    let renew_payload = helpers::lease_renewed_payload(
        "lease-1",
        3_000_000_000,
        vec![], // Empty signature
    );
    let result = reducer.apply(&create_event("lease.renewed", "s", renew_payload), &ctx);
    assert!(matches!(result, Err(LeaseError::MissingSignature { .. })));
}

// =============================================================================
// LeaseReleased Tests
// =============================================================================

#[test]
fn test_lease_released_completed() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // Release with COMPLETED reason
    let release_payload = helpers::lease_released_payload("lease-1", "COMPLETED");
    let release_event = create_event_at("lease.released", "s", release_payload, 1_500_000_000);
    reducer.apply(&release_event, &ctx).unwrap();

    let lease = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease.state, LeaseState::Released);
    assert_eq!(lease.release_reason, Some(ReleaseReason::Completed));
    assert_eq!(lease.terminated_at, Some(1_500_000_000));
    assert!(lease.is_terminal());

    // Work should no longer have active lease
    assert!(!reducer.state().has_active_lease("work-1"));
    assert!(
        reducer
            .state()
            .get_active_lease_for_work("work-1")
            .is_none()
    );
}

#[test]
fn test_lease_released_aborted() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // Release with ABORTED reason
    let release_payload = helpers::lease_released_payload("lease-1", "ABORTED");
    reducer
        .apply(&create_event("lease.released", "s", release_payload), &ctx)
        .unwrap();

    let lease = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease.state, LeaseState::Released);
    assert_eq!(lease.release_reason, Some(ReleaseReason::Aborted));
}

#[test]
fn test_lease_released_voluntary() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // Release with VOLUNTARY reason
    let release_payload = helpers::lease_released_payload("lease-1", "VOLUNTARY");
    reducer
        .apply(&create_event("lease.released", "s", release_payload), &ctx)
        .unwrap();

    let lease = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease.state, LeaseState::Released);
    assert_eq!(lease.release_reason, Some(ReleaseReason::Voluntary));
}

#[test]
fn test_lease_released_unknown_lease_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::lease_released_payload("unknown-lease", "COMPLETED");
    let result = reducer.apply(&create_event("lease.released", "s", payload), &ctx);
    assert!(matches!(result, Err(LeaseError::LeaseNotFound { .. })));
}

#[test]
fn test_lease_released_invalid_reason_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // Try to release with invalid reason
    let release_payload = helpers::lease_released_payload("lease-1", "INVALID_REASON");
    let result = reducer.apply(&create_event("lease.released", "s", release_payload), &ctx);
    assert!(matches!(
        result,
        Err(LeaseError::InvalidReleaseReason { .. })
    ));
}

#[test]
fn test_lease_released_already_terminal_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue and release lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    let release_payload = helpers::lease_released_payload("lease-1", "COMPLETED");
    reducer
        .apply(&create_event("lease.released", "s", release_payload), &ctx)
        .unwrap();

    // Try to release again
    let release_again = helpers::lease_released_payload("lease-1", "ABORTED");
    let result = reducer.apply(&create_event("lease.released", "s", release_again), &ctx);
    assert!(matches!(
        result,
        Err(LeaseError::LeaseAlreadyTerminal { .. })
    ));
}

// =============================================================================
// LeaseExpired Tests
// =============================================================================

#[test]
fn test_lease_expired() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // Expire the lease
    let expire_payload = helpers::lease_expired_payload("lease-1", 2_000_000_000);
    reducer
        .apply(&create_event("lease.expired", "s", expire_payload), &ctx)
        .unwrap();

    let lease = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease.state, LeaseState::Expired);
    assert_eq!(lease.terminated_at, Some(2_000_000_000));
    assert!(lease.is_terminal());

    // Work should no longer have active lease
    assert!(!reducer.state().has_active_lease("work-1"));
}

#[test]
fn test_lease_expired_unknown_lease_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::lease_expired_payload("unknown-lease", 2_000_000_000);
    let result = reducer.apply(&create_event("lease.expired", "s", payload), &ctx);
    assert!(matches!(result, Err(LeaseError::LeaseNotFound { .. })));
}

#[test]
fn test_lease_expired_already_terminal_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue and release lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    let release_payload = helpers::lease_released_payload("lease-1", "COMPLETED");
    reducer
        .apply(&create_event("lease.released", "s", release_payload), &ctx)
        .unwrap();

    // Try to expire a released lease
    let expire_payload = helpers::lease_expired_payload("lease-1", 3_000_000_000);
    let result = reducer.apply(&create_event("lease.expired", "s", expire_payload), &ctx);
    assert!(matches!(
        result,
        Err(LeaseError::LeaseAlreadyTerminal { .. })
    ));
}

// =============================================================================
// LeaseConflict Tests
// =============================================================================

#[test]
fn test_lease_conflict_recorded() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Create a lease first
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // Process a conflict event (doesn't change state, just for audit)
    let conflict_payload = helpers::lease_conflict_payload(
        "work-1",
        vec!["lease-1".to_string(), "lease-2".to_string()],
        "CANONICAL_ROOT",
    );
    // Should succeed without error
    reducer
        .apply(&create_event("lease.conflict", "s", conflict_payload), &ctx)
        .unwrap();

    // Lease state should be unchanged
    let lease = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease.state, LeaseState::Active);
}

// =============================================================================
// Work Can Be Re-Leased After Release Tests
// =============================================================================

#[test]
fn test_work_can_be_released_after_release() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue first lease
    let issue1 = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue1), &ctx)
        .unwrap();

    // Release first lease
    let release1 = helpers::lease_released_payload("lease-1", "COMPLETED");
    reducer
        .apply(&create_event("lease.released", "s", release1), &ctx)
        .unwrap();

    // Now work-1 should be available for new lease
    assert!(!reducer.state().has_active_lease("work-1"));

    // Issue second lease for same work
    let issue2 = helpers::lease_issued_payload(
        "lease-2", // New lease ID
        "work-1",  // Same work
        "actor-2", // Different actor
        2_500_000_000,
        3_500_000_000,
        vec![2],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue2), &ctx)
        .unwrap();

    // New lease should be active
    let new_lease = reducer.state().get_active_lease_for_work("work-1").unwrap();
    assert_eq!(new_lease.lease_id, "lease-2");
    assert_eq!(new_lease.actor_id, "actor-2");
}

#[test]
fn test_work_can_be_released_after_expiration() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue first lease
    let issue1 = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue1), &ctx)
        .unwrap();

    // Expire first lease
    let expire1 = helpers::lease_expired_payload("lease-1", 2_000_000_000);
    reducer
        .apply(&create_event("lease.expired", "s", expire1), &ctx)
        .unwrap();

    // Now work-1 should be available for new lease
    assert!(!reducer.state().has_active_lease("work-1"));

    // Issue second lease for same work
    let issue2 = helpers::lease_issued_payload(
        "lease-2",
        "work-1",
        "actor-2",
        2_500_000_000,
        3_500_000_000,
        vec![2],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue2), &ctx)
        .unwrap();

    // New lease should be active
    assert!(reducer.state().has_active_lease("work-1"));
}

// =============================================================================
// State Query Tests
// =============================================================================

#[test]
fn test_state_counts() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Create 5 leases for different work items
    for i in 1u8..=5 {
        let payload = helpers::lease_issued_payload(
            &format!("lease-{i}"),
            &format!("work-{i}"),
            "actor-1",
            1_000_000_000,
            2_000_000_000,
            vec![i],
        );
        reducer
            .apply(&create_event("lease.issued", "s", payload), &ctx)
            .unwrap();
    }

    assert_eq!(reducer.state().len(), 5);
    assert_eq!(reducer.state().active_count(), 5);
    assert_eq!(reducer.state().released_count(), 0);
    assert_eq!(reducer.state().expired_count(), 0);

    // Release one
    let release1 = helpers::lease_released_payload("lease-1", "COMPLETED");
    reducer
        .apply(&create_event("lease.released", "s", release1), &ctx)
        .unwrap();

    // Expire one
    let expire2 = helpers::lease_expired_payload("lease-2", 2_000_000_000);
    reducer
        .apply(&create_event("lease.expired", "s", expire2), &ctx)
        .unwrap();

    assert_eq!(reducer.state().len(), 5);
    assert_eq!(reducer.state().active_count(), 3);
    assert_eq!(reducer.state().released_count(), 1);
    assert_eq!(reducer.state().expired_count(), 1);
}

#[test]
fn test_active_leases_query() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Create 3 leases
    for i in 1u8..=3 {
        let payload = helpers::lease_issued_payload(
            &format!("lease-{i}"),
            &format!("work-{i}"),
            "actor-1",
            1_000_000_000,
            2_000_000_000,
            vec![i],
        );
        reducer
            .apply(&create_event("lease.issued", "s", payload), &ctx)
            .unwrap();
    }

    // Release one
    let release1 = helpers::lease_released_payload("lease-1", "COMPLETED");
    reducer
        .apply(&create_event("lease.released", "s", release1), &ctx)
        .unwrap();

    let active = reducer.state().active_leases();
    assert_eq!(active.len(), 2);
    // Should be lease-2 and lease-3 (order not guaranteed)
    let active_ids: Vec<&str> = active.iter().map(|l| l.lease_id.as_str()).collect();
    assert!(active_ids.contains(&"lease-2"));
    assert!(active_ids.contains(&"lease-3"));
    assert!(!active_ids.contains(&"lease-1"));
}

#[test]
fn test_leases_by_actor_query() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Create leases for different actors
    let payload1 = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-A",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", payload1), &ctx)
        .unwrap();

    let payload2 = helpers::lease_issued_payload(
        "lease-2",
        "work-2",
        "actor-A",
        1_000_000_000,
        2_000_000_000,
        vec![2],
    );
    reducer
        .apply(&create_event("lease.issued", "s", payload2), &ctx)
        .unwrap();

    let payload3 = helpers::lease_issued_payload(
        "lease-3",
        "work-3",
        "actor-B",
        1_000_000_000,
        2_000_000_000,
        vec![3],
    );
    reducer
        .apply(&create_event("lease.issued", "s", payload3), &ctx)
        .unwrap();

    let leases_for_a = reducer.state().leases_by_actor("actor-A");
    assert_eq!(leases_for_a.len(), 2);

    let leases_for_b = reducer.state().leases_by_actor("actor-B");
    assert_eq!(leases_for_b.len(), 1);

    let leases_for_c = reducer.state().leases_by_actor("actor-C");
    assert!(leases_for_c.is_empty());
}

#[test]
#[allow(deprecated)]
fn test_get_expired_but_active() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Create leases with different expiration times
    let payload1 = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000, // Expires at 2s
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", payload1), &ctx)
        .unwrap();

    let payload2 = helpers::lease_issued_payload(
        "lease-2",
        "work-2",
        "actor-1",
        1_000_000_000,
        3_000_000_000, // Expires at 3s
        vec![2],
    );
    reducer
        .apply(&create_event("lease.issued", "s", payload2), &ctx)
        .unwrap();

    let payload3 = helpers::lease_issued_payload(
        "lease-3",
        "work-3",
        "actor-1",
        1_000_000_000,
        4_000_000_000, // Expires at 4s
        vec![3],
    );
    reducer
        .apply(&create_event("lease.issued", "s", payload3), &ctx)
        .unwrap();

    // At time 2.5s, only lease-1 should be expired
    let expired = reducer.state().get_expired_but_active(2_500_000_000);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].lease_id, "lease-1");

    // At time 3.5s, lease-1 and lease-2 should be expired
    let expired = reducer.state().get_expired_but_active(3_500_000_000);
    assert_eq!(expired.len(), 2);

    // At time 5s, all should be expired
    let expired = reducer.state().get_expired_but_active(5_000_000_000);
    assert_eq!(expired.len(), 3);
}

#[test]
fn test_reset() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", payload), &ctx)
        .unwrap();
    assert!(!reducer.state().is_empty());

    reducer.reset();
    assert!(reducer.state().is_empty());
    assert_eq!(reducer.state().active_count(), 0);
}

#[test]
fn test_ignores_non_lease_events() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    let event = create_event("session.started", "session-1", vec![1, 2, 3]);
    let result = reducer.apply(&event, &ctx);
    assert!(result.is_ok());
    assert!(reducer.state().is_empty());
}

// =============================================================================
// Security Tests - Registrar Signature Validation
// =============================================================================

#[test]
fn test_renewal_on_terminal_lease_errors() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue and expire lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    let expire_payload = helpers::lease_expired_payload("lease-1", 2_000_000_000);
    reducer
        .apply(&create_event("lease.expired", "s", expire_payload), &ctx)
        .unwrap();

    // Try to renew expired lease
    let renew_payload = helpers::lease_renewed_payload("lease-1", 3_000_000_000, vec![2]);
    let result = reducer.apply(&create_event("lease.renewed", "s", renew_payload), &ctx);
    assert!(matches!(
        result,
        Err(LeaseError::LeaseAlreadyTerminal { .. })
    ));
}

// =============================================================================
// Edge Cases and Boundary Conditions
// =============================================================================

#[test]
#[allow(deprecated)]
fn test_lease_at_exact_expiration_boundary() {
    let lease = super::state::Lease::new(
        "lease-1".to_string(),
        "work-1".to_string(),
        "actor-1".to_string(),
        1_000_000_000,
        2_000_000_000,
        vec![1],
    );

    // One nanosecond before expiration
    assert!(!lease.is_expired_at(1_999_999_999));
    assert_eq!(lease.time_remaining(1_999_999_999), 1);

    // Exactly at expiration
    assert!(lease.is_expired_at(2_000_000_000));
    assert_eq!(lease.time_remaining(2_000_000_000), 0);

    // One nanosecond after expiration
    assert!(lease.is_expired_at(2_000_000_001));
    assert_eq!(lease.time_remaining(2_000_000_001), 0);
}

#[test]
fn test_multiple_works_single_actor() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Single actor can hold multiple leases for different work items
    for i in 1u8..=3 {
        let payload = helpers::lease_issued_payload(
            &format!("lease-{i}"),
            &format!("work-{i}"),
            "actor-1", // Same actor
            1_000_000_000,
            2_000_000_000,
            vec![i],
        );
        reducer
            .apply(&create_event("lease.issued", "s", payload), &ctx)
            .unwrap();
    }

    assert_eq!(reducer.state().active_count(), 3);
    let actor_leases = reducer.state().leases_by_actor("actor-1");
    assert_eq!(actor_leases.len(), 3);
}

#[test]
fn test_lease_summary() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    let payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1, 2, 3, 4],
    );
    reducer
        .apply(&create_event("lease.issued", "s", payload), &ctx)
        .unwrap();

    // Renew once
    let renew = helpers::lease_renewed_payload("lease-1", 3_000_000_000, vec![5, 6, 7, 8]);
    reducer
        .apply(&create_event("lease.renewed", "s", renew), &ctx)
        .unwrap();

    let lease = reducer.state().get("lease-1").unwrap();
    let summary = lease.summary();

    assert_eq!(summary.lease_id, "lease-1");
    assert_eq!(summary.work_id, "work-1");
    assert_eq!(summary.actor_id, "actor-1");
    assert_eq!(summary.state, LeaseState::Active);
    assert_eq!(summary.issued_at, 1_000_000_000);
    assert_eq!(summary.expires_at, 3_000_000_000);
    assert_eq!(summary.renewal_count, 1);
}

// =============================================================================
// State Pruning Tests
// =============================================================================

#[test]
fn test_prune_terminal_leases() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Create 3 leases
    for i in 1u8..=3 {
        let payload = helpers::lease_issued_payload(
            &format!("lease-{i}"),
            &format!("work-{i}"),
            "actor-1",
            1_000_000_000,
            2_000_000_000,
            vec![i],
        );
        reducer
            .apply(&create_event("lease.issued", "s", payload), &ctx)
            .unwrap();
    }

    // Release lease-1, expire lease-2
    let release = helpers::lease_released_payload("lease-1", "COMPLETED");
    reducer
        .apply(&create_event("lease.released", "s", release), &ctx)
        .unwrap();

    let expire = helpers::lease_expired_payload("lease-2", 2_000_000_000);
    reducer
        .apply(&create_event("lease.expired", "s", expire), &ctx)
        .unwrap();

    assert_eq!(reducer.state().len(), 3);
    assert_eq!(reducer.state().terminal_count(), 2);
    assert_eq!(reducer.state().active_count(), 1);

    // Prune terminal leases
    let pruned = reducer.state_mut().prune_terminal_leases();
    assert_eq!(pruned, 2);
    assert_eq!(reducer.state().len(), 1);
    assert_eq!(reducer.state().terminal_count(), 0);
    assert!(reducer.state().get("lease-3").is_some());
}

#[test]
fn test_prune_terminal_leases_before_timestamp() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Create leases
    for i in 1u8..=3 {
        let payload = helpers::lease_issued_payload(
            &format!("lease-{i}"),
            &format!("work-{i}"),
            "actor-1",
            1_000_000_000,
            2_000_000_000,
            vec![i],
        );
        reducer
            .apply(&create_event("lease.issued", "s", payload), &ctx)
            .unwrap();
    }

    // Release at different times
    let release1 = helpers::lease_released_payload("lease-1", "COMPLETED");
    let release1_event = create_event_at("lease.released", "s", release1, 1_500_000_000);
    reducer.apply(&release1_event, &ctx).unwrap();

    let release2 = helpers::lease_released_payload("lease-2", "COMPLETED");
    let release2_event = create_event_at("lease.released", "s", release2, 2_500_000_000);
    reducer.apply(&release2_event, &ctx).unwrap();

    assert_eq!(reducer.state().terminal_count(), 2);

    // Prune only leases terminated before 2_000_000_000
    let pruned = reducer
        .state_mut()
        .prune_terminal_leases_before(2_000_000_000);
    assert_eq!(pruned, 1);
    assert!(reducer.state().get("lease-1").is_none()); // Pruned
    assert!(reducer.state().get("lease-2").is_some()); // Retained
}

// =============================================================================
// Duration Validation Tests
// =============================================================================

#[test]
fn test_lease_issued_invalid_duration_rejected() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // expires_at == issued_at (zero duration)
    let payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        1_000_000_000, // Same as issued_at
        vec![1, 2, 3],
    );
    let result = reducer.apply(&create_event("lease.issued", "s", payload), &ctx);
    assert!(matches!(result, Err(LeaseError::InvalidInput { .. })));

    // expires_at < issued_at (negative duration)
    let payload2 = helpers::lease_issued_payload(
        "lease-2",
        "work-2",
        "actor-1",
        2_000_000_000,
        1_000_000_000, // Before issued_at
        vec![1, 2, 3],
    );
    let result2 = reducer.apply(&create_event("lease.issued", "s", payload2), &ctx);
    assert!(matches!(result2, Err(LeaseError::InvalidInput { .. })));
}

#[test]
fn test_renewal_uses_event_timestamp() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // Issue lease
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "actor-1",
        1_000_000_000,
        2_000_000_000,
        vec![1, 2, 3],
    );
    reducer
        .apply(&create_event("lease.issued", "s", issue_payload), &ctx)
        .unwrap();

    // Renew at a specific timestamp
    let renew_payload = helpers::lease_renewed_payload("lease-1", 3_000_000_000, vec![4, 5, 6]);
    let renew_event = create_event_at("lease.renewed", "s", renew_payload, 1_800_000_000);
    reducer.apply(&renew_event, &ctx).unwrap();

    let lease = reducer.state().get("lease-1").unwrap();
    // last_renewed_at should be the event timestamp, not the new_expires_at
    assert_eq!(lease.last_renewed_at, Some(1_800_000_000));
    assert_eq!(lease.expires_at, 3_000_000_000);
}

// =============================================================================
// TCK-00241: Tick-Based Expiry Tests for Reducer State
// =============================================================================

/// TCK-00241: Tests for tick-based expiry detection in `LeaseReducerState`.
mod tck_00241 {
    use super::*;
    use crate::htf::HtfTick;

    const TICK_RATE_HZ: u64 = 1_000_000; // 1MHz

    fn tick(value: u64) -> HtfTick {
        HtfTick::new(value, TICK_RATE_HZ)
    }

    /// TCK-00241: `get_expired_but_active_at_tick` uses tick-based comparison.
    ///
    /// This test verifies that the `LeaseReducerState` method correctly
    /// identifies expired leases using tick-based timing.
    #[test]
    fn get_expired_but_active_at_tick_uses_ticks() {
        let mut reducer = LeaseReducer::new();
        let ctx = ReducerContext::new(1);

        // Create leases using the standard helper (which creates leases without tick
        // data)
        let payload1 = helpers::lease_issued_payload(
            "lease-1",
            "work-1",
            "actor-1",
            1_000_000_000,
            2_000_000_000,
            vec![1],
        );
        reducer
            .apply(&create_event("lease.issued", "s", payload1), &ctx)
            .unwrap();

        // Since leases created via the helper don't have tick data,
        // they should be treated as expired (fail-closed per SEC-CTRL-FAC-0015)
        let expired = reducer.state().get_expired_but_active_at_tick(&tick(1500));

        // Lease without tick data is fail-closed to expired
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].lease_id, "lease-1");
    }

    /// TCK-00241: Leases with tick data use tick-based expiry.
    ///
    /// This test manually sets tick data to verify correct behavior.
    #[test]
    fn leases_with_tick_data_use_tick_expiry() {
        let mut reducer = LeaseReducer::new();
        let ctx = ReducerContext::new(1);

        // Create lease via helper
        let payload = helpers::lease_issued_payload(
            "lease-1",
            "work-1",
            "actor-1",
            1_000_000_000,
            2_000_000_000,
            vec![1],
        );
        reducer
            .apply(&create_event("lease.issued", "s", payload), &ctx)
            .unwrap();

        // Manually add tick data to simulate proper issuance
        {
            let lease = reducer.state_mut().leases.get_mut("lease-1").unwrap();
            lease.issued_at_tick = Some(tick(1000));
            lease.expires_at_tick = Some(tick(5000)); // Expires at tick 5000
        }

        // At tick 4000, lease should NOT be expired
        let expired = reducer.state().get_expired_but_active_at_tick(&tick(4000));
        assert!(expired.is_empty());

        // At tick 5500, lease SHOULD be expired
        let expired = reducer.state().get_expired_but_active_at_tick(&tick(5500));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].lease_id, "lease-1");
    }

    /// TCK-00241: Wall time does not affect tick-based expiry detection.
    ///
    /// This verifies the core acceptance criterion: wall time changes
    /// do not affect lease validity when using tick-based expiry.
    #[test]
    fn wall_time_changes_do_not_affect_tick_expiry_detection() {
        let mut reducer = LeaseReducer::new();
        let ctx = ReducerContext::new(1);

        // Create lease via helper
        let payload = helpers::lease_issued_payload(
            "lease-1",
            "work-1",
            "actor-1",
            1_000_000_000, // Wall time: 1s
            2_000_000_000, // Wall time expiry: 2s
            vec![1],
        );
        reducer
            .apply(&create_event("lease.issued", "s", payload), &ctx)
            .unwrap();

        // Add tick data: expires at tick 10000
        {
            let lease = reducer.state_mut().leases.get_mut("lease-1").unwrap();
            lease.issued_at_tick = Some(tick(1000));
            lease.expires_at_tick = Some(tick(10000));
        }

        // At tick 5000, lease is NOT expired (tick < 10000)
        // Even though wall_time expiry (2s) would have passed
        let expired = reducer.state().get_expired_but_active_at_tick(&tick(5000));
        assert!(
            expired.is_empty(),
            "Lease should NOT be expired at tick 5000 (expires at tick 10000)"
        );

        // At tick 15000, lease IS expired (tick > 10000)
        let expired = reducer.state().get_expired_but_active_at_tick(&tick(15000));
        assert_eq!(
            expired.len(),
            1,
            "Lease SHOULD be expired at tick 15000 (expires at tick 10000)"
        );
    }
}
