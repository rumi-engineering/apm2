//! Security reproduction tests for the lease module.
//!
//! Note: Tests use the legacy `lease_issued_payload` function to verify
//! backwards compatibility with events that lack tick data.

#![allow(deprecated)]

use super::error::LeaseError;
use super::reducer::{LeaseReducer, helpers};
use super::state::LeaseState;
use crate::ledger::EventRecord;
use crate::reducer::{Reducer, ReducerContext};

fn create_event(
    event_type: &str,
    session_id: &str,
    actor_id: &str,
    payload: Vec<u8>,
) -> EventRecord {
    EventRecord::with_timestamp(event_type, session_id, actor_id, payload, 1_000_000_000)
}

#[test]
fn test_security_unauthorized_release_prevented() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // 1. Issue lease to Alice
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "alice", // Lease owner
        1_000_000_000,
        2_000_000_000,
        vec![1, 2, 3],
    );
    reducer
        .apply(
            &create_event("lease.issued", "s1", "registrar", issue_payload),
            &ctx,
        )
        .unwrap();

    // 2. Bob tries to release Alice's lease
    let release_payload = helpers::lease_released_payload("lease-1", "VOLUNTARY");
    let bob_event = create_event("lease.released", "s1", "bob", release_payload);

    // 3. Apply Bob's event - Expect Error
    let result = reducer.apply(&bob_event, &ctx);
    assert!(matches!(result, Err(LeaseError::Unauthorized { .. })));

    // 4. Assert Lease is STILL Active
    let lease_after = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease_after.state, LeaseState::Active);
}

#[test]
fn test_security_expiration_pruning_evasion_prevented() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // 1. Issue lease (Expires at T=2_000_000_000)
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "alice",
        1_000_000_000,
        2_000_000_000,
        vec![1, 2, 3],
    );
    reducer
        .apply(
            &create_event("lease.issued", "s1", "registrar", issue_payload),
            &ctx,
        )
        .unwrap();

    // 2. Attacker expires the lease but sets expired_at to far future (u64::MAX)
    // This would cause the lease to evade time-based pruning if we use
    // event.expired_at for terminated_at.
    let expired_payload = helpers::lease_expired_payload("lease-1", u64::MAX);
    let event = create_event("lease.expired", "s1", "registrar", expired_payload);
    reducer.apply(&event, &ctx).unwrap();

    // 3. Verify lease is expired
    let lease = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease.state, LeaseState::Expired);

    // 4. CRITICAL: terminated_at should be the lease's actual expires_at
    //    (2_000_000_000),
    // NOT the attacker-provided u64::MAX. This prevents pruning evasion.
    assert_eq!(lease.terminated_at, Some(2_000_000_000));

    // 5. Verify pruning works correctly - lease should be prunable at a
    // reasonable time, not requiring waiting until u64::MAX
    let pruned = reducer
        .state_mut()
        .prune_terminal_leases_before(3_000_000_000);
    assert_eq!(pruned, 1);
    assert!(reducer.state().get("lease-1").is_none());
}

#[test]
fn test_security_early_expiration_prevented() {
    let mut reducer = LeaseReducer::new();
    let ctx = ReducerContext::new(1);

    // 1. Issue lease (Expires at T=2_000_000_000)
    let issue_payload = helpers::lease_issued_payload(
        "lease-1",
        "work-1",
        "alice",
        1_000_000_000,
        2_000_000_000,
        vec![1, 2, 3],
    );
    reducer
        .apply(
            &create_event("lease.issued", "s1", "registrar", issue_payload),
            &ctx,
        )
        .unwrap();

    // 2. Malicious actor sends Expired event with T=1_500_000_000 (Before actual
    //    expiration)
    let expired_payload = helpers::lease_expired_payload("lease-1", 1_500_000_000);
    // Event type lease.expired
    let event = create_event("lease.expired", "s1", "bob", expired_payload);

    // 3. Apply event - Expect Error
    let result = reducer.apply(&event, &ctx);
    assert!(matches!(result, Err(LeaseError::InvalidExpiration { .. })));

    // 4. Assert Lease is STILL Active
    let lease_after = reducer.state().get("lease-1").unwrap();
    assert_eq!(lease_after.state, LeaseState::Active);
}
